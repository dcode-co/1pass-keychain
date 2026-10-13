//! Moving items: `send` (with a one-time code, or `--to` a paired device), `receive` and
//! `pair` (PROTOCOL §3, §4, §6).
//!
//! At a terminal, the item names (and, when pairing, the peer's label and the SAS words) are
//! shown before anything is stored or sent, and a person confirms. Without a terminal the
//! policy has already refused whatever needs that confirmation, so nothing here prompts.

use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};

use kc_proto::code::{Code, CodeKind};
use kc_proto::inbox;
use kc_proto::payload::{ChannelPayload, Item, WriterToken};
use kc_proto::relay::{RelayApi, RelayError};
use kc_proto::session::{ReceiverSession, SenderSession, SessionError};
use kc_proto::{CodeError, ItemName, Label, PairOffer, SecretBytes};
use kc_wire::limits::{
    INBOX_MESSAGE_TTL_SECS, MAX_ACK_BYTES, MAX_MESSAGE_BYTES, MAX_PAYLOAD_BYTES, PAD_BUCKET_BYTES,
};
use kc_wire::{ErrorCode, exit};
use serde::Deserialize;
use zeroize::Zeroize as _;

use super::apply::{self, Conflicts, succeeded};
use super::items::not_found;
use super::{Ctx, pairing, say};
use crate::cli::{ConflictPolicy, PairArgs, ReceiveArgs, SendArgs};
use crate::console::Console as _;
use crate::error::{CliError, Result};
use crate::host::Host;
use crate::i18n::tr;
use crate::settings::line_number;
use crate::state::Peer;
use crate::values::{item_name, read_file, read_line_secret, shell_word};

/// Longest code line read from stdin.
const MAX_CODE_LINE: usize = 256;

pub(super) async fn send<H: Host>(ctx: &mut Ctx<'_, H>, args: SendArgs) -> Result<i32> {
    if args.code.as_deref().is_some_and(|c| c != "-") {
        return Err(CliError::usage(tr!(
            "kc never takes a code from the command line (it would stay in shell history and \
             the process list); pass --code - and pipe the code on stdin"
        )));
    }
    let peer = match &args.to {
        Some(label) => Some(find_peer(ctx, label)?),
        None => None,
    };
    let selection = select_items(ctx, &args)?;
    if selection.names.is_empty() && !args.remember {
        say!(ctx, "{}", tr!("Nothing selected; nothing was sent."));
        return Ok(exit::PARTIAL);
    }
    if peer.is_none() {
        check_receipt(&selection.names)?;
    }
    let items = load_items(ctx, &selection.names)?;
    check_size(&items)?;
    let confirm = !selection.from_checklist;
    match peer {
        Some(peer) => send_to_peer(ctx, peer, items, confirm).await,
        None => {
            let opts = CodeSend {
                remember: args.remember,
                code_from_stdin: args.code.is_some(),
                confirm,
            };
            send_with_code(ctx, items, opts).await
        }
    }
}

pub(super) async fn receive<H: Host>(ctx: &mut Ctx<'_, H>, args: ReceiveArgs) -> Result<i32> {
    receive_flow(ctx, args.remember, false, args.on_conflict).await
}

pub(super) async fn pair<H: Host>(ctx: &mut Ctx<'_, H>, args: PairArgs) -> Result<i32> {
    if args.join {
        let opts = CodeSend {
            remember: true,
            code_from_stdin: false,
            confirm: true,
        };
        send_with_code(ctx, Vec::new(), opts).await
    } else {
        receive_flow(ctx, true, true, None).await
    }
}

// ---- choosing items -----------------------------------------------------------------

struct Selection {
    names: Vec<ItemName>,
    /// Picked in the checklist, which is confirmation enough.
    from_checklist: bool,
}

fn select_items<H: Host>(ctx: &mut Ctx<'_, H>, args: &SendArgs) -> Result<Selection> {
    if args.all {
        let names = ctx
            .store
            .list()?
            .into_iter()
            .filter_map(|info| ItemName::new(&info.name).ok())
            .collect();
        return Ok(Selection {
            names,
            from_checklist: false,
        });
    }
    let mut typed: Vec<String> = args.names.iter().chain(&args.names_list).cloned().collect();
    if let Some(path) = &args.bundle {
        typed.extend(read_bundle(path)?);
    }
    let mut names: Vec<ItemName> = Vec::with_capacity(typed.len());
    for t in typed.iter().map(|t| t.trim()).filter(|t| !t.is_empty()) {
        let name = item_name(t)?;
        if !names.contains(&name) {
            names.push(name);
        }
    }
    if !names.is_empty() || args.bundle.is_some() {
        return Ok(Selection {
            names,
            from_checklist: false,
        });
    }
    // No names: the checklist. The policy refused this without a terminal.
    let options: Vec<String> = ctx.store.list()?.into_iter().map(|i| i.name).collect();
    if options.is_empty() {
        if args.remember {
            return Ok(Selection {
                names: Vec::new(),
                from_checklist: true,
            });
        }
        return Err(CliError::not_found(tr!("there are no items to send"))
            .with_hint(tr!("add one with `kc set NAME`")));
    }
    let chosen = ctx.multi_select(&tr!("Items to send:"), &options)?;
    let names = chosen
        .into_iter()
        .filter_map(|i| options.get(i))
        .filter_map(|n| ItemName::new(n).ok())
        .collect();
    Ok(Selection {
        names,
        from_checklist: true,
    })
}

/// A bundle file: `items = ["A", "B"]` (`names` works too).
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Bundle {
    #[serde(alias = "names")]
    items: Vec<String>,
}

fn read_bundle(path: &Path) -> Result<Vec<String>> {
    let shown = path.display();
    let bytes = read_file(path, 1 << 20)?;
    let not_a_bundle = |line: Option<usize>| {
        // The parser's own message could quote the file, and a mistaken --bundle .env would
        // print a secret. Only the line number is shown.
        CliError::usage(match line {
            Some(line) => tr!(
                "{file} isn't a bundle file (line {line}): expected items = [\"NAME\", …]",
                file = shown,
                line = line
            ),
            None => tr!(
                "{file} isn't a bundle file: expected items = [\"NAME\", …]",
                file = shown
            ),
        })
    };
    let text = std::str::from_utf8(&bytes).map_err(|_| not_a_bundle(None))?;
    let bundle: Bundle =
        toml::from_str(text).map_err(|e| not_a_bundle(line_number(text, e.span())))?;
    Ok(bundle.items)
}

fn load_items<H: Host>(ctx: &Ctx<'_, H>, names: &[ItemName]) -> Result<Vec<Item>> {
    let now = ctx.host.now();
    let mut items = Vec::with_capacity(names.len());
    for name in names {
        let Some(value) = ctx.store.get(name.as_str())? else {
            return Err(not_found(name));
        };
        let updated_at = ctx
            .store
            .info(name.as_str())
            .ok()
            .flatten()
            .and_then(|info| info.updated_at)
            .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
            .and_then(|d| i64::try_from(d.as_secs()).ok())
            .unwrap_or(now);
        items.push(Item {
            name: name.clone(),
            value: SecretBytes::from(value.into_zeroizing()),
            updated_at,
        });
    }
    Ok(items)
}

/// Refuses early, before anyone waits on a code, what can't fit in one transfer.
fn check_size(items: &[Item]) -> Result<()> {
    let limit = MAX_PAYLOAD_BYTES.min(MAX_MESSAGE_BYTES) - 8 * 1024;
    let total: usize = items
        .iter()
        .map(|i| i.name.as_str().len() + i.value.len() + 16)
        .sum();
    if total > limit {
        return Err(CliError::usage(tr!(
            "these items add up to {total} KiB; one transfer carries about {limit} KiB",
            total = total.div_ceil(1024),
            limit = limit / 1024
        ))
        .with_hint(tr!("send them in smaller groups")));
    }
    Ok(())
}

/// The largest receipt (`ChannelAck`, postcard) that fits the relay's 16 KiB ack slot: a
/// 4-byte length plus the encoding, padded to a multiple of 4096, plus the 24-byte nonce
/// and the 16-byte tag.
const MAX_RECEIPT: usize = (MAX_ACK_BYTES - 24 - 16) / PAD_BUCKET_BYTES * PAD_BUCKET_BYTES - 4;

/// The largest receipt an honest receiver writes for items with these names: each result
/// repeats the name and may carry a new one (`NAME-N`, at most 128 characters), and a
/// pairing offer may come along.
fn receipt_bound<'a>(names: impl IntoIterator<Item = &'a ItemName>) -> usize {
    const FIXED: usize = 1 + 5 + 1 + 160; // version, count, Option<PairOffer>
    FIXED
        + names
            .into_iter()
            .map(|name| {
                let len = name.as_str().len();
                2 + len + 1 + 2 + (len + 4).min(128)
            })
            .sum::<usize>()
}

/// Refuses a code transfer whose receipt might not fit: the receiver would store the items
/// and then be unable to say so.
fn check_receipt(names: &[ItemName]) -> Result<()> {
    if receipt_bound(names) <= MAX_RECEIPT {
        return Ok(());
    }
    let fit = (1..=names.len())
        .take_while(|n| receipt_bound(&names[..*n]) <= MAX_RECEIPT)
        .last()
        .unwrap_or(0);
    Err(CliError::usage(tr!(
        "{n} items are too many for one transfer: the receiving device confirms each one, and \
         that receipt must fit in 16 KiB",
        n = names.len()
    ))
    .with_hint(tr!("send them in groups of at most {fit}", fit = fit)))
}

/// Every name, so a person confirming a transfer sees all of it.
fn names_of(items: &[Item]) -> String {
    items
        .iter()
        .map(|i| i.name.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

// ---- remembered devices ------------------------------------------------------------------

fn find_peer<H: Host>(ctx: &Ctx<'_, H>, label: &str) -> Result<Peer> {
    ctx.state.load_peers()?.find(label).cloned().ok_or_else(|| {
        CliError::not_found(tr!("no paired device has that label"))
            .with_hint(tr!("`kc peers` lists them; `kc pair` pairs a new one"))
    })
}

async fn send_to_peer<H: Host>(
    ctx: &mut Ctx<'_, H>,
    peer: Peer,
    items: Vec<Item>,
    confirm: bool,
) -> Result<i32> {
    let label = peer.label.clone();
    let key = pairing::device_key(ctx)?.ok_or_else(|| {
        CliError::not_found(tr!(
            "this device has no device key; pair it first with `kc pair`"
        ))
    })?;
    let stored = ctx.store.get_internal(&peer.token_key())?.ok_or_else(|| {
        CliError::not_found(tr!(
            "the keychain has no token for sending to {label}; pair with it again",
            label = label
        ))
    })?;
    let mut raw: [u8; 32] = stored.as_bytes().try_into().map_err(|_| {
        CliError::failure(tr!(
            "the token for {label} is damaged; pair again",
            label = label
        ))
    })?;
    let token = WriterToken::from_bytes(raw);
    raw.zeroize();
    drop(stored);

    if ctx.interactive() && confirm {
        say!(ctx, "{}", tr!("Items: {names}", names = names_of(&items)));
        let (n, fingerprint) = (items.len(), peer.fingerprint.short());
        let question = if n == 1 {
            tr!(
                "Send {n} item to {label} ({fingerprint})?",
                n = n,
                label = label,
                fingerprint = fingerprint
            )
        } else {
            tr!(
                "Send {n} items to {label} ({fingerprint})?",
                n = n,
                label = label,
                fingerprint = fingerprint
            )
        };
        if !ctx.confirm(&question, true)? {
            say!(ctx, "{}", tr!("Nothing was sent."));
            return Ok(exit::PARTIAL);
        }
    }
    let count = items.len();
    let ttl = Duration::from_secs(INBOX_MESSAGE_TTL_SECS);
    let sealed = inbox::seal(&key, &peer.device_pk, &items, ttl, ctx.host.now())?;
    drop(items);
    let relay = ctx.connect()?;
    relay
        .post_message(&peer.inbox_id.to_b64url(), &token.bearer(), &sealed.body)
        .await
        .map_err(|e| post_error(e, &label))?;
    let text = if count == 1 {
        tr!(
            "Sent {n} item to {label}. They're stored there when `kc inbox` runs (within 72 hours).",
            n = count,
            label = label
        )
    } else {
        tr!(
            "Sent {n} items to {label}. They're stored there when `kc inbox` runs (within 72 hours).",
            n = count,
            label = label
        )
    };
    say!(ctx, "{text}");
    Ok(exit::OK)
}

fn post_error(e: RelayError, label: &Label) -> CliError {
    match e.code() {
        Some(ErrorCode::Unauthorized) => CliError::new(
            exit::AUTH_FAILED,
            tr!(
                "{label} no longer accepts messages from this device",
                label = label
            ),
        )
        .with_hint(tr!(
            "it was unpaired there, or one of the devices rotated its key; pair again"
        )),
        Some(ErrorCode::InboxFull) => CliError::new(
            exit::RELAY_UNAVAILABLE,
            tr!(
                "{label}'s inbox is full: at most 10 messages (2 MiB) from each device, and 20 \
                 in all, wait there",
                label = label
            ),
        )
        .with_hint(tr!(
            "run `kc inbox` on {label}, then send again",
            label = label
        )),
        Some(ErrorCode::RateLimited) => {
            let hint = e.retry_after().map_or_else(
                || tr!("try again"),
                |d| tr!("try again in {seconds} s", seconds = d.as_secs().max(1)),
            );
            CliError::new(
                exit::RELAY_UNAVAILABLE,
                tr!(
                    "the relay is limiting messages from this device to {label}",
                    label = label
                ),
            )
            .with_hint(hint)
        }
        Some(ErrorCode::TooLarge) => CliError::usage(tr!(
            "the message to {label} is larger than the relay accepts",
            label = label
        ))
        .with_hint(tr!("send fewer items at a time")),
        _ => CliError::from(e).context(tr!("sending to {label}", label = label)),
    }
}

// ---- one-time codes ------------------------------------------------------------------------

struct CodeSend {
    remember: bool,
    code_from_stdin: bool,
    /// Ask before sending (no checklist was shown).
    confirm: bool,
}

/// A code error without the typed text: a mistyped word is part of a secret code, and a
/// piped mistake could be anything. At a terminal, where the person sees what they typed
/// anyway, the suggested word is shown too.
fn code_error_text(e: &CodeError, interactive: bool) -> String {
    match e {
        CodeError::Empty => tr!("no code was entered"),
        CodeError::BadChannel => {
            tr!("a code starts with the channel number (1-9999), like 4721-absurd-amulet")
        }
        CodeError::WordCount { found } => tr!(
            "a code has 2 words (transfer) or 3 words (pairing) after the number, but {found} \
             were entered",
            found = found
        ),
        // A whole sentence per kind (the code found is always the other one), so the kind
        // names are translated with it.
        CodeError::WrongKind { expected, .. } => match expected {
            CodeKind::Pairing => {
                tr!("this needs a pairing code (3 words), but a transfer code was entered")
            }
            CodeKind::Transfer => {
                tr!("this needs a transfer code (2 words), but a pairing code was entered")
            }
        },
        CodeError::UnknownWord {
            position,
            suggestion,
            ..
        } => match suggestion {
            Some(word) if interactive => tr!(
                "word {position} is not a code word; did you mean {word}?",
                position = position,
                word = format!("{word:?}")
            ),
            _ => tr!(
                "word {position} is not a code word; check its spelling",
                position = position
            ),
        },
        CodeError::MisplacedWord { position } => tr!(
            "word {position} belongs at a different position; check the order of the words",
            position = position
        ),
    }
}

fn read_code<H: Host>(
    ctx: &mut Ctx<'_, H>,
    kind: Option<CodeKind>,
    from_stdin: bool,
) -> Result<Code> {
    let parse = |typed: &str| match kind {
        Some(kind) => Code::parse_as(typed, kind),
        None => Code::parse(typed),
    };
    if from_stdin {
        let line = read_line_secret(ctx.host.console().stdin(), MAX_CODE_LINE).map_err(|e| {
            CliError::usage(tr!("can't read the code from stdin: {error}", error = e))
        })?;
        return parse(&line).map_err(|e| {
            let err = CliError::usage(tr!(
                "invalid code: {reason}",
                reason = code_error_text(&e, false)
            ));
            match e {
                CodeError::WrongKind { .. } => err.with_hint(tr!(
                    "on the other device, run `kc receive --remember` or `kc pair`"
                )),
                _ => err,
            }
        });
    }
    let prompt = match kind {
        Some(CodeKind::Pairing) => tr!("Pairing code shown on the other device:"),
        _ => tr!("Code shown on the other device:"),
    };
    for _ in 0..5 {
        let typed = ctx.text(&prompt)?;
        match parse(&typed) {
            Ok(code) => return Ok(code),
            Err(e) => say!(ctx, "{}", code_error_text(&e, true)),
        }
    }
    Err(CliError::usage(tr!("too many invalid codes")))
}

/// Sends `items` over a one-time code.
///
/// When pairing, the sender shows the SAS words as soon as the keys are confirmed, but asks
/// whether they match only after the receipt: the receiving side can show its words only
/// once the payload has arrived, so asking earlier would make the person confirm blind.
/// Declining then forgets the other device and revokes the token it was given.
async fn send_with_code<H: Host>(
    ctx: &mut Ctx<'_, H>,
    items: Vec<Item>,
    opts: CodeSend,
) -> Result<i32> {
    let code = read_code(
        ctx,
        opts.remember.then_some(CodeKind::Pairing),
        opts.code_from_stdin,
    )?;
    let relay = ctx.connect()?;
    let _pairing = match opts.remember {
        true => Some(pairing_lock(ctx)?),
        false => None,
    };
    let mut ident = match opts.remember {
        true => Some(pairing::ensure_identity(ctx, &relay).await?),
        false => None,
    };
    let mut tx = SenderSession::join(&relay, &code, ctx.host.session_options()).await?;
    drop(code);
    let sas = tx.sas();
    if let Some(sas) = &sas {
        let (before, after) = crate::i18n::around(
            "Check that both screens show the same words:  {words}",
            "words",
        );
        say!(ctx, "{before}{sas}{after}");
    }
    if ctx.interactive() && opts.confirm && !items.is_empty() {
        say!(ctx, "{}", tr!("Items: {names}", names = names_of(&items)));
        let n = items.len();
        let question = if n == 1 {
            tr!("Send {n} item to the device showing this code?", n = n)
        } else {
            tr!("Send {n} items to the device showing this code?", n = n)
        };
        let answer = ctx.confirm(&question, true);
        if !matches!(answer, Ok(true)) {
            // Closing the channel tells the other side at once, instead of at its timeout.
            tx.abort().await;
            answer?;
            say!(ctx, "{}", tr!("Cancelled; nothing was sent."));
            return Ok(exit::PARTIAL);
        }
    }
    if sas.is_some() && !opts.remember {
        say!(
            ctx,
            "{}",
            tr!("The other device asked to pair; this send doesn't (that needs --remember).")
        );
    }
    let prepared = match &mut ident {
        Some(ident) => match pairing::prepare_offer(ctx, &relay, ident).await {
            Ok(prepared) => Some(prepared),
            Err(e) => {
                tx.abort().await;
                return Err(e);
            }
        },
        None => None,
    };
    let sent = items.len();
    let payload = ChannelPayload::new(items, prepared.as_ref().map(|p| p.offer.clone()));
    let result = tx.send(&payload).await;
    drop(payload);
    let ack = match result {
        Ok(ack) => ack,
        Err(e) => {
            if let (Some(ident), Some(prepared)) = (&ident, prepared) {
                pairing::discard_offer(ctx, &relay, ident, prepared).await;
            }
            // Refused before anything was written: nothing reached the other device.
            let nothing_sent = matches!(e, SessionError::Invalid(_) | SessionError::TooLarge(_));
            let mut err = CliError::from(e);
            if !nothing_sent && sent > 0 {
                err.hint = Some(tr!(
                    "no receipt came back, so it isn't known whether the other device stored \
                     the items; check there with `kc list` or `kc get NAME --fingerprint`"
                ));
            }
            return Err(err);
        }
    };
    let mut code = if ack.results.len() == sent && ack.results.iter().all(|r| succeeded(&r.status))
    {
        exit::OK
    } else {
        exit::PARTIAL
    };
    if sent > 0 {
        let text = if sent == 1 {
            tr!("Sent {n} item:", n = sent)
        } else {
            tr!("Sent {n} items:", n = sent)
        };
        say!(ctx, "{text}");
        apply::print_results(ctx, &ack.results, false);
    }
    let (Some(ident), Some(prepared)) = (ident, prepared) else {
        return Ok(code);
    };
    let Some(their) = &ack.pair else {
        pairing::discard_offer(ctx, &relay, &ident, prepared).await;
        say!(
            ctx,
            "{}",
            tr!("The other device didn't pair (it declined, or ran without --remember).")
        );
        return Ok(exit::PARTIAL);
    };
    let (label, known) = match local_label(ctx, their) {
        Ok(found) => found,
        Err(e) => {
            pairing::discard_offer(ctx, &relay, &ident, prepared).await;
            return Err(e);
        }
    };
    let fp = their.device_pk.fingerprint();
    announce_offer(ctx, &label, known, their, &fp);
    // The receiving screen shows its words now. The policy keeps non-interactive runs from
    // getting here (`--remember` needs a terminal); without one, nothing is paired.
    let matched = if ctx.interactive() {
        let question = tr!(
            "Do both screens show the same words? Pair with {label}?",
            label = label
        );
        match ctx.confirm(&question, false) {
            Ok(answer) => answer,
            Err(e) => {
                pairing::discard_offer(ctx, &relay, &ident, prepared).await;
                return Err(e);
            }
        }
    } else {
        false
    };
    if matched {
        let label = pairing::remember_peer(ctx, &relay, &ident, their, prepared).await?;
        pairing::announce_pairing(ctx, &label, &fp);
    } else {
        pairing::discard_offer(ctx, &relay, &ident, prepared).await;
        say!(
            ctx,
            "{}",
            tr!(
                "Not paired. The other device may list this one as paired; remove it there with \
                 `kc peers rm`."
            )
        );
        code = exit::AUTH_FAILED;
    }
    Ok(code)
}

/// Who the device offering to pair is: a known peer, or the label it suggests.
fn announce_offer<H: Host>(
    ctx: &mut Ctx<'_, H>,
    label: &Label,
    known: bool,
    offer: &PairOffer,
    fp: &kc_proto::Fingerprint,
) {
    let text = if known {
        tr!(
            "The other device is {label}, already paired (fingerprint {fingerprint}).",
            label = label,
            fingerprint = fp.short()
        )
    } else {
        tr!(
            "The other device calls itself {label} (fingerprint {fingerprint}).",
            label = offer.suggested_label,
            fingerprint = fp.short()
        )
    };
    say!(ctx, "{text}");
}

/// One pairing at a time on this device.
fn pairing_lock<H: Host>(ctx: &Ctx<'_, H>) -> Result<crate::state::StateLock> {
    ctx.state.try_lock_pairing().ok_or_else(|| {
        CliError::failure(tr!(
            "another pairing is under way on this device; finish or cancel it first"
        ))
    })
}

/// How this device will call a peer that offers to pair: its existing label if the key is
/// already known, else the suggestion made valid and unique here.
fn local_label<H: Host>(ctx: &Ctx<'_, H>, offer: &PairOffer) -> Result<(Label, bool)> {
    let peers = ctx.state.load_peers()?;
    Ok(match peers.by_fingerprint(&offer.device_pk.fingerprint()) {
        Some(known) => (known.label.clone(), true),
        None => (
            Label::sanitize(offer.suggested_label.as_str()).unique(|l| peers.label_taken(l)),
            false,
        ),
    })
}

async fn receive_flow<H: Host>(
    ctx: &mut Ctx<'_, H>,
    remember: bool,
    pair_command: bool,
    on_conflict: Option<ConflictPolicy>,
) -> Result<i32> {
    let relay = ctx.connect()?;
    let _pairing = match remember {
        true => Some(pairing_lock(ctx)?),
        false => None,
    };
    let mut ident = match remember {
        true => Some(pairing::ensure_identity(ctx, &relay).await?),
        false => None,
    };
    let kind = if remember {
        CodeKind::Pairing
    } else {
        CodeKind::Transfer
    };
    let mut rx = ReceiverSession::open(&relay, kind, ctx.host.session_options()).await?;
    {
        let code = rx.code().to_canonical();
        let (before, after) = crate::i18n::around("Code: {code}", "code");
        say!(ctx, "{before}{}{after}", code.as_str());
        let other = match (pair_command, remember) {
            (true, _) => "kc pair --join",
            (false, true) => "kc send --remember NAME…",
            (false, false) => "kc send NAME…",
        };
        say!(
            ctx,
            "{}",
            tr!(
                "On the other device, run `{command}` and enter the code. It works once, for up to 10 minutes.",
                command = other
            )
        );
        ctx.host.console().code_shown(&code);
    }
    let received = rx.exchange().await?;
    let payload = received.payload;
    let items = &payload.items;
    if receipt_bound(items.iter().map(|i| &i.name)) > MAX_RECEIPT {
        let count = items.len();
        rx.abort().await;
        return Err(CliError::usage(tr!(
            "the other device sent {count} items at once, more than one transfer can confirm; \
             nothing was stored",
            count = count
        ))
        .with_hint(tr!("send them in smaller groups")));
    }

    let peer_label = match &payload.pair {
        Some(offer) => {
            let (label, known) = local_label(ctx, offer)?;
            let fp = offer.device_pk.fingerprint();
            announce_offer(ctx, &label, known, offer, &fp);
            Some(label)
        }
        None => None,
    };
    if let Some(sas) = &received.sas {
        let (before, after) = crate::i18n::around(
            "Check that both screens show the same words:  {words}",
            "words",
        );
        say!(ctx, "{before}{sas}{after}");
    }
    if !items.is_empty() {
        let (n, names) = (items.len(), names_of(items));
        let text = if n == 1 {
            tr!("Received {n} item: {names}", n = n, names = names)
        } else {
            tr!("Received {n} items: {names}", n = n, names = names)
        };
        say!(ctx, "{text}");
    }
    let pairing = ident.is_some() && payload.pair.is_some();
    if remember && payload.pair.is_none() {
        say!(
            ctx,
            "{}",
            tr!("The other device didn't offer to pair (it needs --remember).")
        );
    }

    if ctx.interactive() && (pairing || !items.is_empty()) {
        let question = match (pairing, items.len()) {
            (true, 0) => tr!("Do the words match? Pair with this device?"),
            (true, 1) => tr!("Do the words match? Pair and store {n} item?", n = 1),
            (true, n) => tr!("Do the words match? Pair and store {n} items?", n = n),
            (false, 1) => tr!("Store {n} item?", n = 1),
            (false, n) => tr!("Store {n} items?", n = n),
        };
        let answer = match ctx.confirm(&question, !pairing) {
            Ok(answer) => answer,
            Err(e) => {
                // Interrupted: close the channel so the other side stops waiting now.
                rx.abort().await;
                return Err(e);
            }
        };
        if !answer {
            let _ = rx.ack(apply::declined(items), None).await;
            say!(ctx, "{}", tr!("Nothing was stored."));
            return Ok(if pairing {
                exit::AUTH_FAILED
            } else {
                exit::PARTIAL
            });
        }
    }

    let from = peer_label
        .as_ref()
        .map_or_else(|| "a one-time code".to_owned(), |l| l.to_string());
    let conflicts = Conflicts::from_flag(on_conflict, ctx.interactive(), true);
    let applied = match apply::apply_items(ctx, items, conflicts, &from, None) {
        Ok(applied) => applied,
        Err(e) => {
            // A conflict question was interrupted; items before it may be stored.
            rx.abort().await;
            return Err(e.with_hint(tr!("items before the interrupted one may be stored here")));
        }
    };

    // Pairing: the peer is stored before the receipt (which carries our offer) goes out.
    // Once the other device has our offer it may post here at once, and that message must
    // not meet an unknown sender.
    let mut pair_error = None;
    let mut paired = None;
    let mut our_offer = None;
    if let (Some(ident), Some(their)) = (&mut ident, &payload.pair) {
        match pairing::prepare_offer(ctx, &relay, ident).await {
            Ok(prepared) => {
                let offer = prepared.offer.clone();
                match pairing::remember_peer(ctx, &relay, ident, their, prepared).await {
                    Ok(label) => {
                        our_offer = Some(offer);
                        paired = Some((label, their.device_pk.fingerprint()));
                    }
                    Err(e) => pair_error = Some(e),
                }
            }
            Err(e) => pair_error = Some(e),
        }
    }
    let acked = rx.ack(applied.results.clone(), our_offer).await;
    if !applied.results.is_empty() {
        say!(ctx, "{}", tr!("Stored here:"));
        apply::print_results(ctx, &applied.results, true);
    }
    if let Err(e) = acked {
        let err = CliError::from(e).context(tr!(
            "the items above are stored here, but the receipt didn't reach the other device"
        ));
        return Err(match paired {
            Some((label, _)) => err.with_hint(tr!(
                "this device paired with {label}; if the other side reports a failure, run \
                 `kc peers rm {word}` here and pair again",
                label = label,
                word = shell_word(label.as_str())
            )),
            None => err,
        });
    }
    if let Some((e, _)) = &applied.keychain_error {
        say!(ctx, "{}", tr!("Keychain error: {error}", error = e));
    }
    let mut code = applied.exit_code();
    if let Some((label, fp)) = &paired {
        pairing::announce_pairing(ctx, label, fp);
    } else if remember {
        if let Some(e) = pair_error {
            say!(ctx, "{}", tr!("Not paired: {reason}", reason = e.message));
            if code == exit::OK {
                code = e.code;
            }
        } else if code == exit::OK {
            code = exit::PARTIAL;
        }
    }
    Ok(code)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bundle_errors_never_quote_the_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("oops.env");
        std::fs::write(&path, "A=1\nSOME_SETTING=not-a-real-value\n").unwrap();
        let err = read_bundle(&path).unwrap_err();
        assert!(!err.message.contains("not-a-real"), "{}", err.message);
        assert!(err.message.contains("line"), "{}", err.message);

        std::fs::write(&path, "items = \"not-a-real-value\"\n").unwrap();
        let err = read_bundle(&path).unwrap_err();
        assert!(!err.message.contains("not-a-real"), "{}", err.message);

        let good = dir.path().join("new-machine.toml");
        std::fs::write(&good, "items = [\"GITHUB_TOKEN\", \"app.env\"]\n").unwrap();
        assert_eq!(read_bundle(&good).unwrap(), ["GITHUB_TOKEN", "app.env"]);
        std::fs::write(&good, "names = [\"A\"]\n").unwrap();
        assert_eq!(read_bundle(&good).unwrap(), ["A"]);
    }

    #[test]
    fn receipts_always_fit() {
        let names = |n: usize, len: usize| -> Vec<ItemName> {
            (0..n)
                .map(|i| ItemName::new(&format!("{i:0>len$}")).unwrap())
                .collect()
        };
        assert_eq!(MAX_RECEIPT, 12_284);
        assert!(check_receipt(&names(200, 20)).is_ok());
        let err = check_receipt(&names(60, 128)).unwrap_err();
        assert_eq!(err.code, exit::USAGE);
        assert!(err.hint.unwrap().contains("at most 46"));

        // The bound holds for the worst receipt an honest receiver writes: every item
        // renamed to a 128-character name, plus a pairing offer.
        let worst = names(46, 128);
        let results = worst
            .iter()
            .map(|n| kc_proto::ItemResult {
                name: n.clone(),
                status: kc_proto::ItemStatus::Renamed(ItemName::new(&"y".repeat(128)).unwrap()),
            })
            .collect();
        let offer = PairOffer {
            suggested_label: Label::new(&"l".repeat(64)).unwrap(),
            device_pk: *kc_proto::DeviceKeyPair::generate().public(),
            inbox_id: kc_proto::payload::InboxId([0; 16]),
            writer_token: WriterToken::generate(),
        };
        let ack = kc_proto::ChannelAck::new(results, Some(offer));
        let encoded = postcard::to_allocvec(&ack).unwrap();
        assert!(encoded.len() <= receipt_bound(&worst), "{}", encoded.len());
        assert!(receipt_bound(&worst) <= MAX_RECEIPT);
    }

    #[test]
    fn size_check_and_name_lists() {
        let item = |name: &str, len: usize| Item {
            name: ItemName::new(name).unwrap(),
            value: SecretBytes::new(vec![b'x'; len]),
            updated_at: 0,
        };
        assert!(check_size(&[item("a", 1000)]).is_ok());
        assert!(check_size(&[item("a", 200 * 1024), item("b", 60 * 1024)]).is_err());
        let many: Vec<Item> = (0..25).map(|i| item(&format!("n{i}"), 1)).collect();
        let shown = names_of(&many);
        assert!(shown.starts_with("n0, n1"));
        assert!(shown.ends_with("n23, n24"));
    }
}
