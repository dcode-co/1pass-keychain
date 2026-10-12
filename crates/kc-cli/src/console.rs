//! The terminal as the commands see it: three streams and a few prompts.
//!
//! Commands only prompt when the session is interactive (see [`crate::policy`]); the
//! [`TermConsole`] prompts with inquire on stderr, so stdout stays clean for data. Tests
//! script the prompts with their own [`Console`].

use std::io::{self, Read, Write};

use zeroize::{Zeroize as _, Zeroizing};

/// Why a prompt didn't produce an answer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PromptError {
    /// Esc.
    Cancelled,
    /// Ctrl-C.
    Interrupted,
    /// No terminal, or an I/O error.
    Failed(String),
}

pub trait Console {
    /// Data: values, listings, JSON.
    fn stdout(&mut self) -> &mut dyn Write;
    /// Messages and progress for people.
    fn stderr(&mut self) -> &mut dyn Write;
    fn stdin(&mut self) -> &mut dyn Read;

    fn confirm(&mut self, message: &str, default: bool) -> Result<bool, PromptError>;
    /// One of `options`; returns its index.
    fn select(
        &mut self,
        message: &str,
        options: &[String],
        default: usize,
    ) -> Result<usize, PromptError>;
    /// A checklist; returns the indices of the checked options, in order.
    fn multi_select(
        &mut self,
        message: &str,
        options: &[String],
    ) -> Result<Vec<usize>, PromptError>;
    /// Hidden input, for secret values.
    fn secret(&mut self, message: &str) -> Result<Zeroizing<String>, PromptError>;
    /// Visible input, for codes.
    fn text(&mut self, message: &str) -> Result<Zeroizing<String>, PromptError>;

    /// Called right after the receiving side shows its code. Tests use it to hand the code
    /// to the sending side.
    fn code_shown(&mut self, _code: &str) {}
}

/// The process's own stdin, stdout and stderr, with inquire prompts on stderr.
pub struct TermConsole {
    stdout: io::Stdout,
    stderr: io::Stderr,
    stdin: RawStdin,
}

/// stdin read without std's buffer. That buffer is never wiped, and what kc reads from
/// stdin (values, codes) is secret, so reads go straight to a duplicate of the descriptor.
struct RawStdin {
    file: Option<std::fs::File>,
}

impl Read for RawStdin {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        if self.file.is_none() {
            self.file = Some(duplicate_stdin()?);
        }
        match self.file.as_mut() {
            Some(file) => file.read(buf),
            None => Ok(0),
        }
    }
}

#[cfg(unix)]
fn duplicate_stdin() -> io::Result<std::fs::File> {
    use std::os::fd::AsFd as _;
    Ok(std::fs::File::from(
        io::stdin().as_fd().try_clone_to_owned()?,
    ))
}

#[cfg(windows)]
fn duplicate_stdin() -> io::Result<std::fs::File> {
    use std::os::windows::io::AsHandle as _;
    Ok(std::fs::File::from(
        io::stdin().as_handle().try_clone_to_owned()?,
    ))
}

impl TermConsole {
    pub fn new() -> TermConsole {
        TermConsole {
            stdout: io::stdout(),
            stderr: io::stderr(),
            stdin: RawStdin { file: None },
        }
    }

    /// Our own output goes out before inquire draws a prompt.
    fn before_prompt(&mut self) {
        let _ = self.stdout.flush();
        let _ = self.stderr.flush();
    }
}

impl Default for TermConsole {
    fn default() -> TermConsole {
        TermConsole::new()
    }
}

fn prompt_error(e: inquire::InquireError) -> PromptError {
    use inquire::InquireError as E;
    match e {
        E::OperationCanceled => PromptError::Cancelled,
        E::OperationInterrupted => PromptError::Interrupted,
        E::NotTTY => PromptError::Failed("no terminal to prompt on".into()),
        E::IO(e) => PromptError::Failed(e.to_string()),
        E::InvalidConfiguration(m) => PromptError::Failed(m),
        E::Custom(e) => PromptError::Failed(e.to_string()),
    }
}

impl Console for TermConsole {
    fn stdout(&mut self) -> &mut dyn Write {
        &mut self.stdout
    }

    fn stderr(&mut self) -> &mut dyn Write {
        &mut self.stderr
    }

    fn stdin(&mut self) -> &mut dyn Read {
        &mut self.stdin
    }

    fn confirm(&mut self, message: &str, default: bool) -> Result<bool, PromptError> {
        self.before_prompt();
        inquire::Confirm::new(message)
            .with_default(default)
            .prompt()
            .map_err(prompt_error)
    }

    fn select(
        &mut self,
        message: &str,
        options: &[String],
        default: usize,
    ) -> Result<usize, PromptError> {
        self.before_prompt();
        inquire::Select::new(message, options.to_vec())
            .with_starting_cursor(default.min(options.len().saturating_sub(1)))
            .raw_prompt()
            .map(|choice| choice.index)
            .map_err(prompt_error)
    }

    fn multi_select(
        &mut self,
        message: &str,
        options: &[String],
    ) -> Result<Vec<usize>, PromptError> {
        self.before_prompt();
        inquire::MultiSelect::new(message, options.to_vec())
            .with_page_size(15)
            .with_help_message("space: check, enter: done, type to filter")
            .raw_prompt()
            .map(|chosen| chosen.into_iter().map(|c| c.index).collect())
            .map_err(prompt_error)
    }

    fn secret(&mut self, message: &str) -> Result<Zeroizing<String>, PromptError> {
        self.before_prompt();
        read_line(message, false)
    }

    fn text(&mut self, message: &str) -> Result<Zeroizing<String>, PromptError> {
        self.before_prompt();
        read_line(message, true)
    }
}

/// Leaves raw mode when dropped, however the prompt ends.
struct RawMode;

impl Drop for RawMode {
    fn drop(&mut self) {
        let _ = crossterm::terminal::disable_raw_mode();
    }
}

/// Reads one line at the terminal, key by key, into a wiped buffer that grows by copying
/// into a new wiped buffer. Unlike inquire's line editor, no copy of what was typed is left
/// in memory that isn't wiped (crossterm's own per-key event buffers aside). `echo` shows
/// the typed text (codes); secrets aren't shown at all.
///
/// Keys: Enter ends the line, Backspace and Ctrl-U edit it, Esc cancels and Ctrl-C
/// interrupts.
fn read_line(message: &str, echo: bool) -> Result<Zeroizing<String>, PromptError> {
    use crossterm::event::{self, Event, KeyCode, KeyEventKind, KeyModifiers};

    let failed = |e: io::Error| PromptError::Failed(e.to_string());
    let mut err = io::stderr();
    write!(err, "{message} ").map_err(failed)?;
    err.flush().map_err(failed)?;
    crossterm::terminal::enable_raw_mode().map_err(failed)?;
    let raw = RawMode;
    let mut line = Zeroizing::new(String::with_capacity(128));
    let outcome = loop {
        let key = match event::read().map_err(failed)? {
            Event::Key(key) if key.kind != KeyEventKind::Release => key,
            _ => continue,
        };
        let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
        match key.code {
            KeyCode::Enter => break Ok(()),
            KeyCode::Esc => break Err(PromptError::Cancelled),
            KeyCode::Char('c') if ctrl => break Err(PromptError::Interrupted),
            KeyCode::Char('d') if ctrl && line.is_empty() => break Err(PromptError::Cancelled),
            KeyCode::Char('u') if ctrl => {
                if echo {
                    for _ in 0..line.chars().count() {
                        let _ = write!(err, "\x08 \x08");
                    }
                }
                line.zeroize();
            }
            KeyCode::Backspace => {
                if line.pop().is_some() && echo {
                    let _ = write!(err, "\x08 \x08");
                }
            }
            KeyCode::Char(c) if !ctrl && !c.is_control() => {
                if line.len() + c.len_utf8() > line.capacity() {
                    let mut bigger = Zeroizing::new(String::with_capacity(line.capacity() * 2));
                    bigger.push_str(&line);
                    line = bigger;
                }
                line.push(c);
                if echo {
                    let _ = write!(err, "{c}");
                }
            }
            _ => {}
        }
        let _ = err.flush();
    };
    drop(raw);
    let _ = write!(err, "\r\n");
    let _ = err.flush();
    outcome.map(|()| line)
}
