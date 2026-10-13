//! Relay delivery failure injection; all other calls use the authenticated memory relay.
use super::*;
use kc_wire::{ChannelAllocated, ChannelJoined, DeleteReason, InboxCreated, InboxMessages,
    MessageAccepted, Phase, WriterRegister, WriterRegistered};

pub struct FaultRelay {
    pub inner: MemoryRelay,
    pub fail_post: std::sync::Arc<std::sync::atomic::AtomicBool>,
}
impl Clone for FaultRelay {
    fn clone(&self) -> Self { Self { inner: self.inner.clone(), fail_post: self.fail_post.clone() } }
}
impl FaultRelay {
    pub fn new(inner: MemoryRelay) -> Self {
        Self { inner, fail_post: Default::default() }
    }
}
impl Net for FaultRelay {
    type Relay = Self;
    fn connect(&self, _url: &RelayUrl) -> Result<Self, CliError> { Ok(self.clone()) }
    async fn limits(&self, _url: &RelayUrl) -> Result<Limits, RelayError> { Ok(Limits::current()) }
}
impl RelayApi for FaultRelay {
    async fn allocate(&self) -> Result<ChannelAllocated, RelayError> {
        self.inner.allocate().await
    }
    async fn join(&self, channel: u16) -> Result<ChannelJoined, RelayError> {
        self.inner.join(channel).await
    }
    async fn put_phase(
        &self,
        channel: u16,
        side_token: &str,
        phase: Phase,
        body: &[u8],
    ) -> Result<(), RelayError> {
        self.inner.put_phase(channel, side_token, phase, body).await
    }
    async fn get_phase(
        &self,
        channel: u16,
        side_token: &str,
        phase: Phase,
        wait: Duration,
    ) -> Result<Option<Vec<u8>>, RelayError> {
        self.inner.get_phase(channel, side_token, phase, wait).await
    }
    async fn delete_channel(
        &self,
        channel: u16,
        side_token: &str,
        reason: DeleteReason,
    ) -> Result<(), RelayError> {
        self.inner.delete_channel(channel, side_token, reason).await
    }
    async fn create_inbox(&self) -> Result<InboxCreated, RelayError> {
        self.inner.create_inbox().await
    }
    async fn register_writer(
        &self,
        inbox_id: &str,
        owner_token: &str,
        request: &WriterRegister,
    ) -> Result<WriterRegistered, RelayError> {
        self.inner.register_writer(inbox_id, owner_token, request).await
    }
    async fn delete_writer(
        &self,
        inbox_id: &str,
        owner_token: &str,
        writer_id: &str,
    ) -> Result<(), RelayError> {
        self.inner.delete_writer(inbox_id, owner_token, writer_id).await
    }
    async fn post_message(
        &self,
        inbox_id: &str,
        writer_token: &str,
        body: &[u8],
    ) -> Result<MessageAccepted, RelayError> {
        if self.fail_post.swap(false, std::sync::atomic::Ordering::SeqCst) {
            return Err(kc_proto::relay::RelayError::Transport("injected post failure".into()));
        }
        self.inner.post_message(inbox_id, writer_token, body).await
    }
    async fn list_messages(
        &self,
        inbox_id: &str,
        owner_token: &str,
        wait: Duration,
    ) -> Result<InboxMessages, RelayError> {
        self.inner.list_messages(inbox_id, owner_token, wait).await
    }
    async fn delete_message(
        &self,
        inbox_id: &str,
        owner_token: &str,
        msg_id: &str,
    ) -> Result<(), RelayError> {
        self.inner.delete_message(inbox_id, owner_token, msg_id).await
    }
    async fn delete_inbox(
        &self,
        inbox_id: &str,
        owner_token: &str,
    ) -> Result<(), RelayError> {
        self.inner.delete_inbox(inbox_id, owner_token).await
    }
}
