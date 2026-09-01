use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use og_protocol::Envelope;
use tokio::sync::mpsc;

pub type Outbox = mpsc::UnboundedSender<Envelope>;

/// The relay's entire routable state: which IDs currently have a live
/// connection, and how to reach them. Nothing here survives a process
/// restart, and nothing here is message content — only routing addresses.
#[derive(Default)]
pub struct Router {
    connections: Mutex<HashMap<[u8; 32], Outbox>>,
}

impl Router {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Registers a newly authenticated connection. Returns `false` (and
    /// does not register) if this ID already has a live connection — the
    /// relay holds no queue, so only one active connection per ID makes
    /// sense; a second claimant looks exactly like an ID-squatting attempt.
    pub fn register(&self, id: [u8; 32], outbox: Outbox) -> bool {
        let mut conns = self.connections.lock().unwrap();
        if conns.contains_key(&id) {
            return false;
        }
        conns.insert(id, outbox);
        true
    }

    pub fn unregister(&self, id: &[u8; 32]) {
        self.connections.lock().unwrap().remove(id);
    }

    /// Attempts to forward an envelope to its recipient's live connection.
    /// Returns `false` if the recipient has no live connection right now —
    /// the caller must tell the sender, since the relay never buffers
    /// anything itself: there is no retry, no queue, no persistence.
    pub fn route(&self, envelope: Envelope) -> bool {
        let conns = self.connections.lock().unwrap();
        match conns.get(&envelope.to_id) {
            Some(outbox) => outbox.send(envelope).is_ok(),
            None => false,
        }
    }

    #[cfg(test)]
    pub fn is_registered(&self, id: &[u8; 32]) -> bool {
        self.connections.lock().unwrap().contains_key(id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn second_registration_of_the_same_id_is_rejected() {
        let router = Router::new();
        let (tx1, _rx1) = mpsc::unbounded_channel();
        let (tx2, _rx2) = mpsc::unbounded_channel();
        assert!(router.register([1u8; 32], tx1));
        assert!(!router.register([1u8; 32], tx2));
    }

    #[test]
    fn routing_to_an_unregistered_id_reports_failure() {
        let router = Router::new();
        let envelope = Envelope::new([9u8; 32], [1u8; 32], 0, b"ciphertext").unwrap();
        assert!(!router.route(envelope));
    }

    #[test]
    fn routing_to_a_registered_id_delivers_the_envelope() {
        let router = Router::new();
        let (tx, mut rx) = mpsc::unbounded_channel();
        router.register([2u8; 32], tx);

        let envelope = Envelope::new([2u8; 32], [1u8; 32], 0, b"ciphertext").unwrap();
        assert!(router.route(envelope));
        let received = rx.try_recv().unwrap();
        assert_eq!(received.to_id, [2u8; 32]);
    }

    #[test]
    fn unregister_makes_the_id_unroutable_again() {
        let router = Router::new();
        let (tx, _rx) = mpsc::unbounded_channel();
        router.register([3u8; 32], tx);
        assert!(router.is_registered(&[3u8; 32]));
        router.unregister(&[3u8; 32]);
        assert!(!router.is_registered(&[3u8; 32]));
        let envelope = Envelope::new([3u8; 32], [1u8; 32], 0, b"ciphertext").unwrap();
        assert!(!router.route(envelope));
    }
}
