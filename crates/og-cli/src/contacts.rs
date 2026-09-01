use std::collections::HashMap;
use std::path::PathBuf;

use ed25519_dalek::VerifyingKey;
use og_crypto::identity;
use serde::{Deserialize, Serialize};

/// Contacts are never secret — they're just an address book of public
/// IDs, so unlike the identity file this is stored in plain postcard, not
/// encrypted at rest.
#[derive(Default, Serialize, Deserialize)]
struct ContactsFile {
    entries: HashMap<String, [u8; 32]>,
}

pub struct Contacts {
    path: PathBuf,
    file: ContactsFile,
}

impl Contacts {
    pub fn load_or_default(path: PathBuf) -> Self {
        let file = std::fs::read(&path).ok().and_then(|bytes| postcard::from_bytes(&bytes).ok()).unwrap_or_default();
        Self { path, file }
    }

    pub fn save(&self) -> anyhow::Result<()> {
        if let Some(parent) = self.path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let bytes = postcard::to_allocvec(&self.file)?;
        std::fs::write(&self.path, bytes)?;
        Ok(())
    }

    pub fn add(&mut self, nickname: String, id: [u8; 32]) {
        self.file.entries.insert(nickname, id);
    }

    pub fn nickname_for(&self, id: &[u8; 32]) -> Option<&str> {
        self.file.entries.iter().find(|(_, v)| *v == id).map(|(k, _)| k.as_str())
    }

    pub fn list(&self) -> impl Iterator<Item = (&str, [u8; 32])> {
        self.file.entries.iter().map(|(k, v)| (k.as_str(), *v))
    }

    /// Resolves a nickname first, falling back to parsing the argument as
    /// a raw `og1...` id directly — so contacts are a convenience, never
    /// a requirement.
    pub fn resolve(&self, nickname_or_id: &str) -> Option<[u8; 32]> {
        if let Some(id) = self.file.entries.get(nickname_or_id) {
            return Some(*id);
        }
        identity::decode_id(nickname_or_id).ok().map(|vk: VerifyingKey| vk.to_bytes())
    }
}
