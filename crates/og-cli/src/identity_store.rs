use std::io::{IsTerminal, Write};
use std::path::Path;

use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use og_crypto::identity::Identity;
use og_crypto::keystore::{self, EncryptedIdentity, KdfParams};

/// Loads the identity at `path`, prompting for its passphrase, or — if
/// nothing exists there yet — generates a fresh one and asks the user to
/// set a passphrase to encrypt it at rest before saving.
pub fn load_or_create(path: &Path) -> anyhow::Result<Identity> {
    if path.exists() {
        println!("Loading identity from {}", path.display());
        let passphrase = read_masked("Passphrase: ")?;
        let encrypted = keystore::load_from_file(path)?;
        keystore::open_identity(&encrypted, passphrase.as_bytes())
            .map_err(|_| anyhow::anyhow!("wrong passphrase, or the identity file is corrupt"))
    } else {
        println!("No identity found at {} — generating a new one.", path.display());
        let identity = Identity::generate();
        println!("Your id: {}", identity.id());
        println!("Set a passphrase to encrypt the private key at rest (this is NOT recoverable if lost).");
        let passphrase = loop {
            let p1 = read_masked("New passphrase: ")?;
            let p2 = read_masked("Confirm passphrase: ")?;
            if p1 == p2 && !p1.is_empty() {
                break p1;
            }
            println!("Passphrases didn't match (or were empty) — try again.");
        };
        let encrypted: EncryptedIdentity = keystore::seal_identity(&identity, passphrase.as_bytes(), KdfParams::DESKTOP)?;
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        keystore::save_to_file(&encrypted, path)?;
        println!("Saved encrypted identity to {}", path.display());
        Ok(identity)
    }
}

/// Reads a line of input with the terminal echo suppressed, so a
/// passphrase never lands in the terminal's own scrollback/history. Raw
/// mode needs a real console; when stdin isn't one (piped input, e.g. for
/// scripted/automated use) this falls back to a plain, echoed read rather
/// than hanging forever waiting for console events that will never come.
fn read_masked(prompt: &str) -> anyhow::Result<String> {
    print!("{prompt}");
    std::io::stdout().flush()?;

    if !std::io::stdin().is_terminal() {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        println!();
        return Ok(line.trim_end_matches(['\n', '\r']).to_string());
    }

    enable_raw_mode()?;
    let mut buf = String::new();
    let result: anyhow::Result<()> = loop {
        match event::read() {
            Ok(Event::Key(k)) if k.kind == KeyEventKind::Press => match k.code {
                KeyCode::Enter => break Ok(()),
                KeyCode::Backspace => {
                    buf.pop();
                }
                KeyCode::Char(c) => buf.push(c),
                KeyCode::Esc => break Err(anyhow::anyhow!("input cancelled")),
                _ => {}
            },
            Ok(_) => {}
            Err(e) => break Err(e.into()),
        }
    };
    disable_raw_mode()?;
    println!();
    result?;
    Ok(buf)
}
