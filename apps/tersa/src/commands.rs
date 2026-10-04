// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Command implementations.

use std::process::{Command as Process, Stdio};
use std::sync::Arc;

use tersa_application::mailbox::{AccountId, MailboxReader, StoreLimit};
use tersa_application::sync::SyncReport;
use tersa_keys::RootKey;
use tersa_presentation::terminal::SafeText;
use tersa_sync_runtime::{Installation, Revocation, Runtime};
use tersa_vault::{SlotKind, Vault, VaultError, VaultState};

use crate::config::{Config, Paths};
use crate::prompt;

const PASSPHRASE_ATTEMPTS: usize = 3;

pub struct Context {
    pub paths: Paths,
    pub config: Config,
}

/// Whether unlocking may create the vault.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Create {
    Allowed,
    Forbidden,
}

fn open_vault(context: &Context) -> Result<Vault, String> {
    Vault::open(&context.paths.data_dir, context.config.backend).map_err(|error| match error {
        VaultError::KeyringUnavailable => "no system keyring is reachable; set \
             `[vault] backend = \"file\"` to use a passphrase-protected key file instead"
            .to_owned(),
        other => other.to_string(),
    })
}

fn unlock(context: &Context, create: Create) -> Result<Option<Arc<Installation>>, String> {
    let vault = open_vault(context)?;
    let root = match vault.state().map_err(|error| error.to_string())? {
        VaultState::Empty if create == Create::Forbidden => return Ok(None),
        VaultState::Empty => {
            let passphrase = if vault.kind() == SlotKind::File || context.config.passphrase {
                if vault.kind() == SlotKind::File {
                    eprintln!(
                        "No system keyring is available, so tersa protects its key with a \
                         passphrase you will enter each time."
                    );
                }
                Some(prompt::new_passphrase().map_err(|error| error.to_string())?)
            } else {
                None
            };
            vault
                .create(passphrase.as_ref().map(|value| value.as_bytes()))
                .map_err(|error| error.to_string())?
        }
        VaultState::Unprotected => vault.unlock(None).map_err(|error| error.to_string())?,
        VaultState::PassphraseProtected => unlock_with_passphrase(&vault)?,
    };
    let installation =
        Installation::open(&context.paths.data_dir, root).map_err(|error| error.to_string())?;
    Ok(Some(Arc::new(installation)))
}

fn unlock_with_passphrase(vault: &Vault) -> Result<RootKey, String> {
    for _ in 0..PASSPHRASE_ATTEMPTS {
        let passphrase = prompt::passphrase("Passphrase: ").map_err(|error| error.to_string())?;
        match vault.unlock(Some(passphrase.as_bytes())) {
            Ok(root) => return Ok(root),
            Err(VaultError::WrongPassphrase) => eprintln!("Wrong passphrase."),
            Err(other) => return Err(other.to_string()),
        }
    }
    Err("too many wrong passphrases".to_owned())
}

fn require_installation(context: &Context) -> Result<Arc<Installation>, String> {
    unlock(context, Create::Forbidden)?
        .ok_or_else(|| "no accounts yet; run `tersa account add`".to_owned())
}

fn runtime(context: &Context, installation: Arc<Installation>) -> Result<Runtime, String> {
    let client = context.config.oauth_client(&context.paths.config_file())?;
    Runtime::new(installation, client).map_err(|error| error.to_string())
}

fn executor() -> Result<tokio::runtime::Runtime, String> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("could not start the async runtime: {error}"))
}

fn resolve_account(installation: &Installation, raw: &str) -> Result<AccountId, String> {
    let accounts = installation.accounts().map_err(|error| error.to_string())?;
    let mut matches = accounts
        .into_iter()
        .filter(|account| account.as_str() == raw || account.as_str().starts_with(raw));
    match (matches.next(), matches.next()) {
        (Some(account), None) => Ok(account),
        (Some(_), Some(_)) => Err(format!("`{raw}` matches more than one account")),
        (None, _) => Err(format!(
            "no account matches `{raw}`; see `tersa account list`"
        )),
    }
}

fn describe_report(report: SyncReport) -> String {
    let progress = report.progress();
    format!(
        "{} messages, {} bodies cached",
        progress.envelopes, progress.bodies_cached
    )
}

fn open_browser(url: &str) {
    eprintln!(
        "Opening your browser to sign in with Google. If it does not open, visit:\n\n{url}\n"
    );
    let opener = if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    // Arguments are passed as a vector, never through a shell.
    let _ = Process::new(opener)
        .arg(url)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status();
}

pub fn account_add(context: &Context) -> Result<(), String> {
    // Fail on a missing OAuth client before creating any key material.
    context.config.oauth_client(&context.paths.config_file())?;
    let installation = unlock(context, Create::Allowed)?
        .ok_or_else(|| "could not initialize local storage".to_owned())?;
    let runtime = runtime(context, installation)?;
    let added = executor()?
        .block_on(runtime.add_account(open_browser))
        .map_err(|error| error.to_string())?;
    if added.already_present {
        println!(
            "Account {} was already added; its access was renewed.",
            added.account.as_str()
        );
    } else {
        println!("Added account {}.", added.account.as_str());
    }
    match added.first_sync {
        Ok(report) => println!("First sync: {}.", describe_report(report)),
        Err(error) => eprintln!("The first sync failed: {error}. Run `tersa sync` to retry."),
    }
    Ok(())
}

pub fn account_list(context: &Context) -> Result<(), String> {
    let Some(installation) = unlock(context, Create::Forbidden)? else {
        println!("No accounts yet. Run `tersa account add`.");
        return Ok(());
    };
    let accounts = installation.accounts().map_err(|error| error.to_string())?;
    if accounts.is_empty() {
        println!("No accounts yet. Run `tersa account add`.");
    }
    for account in accounts {
        println!("{}", account.as_str());
    }
    Ok(())
}

pub fn account_remove(context: &Context, raw: &str) -> Result<(), String> {
    let installation = require_installation(context)?;
    let account = resolve_account(&installation, raw)?;
    let runtime = runtime(context, installation)?;
    let revocation = executor()?
        .block_on(runtime.remove_account(&account))
        .map_err(|error| error.to_string())?;
    println!("Removed account {} and its local data.", account.as_str());
    if revocation == Revocation::Unconfirmed {
        eprintln!(
            "Google did not confirm revoking access. You can revoke it at \
             https://myaccount.google.com/permissions"
        );
    }
    Ok(())
}

pub fn sync(context: &Context, raw: Option<&str>) -> Result<(), String> {
    let installation = require_installation(context)?;
    let accounts = match raw {
        Some(raw) => vec![resolve_account(&installation, raw)?],
        None => installation.accounts().map_err(|error| error.to_string())?,
    };
    if accounts.is_empty() {
        println!("No accounts yet. Run `tersa account add`.");
        return Ok(());
    }
    let runtime = runtime(context, installation)?;
    let executor = executor()?;
    let mut failures = 0_usize;
    for account in &accounts {
        match executor.block_on(runtime.sync_account(account)) {
            Ok(report) => println!("{}: {}", account.as_str(), describe_report(report)),
            Err(error) => {
                failures += 1;
                eprintln!("{}: {error}", account.as_str());
            }
        }
    }
    if failures == 0 {
        Ok(())
    } else {
        Err(format!(
            "{failures} of {} accounts failed to sync",
            accounts.len()
        ))
    }
}

pub fn inbox(context: &Context, raw: Option<&str>, limit: u16) -> Result<(), String> {
    let installation = require_installation(context)?;
    let account = match raw {
        Some(raw) => resolve_account(&installation, raw)?,
        None => installation
            .accounts()
            .map_err(|error| error.to_string())?
            .into_iter()
            .next()
            .ok_or_else(|| "no accounts yet; run `tersa account add`".to_owned())?,
    };
    let store = installation
        .open_store(&account)
        .map_err(|error| error.to_string())?;
    let limit = StoreLimit::new(limit).map_err(|_error| "invalid limit".to_owned())?;
    let envelopes = executor()?
        .block_on(store.list_envelopes(&account, limit))
        .map_err(|_error| "could not read the local mailbox".to_owned())?;
    if envelopes.is_empty() {
        println!("No cached mail. Run `tersa sync`.");
    }
    for envelope in envelopes {
        let marker = if envelope.is_unread() { '*' } else { ' ' };
        println!(
            "{marker} {}  {:<28}  {}",
            crate::dates::format_utc(envelope.received_at().as_millis()),
            truncate(&SafeText::single_line(envelope.from().as_str()), 28),
            SafeText::single_line(envelope.subject().as_str()),
        );
    }
    Ok(())
}

fn truncate(text: &SafeText, width: usize) -> String {
    let mut characters = text.as_str().chars();
    let head: String = characters.by_ref().take(width).collect();
    if characters.next().is_some() {
        let mut shortened: String = head.chars().take(width.saturating_sub(1)).collect();
        shortened.push('…');
        shortened
    } else {
        head
    }
}

pub fn doctor(context: &Context) {
    let config_file = context.paths.config_file();
    println!("config file:   {}", config_file.display());
    println!(
        "               {}",
        if context.config.file_found {
            "found"
        } else {
            "not found"
        }
    );
    println!("data dir:      {}", context.paths.data_dir.display());
    let client = match (
        &context.config.client_id,
        context.config.has_client_secret(),
    ) {
        (Some(_), true) => "configured (client id and secret)",
        (Some(_), false) => "client id only (Google desktop clients usually need the secret)",
        (None, _) => "missing — see `tersa account add` for setup",
    };
    println!("oauth client:  {client}");
    match open_vault(context) {
        Ok(vault) => {
            let backend = match vault.kind() {
                SlotKind::Keyring => "system keyring",
                SlotKind::File => "passphrase-protected key file",
            };
            let state = match vault.state() {
                Ok(VaultState::Empty) => "no key yet".to_owned(),
                Ok(VaultState::Unprotected) => "key present".to_owned(),
                Ok(VaultState::PassphraseProtected) => {
                    "key present, passphrase required".to_owned()
                }
                Err(error) => format!("error: {error}"),
            };
            println!("key storage:   {backend} ({state})");
        }
        Err(error) => println!("key storage:   unavailable ({error})"),
    }
}
