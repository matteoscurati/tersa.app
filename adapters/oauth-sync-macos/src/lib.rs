// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Trusted macOS OAuth token-lifecycle and bounded Gmail sync composition.
//!
//! This crate is the sole executor of Step 3's network-and-write composition:
//! it forwards the validated OAuth grant into the token exchange, refreshes the
//! access token proactively, gates account identity, and drives the bounded
//! recent sync into the encrypted store. It loads the refresh token from the
//! `tersa-keychain-macos` store, drives the `tersa-gmail-rest-macos` token
//! transport and read adapter, and reconciles through the validated
//! `SQLCipher` write path — all on a pinned current-thread `tokio` runtime.
//!
//! It is the only macOS crate besides the Gmail adapter that reaches the
//! network (reqwest, transitively through `tersa-gmail-rest-macos`); the
//! retrieval-only CLI never depends on it, so the CLI stays network-free.
//!
//! 3d-2 landed the account-identity gate and the gated bounded sync over the
//! inward ports ([`gated_sync`]) plus the token-lifecycle composition. 3d-3a adds
//! the concrete `GmailSession` — one access token backing both the gate's
//! subject and the mailbox surface — with `id_token` freshness validated against a
//! wall clock at construction. Later 3d-3 slices landed the Rust-owned sync
//! worker, its FFI begins, and the cancel-fenced connect; 3d-3d adds the
//! disconnect (consent-withdrawal) teardown: the permit slot's disconnecting
//! coordination with its sync-only cancel registration, and the un-cancellable
//! disconnect worker.

#![forbid(unsafe_code)]

use core::fmt;

use tersa_application::identity::{
    AccountIdentityHasher, AccountIdentityStore, AccountProfile, GateError, IdentityDecision,
    IdentityHash, IdentityReconcile, decide, normalize_subject,
};
use tersa_application::mailbox::{AccountId, MailboxStore, MailboxStoreError, RemoteMailbox};
#[cfg(target_os = "macos")]
use tersa_application::mailbox::{
    BoxFuture, Message, MessageEnvelope, MessageId, Page, PageSize, PageToken, RemoteMailboxError,
};
#[cfg(target_os = "macos")]
use tersa_application::oauth::{AuthorizationGrant, MonotonicClock, WallClock};
use tersa_application::sync::{SyncCoordinator, SyncFailure, SyncPolicy, SyncReport};
#[cfg(target_os = "macos")]
use tersa_application::token::{
    AccessToken, AccountSubject, IdentityExpiry, TokenClientConfig, TokenError, TokenTransport,
    exchange_grant, refresh_access_token,
};
#[cfg(target_os = "macos")]
use tersa_gmail_rest_macos::GmailMailbox;
#[cfg(target_os = "macos")]
use tersa_keychain_macos::oauth_token::{RefreshTokenError, RefreshTokenStore};
#[cfg(target_os = "macos")]
use zeroize::Zeroizing;

// The per-slot whole-cycle permit, the disconnect coordination on it, and the
// Rust-owned worker that holds it are macOS-only: they depend on the platform's
// tokio runtime and the Gmail session. `permit` is crate-internal: the
// mailbox-sync FFI drives a disconnect through `worker::begin_disconnect`, which
// claims the coordination lease + sets the fence itself, so the fence-clearing
// capability never crosses the crate boundary.
#[cfg(target_os = "macos")]
pub(crate) mod permit;
#[cfg(target_os = "macos")]
pub mod worker;

/// Reports why a gated sync stopped before or during the bounded sync.
#[derive(Debug)]
#[non_exhaustive]
pub enum GatedSyncError {
    /// The account-identity gate blocked the sync; no envelope was ever written.
    Gate(GateError),
    /// The gate passed but the bounded sync itself failed.
    Sync(SyncFailure),
}

impl fmt::Display for GatedSyncError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Gate(_) => formatter.write_str("the account-identity gate blocked the sync"),
            Self::Sync(_) => formatter.write_str("the bounded sync failed"),
        }
    }
}

impl std::error::Error for GatedSyncError {}

/// Resolves the account-identity gate before any sync write.
///
/// Hashes the connected account's validated subject against the
/// installation-derived salt, compares it with the recorded hash for the fixed
/// account slot, and either records it (first connect), preserves the cached
/// mailbox (same account), or clears the cached mailbox and records the new hash
/// in one transaction (different account).
///
/// Fails closed: a hasher or store-read failure returns a [`GateError`] and the
/// caller must not proceed to any sync write. A read failure is never mistaken
/// for a first connect, so an unavailable identity can never re-baseline the
/// store to whoever happens to be connected. The subject itself is in-hand and
/// already validated (by the session at construction), so obtaining it is
/// infallible.
/// The most gate read-decide-record attempts before failing closed. Each lost
/// race means a concurrent cycle committed its own identity, which happens at most
/// once per racer, so a small bound converges in practice; exhaustion is a fault
/// (a livelock or tamper), never a reason to sync under an uncommitted identity.
const MAX_GATE_ATTEMPTS: u8 = 4;

async fn run_identity_gate<P, H, St>(
    account: &AccountId,
    profile: &P,
    hasher: &H,
    store: &St,
) -> Result<IdentityHash, GateError>
where
    P: AccountProfile,
    H: AccountIdentityHasher,
    St: AccountIdentityStore,
{
    let normalized = normalize_subject(profile.subject());
    let fresh = hasher
        .hash(account, &normalized)
        .map_err(GateError::Hasher)?;
    drop(normalized);
    // Read → decide → compare-and-set record, retried on a lost race. A concurrent
    // cycle (cross-process, or an undisciplined caller without the whole-cycle
    // permit) can change the recorded identity between our read and our record; the
    // store's CAS aborts that stale decision with `IdentityRaced`, and we re-read
    // and re-decide against the new state. It converges because a racer commits its
    // identity exactly once, so a bounded number of attempts always reaches a settled
    // state; exhaustion fails closed rather than syncing under an unknown one.
    for _ in 0..MAX_GATE_ATTEMPTS {
        let stored = store
            .load_identity(account)
            .await
            .map_err(GateError::Store)?;
        let action = match decide(stored.as_ref(), &fresh) {
            // The same account: preserve the cached mailbox, write nothing.
            IdentityDecision::Match => return Ok(fresh),
            IdentityDecision::FirstRecord => IdentityReconcile::RecordOnly,
            IdentityDecision::ClearAndRecord => IdentityReconcile::ClearMailboxAndRecord,
        };
        match store
            .reconcile_identity(account, &fresh, action, stored.as_ref())
            .await
        {
            // The gate returns the committed hash as the fence for the sync: every
            // subsequent mailbox write re-checks the recorded identity equals it.
            Ok(()) => return Ok(fresh),
            // A racing cycle recorded a different identity under us — fall through to
            // the next attempt, which re-reads and re-decides against the new state
            // (it may now be Match, or a clear).
            Err(MailboxStoreError::IdentityRaced) => {}
            Err(other) => return Err(GateError::Store(other)),
        }
    }
    // Persistently lost the race: never sync under an identity we could not commit.
    Err(GateError::Store(MailboxStoreError::IdentityRaced))
}

/// Runs the account-identity gate, then the bounded recent sync — over one
/// account session.
///
/// `session` exposes BOTH the profile-fetch surface (`AccountProfile`) and the
/// mailbox-read surface (`RemoteMailbox`), so a single credential necessarily
/// backs the identity check and the sync it guards. This makes the gate's core
/// invariant — the account whose identity is checked is the account whose mail is
/// written — a type-level guarantee, not a caller contract: a caller cannot check
/// one Google user's identity and then sync a different user's mail, because there
/// is only one session (hence one access token) to build both surfaces from. The
/// concrete macOS session (3d-3) must therefore hold a single access token and
/// derive both surfaces from it.
///
/// The gate borrows the session and completes first; only then is the session
/// moved into a [`SyncCoordinator`] as the remote and the sync driven. Because
/// the gate runs to a successful completion before the coordinator exists, a
/// blocked gate means `sync_recent` — and therefore every mailbox write — never
/// runs.
///
/// The identity hash is recorded (or the mailbox cleared and the hash recorded)
/// inside the gate, committed BEFORE any message is synced. So a "messages present
/// but identity absent" state — which the missing-row-is-first-connect branch
/// would misread — is unreachable without tampering with the encrypted store
/// itself, which already requires the database key.
///
/// # Concurrency
///
/// This function requires external per-account serialization across the WHOLE
/// gate-to-write cycle and MUST NOT be called concurrently for the same account
/// slot. The gate's load/decide/record and the sync it guards are distinct steps
/// (each call builds its own [`SyncCoordinator`], whose single-flight set is
/// per-call, not shared), so two overlapping cycles could interleave a stale
/// record over a committed one and let two accounts' mail coexist. Enforcement is
/// NOT provided here: it belongs to the 3d-3 Rust-owned sync worker (the sole
/// production caller, holding one whole-cycle permit per slot) plus an
/// in-transaction identity fence that re-checks the recorded hash inside every
/// mailbox-write transaction. Callers without that discipline break the invariant.
///
/// # Errors
///
/// Returns [`GatedSyncError::Gate`] when the identity gate blocks the sync (no
/// write occurred) and [`GatedSyncError::Sync`] when the bounded sync fails.
pub async fn gated_sync<S, St, H>(
    account: &AccountId,
    session: S,
    hasher: &H,
    store: St,
    policy: SyncPolicy,
) -> Result<SyncReport, GatedSyncError>
where
    S: AccountProfile + RemoteMailbox,
    St: MailboxStore + AccountIdentityStore,
    H: AccountIdentityHasher,
{
    let fence = run_identity_gate(account, &session, hasher, &store)
        .await
        .map_err(GatedSyncError::Gate)?;
    let coordinator = SyncCoordinator::new(session, store);
    coordinator
        .sync_recent(account, policy, &fence)
        .await
        .map_err(GatedSyncError::Sync)
}

/// A connected account's short-lived access token and validated OIDC subject.
///
/// Produced by `connect_account` and [`refresh_account`] from a SINGLE token
/// response, so the access token and the identity-gate `subject` always share an
/// origin (the same principal). 3d-3 builds the sync session from both, feeding
/// the subject to the gate and the access token to the mailbox surface.
#[cfg(target_os = "macos")]
#[derive(Debug)]
pub struct ConnectedAccount {
    access_token: AccessToken,
    subject: AccountSubject,
    identity_expiry: IdentityExpiry,
}

#[cfg(target_os = "macos")]
impl ConnectedAccount {
    /// Returns the short-lived access token with its monotonic expiry.
    #[must_use]
    pub fn access_token(&self) -> &AccessToken {
        &self.access_token
    }

    /// Returns the validated subject of the connected account.
    #[must_use]
    pub fn subject(&self) -> &AccountSubject {
        &self.subject
    }

    /// Returns the `id_token`'s Unix-second freshness window, validated at session
    /// construction against a wall clock.
    #[must_use]
    pub fn identity_expiry(&self) -> IdentityExpiry {
        self.identity_expiry
    }

    /// Splits the connected account into the access token, subject, and freshness
    /// window.
    #[must_use]
    pub fn into_parts(self) -> (AccessToken, AccountSubject, IdentityExpiry) {
        (self.access_token, self.subject, self.identity_expiry)
    }
}

/// Reports why a token-lifecycle step failed.
#[cfg(target_os = "macos")]
#[derive(Debug)]
#[non_exhaustive]
pub enum TokenLifecycleError {
    /// The token exchange or refresh failed. Includes
    /// [`TokenError::IdentityUnverified`], which is non-destructive — the stored
    /// refresh token is left intact for a retry.
    Token(TokenError),
    /// The refresh-token store rejected a read or write.
    Store(RefreshTokenError),
    /// A refresh was requested but no refresh token is stored; re-connect needed.
    NoStoredToken,
    /// The exchange returned no refresh token, so offline refresh is impossible.
    MissingRefreshToken,
    /// The connect was cancelled, observed at one of the three cancel fences:
    /// BEFORE the exchange (no token was ever minted), after the exchange but
    /// BEFORE the refresh-token store (nothing was persisted), or AFTER it
    /// (the cleanup restored the snapshotted prior credential, or deleted the
    /// just-stored token when there was none). A minted token was revoked
    /// best-effort ONLY when the pre-exchange snapshot definitively read
    /// empty (`Ok(None)`) — with a prior credential the minted token is
    /// same-grant and disconnect (3d-3d) revokes it later, and an unreadable
    /// store never licenses a revoke. The local cleanup completed. No NEW
    /// connection was created — but a cancelled RE-connect preserves the
    /// prior credential, so the account may still be connected.
    Cancelled,
    /// The connect was cancelled and the cancellation was acknowledged, but
    /// the post-store cleanup's delete/restore write failed persistently: a
    /// usable token may still sit in the Keychain. NOT a clean cancel — the
    /// worker maps it to `STATUS_INTERNAL` (never `STATUS_CANCELLED`) so 3e
    /// can surface "cancelled — please disconnect to be sure"; disconnect
    /// (3d-3d) deletes the stored token regardless.
    CancelledCleanupIncomplete,
}

#[cfg(target_os = "macos")]
impl core::fmt::Display for TokenLifecycleError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let message = match self {
            Self::Token(_) => "the token exchange or refresh failed",
            Self::Store(_) => "the refresh-token store failed",
            Self::NoStoredToken => "no refresh token is stored; re-connect is required",
            Self::MissingRefreshToken => "the token exchange returned no refresh token",
            Self::Cancelled => {
                "the connect was cancelled; no new connection was created (any pre-existing credential is preserved)"
            }
            Self::CancelledCleanupIncomplete => {
                "the connect was cancelled but a token may remain stored"
            }
        };
        formatter.write_str(message)
    }
}

#[cfg(target_os = "macos")]
impl std::error::Error for TokenLifecycleError {}

/// One connect-account flow's session: the SINGLE source for both claiming the
/// finished grant and querying cancellation, so the claim and the cancel fences
/// provably reference the same session.
///
/// This replaces what would otherwise be two separately-passed closures (a
/// claim and an `is_cancelled` query) that could be silently wired to two
/// DIFFERENT sessions. The bridge's implementation (3b-2) holds the OAuth
/// `session_id` and answers [`ConnectSession::claim`] from `claim_grant(id)`
/// and [`ConnectSession::is_cancelled`] from `is_session_cancelled(id)`, so the
/// two share the id by construction.
#[cfg(target_os = "macos")]
pub trait ConnectSession {
    /// Claims the finished grant and its pinned token-client config for this
    /// session, exactly once: a missing, expired, cancelled, or already-claimed
    /// session yields `None`.
    fn claim(&self) -> Option<(AuthorizationGrant, TokenClientConfig)>;

    /// Whether this session has been cancelled. Checked at the cancel fences:
    /// before the exchange, after the exchange mints tokens, and again after
    /// the refresh-token store.
    fn is_cancelled(&self) -> bool;

    /// Acknowledges that the connect cycle finished, releasing the claimed
    /// session's in-flight lease so its cancel tombstone (if any) resumes
    /// normal TTL reaping. Idempotent and infallible. The connect worker calls
    /// this EXACTLY ONCE after the whole claimed cycle (setup, connect, and
    /// sync) returns, on every outcome — and never from `Drop`: a mid-connect
    /// future drop must NOT retire the tombstone (that would reopen the
    /// store-without-fence bypass the tombstone closes). A claim-miss takes
    /// no lease and must never be completed.
    fn complete(&self);
}

/// Whether the provider confirmed a best-effort token revocation.
///
/// Only the disconnect (3d-3d) teardown consumes this: it maps the outcome
/// onto the worker's closed status set, so a locally-successful teardown whose
/// /revoke could not be confirmed is reported DISTINCTLY from a confirmed one.
/// The connect flow's cancel fences discard it — there the revoke is
/// fire-and-forget (nothing is stored, or the just-stored copy was deleted
/// first), so the outcome changes no behavior on that path.
#[cfg(target_os = "macos")]
#[derive(Debug)]
#[must_use = "the disconnect teardown maps this to the revoke-unconfirmed status; dropping it silently loses the M2 signal"]
pub(crate) enum RevokeOutcome {
    /// The revoke HTTP call succeeded — on the first attempt OR the one retry.
    Confirmed,
    /// Both the first attempt and the one retry failed.
    Failed,
}

/// Revokes a provider-minted token best-effort, retrying ONCE on failure, and
/// reports whether the provider confirmed the revocation.
///
/// Used by the connect flow's cancel fences and store-failure path, and by the
/// disconnect (3d-3d) teardown for the ONE stored token it loads under the
/// whole-cycle permit. Consent withdrawal never gates on the network: on every
/// path the local teardown proceeds whether or not the revoke succeeds. On the
/// connect fence paths nothing is stored (or the just-stored copy was deleted
/// first), so a revoke that fails permanently there leaves a LIVE token at the
/// provider with no in-app remedy — the user can only revoke it from their
/// Google account settings. The single immediate retry shrinks that window to
/// a persistent network or provider failure; it cannot close it.
#[cfg(target_os = "macos")]
pub(crate) async fn revoke_best_effort<T: TokenTransport>(
    transport: &T,
    token: &Zeroizing<String>,
) -> RevokeOutcome {
    if transport.revoke(token).await.is_err() && transport.revoke(token).await.is_err() {
        return RevokeOutcome::Failed;
    }
    RevokeOutcome::Confirmed
}

/// Exchanges a forwarded authorization grant and persists the refresh token.
///
/// Forwards `grant` into the token exchange, requires a validated `subject` (a
/// subject-less response fails, so a connected account's identity is always
/// verified), persists the granted refresh token to `refresh_store`, and returns
/// the short-lived access token with that subject. The grant is dropped (wiped)
/// as soon as the exchange consumes it.
///
/// # Lease
///
/// This function neither claims nor releases the session's in-flight lease:
/// the caller MUST hold a successful [`ConnectSession::claim`] and MUST run
/// [`ConnectSession::complete`] EXACTLY ONCE after this returns, on every
/// outcome. The connect worker does both around the whole claimed cycle.
///
/// # Snapshot-conditional revocation (fail-closed)
///
/// Google `/revoke` revokes the whole GRANT, not one token: revoking a token
/// minted during a connect that ran OVER an existing stored credential would
/// kill the user's working connection. So BEFORE the exchange, the connect
/// snapshots the stored credential (one Keychain read per user-initiated
/// connect, TOCTOU-free because the per-slot whole-cycle permit serializes the
/// slot). Every revoke below fires ONLY when the snapshot DEFINITIVELY read
/// empty (`Ok(None)`): a failed read is UNKNOWN, not "no credential", and an
/// unknown snapshot never licenses a revoke — a grant-scoped /revoke would
/// kill a credential an unreadable store merely hid. With a prior credential,
/// the minted token is same-grant and disconnect (3d-3d) revokes it later —
/// so the connect never revokes, and a cancel restores the prior state
/// instead.
///
/// `session` is the connect flow's cancel-fence query, checked THREE times:
///
/// - PRE-EXCHANGE, before the exchange runs: a cancel observed here means the
///   user cancelled right after the callback, so the connect aborts with
///   [`TokenLifecycleError::Cancelled`] before any token is minted — nothing
///   to revoke or orphan, nothing stored.
/// - PRE-STORE, right after the exchange mints tokens and BEFORE the refresh
///   token is even extracted (so the fence sits above the
///   [`TokenLifecycleError::MissingRefreshToken`] check): a cancel observed
///   here revokes whichever token the exchange minted IFF the snapshot
///   definitively read empty — revoking either the refresh or the access
///   token revokes the grant at Google — and aborts with
///   [`TokenLifecycleError::Cancelled`], storing nothing. With a prior
///   credential or an unknown snapshot, nothing is revoked and any stored
///   token is left intact.
/// - POST-STORE, right after the refresh token is persisted: a cancel that
///   landed in the check→store window runs the cleanup
///   (`finish_cancelled_cleanup`): WITH a snapshotted prior credential it
///   RESTORES the prior bytes and revokes nothing (the stored token is the
///   live handle); WITHOUT one it deletes the just-stored token and revokes
///   it, so no usable credential survives anywhere. The restore-vs-delete
///   choice keys off `prior`, NOT `revocable`: on an unknown (`Err`) read
///   `prior` is None, so the cleanup deletes the just-stored token, which is
///   safe — the token it deletes is the one THIS connect stored. The
///   delete/restore write is retried once (symmetric with
///   `revoke_best_effort`); a persistent failure returns
///   [`TokenLifecycleError::CancelledCleanupIncomplete`] — NOT
///   [`TokenLifecycleError::Cancelled`] — because a usable token may remain in
///   the Keychain. The per-slot whole-cycle permit guarantees no concurrent
///   connect for this account, so the restore/delete cannot clobber another
///   connect; disconnect (3d-3d) remains the backstop for a cancel landing
///   after THIS check.
///
/// The [`TokenLifecycleError::MissingRefreshToken`] path is NOT gated on
/// cancel: with a definitively-empty snapshot the handle-less grant's access
/// token is revoked best-effort (closing the strand AND letting Google mint a
/// refresh on retry); with a prior credential or an unknown snapshot, nothing
/// is revoked — the stored token (if any) is the live handle.
///
/// Revocation is best-effort with one retry (see `revoke_best_effort`): consent
/// withdrawal never gates on the network succeeding. Separately, a FAILED store
/// revokes the minted token best-effort IFF the snapshot definitively read
/// empty, before returning [`TokenLifecycleError::Store`], so a failed first
/// store never strands a live grant at the provider with no local record.
/// An explicitly under-scoped first connect follows the same revocation rule:
/// with a definitively-empty snapshot it revokes the minted refresh token (or
/// access token when no refresh token exists) before returning
/// [`TokenError::InsufficientScope`]; with a prior or unreadable credential it
/// never risks a grant-scoped revoke.
///
/// # Concurrency
///
/// Connect cancellation flows through the tombstone/lease ONLY;
/// `WorkerHandles::request_cancel` must never fire mid-connect; disconnect
/// (3d-3d) serializes on the whole-cycle permit and deletes regardless. The
/// bridge lease (`complete_session`) makes an accidental mid-connect drop
/// fail-safe (the tombstone stays pinned) but does not un-store a token.
///
/// # Errors
///
/// Returns [`TokenLifecycleError::Token`] when the exchange fails (including a
/// missing/invalid identity or insufficient Gmail scope),
/// [`TokenLifecycleError::MissingRefreshToken`] when
/// the exchange returns no refresh token, [`TokenLifecycleError::Cancelled`]
/// when any fence observes a cancellation and the local cleanup completes,
/// [`TokenLifecycleError::CancelledCleanupIncomplete`] when the post-store
/// cleanup's delete/restore write fails persistently, and
/// [`TokenLifecycleError::Store`] when the Keychain rejects the write (the
/// minted token is revoked best-effort first IFF the snapshot definitively
/// read empty).
#[cfg(target_os = "macos")]
pub(crate) async fn connect_account<T, S, C, St>(
    account: &AccountId,
    grant: AuthorizationGrant,
    config: &TokenClientConfig,
    transport: &T,
    refresh_store: &S,
    clock: &C,
    session: &St,
) -> Result<ConnectedAccount, TokenLifecycleError>
where
    T: TokenTransport,
    S: RefreshTokenStore,
    C: MonotonicClock,
    St: ConnectSession + ?Sized,
{
    // PRE-EXCHANGE fence: the user cancelled right after the callback, before
    // the exchange ran — abort now so no token is ever minted (nothing to
    // revoke or orphan). This is downstream of the worker's claim, so the
    // in-flight lease is held and is released by the worker's
    // `ConnectSession::complete`.
    if session.is_cancelled() {
        return Err(TokenLifecycleError::Cancelled);
    }
    // Snapshot the stored credential BEFORE the exchange. Only a DEFINITIVE
    // "nothing stored" (`Ok(None)`) licenses revoking a minted token below:
    // a grant-scoped /revoke would kill a credential an unreadable store
    // merely hid, so a FAILED read is UNKNOWN — never the revoking branch.
    let loaded = refresh_store.load(account);
    let revocable = matches!(loaded, Ok(None));
    let prior = loaded.ok().flatten();

    let success = exchange_grant(&grant, config, transport, clock)
        .await
        .map_err(TokenLifecycleError::Token)?;
    drop(grant);
    let (access_token, rotated_refresh, subject, identity_expiry, gmail_read_granted) =
        success.into_parts();
    // PRE-STORE fence: consent withdrawn mid-exchange — abort, storing nothing.
    if session.is_cancelled() {
        if revocable {
            // Revoke whichever token the exchange minted (revoking either
            // revokes the grant at Google). With a prior credential — or an
            // UNREADABLE snapshot, behind which a live grant could be hiding —
            // this must NOT fire: the minted token is same-grant, so the
            // revoke would kill the user's working connection.
            let token_to_revoke = rotated_refresh.as_ref().unwrap_or(access_token.secret());
            // The connect fences are fire-and-forget: nothing is stored (or the
            // just-stored copy was deleted first), so the outcome is discarded.
            let _ = revoke_best_effort(transport, token_to_revoke).await;
        }
        return Err(TokenLifecycleError::Cancelled);
    }
    // An explicitly under-scoped first connect must not strand a live provider
    // grant after Tersa refuses to store it. Preserve the minted zeroizing
    // access/refresh handle through this lifecycle boundary, revoke it best-
    // effort when the pre-exchange snapshot definitively proved no prior
    // credential exists, then surface the permission-specific terminal.
    if !gmail_read_granted {
        if revocable {
            let token_to_revoke = rotated_refresh.as_ref().unwrap_or(access_token.secret());
            let _ = revoke_best_effort(transport, token_to_revoke).await;
        }
        return Err(TokenLifecycleError::Token(TokenError::InsufficientScope));
    }
    // NOT gated on cancel: a refresh-less exchange strands the grant's only
    // handle, so revoke the access token IFF the snapshot definitively read
    // empty (an unknown read never revokes).
    let Some(refresh) = rotated_refresh else {
        if revocable {
            let _ = revoke_best_effort(transport, access_token.secret()).await;
        }
        return Err(TokenLifecycleError::MissingRefreshToken);
    };
    if let Err(error) = refresh_store.store(account, &refresh) {
        // A failed FIRST store leaves no local record of the minted token:
        // revoke it best-effort rather than strand a live grant at the
        // provider. With a prior credential the stored token is the record,
        // and with an UNREADABLE snapshot a live grant could be hiding — so
        // only a definitively-empty snapshot revokes here.
        if revocable {
            let _ = revoke_best_effort(transport, &refresh).await;
        }
        return Err(TokenLifecycleError::Store(error));
    }
    // POST-STORE fence: the cancel landed in the check→store window. The
    // cleanup keys its restore-vs-delete choice off `prior`: restore iff a
    // prior credential is present, delete otherwise — on an unknown (`Err`)
    // read `prior` is None, so it deletes the just-stored token, which is
    // safe: the token it deletes is the one THIS connect stored.
    if session.is_cancelled() {
        return finish_cancelled_cleanup(
            refresh_store,
            transport,
            account,
            &refresh,
            prior.as_ref(),
        )
        .await;
    }
    Ok(ConnectedAccount {
        access_token,
        subject,
        identity_expiry,
    })
}

/// Runs the post-store cancel cleanup for [`connect_account`].
///
/// WITH a snapshotted prior credential, RESTORES the prior bytes over the
/// just-stored token and revokes NOTHING (the minted token is same-grant;
/// disconnect (3d-3d) revokes it later). WITHOUT one, deletes the just-stored
/// token and revokes it best-effort — the delete-vs-restore choice keys off
/// `prior` alone, so an UNKNOWN (`Err`) snapshot read lands here too: `prior`
/// is None and the cleanup deletes the just-stored token, which is safe
/// because the token it deletes is the one THIS connect stored. The
/// delete/restore WRITE is retried once, symmetric with `revoke_best_effort`.
/// A persistent write failure returns
/// [`TokenLifecycleError::CancelledCleanupIncomplete`] — NOT
/// [`TokenLifecycleError::Cancelled`] — and revokes nothing: a usable token
/// may still sit in the Keychain, and disconnect (3d-3d) is the remedy. On
/// success the cancel is clean and [`TokenLifecycleError::Cancelled`] is
/// returned.
#[cfg(target_os = "macos")]
async fn finish_cancelled_cleanup<S, T>(
    refresh_store: &S,
    transport: &T,
    account: &AccountId,
    refresh: &Zeroizing<String>,
    prior: Option<&Zeroizing<String>>,
) -> Result<ConnectedAccount, TokenLifecycleError>
where
    S: RefreshTokenStore,
    T: TokenTransport,
{
    let cleanup_write = || match prior {
        Some(prior_bytes) => refresh_store.store(account, prior_bytes),
        None => refresh_store.delete(account),
    };
    if cleanup_write().is_err() && cleanup_write().is_err() {
        return Err(TokenLifecycleError::CancelledCleanupIncomplete);
    }
    if prior.is_none() {
        let _ = revoke_best_effort(transport, refresh).await;
    }
    Err(TokenLifecycleError::Cancelled)
}

/// Refreshes the access token from the stored refresh token.
///
/// Loads the stored refresh token, refreshes, persists a rotated refresh token
/// when the provider returns one, and returns the fresh access token with the
/// re-verified subject. A subject-less refresh fails (fail-closed identity),
/// leaving the stored token intact for a retry.
///
/// # Errors
///
/// Returns [`TokenLifecycleError::NoStoredToken`] when nothing is stored,
/// [`TokenLifecycleError::Token`] when the refresh fails (including a
/// missing/invalid identity), and [`TokenLifecycleError::Store`] on a Keychain
/// read or write failure.
#[cfg(target_os = "macos")]
pub async fn refresh_account<T, S, C>(
    account: &AccountId,
    config: &TokenClientConfig,
    transport: &T,
    refresh_store: &S,
    clock: &C,
) -> Result<ConnectedAccount, TokenLifecycleError>
where
    T: TokenTransport,
    S: RefreshTokenStore,
    C: MonotonicClock,
{
    let stored = refresh_store
        .load(account)
        .map_err(TokenLifecycleError::Store)?
        .ok_or(TokenLifecycleError::NoStoredToken)?;
    let success = refresh_access_token(&stored, config, transport, clock)
        .await
        .map_err(TokenLifecycleError::Token)?;
    drop(stored);
    let (access_token, rotated_refresh, subject, identity_expiry, gmail_read_granted) =
        success.into_parts();
    if !gmail_read_granted {
        return Err(TokenLifecycleError::Token(TokenError::InsufficientScope));
    }
    if let Some(refresh) = rotated_refresh {
        refresh_store
            .store(account, &refresh)
            .map_err(TokenLifecycleError::Store)?;
    }
    Ok(ConnectedAccount {
        access_token,
        subject,
        identity_expiry,
    })
}

/// Proactively refreshes only when the access token is within `skew_margin` of
/// expiry, so a sync never begins on a token that could expire mid-flight.
///
/// Returns `Ok(None)` when the current token is still fresh (no refresh
/// performed), or `Ok(Some(..))` with the refreshed account.
///
/// # Errors
///
/// Propagates [`refresh_account`]'s errors when a refresh is due and fails.
#[cfg(target_os = "macos")]
pub async fn refresh_if_due<T, S, C>(
    account: &AccountId,
    access_token: &AccessToken,
    skew_margin: core::time::Duration,
    config: &TokenClientConfig,
    transport: &T,
    refresh_store: &S,
    clock: &C,
) -> Result<Option<ConnectedAccount>, TokenLifecycleError>
where
    T: TokenTransport,
    S: RefreshTokenStore,
    C: MonotonicClock,
{
    if access_token.needs_refresh(clock, skew_margin) {
        let refreshed = refresh_account(account, config, transport, refresh_store, clock).await?;
        Ok(Some(refreshed))
    } else {
        Ok(None)
    }
}

/// The maximum accepted clock skew when validating `id_token` freshness (2 min).
#[cfg(target_os = "macos")]
const IDENTITY_SKEW_SECS: u64 = 120;

/// Reports why a [`GmailSession`] could not be built.
#[cfg(target_os = "macos")]
#[derive(Debug)]
#[non_exhaustive]
pub enum GmailSessionError {
    /// The `id_token` was expired or future-dated — non-destructive, retryable.
    Identity(TokenError),
    /// The mailbox surface could not be constructed from the access token.
    Mailbox(RemoteMailboxError),
}

#[cfg(target_os = "macos")]
impl core::fmt::Display for GmailSessionError {
    fn fmt(&self, formatter: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Identity(_) => formatter.write_str("the id_token failed freshness validation"),
            Self::Mailbox(_) => formatter.write_str("the mailbox surface could not be built"),
        }
    }
}

#[cfg(target_os = "macos")]
impl std::error::Error for GmailSessionError {}

/// One connected account's mailbox surface plus its validated OIDC subject, both
/// derived from a SINGLE access token.
///
/// The gate hashes the subject and the sync reads the mailbox, both backed by the
/// one token — so the checked identity and the written identity necessarily
/// coincide (the type-level guarantee [`gated_sync`] relies on). It is built only
/// from a [`ConnectedAccount`] whose subject the token layer already validated, so
/// the gate is never fed a hand-minted subject; construction also validates the
/// `id_token`'s freshness against a wall clock before the session can drive
/// anything.
#[cfg(target_os = "macos")]
pub struct GmailSession {
    mailbox: GmailMailbox,
    subject: AccountSubject,
}

#[cfg(target_os = "macos")]
impl GmailSession {
    /// Builds a session from a connected account, validating `id_token` freshness
    /// against `wall_clock` first.
    ///
    /// # Errors
    ///
    /// Returns [`GmailSessionError::Identity`] when the `id_token` is expired or
    /// future-dated (non-destructive), and [`GmailSessionError::Mailbox`] when the
    /// access token cannot construct the mailbox surface.
    pub fn new<W: WallClock>(
        account: AccountId,
        connected: ConnectedAccount,
        wall_clock: &W,
    ) -> Result<Self, GmailSessionError> {
        connected
            .identity_expiry()
            .validate_fresh(wall_clock.unix_time(), IDENTITY_SKEW_SECS)
            .map_err(GmailSessionError::Identity)?;
        let (access_token, subject, _identity_expiry) = connected.into_parts();
        let mailbox = GmailMailbox::new(account, access_token.secret().as_str().to_owned())
            .map_err(GmailSessionError::Mailbox)?;
        Ok(Self { mailbox, subject })
    }
}

#[cfg(target_os = "macos")]
impl fmt::Debug for GmailSession {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("GmailSession([REDACTED])")
    }
}

#[cfg(target_os = "macos")]
impl AccountProfile for GmailSession {
    fn subject(&self) -> &AccountSubject {
        &self.subject
    }
}

#[cfg(target_os = "macos")]
impl RemoteMailbox for GmailSession {
    fn list_recent_envelopes<'a>(
        &'a self,
        account: &'a AccountId,
        size: PageSize,
        page_token: Option<&'a PageToken>,
    ) -> BoxFuture<'a, Result<Page<MessageEnvelope>, RemoteMailboxError>> {
        self.mailbox
            .list_recent_envelopes(account, size, page_token)
    }

    fn fetch_message<'a>(
        &'a self,
        account: &'a AccountId,
        message_id: &'a MessageId,
    ) -> BoxFuture<'a, Result<Message, RemoteMailboxError>> {
        self.mailbox.fetch_message(account, message_id)
    }
}

/// Builds the pinned current-thread `tokio` runtime that will drive the
/// connect-time token exchange and the bounded sync worker.
///
/// A dedicated current-thread runtime keeps the composition's async network
/// work off the main thread and out of every other crate; the retrieval-only
/// CLI never constructs it.
///
/// # Errors
///
/// Returns the `tokio` build error when the runtime cannot be created.
#[cfg(target_os = "macos")]
pub fn build_sync_runtime() -> std::io::Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
}

// Rust guideline compliant 1.0.

#[cfg(test)]
mod tests {
    #![expect(clippy::unwrap_used, reason = "tests construct valid fixtures")]

    use std::pin::pin;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex};
    use std::task::{Context, Poll, Waker};

    use tersa_application::identity::{
        AccountIdentityHasher, AccountIdentityStore, AccountProfile, GateError, HasherError,
        IdentityHash, IdentityReconcile,
    };
    use tersa_application::mailbox::{
        AccountId, BoxFuture, MailboxReader, MailboxStore, MailboxStoreError, Message,
        MessageEnvelope, MessageId, Page, PageSize, PageToken, RemoteMailbox, RemoteMailboxError,
        StoreLimit, ThreadId,
    };
    use tersa_application::sync::SyncPolicy;
    use tersa_application::token::AccountSubject;
    use zeroize::Zeroizing;

    use super::{GatedSyncError, gated_sync, run_identity_gate};

    fn subject(value: &str) -> AccountSubject {
        AccountSubject::from_raw_for_test(Zeroizing::new(value.to_owned()))
    }

    fn account() -> AccountId {
        AccountId::new("account-a").unwrap()
    }

    fn drive<T>(future: impl Future<Output = T>) -> T {
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        let mut future = pin!(future);
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("composition future must complete synchronously"),
        }
    }

    struct FakeProfile(AccountSubject);

    impl AccountProfile for FakeProfile {
        fn subject(&self) -> &AccountSubject {
            &self.0
        }
    }

    struct FakeHasher {
        output: Result<[u8; 32], HasherError>,
        seen: Mutex<Vec<String>>,
    }

    impl FakeHasher {
        fn ok(bytes: [u8; 32]) -> Self {
            Self {
                output: Ok(bytes),
                seen: Mutex::new(Vec::new()),
            }
        }
        fn failing() -> Self {
            Self {
                output: Err(HasherError::Unavailable),
                seen: Mutex::new(Vec::new()),
            }
        }
    }

    impl AccountIdentityHasher for FakeHasher {
        fn hash(
            &self,
            _account: &AccountId,
            normalized: &Zeroizing<String>,
        ) -> Result<IdentityHash, HasherError> {
            self.seen
                .lock()
                .unwrap()
                .push(normalized.as_str().to_owned());
            self.output.map(IdentityHash::from_bytes)
        }
    }

    /// Shared log of the identity-record actions a gate applied, readable after the
    /// store is moved into `gated_sync`.
    type IdentityReconcileLog = Arc<Mutex<Vec<([u8; 32], IdentityReconcile)>>>;

    #[derive(Default)]
    struct FakeStore {
        stored: Mutex<Option<[u8; 32]>>,
        load_error: bool,
        reconcile_error: bool,
        identity_reconciles: IdentityReconcileLog,
        sync_reconciles: Arc<AtomicUsize>,
        sync_fences: Arc<Mutex<Vec<[u8; 32]>>>,
        // When set, the next `reconcile_identity` simulates a concurrent cycle
        // having recorded this identity first (then unsets), so the caller's
        // compare-and-set loses the race once and must re-read and re-decide.
        race_next: Mutex<Option<[u8; 32]>>,
    }

    impl FakeStore {
        fn with_stored(bytes: [u8; 32]) -> Self {
            Self {
                stored: Mutex::new(Some(bytes)),
                ..Self::default()
            }
        }
        /// A store whose first `reconcile_identity` loses the compare-and-set to a
        /// concurrent cycle that recorded `bytes`, exercising the gate's retry.
        fn racing_first_write_to(bytes: [u8; 32]) -> Self {
            Self {
                race_next: Mutex::new(Some(bytes)),
                ..Self::default()
            }
        }
        fn identity_reconciles(&self) -> Vec<([u8; 32], IdentityReconcile)> {
            self.identity_reconciles.lock().unwrap().clone()
        }
        /// A shared handle to the recorded reconcile actions, kept after the store
        /// is moved into `gated_sync`, so a test can prove a retried gate re-decided.
        fn identity_reconciles_probe(&self) -> IdentityReconcileLog {
            Arc::clone(&self.identity_reconciles)
        }
        /// A shared handle to the sync-write counter, kept after the store is
        /// moved into `gated_sync`, so a test can prove the write did or did not run.
        fn sync_probe(&self) -> Arc<AtomicUsize> {
            Arc::clone(&self.sync_reconciles)
        }
        /// A shared handle to the fences threaded into the sync writes, so a test
        /// can prove the gate handed the freshly-committed identity hash to the
        /// coordinator rather than a stale, constant, or unrelated value.
        fn fence_probe(&self) -> Arc<Mutex<Vec<[u8; 32]>>> {
            Arc::clone(&self.sync_fences)
        }
    }

    impl AccountIdentityStore for FakeStore {
        fn load_identity<'a>(
            &'a self,
            _account: &'a AccountId,
        ) -> BoxFuture<'a, Result<Option<IdentityHash>, MailboxStoreError>> {
            Box::pin(async move {
                if self.load_error {
                    return Err(MailboxStoreError::Storage);
                }
                Ok(self.stored.lock().unwrap().map(IdentityHash::from_bytes))
            })
        }

        fn reconcile_identity<'a>(
            &'a self,
            _account: &'a AccountId,
            fresh: &'a IdentityHash,
            action: IdentityReconcile,
            expected: Option<&'a IdentityHash>,
        ) -> BoxFuture<'a, Result<(), MailboxStoreError>> {
            let expected = expected.map(|hash| *hash.as_bytes());
            Box::pin(async move {
                // A concurrent cycle records its identity just before our read, once.
                if let Some(winner) = self.race_next.lock().unwrap().take() {
                    *self.stored.lock().unwrap() = Some(winner);
                }
                // Compare-and-set against the identity the gate observed.
                if *self.stored.lock().unwrap() != expected {
                    return Err(MailboxStoreError::IdentityRaced);
                }
                self.identity_reconciles
                    .lock()
                    .unwrap()
                    .push((*fresh.as_bytes(), action));
                if self.reconcile_error {
                    return Err(MailboxStoreError::Storage);
                }
                *self.stored.lock().unwrap() = Some(*fresh.as_bytes());
                Ok(())
            })
        }
    }

    impl MailboxReader for FakeStore {
        fn list_envelopes<'a>(
            &'a self,
            _account: &'a AccountId,
            _limit: StoreLimit,
        ) -> BoxFuture<'a, Result<Vec<MessageEnvelope>, MailboxStoreError>> {
            Box::pin(async { Ok(Vec::new()) })
        }
        fn thread_envelopes<'a>(
            &'a self,
            _account: &'a AccountId,
            _thread_id: &'a ThreadId,
            _limit: StoreLimit,
        ) -> BoxFuture<'a, Result<Vec<MessageEnvelope>, MailboxStoreError>> {
            Box::pin(async { Ok(Vec::new()) })
        }
    }

    impl MailboxStore for FakeStore {
        fn upsert_envelopes<'a>(
            &'a self,
            _account: &'a AccountId,
            _envelopes: &'a [MessageEnvelope],
        ) -> BoxFuture<'a, Result<(), MailboxStoreError>> {
            Box::pin(async { Ok(()) })
        }
        fn put_message<'a>(
            &'a self,
            _account: &'a AccountId,
            _message: &'a Message,
        ) -> BoxFuture<'a, Result<(), MailboxStoreError>> {
            Box::pin(async { Ok(()) })
        }
        fn reconcile_recent_envelopes<'a>(
            &'a self,
            _account: &'a AccountId,
            _envelopes: &'a [MessageEnvelope],
            _keep_limit: StoreLimit,
            fence: &'a IdentityHash,
        ) -> BoxFuture<'a, Result<Vec<MessageId>, MailboxStoreError>> {
            self.sync_reconciles.fetch_add(1, Ordering::SeqCst);
            self.sync_fences.lock().unwrap().push(*fence.as_bytes());
            Box::pin(async { Ok(Vec::new()) })
        }
        fn cache_message_if_present<'a>(
            &'a self,
            _account: &'a AccountId,
            _message: &'a Message,
            _fence: &'a IdentityHash,
        ) -> BoxFuture<'a, Result<bool, MailboxStoreError>> {
            Box::pin(async { Ok(false) })
        }
        fn message<'a>(
            &'a self,
            _account: &'a AccountId,
            _message_id: &'a MessageId,
        ) -> BoxFuture<'a, Result<Option<Message>, MailboxStoreError>> {
            Box::pin(async { Ok(None) })
        }
    }

    // One session object exposes both the profile and the mailbox surface, so a
    // test cannot accidentally pair one account's profile with another's mail —
    // the same constraint `gated_sync` now imposes on production callers.
    impl RemoteMailbox for FakeProfile {
        fn list_recent_envelopes<'a>(
            &'a self,
            _account: &'a AccountId,
            _size: PageSize,
            _page_token: Option<&'a PageToken>,
        ) -> BoxFuture<'a, Result<Page<MessageEnvelope>, RemoteMailboxError>> {
            Box::pin(async { Ok(Page::new(Vec::new(), None)) })
        }
        fn fetch_message<'a>(
            &'a self,
            _account: &'a AccountId,
            _message_id: &'a MessageId,
        ) -> BoxFuture<'a, Result<Message, RemoteMailboxError>> {
            Box::pin(async { Err(RemoteMailboxError::NotFound) })
        }
    }

    fn run_gate(
        profile: &FakeProfile,
        hasher: &FakeHasher,
        store: &FakeStore,
    ) -> Result<(), GateError> {
        // Existing gate tests assert only the reconcile side effects, not the
        // returned fence, so collapse the fence to `()` for them; the fence path
        // itself is exercised where `gated_sync` threads it into the writers.
        drive(run_identity_gate(&account(), profile, hasher, store)).map(|_fence| ())
    }

    #[test]
    fn first_connect_records_only() {
        let store = FakeStore::default();
        run_gate(
            &FakeProfile(subject("user-sub")),
            &FakeHasher::ok([5; 32]),
            &store,
        )
        .unwrap();
        assert_eq!(
            store.identity_reconciles(),
            vec![([5; 32], IdentityReconcile::RecordOnly)]
        );
    }

    #[test]
    fn same_account_preserves_the_store() {
        let store = FakeStore::with_stored([5; 32]);
        run_gate(
            &FakeProfile(subject("user-sub")),
            &FakeHasher::ok([5; 32]),
            &store,
        )
        .unwrap();
        // A match writes nothing.
        assert!(store.identity_reconciles().is_empty());
    }

    #[test]
    fn different_account_clears_and_records() {
        let store = FakeStore::with_stored([5; 32]);
        run_gate(
            &FakeProfile(subject("other-sub")),
            &FakeHasher::ok([9; 32]),
            &store,
        )
        .unwrap();
        assert_eq!(
            store.identity_reconciles(),
            vec![([9; 32], IdentityReconcile::ClearMailboxAndRecord)]
        );
    }

    #[test]
    fn a_lost_first_record_race_re_decides_and_clears_instead_of_re_recording() {
        // A concurrent cycle records a DIFFERENT account's identity ([1;32]) between
        // this gate's read and its compare-and-set. The gate must not blindly retry
        // its stale first-record (which would leave the other account's cached mail
        // in place under the new identity); it re-reads, re-decides ClearAndRecord,
        // and only then records — the cross-process backstop the permit cannot give.
        let store = FakeStore::racing_first_write_to([1; 32]);
        let reconciles = store.identity_reconciles_probe();
        let report = drive(gated_sync(
            &account(),
            FakeProfile(subject("user-sub")),
            &FakeHasher::ok([9; 32]),
            store,
            policy(),
        ));
        assert!(report.is_ok());
        // The raced RecordOnly recorded nothing; only the re-decided clear did.
        assert_eq!(
            *reconciles.lock().unwrap(),
            vec![([9; 32], IdentityReconcile::ClearMailboxAndRecord)]
        );
    }

    #[test]
    fn a_persistently_lost_race_fails_closed_without_syncing() {
        // If every attempt loses the race, the gate exhausts its bounded retries and
        // fails closed rather than syncing under an identity it could not commit.
        struct AlwaysRacingStore;
        impl AccountIdentityStore for AlwaysRacingStore {
            fn load_identity<'a>(
                &'a self,
                _account: &'a AccountId,
            ) -> BoxFuture<'a, Result<Option<IdentityHash>, MailboxStoreError>> {
                Box::pin(async { Ok(None) })
            }
            fn reconcile_identity<'a>(
                &'a self,
                _account: &'a AccountId,
                _fresh: &'a IdentityHash,
                _action: IdentityReconcile,
                _expected: Option<&'a IdentityHash>,
            ) -> BoxFuture<'a, Result<(), MailboxStoreError>> {
                Box::pin(async { Err(MailboxStoreError::IdentityRaced) })
            }
        }
        let hasher = FakeHasher::ok([9; 32]);
        let error = drive(run_identity_gate(
            &account(),
            &FakeProfile(subject("user-sub")),
            &hasher,
            &AlwaysRacingStore,
        ))
        .unwrap_err();
        assert!(matches!(
            error,
            GateError::Store(MailboxStoreError::IdentityRaced)
        ));
    }

    #[test]
    fn subject_is_normalized_before_hashing() {
        let store = FakeStore::default();
        let hasher = FakeHasher::ok([5; 32]);
        drive(run_identity_gate(
            &account(),
            &FakeProfile(subject("  Sub-XYZ-123  ")),
            &hasher,
            &store,
        ))
        .unwrap();
        // Trim only — a `sub` is case-sensitive, so casing must be preserved.
        assert_eq!(hasher.seen.lock().unwrap().as_slice(), ["Sub-XYZ-123"]);
    }

    #[test]
    fn a_hasher_failure_fails_closed() {
        let store = FakeStore::with_stored([5; 32]);
        let result = run_gate(
            &FakeProfile(subject("user-sub")),
            &FakeHasher::failing(),
            &store,
        );
        assert_eq!(result, Err(GateError::Hasher(HasherError::Unavailable)));
        assert!(store.identity_reconciles().is_empty());
    }

    #[test]
    fn a_load_failure_fails_closed_and_never_rebaselines() {
        let store = FakeStore {
            stored: Mutex::new(Some([5; 32])),
            load_error: true,
            ..FakeStore::default()
        };
        let result = run_gate(
            &FakeProfile(subject("user-sub")),
            &FakeHasher::ok([9; 32]),
            &store,
        );
        assert_eq!(result, Err(GateError::Store(MailboxStoreError::Storage)));
        // An unreadable identity must never be treated as a first connect.
        assert!(store.identity_reconciles().is_empty());
    }

    #[test]
    fn a_reconcile_failure_surfaces_as_a_store_error() {
        let store = FakeStore {
            reconcile_error: true,
            ..FakeStore::default()
        };
        let result = run_gate(
            &FakeProfile(subject("user-sub")),
            &FakeHasher::ok([9; 32]),
            &store,
        );
        assert_eq!(result, Err(GateError::Store(MailboxStoreError::Storage)));
    }

    fn policy() -> SyncPolicy {
        SyncPolicy::new(
            PageSize::new(10).unwrap(),
            1,
            StoreLimit::new(10).unwrap(),
            StoreLimit::new(1).unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn a_blocked_gate_never_reaches_the_sync_write() {
        let store = FakeStore::with_stored([5; 32]);
        let sync_writes = store.sync_probe();
        let error = drive(gated_sync(
            &account(),
            FakeProfile(subject("user-sub")),
            &FakeHasher::failing(),
            store,
            policy(),
        ))
        .unwrap_err();
        assert!(matches!(
            error,
            GatedSyncError::Gate(GateError::Hasher(HasherError::Unavailable))
        ));
        // The gate blocked before the coordinator existed: no sync write ran.
        assert_eq!(sync_writes.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn a_passing_gate_runs_the_bounded_sync() {
        let store = FakeStore::default();
        let sync_writes = store.sync_probe();
        let sync_fences = store.fence_probe();
        let report = drive(gated_sync(
            &account(),
            FakeProfile(subject("user-sub")),
            &FakeHasher::ok([5; 32]),
            store,
            policy(),
        ));
        assert!(report.is_ok());
        // The gate passed, so the bounded sync ran exactly once.
        assert_eq!(sync_writes.load(Ordering::SeqCst), 1);
        // ...and it received the freshly-committed identity hash as its fence, so
        // the handoff is behaviorally verified — not merely that a write happened.
        // First connect: the fence is the hasher output the gate just recorded.
        assert_eq!(*sync_fences.lock().unwrap(), vec![[5; 32]]);
    }

    #[test]
    fn a_matching_gate_threads_the_verified_hash_as_the_fence() {
        // Same account: the gate writes nothing, but the sync still runs and its
        // fence is the verified identity hash the store already held.
        let store = FakeStore::with_stored([5; 32]);
        let sync_fences = store.fence_probe();
        let report = drive(gated_sync(
            &account(),
            FakeProfile(subject("user-sub")),
            &FakeHasher::ok([5; 32]),
            store,
            policy(),
        ));
        assert!(report.is_ok());
        assert_eq!(*sync_fences.lock().unwrap(), vec![[5; 32]]);
    }

    #[test]
    fn a_changed_account_threads_the_newly_committed_hash_as_the_fence() {
        // A different account connects: the gate clears and records the NEW hash,
        // and the fence handed to the sync must be that new hash, never the prior
        // one — otherwise a stale fence could match the wrong recorded identity.
        let store = FakeStore::with_stored([1; 32]);
        let sync_fences = store.fence_probe();
        let report = drive(gated_sync(
            &account(),
            FakeProfile(subject("other-sub")),
            &FakeHasher::ok([9; 32]),
            store,
            policy(),
        ));
        assert!(report.is_ok());
        assert_eq!(*sync_fences.lock().unwrap(), vec![[9; 32]]);
    }
}

#[cfg(test)]
#[cfg(target_os = "macos")]
mod token_lifecycle_tests {
    #![expect(clippy::unwrap_used, reason = "tests construct valid fixtures")]

    use std::pin::pin;
    use std::sync::Arc;
    use std::sync::Mutex;
    use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
    use std::task::{Context, Poll, Waker};
    use std::time::Duration;

    use tersa_application::identity::AccountProfile;
    use tersa_application::mailbox::{AccountId, BoxFuture};
    use tersa_application::oauth::{
        AuthorizationConfig, AuthorizationGrant, MonotonicClock, WallClock, prepare_authorization,
    };
    use tersa_application::token::{
        ExchangeRequest, IdTokenClaims, RefreshRequest, TokenClientConfig, TokenError,
        TokenResponse, TokenTransport, TokenTransportError,
    };
    use tersa_keychain_macos::oauth_token::{RefreshTokenError, RefreshTokenStore};
    use url::Url;
    use zeroize::Zeroizing;

    use super::{
        ConnectSession, GmailSession, GmailSessionError, TokenLifecycleError, connect_account,
        refresh_account, refresh_if_due,
    };

    #[derive(Debug)]
    struct FakeWallClock(u64);

    impl WallClock for FakeWallClock {
        fn unix_time(&self) -> u64 {
            self.0
        }
    }

    fn connect_for_session() -> super::ConnectedAccount {
        let store = FakeRefreshStore::empty();
        drive(connect_account(
            &account(),
            make_grant(),
            &config(),
            &FakeTransport::success(Some("granted-refresh")),
            &store,
            &TestClock::at(0),
            &FakeSession::never(),
        ))
        .unwrap()
    }

    #[test]
    fn session_accepts_a_fresh_id_token_and_exposes_the_subject() {
        // valid_claims: iat=1000, exp=5000; now=3000 is within the window.
        let session = GmailSession::new(account(), connect_for_session(), &FakeWallClock(3_000))
            .expect("a fresh id_token builds a session");
        assert_eq!(session.subject().as_str(), TEST_SUBJECT);
    }

    #[test]
    fn session_rejects_a_stale_id_token_non_destructively() {
        // now well past exp + skew -> expired.
        let error = GmailSession::new(account(), connect_for_session(), &FakeWallClock(10_000))
            .expect_err("a stale id_token must not build a session");
        assert!(matches!(error, GmailSessionError::Identity(_)));
    }

    #[test]
    fn session_rejects_a_future_minted_id_token() {
        // now well before iat -> future-minted.
        let error = GmailSession::new(account(), connect_for_session(), &FakeWallClock(1))
            .expect_err("a future-minted id_token must not build a session");
        assert!(matches!(error, GmailSessionError::Identity(_)));
    }

    const CLIENT_ID: &str = "public-test-client";
    const TEST_SUBJECT: &str = "sub-000123";

    fn account() -> AccountId {
        AccountId::new("account-a").unwrap()
    }

    fn redirect() -> Url {
        Url::parse("app.tersa.oauth.test:/oauth/callback").unwrap()
    }

    fn config() -> TokenClientConfig {
        TokenClientConfig::new(CLIENT_ID, redirect(), None).unwrap()
    }

    fn drive<T>(future: impl Future<Output = T>) -> T {
        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        let mut future = pin!(future);
        match future.as_mut().poll(&mut context) {
            Poll::Ready(value) => value,
            Poll::Pending => panic!("composition future must complete synchronously"),
        }
    }

    fn make_grant() -> AuthorizationGrant {
        let authorization_config =
            AuthorizationConfig::new(CLIENT_ID, redirect(), Duration::from_secs(60)).unwrap();
        let prepared = prepare_authorization(authorization_config, TestClock::at(0)).unwrap();
        let state = prepared
            .authorization_url()
            .query_pairs()
            .find_map(|(name, value)| (name == "state").then(|| value.into_owned()))
            .unwrap();
        let mut callback = redirect();
        callback
            .query_pairs_mut()
            .append_pair("state", &state)
            .append_pair("code", "test-code");
        let (_config, mut session) = prepared.into_parts();
        session.finish(&callback).unwrap()
    }

    const TEST_IAT: u64 = 1_000;
    const TEST_EXP: u64 = 5_000;

    fn valid_claims() -> IdTokenClaims {
        IdTokenClaims::new(
            Zeroizing::new(TEST_SUBJECT.to_owned()),
            vec![CLIENT_ID.to_owned()],
            "https://accounts.google.com".to_owned(),
            None,
            TEST_IAT,
            TEST_EXP,
        )
    }

    #[derive(Clone, Debug)]
    struct TestClock(Arc<AtomicU64>);

    impl TestClock {
        fn at(seconds: u64) -> Self {
            Self(Arc::new(AtomicU64::new(seconds)))
        }
        fn set(&self, seconds: u64) {
            self.0.store(seconds, Ordering::SeqCst);
        }
    }

    impl MonotonicClock for TestClock {
        fn now(&self) -> Duration {
            Duration::from_secs(self.0.load(Ordering::SeqCst))
        }
    }

    #[derive(Debug)]
    struct FakeTransport {
        rotated_refresh_token: Option<Zeroizing<String>>,
        claims: Option<IdTokenClaims>,
        gmail_read_granted: bool,
        revoke_result: Result<(), TokenTransportError>,
        revoked: Mutex<Vec<Zeroizing<String>>>,
        exchanges: AtomicUsize,
    }

    impl FakeTransport {
        fn success(rotated: Option<&str>) -> Self {
            Self {
                rotated_refresh_token: rotated.map(|token| Zeroizing::new(token.to_owned())),
                claims: Some(valid_claims()),
                gmail_read_granted: true,
                revoke_result: Ok(()),
                revoked: Mutex::new(Vec::new()),
                exchanges: AtomicUsize::new(0),
            }
        }
        fn without_id_token() -> Self {
            Self {
                rotated_refresh_token: Some(Zeroizing::new("refresh".to_owned())),
                claims: None,
                gmail_read_granted: true,
                revoke_result: Ok(()),
                revoked: Mutex::new(Vec::new()),
                exchanges: AtomicUsize::new(0),
            }
        }
        /// A transport whose revoke fails, so a test can prove the fences still
        /// abort (and retry once) when revocation itself fails.
        fn with_failing_revoke(mut self) -> Self {
            self.revoke_result = Err(TokenTransportError::Transport);
            self
        }
        fn under_scoped(mut self) -> Self {
            self.gmail_read_granted = false;
            self
        }
        fn response(&self) -> TokenResponse {
            TokenResponse::new_with_gmail_read_grant(
                Zeroizing::new("fake-access-token".to_owned()),
                Duration::from_secs(3_600),
                self.rotated_refresh_token.clone(),
                self.claims.clone(),
                self.gmail_read_granted,
            )
        }
        fn revoked(&self) -> Vec<String> {
            self.revoked
                .lock()
                .unwrap()
                .iter()
                .map(|token| token.as_str().to_owned())
                .collect()
        }
        /// How many exchanges were actually polled, so a test can prove a
        /// pre-exchange cancel minted no token at all.
        fn exchange_calls(&self) -> usize {
            self.exchanges.load(Ordering::SeqCst)
        }
    }

    impl TokenTransport for FakeTransport {
        fn exchange(
            &self,
            _request: ExchangeRequest,
        ) -> BoxFuture<'_, Result<TokenResponse, TokenTransportError>> {
            let response = self.response();
            // Record INSIDE the awaited future (the same discipline as the
            // revoke log): an exchange that was never polled — a pre-exchange
            // fence that aborted first — leaves no trace.
            Box::pin(async move {
                self.exchanges.fetch_add(1, Ordering::SeqCst);
                Ok(response)
            })
        }
        fn refresh(
            &self,
            _request: RefreshRequest,
        ) -> BoxFuture<'_, Result<TokenResponse, TokenTransportError>> {
            let response = self.response();
            Box::pin(async move { Ok(response) })
        }
        fn revoke<'a>(
            &'a self,
            token: &'a Zeroizing<String>,
        ) -> BoxFuture<'a, Result<(), TokenTransportError>> {
            // Record INSIDE the awaited future: a revoke that was constructed but
            // never polled (a fence that forgot to await it) leaves no trace, so
            // the assertions on `revoked()` fail rather than pass vacuously.
            Box::pin(async move {
                self.revoked.lock().unwrap().push(token.clone());
                self.revoke_result
            })
        }
    }

    struct FakeRefreshStore {
        stored: Mutex<Option<Zeroizing<String>>>,
        fail_load: bool,
        /// Store calls whose 0-based index is >= this one fail, so a test can
        /// let the initial store succeed and fail only the cleanup's restore
        /// write.
        fail_stores_from: Option<usize>,
        fail_delete: bool,
        store_calls: AtomicUsize,
        delete_calls: AtomicUsize,
    }

    impl FakeRefreshStore {
        fn empty() -> Self {
            Self {
                stored: Mutex::new(None),
                fail_load: false,
                fail_stores_from: None,
                fail_delete: false,
                store_calls: AtomicUsize::new(0),
                delete_calls: AtomicUsize::new(0),
            }
        }
        fn with_token(token: &str) -> Self {
            Self {
                stored: Mutex::new(Some(Zeroizing::new(token.to_owned()))),
                ..Self::empty()
            }
        }
        /// Every load and store fails — the Keychain is down for the whole
        /// connect, so the snapshot read is UNKNOWN (`Err`), never revocable.
        fn failing() -> Self {
            Self {
                fail_load: true,
                fail_stores_from: Some(0),
                ..Self::empty()
            }
        }
        /// Store calls from `from` (0-based) onward fail.
        fn failing_stores_from(mut self, from: usize) -> Self {
            self.fail_stores_from = Some(from);
            self
        }
        /// Every delete fails.
        fn failing_deletes(mut self) -> Self {
            self.fail_delete = true;
            self
        }
        fn stored(&self) -> Option<String> {
            self.stored
                .lock()
                .unwrap()
                .as_ref()
                .map(|token| token.as_str().to_owned())
        }
    }

    impl RefreshTokenStore for FakeRefreshStore {
        fn store(
            &self,
            _account: &AccountId,
            token: &Zeroizing<String>,
        ) -> Result<(), RefreshTokenError> {
            let call = self.store_calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_stores_from.is_some_and(|from| call >= from) {
                return Err(RefreshTokenError::OperationFailed);
            }
            *self.stored.lock().unwrap() = Some(token.clone());
            Ok(())
        }
        fn load(
            &self,
            _account: &AccountId,
        ) -> Result<Option<Zeroizing<String>>, RefreshTokenError> {
            if self.fail_load {
                return Err(RefreshTokenError::OperationFailed);
            }
            Ok(self.stored.lock().unwrap().clone())
        }
        fn delete(&self, _account: &AccountId) -> Result<(), RefreshTokenError> {
            self.delete_calls.fetch_add(1, Ordering::SeqCst);
            if self.fail_delete {
                return Err(RefreshTokenError::OperationFailed);
            }
            *self.stored.lock().unwrap() = None;
            Ok(())
        }
    }

    /// A fake [`ConnectSession`] for the `connect_account` tests. The claim is
    /// never exercised here (only the worker claims), and `is_cancelled`
    /// answers `false` for the first `cancel_from` fence checks and `true`
    /// from then on, so a test can place the cancel exactly at the
    /// pre-exchange, pre-store, or post-store fence.
    struct FakeSession {
        cancel_from: usize,
        checks: AtomicUsize,
    }

    impl FakeSession {
        /// Never cancelled: every fence passes.
        fn never() -> Self {
            Self {
                cancel_from: usize::MAX,
                checks: AtomicUsize::new(0),
            }
        }
        /// Cancelled right after the callback: the FIRST (pre-exchange) fence
        /// observes it, so the exchange never runs.
        fn cancelled_before_the_exchange() -> Self {
            Self {
                cancel_from: 0,
                ..Self::never()
            }
        }
        /// Cancelled while the exchange is in flight: the pre-exchange fence
        /// passes and the PRE-STORE fence observes it.
        fn cancelled_during_the_exchange() -> Self {
            Self {
                cancel_from: 1,
                ..Self::never()
            }
        }
        /// Cancelled in the check→store window: both earlier fences pass and
        /// the POST-STORE fence observes the cancel.
        fn cancelled_in_the_store_window() -> Self {
            Self {
                cancel_from: 2,
                ..Self::never()
            }
        }
    }

    impl ConnectSession for FakeSession {
        fn claim(&self) -> Option<(AuthorizationGrant, TokenClientConfig)> {
            None
        }
        fn is_cancelled(&self) -> bool {
            self.checks.fetch_add(1, Ordering::SeqCst) >= self.cancel_from
        }
        fn complete(&self) {
            // The exactly-once lease release is owned by the worker's
            // `complete_after`, which these crate-root tests never drive.
        }
    }

    #[test]
    fn connect_persists_the_refresh_token_and_returns_the_subject() {
        let store = FakeRefreshStore::empty();
        let connected = drive(connect_account(
            &account(),
            make_grant(),
            &config(),
            &FakeTransport::success(Some("granted-refresh")),
            &store,
            &TestClock::at(0),
            &FakeSession::never(),
        ))
        .unwrap();
        assert_eq!(connected.subject().as_str(), TEST_SUBJECT);
        assert_eq!(store.stored().as_deref(), Some("granted-refresh"));
        assert_eq!(store.store_calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn connect_cancelled_at_the_fence_revokes_the_minted_token_and_stores_nothing() {
        let store = FakeRefreshStore::empty();
        let transport = FakeTransport::success(Some("granted-refresh"));
        // The cancel lands while the exchange is in flight, so the pre-store
        // fence — after the exchange, before the store — observes it.
        let error = drive(connect_account(
            &account(),
            make_grant(),
            &config(),
            &transport,
            &store,
            &TestClock::at(0),
            &FakeSession::cancelled_during_the_exchange(),
        ))
        .unwrap_err();
        assert!(matches!(error, TokenLifecycleError::Cancelled));
        // The just-minted refresh token was revoked best-effort (recording inside
        // the future proves the revoke was actually polled)...
        assert_eq!(transport.revoked(), vec!["granted-refresh".to_owned()]);
        // ...and nothing was persisted: no connected account is left behind.
        assert_eq!(store.store_calls.load(Ordering::SeqCst), 0);
        assert_eq!(store.stored(), None);
    }

    #[test]
    fn connect_cancelled_with_a_failing_revoke_still_aborts_and_stores_nothing() {
        let store = FakeRefreshStore::empty();
        let transport = FakeTransport::success(Some("granted-refresh")).with_failing_revoke();
        // Revocation fails, but consent withdrawal never gates on the network:
        // the connect still aborts with Cancelled.
        let error = drive(connect_account(
            &account(),
            make_grant(),
            &config(),
            &transport,
            &store,
            &TestClock::at(0),
            &FakeSession::cancelled_during_the_exchange(),
        ))
        .unwrap_err();
        assert!(matches!(error, TokenLifecycleError::Cancelled));
        // The failed revoke was retried exactly once: two polled attempts.
        assert_eq!(
            transport.revoked(),
            vec!["granted-refresh".to_owned(), "granted-refresh".to_owned()]
        );
        assert_eq!(store.store_calls.load(Ordering::SeqCst), 0);
        assert_eq!(store.stored(), None);
    }

    #[test]
    fn a_cancelled_reconnect_leaves_the_existing_token_intact() {
        // A RE-connect while a working token is stored: the cancel must not
        // clobber the existing credential, and must NOT revoke the minted
        // token — it is same-grant, so a revoke would kill the user's working
        // connection. The pre-store fence aborts before any store or delete
        // touches the slot.
        let store = FakeRefreshStore::with_token("existing-refresh");
        let transport = FakeTransport::success(Some("granted-refresh"));
        let error = drive(connect_account(
            &account(),
            make_grant(),
            &config(),
            &transport,
            &store,
            &TestClock::at(0),
            &FakeSession::cancelled_during_the_exchange(),
        ))
        .unwrap_err();
        assert!(matches!(error, TokenLifecycleError::Cancelled));
        // NO revoke (same-grant), no store, no delete: the already-stored
        // credential survives untouched.
        assert!(transport.revoked().is_empty());
        assert_eq!(store.store_calls.load(Ordering::SeqCst), 0);
        assert_eq!(store.delete_calls.load(Ordering::SeqCst), 0);
        assert_eq!(store.stored().as_deref(), Some("existing-refresh"));
    }

    #[test]
    fn connect_cancelled_without_a_refresh_token_revokes_the_access_token() {
        // The fence sits ABOVE the MissingRefreshToken check: when the exchange
        // minted only an access token, that access token is what gets revoked
        // (revoking either token revokes the grant at Google).
        let store = FakeRefreshStore::empty();
        let transport = FakeTransport::success(None);
        let error = drive(connect_account(
            &account(),
            make_grant(),
            &config(),
            &transport,
            &store,
            &TestClock::at(0),
            &FakeSession::cancelled_during_the_exchange(),
        ))
        .unwrap_err();
        assert!(matches!(error, TokenLifecycleError::Cancelled));
        assert_eq!(transport.revoked(), vec!["fake-access-token".to_owned()]);
        assert_eq!(store.store_calls.load(Ordering::SeqCst), 0);
        assert_eq!(store.stored(), None);
    }

    #[test]
    fn first_connect_with_insufficient_scope_revokes_and_stores_nothing() {
        let store = FakeRefreshStore::empty();
        let transport = FakeTransport::success(Some("under-scoped-refresh")).under_scoped();
        let error = drive(connect_account(
            &account(),
            make_grant(),
            &config(),
            &transport,
            &store,
            &TestClock::at(0),
            &FakeSession::never(),
        ))
        .unwrap_err();
        assert!(matches!(
            error,
            TokenLifecycleError::Token(TokenError::InsufficientScope)
        ));
        assert_eq!(transport.revoked(), vec!["under-scoped-refresh".to_owned()]);
        assert_eq!(store.store_calls.load(Ordering::SeqCst), 0);
        assert_eq!(store.stored(), None);
    }

    #[test]
    fn connect_cancelled_after_the_store_deletes_the_token_and_revokes_it() {
        // The cancel lands in the check→store window: the pre-store fence passes,
        // the token is stored, and the POST-STORE fence observes the cancel.
        let store = FakeRefreshStore::empty();
        let transport = FakeTransport::success(Some("granted-refresh"));
        let error = drive(connect_account(
            &account(),
            make_grant(),
            &config(),
            &transport,
            &store,
            &TestClock::at(0),
            &FakeSession::cancelled_in_the_store_window(),
        ))
        .unwrap_err();
        assert!(matches!(error, TokenLifecycleError::Cancelled));
        // The token WAS stored, then deleted again, and revoked: no connected
        // account survives the post-store fence.
        assert_eq!(store.store_calls.load(Ordering::SeqCst), 1);
        assert_eq!(store.delete_calls.load(Ordering::SeqCst), 1);
        assert_eq!(store.stored(), None);
        assert_eq!(transport.revoked(), vec!["granted-refresh".to_owned()]);
    }

    #[test]
    fn connect_revokes_the_minted_token_when_the_store_fails() {
        // A failed store leaves no local record of the minted token, so the
        // token is revoked best-effort rather than stranding a live grant.
        // The revoke is licensed by a DEFINITIVELY-empty snapshot: the load
        // reads `Ok(None)` and only the write fails.
        let store = FakeRefreshStore::empty().failing_stores_from(0);
        let transport = FakeTransport::success(Some("granted-refresh"));
        let error = drive(connect_account(
            &account(),
            make_grant(),
            &config(),
            &transport,
            &store,
            &TestClock::at(0),
            &FakeSession::never(),
        ))
        .unwrap_err();
        assert!(matches!(error, TokenLifecycleError::Store(_)));
        assert_eq!(store.store_calls.load(Ordering::SeqCst), 1);
        assert_eq!(transport.revoked(), vec!["granted-refresh".to_owned()]);
        assert_eq!(store.stored(), None);
    }

    #[test]
    fn a_failed_snapshot_read_is_unknown_and_revokes_nothing() {
        // A load that returns `Err` is UNKNOWN, not "no credential": a live
        // grant could be hiding behind the unreadable store, so NONE of the
        // three revoke-gated paths may fire a grant-scoped revoke.

        // 1. The pre-store cancel fence.
        let store = FakeRefreshStore::failing();
        let transport = FakeTransport::success(Some("granted-refresh"));
        let error = drive(connect_account(
            &account(),
            make_grant(),
            &config(),
            &transport,
            &store,
            &TestClock::at(0),
            &FakeSession::cancelled_during_the_exchange(),
        ))
        .unwrap_err();
        assert!(matches!(error, TokenLifecycleError::Cancelled));
        assert!(transport.revoked().is_empty());
        assert_eq!(store.store_calls.load(Ordering::SeqCst), 0);

        // 2. The missing-refresh path (not gated on cancel).
        let store = FakeRefreshStore::failing();
        let transport = FakeTransport::success(None);
        let error = drive(connect_account(
            &account(),
            make_grant(),
            &config(),
            &transport,
            &store,
            &TestClock::at(0),
            &FakeSession::never(),
        ))
        .unwrap_err();
        assert!(matches!(error, TokenLifecycleError::MissingRefreshToken));
        assert!(transport.revoked().is_empty());

        // 3. The store-failure path.
        let store = FakeRefreshStore::failing();
        let transport = FakeTransport::success(Some("granted-refresh"));
        let error = drive(connect_account(
            &account(),
            make_grant(),
            &config(),
            &transport,
            &store,
            &TestClock::at(0),
            &FakeSession::never(),
        ))
        .unwrap_err();
        assert!(matches!(error, TokenLifecycleError::Store(_)));
        assert_eq!(store.store_calls.load(Ordering::SeqCst), 1);
        assert!(transport.revoked().is_empty());
    }

    #[test]
    fn connect_with_a_prior_credential_never_revokes_when_the_store_fails() {
        // A failed store on a RE-connect: the stored token is the live handle
        // and the local record, so the minted token is NOT revoked
        // (same-grant) — only the store error surfaces.
        let store = FakeRefreshStore::with_token("existing-refresh").failing_stores_from(0);
        let transport = FakeTransport::success(Some("granted-refresh"));
        let error = drive(connect_account(
            &account(),
            make_grant(),
            &config(),
            &transport,
            &store,
            &TestClock::at(0),
            &FakeSession::never(),
        ))
        .unwrap_err();
        assert!(matches!(error, TokenLifecycleError::Store(_)));
        assert_eq!(store.store_calls.load(Ordering::SeqCst), 1);
        assert!(transport.revoked().is_empty());
        assert_eq!(store.stored().as_deref(), Some("existing-refresh"));
    }

    #[test]
    fn connect_cancelled_after_the_store_restores_the_prior_credential() {
        // A RE-connect cancelled in the check→store window: the minted token
        // WAS stored over the existing credential, so the cleanup RESTORES the
        // prior bytes — a second store — and revokes NOTHING (the minted token
        // is same-grant; disconnect (3d-3d) revokes it later).
        let store = FakeRefreshStore::with_token("existing-refresh");
        let transport = FakeTransport::success(Some("granted-refresh"));
        let error = drive(connect_account(
            &account(),
            make_grant(),
            &config(),
            &transport,
            &store,
            &TestClock::at(0),
            &FakeSession::cancelled_in_the_store_window(),
        ))
        .unwrap_err();
        assert!(matches!(error, TokenLifecycleError::Cancelled));
        // The minted token was stored, then the prior credential was stored
        // back over it: two stores, no delete, and the stored value equals
        // the prior.
        assert_eq!(store.store_calls.load(Ordering::SeqCst), 2);
        assert_eq!(store.delete_calls.load(Ordering::SeqCst), 0);
        assert_eq!(store.stored().as_deref(), Some("existing-refresh"));
        assert!(transport.revoked().is_empty());
    }

    #[test]
    fn connect_cancelled_after_the_store_with_a_failing_delete_reports_incomplete_cleanup() {
        // The cleanup's delete fails persistently (one retry, symmetric with
        // the revoke retry): the cancel is acknowledged, but a usable token
        // may still sit in the Keychain, so the residual variant — NOT
        // Cancelled — is returned and nothing is revoked.
        let store = FakeRefreshStore::empty().failing_deletes();
        let transport = FakeTransport::success(Some("granted-refresh"));
        let error = drive(connect_account(
            &account(),
            make_grant(),
            &config(),
            &transport,
            &store,
            &TestClock::at(0),
            &FakeSession::cancelled_in_the_store_window(),
        ))
        .unwrap_err();
        assert!(matches!(
            error,
            TokenLifecycleError::CancelledCleanupIncomplete
        ));
        // The delete was attempted, then retried exactly once...
        assert_eq!(store.delete_calls.load(Ordering::SeqCst), 2);
        // ...the minted token REMAINS stored (usable)...
        assert_eq!(store.stored().as_deref(), Some("granted-refresh"));
        // ...and nothing was revoked: disconnect (3d-3d) is the remedy.
        assert!(transport.revoked().is_empty());
    }

    #[test]
    fn connect_cancelled_after_the_store_with_a_failing_restore_reports_incomplete_cleanup() {
        // WITH a prior credential, the cleanup restores the prior bytes; when
        // that restore store fails persistently (the initial store succeeded,
        // then the restore attempt plus one retry fail), the residual variant
        // is returned and the minted token — which displaced the prior —
        // remains stored.
        let store = FakeRefreshStore::with_token("existing-refresh").failing_stores_from(1);
        let transport = FakeTransport::success(Some("granted-refresh"));
        let error = drive(connect_account(
            &account(),
            make_grant(),
            &config(),
            &transport,
            &store,
            &TestClock::at(0),
            &FakeSession::cancelled_in_the_store_window(),
        ))
        .unwrap_err();
        assert!(matches!(
            error,
            TokenLifecycleError::CancelledCleanupIncomplete
        ));
        // The initial store succeeded, then the restore was attempted and
        // retried exactly once: three store calls in total.
        assert_eq!(store.store_calls.load(Ordering::SeqCst), 3);
        assert_eq!(store.delete_calls.load(Ordering::SeqCst), 0);
        assert_eq!(store.stored().as_deref(), Some("granted-refresh"));
        assert!(transport.revoked().is_empty());
    }

    #[test]
    fn connect_cancelled_before_the_exchange_mints_nothing() {
        // The user cancels right after the callback: the PRE-EXCHANGE fence
        // observes it, so the exchange never runs — no token is minted, hence
        // nothing to revoke, store, or orphan. The lease is unaffected: it is
        // held by the worker's claim and released by its `complete()`.
        let store = FakeRefreshStore::empty();
        let transport = FakeTransport::success(Some("granted-refresh"));
        let error = drive(connect_account(
            &account(),
            make_grant(),
            &config(),
            &transport,
            &store,
            &TestClock::at(0),
            &FakeSession::cancelled_before_the_exchange(),
        ))
        .unwrap_err();
        assert!(matches!(error, TokenLifecycleError::Cancelled));
        // The exchange was never polled: no token exists anywhere.
        assert_eq!(transport.exchange_calls(), 0);
        assert!(transport.revoked().is_empty());
        assert_eq!(store.store_calls.load(Ordering::SeqCst), 0);
        assert_eq!(store.stored(), None);
    }

    #[test]
    fn connect_not_cancelled_at_the_fence_stores_without_revoking() {
        let store = FakeRefreshStore::empty();
        let transport = FakeTransport::success(Some("granted-refresh"));
        let connected = drive(connect_account(
            &account(),
            make_grant(),
            &config(),
            &transport,
            &store,
            &TestClock::at(0),
            &FakeSession::never(),
        ))
        .unwrap();
        assert_eq!(connected.subject().as_str(), TEST_SUBJECT);
        assert_eq!(store.stored().as_deref(), Some("granted-refresh"));
        // No cancellation observed: neither fence touches the revoke endpoint,
        // and the post-store fence deletes nothing.
        assert!(transport.revoked().is_empty());
        assert_eq!(store.delete_calls.load(Ordering::SeqCst), 0);
    }

    #[test]
    fn connect_without_a_refresh_token_fails() {
        let store = FakeRefreshStore::empty();
        let transport = FakeTransport::success(None);
        let error = drive(connect_account(
            &account(),
            make_grant(),
            &config(),
            &transport,
            &store,
            &TestClock::at(0),
            &FakeSession::never(),
        ))
        .unwrap_err();
        assert!(matches!(error, TokenLifecycleError::MissingRefreshToken));
        // Not a cancel, but NO prior credential exists: the handle-less
        // grant's access token is revoked (closing the strand AND letting
        // Google mint a refresh on retry), and nothing was stored.
        assert_eq!(transport.revoked(), vec!["fake-access-token".to_owned()]);
        assert_eq!(store.store_calls.load(Ordering::SeqCst), 0);
        assert_eq!(store.stored(), None);
    }

    #[test]
    fn connect_without_a_refresh_token_and_a_prior_credential_never_revokes() {
        // The exchange minted no refresh token, but a working credential is
        // stored: the minted access token is same-grant, so revoking it would
        // kill the user's working connection. Never revoke — the stored token
        // is the live handle.
        let store = FakeRefreshStore::with_token("existing-refresh");
        let transport = FakeTransport::success(None);
        let error = drive(connect_account(
            &account(),
            make_grant(),
            &config(),
            &transport,
            &store,
            &TestClock::at(0),
            &FakeSession::never(),
        ))
        .unwrap_err();
        assert!(matches!(error, TokenLifecycleError::MissingRefreshToken));
        assert!(transport.revoked().is_empty());
        assert_eq!(store.store_calls.load(Ordering::SeqCst), 0);
        assert_eq!(store.delete_calls.load(Ordering::SeqCst), 0);
        assert_eq!(store.stored().as_deref(), Some("existing-refresh"));
    }

    #[test]
    fn connect_propagates_a_missing_identity_without_deleting_the_credential() {
        let error = drive(connect_account(
            &account(),
            make_grant(),
            &config(),
            &FakeTransport::without_id_token(),
            &FakeRefreshStore::empty(),
            &TestClock::at(0),
            &FakeSession::never(),
        ))
        .unwrap_err();
        // IdentityUnverified is non-destructive — never ConsentRevoked.
        assert!(matches!(
            error,
            TokenLifecycleError::Token(TokenError::IdentityUnverified)
        ));
    }

    #[test]
    fn refresh_loads_refreshes_and_persists_a_rotated_token() {
        let store = FakeRefreshStore::with_token("old-refresh");
        let connected = drive(refresh_account(
            &account(),
            &config(),
            &FakeTransport::success(Some("rotated-refresh")),
            &store,
            &TestClock::at(0),
        ))
        .unwrap();
        assert_eq!(connected.subject().as_str(), TEST_SUBJECT);
        assert_eq!(store.stored().as_deref(), Some("rotated-refresh"));
    }

    #[test]
    fn refresh_keeps_the_stored_token_when_not_rotated() {
        let store = FakeRefreshStore::with_token("kept-refresh");
        drive(refresh_account(
            &account(),
            &config(),
            &FakeTransport::success(None),
            &store,
            &TestClock::at(0),
        ))
        .unwrap();
        assert_eq!(store.stored().as_deref(), Some("kept-refresh"));
    }

    #[test]
    fn refresh_without_a_stored_token_fails() {
        let error = drive(refresh_account(
            &account(),
            &config(),
            &FakeTransport::success(Some("refresh")),
            &FakeRefreshStore::empty(),
            &TestClock::at(0),
        ))
        .unwrap_err();
        assert!(matches!(error, TokenLifecycleError::NoStoredToken));
    }

    #[test]
    fn refresh_surfaces_a_store_failure() {
        let error = drive(refresh_account(
            &account(),
            &config(),
            &FakeTransport::success(Some("refresh")),
            &FakeRefreshStore::failing(),
            &TestClock::at(0),
        ))
        .unwrap_err();
        assert!(matches!(error, TokenLifecycleError::Store(_)));
    }

    #[test]
    fn refresh_if_due_skips_a_fresh_token_and_refreshes_a_stale_one() {
        let clock = TestClock::at(0);
        let store = FakeRefreshStore::empty();
        // Connect at t=0: the access token expires at t=3600.
        let connected = drive(connect_account(
            &account(),
            make_grant(),
            &config(),
            &FakeTransport::success(Some("granted-refresh")),
            &store,
            &clock,
            &FakeSession::never(),
        ))
        .unwrap();
        let (access_token, _subject, _expiry) = connected.into_parts();

        // Still fresh at t=0 with a 60s skew: no refresh runs.
        let outcome = drive(refresh_if_due(
            &account(),
            &access_token,
            Duration::from_secs(60),
            &config(),
            &FakeTransport::success(Some("rotated")),
            &store,
            &clock,
        ))
        .unwrap();
        assert!(outcome.is_none());

        // Within the skew of expiry at t=3560: a refresh runs and rotates.
        clock.set(3_560);
        let outcome = drive(refresh_if_due(
            &account(),
            &access_token,
            Duration::from_secs(60),
            &config(),
            &FakeTransport::success(Some("rotated")),
            &store,
            &clock,
        ))
        .unwrap();
        assert!(outcome.is_some());
        assert_eq!(store.stored().as_deref(), Some("rotated"));
    }
}
