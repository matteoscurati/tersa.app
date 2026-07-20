// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! Provides the per-account OAuth refresh-token Keychain surface.
//!
//! This module is a sibling of the root-key module and never names the root
//! key's Keychain identity. It stores exactly one refresh token per account
//! under a distinct service, with `WhenUnlockedThisDeviceOnly` accessibility,
//! and is the only place in the crate that performs `SecItemUpdate` or
//! `SecItemDelete` — always against the token service, never the installation
//! root key. Every operation is fixed to the token service through a helper
//! that accepts no service parameter, and the token is held only in zeroizing
//! memory and is never logged.

use core::fmt;

use tersa_platform::secure_storage::AccountId;
use zeroize::Zeroizing;

/// A closed, redacted failure of the refresh-token Keychain surface.
#[derive(Clone, Copy, Eq, PartialEq)]
#[non_exhaustive]
pub enum RefreshTokenError {
    /// A Keychain operation failed.
    OperationFailed,
    /// A stored item was malformed: wrong type, oversized, or invalid UTF-8.
    Invalid,
}

impl fmt::Display for RefreshTokenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::OperationFailed => "the refresh-token Keychain operation failed",
            Self::Invalid => "the stored refresh token is malformed",
        };
        formatter.write_str(message)
    }
}

impl fmt::Debug for RefreshTokenError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RefreshTokenError([REDACTED])")
    }
}

impl std::error::Error for RefreshTokenError {}

/// The result of attempting to insert a new refresh-token item.
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
#[cfg(any(target_os = "macos", test))]
enum AddOutcome {
    Added,
    Duplicate,
}

/// The result of attempting to update an existing refresh-token item.
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
#[cfg(any(target_os = "macos", test))]
enum UpdateOutcome {
    Updated,
    Missing,
}

/// The result of attempting to delete a refresh-token item.
#[derive(Clone, Copy, Eq, PartialEq, Debug)]
#[cfg(any(target_os = "macos", test))]
enum DeleteOutcome {
    Deleted,
    NotFound,
}

/// The raw, per-account Keychain operations for one refresh-token item.
///
/// No method accepts a service, query, or attribute set, so no caller can
/// retarget the installation root key: every implementation fixes the token
/// service itself.
#[cfg(any(target_os = "macos", test))]
trait RefreshTokenBackend {
    fn add(
        &self,
        account: &AccountId,
        token: &Zeroizing<String>,
    ) -> Result<AddOutcome, RefreshTokenError>;
    fn update(
        &self,
        account: &AccountId,
        token: &Zeroizing<String>,
    ) -> Result<UpdateOutcome, RefreshTokenError>;
    fn load(&self, account: &AccountId) -> Result<Option<Zeroizing<String>>, RefreshTokenError>;
    fn delete(&self, account: &AccountId) -> Result<DeleteOutcome, RefreshTokenError>;
}

/// A refresh token outside these bounds is rejected before it is persisted,
/// symmetrically with the load-side decode bound.
#[cfg(any(target_os = "macos", test))]
const MAX_REFRESH_TOKEN_LEN: usize = 16 * 1024;

/// Stores the refresh token for `account`, inserting or atomically replacing it.
///
/// A first store inserts; a rotation updates the existing item in place. The
/// single `Missing`-after-`Duplicate` race (the item deleted between the insert
/// attempt and the update) is not reachable under the single-flight bootstrap
/// lock, but is insured with exactly one retried insert.
#[cfg(any(target_os = "macos", test))]
fn store_refresh_token(
    backend: &impl RefreshTokenBackend,
    account: &AccountId,
    token: &Zeroizing<String>,
) -> Result<(), RefreshTokenError> {
    if token.is_empty() || token.len() > MAX_REFRESH_TOKEN_LEN {
        return Err(RefreshTokenError::Invalid);
    }
    match backend.add(account, token)? {
        AddOutcome::Added => Ok(()),
        AddOutcome::Duplicate => match backend.update(account, token)? {
            UpdateOutcome::Updated => Ok(()),
            UpdateOutcome::Missing => match backend.add(account, token)? {
                AddOutcome::Added => Ok(()),
                AddOutcome::Duplicate => Err(RefreshTokenError::OperationFailed),
            },
        },
    }
}

/// Loads the stored refresh token for `account`, if present.
#[cfg(any(target_os = "macos", test))]
fn load_refresh_token(
    backend: &impl RefreshTokenBackend,
    account: &AccountId,
) -> Result<Option<Zeroizing<String>>, RefreshTokenError> {
    backend.load(account)
}

/// Deletes the refresh token for `account`.
///
/// A missing item is success (idempotent disconnect); every other failure
/// surfaces, so a revoke-and-clear disconnect never silently leaves a persisted
/// token behind.
#[cfg(any(target_os = "macos", test))]
fn delete_refresh_token(
    backend: &impl RefreshTokenBackend,
    account: &AccountId,
) -> Result<(), RefreshTokenError> {
    match backend.delete(account)? {
        DeleteOutcome::Deleted | DeleteOutcome::NotFound => Ok(()),
    }
}

/// The per-account refresh-token store consumed by the sync composition.
///
/// The token is the only persisted OAuth credential. It never crosses the C
/// ABI, is never written to the `SQLCipher` store, and is never logged.
pub trait RefreshTokenStore {
    /// Persists `token` for `account`, replacing any existing token in place.
    ///
    /// # Errors
    ///
    /// Returns a redacted [`RefreshTokenError`] when the Keychain rejects the
    /// insert or replace.
    fn store(
        &self,
        account: &AccountId,
        token: &Zeroizing<String>,
    ) -> Result<(), RefreshTokenError>;

    /// Loads the stored token for `account`, if present.
    ///
    /// # Errors
    ///
    /// Returns a redacted [`RefreshTokenError`] when the Keychain read fails or
    /// the stored item is malformed.
    fn load(&self, account: &AccountId) -> Result<Option<Zeroizing<String>>, RefreshTokenError>;

    /// Removes the token for `account`; a missing token is success.
    ///
    /// # Errors
    ///
    /// Returns a redacted [`RefreshTokenError`] when the Keychain delete fails
    /// for any reason other than a missing item.
    fn delete(&self, account: &AccountId) -> Result<(), RefreshTokenError>;
}

/// The production macOS refresh-token store for the signing-time access group.
///
/// Persists the token under a distinct service in the configured access group,
/// with `WhenUnlockedThisDeviceOnly` accessibility, through the data-protection
/// Keychain. It is the sole `SecItemUpdate` / `SecItemDelete` site in the crate,
/// always fixed to the token service.
#[cfg(target_os = "macos")]
pub struct DataProtectionRefreshTokenStore {
    backend: token_keychain::MacosRefreshTokenBackend,
}

#[cfg(target_os = "macos")]
impl fmt::Debug for DataProtectionRefreshTokenStore {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DataProtectionRefreshTokenStore([REDACTED])")
    }
}

#[cfg(target_os = "macos")]
impl DataProtectionRefreshTokenStore {
    /// Creates the production refresh-token store.
    ///
    /// # Errors
    ///
    /// Returns [`RefreshTokenError::OperationFailed`] when the signing-time App
    /// Group is absent.
    pub fn new() -> Result<Self, RefreshTokenError> {
        Ok(Self {
            backend: token_keychain::MacosRefreshTokenBackend::new()?,
        })
    }
}

#[cfg(target_os = "macos")]
impl RefreshTokenStore for DataProtectionRefreshTokenStore {
    fn store(
        &self,
        account: &AccountId,
        token: &Zeroizing<String>,
    ) -> Result<(), RefreshTokenError> {
        store_refresh_token(&self.backend, account, token)
    }

    fn load(&self, account: &AccountId) -> Result<Option<Zeroizing<String>>, RefreshTokenError> {
        load_refresh_token(&self.backend, account)
    }

    fn delete(&self, account: &AccountId) -> Result<(), RefreshTokenError> {
        delete_refresh_token(&self.backend, account)
    }
}

#[cfg(target_os = "macos")]
#[expect(
    unsafe_code,
    clippy::borrow_as_ptr,
    reason = "Security.framework and Core Foundation expose the token add/rotate/delete/read contract only through audited C FFI, fixed by construction to the token service."
)]
mod token_keychain {
    use super::{AddOutcome, DeleteOutcome, RefreshTokenBackend, RefreshTokenError, UpdateOutcome};
    use core_foundation::array::CFArray;
    use core_foundation::base::{
        CFIndexConvertible, CFRange, CFType, CFTypeRef, TCFType, kCFAllocatorDefault,
        kCFAllocatorNull,
    };
    use core_foundation::boolean::CFBoolean;
    use core_foundation::data::{CFData, CFDataCreateWithBytesNoCopy};
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::number::CFNumber;
    use core_foundation::string::{CFString, CFStringRef};
    use security_framework_sys::{access_control, base, item, keychain_item};
    use tersa_platform::secure_storage::AccountId;
    use zeroize::Zeroizing;

    /// Private to this module — the only service the token FFI ever targets.
    const TOKEN_SERVICE: &str = "app.tersa.mac.oauth-refresh-token.v1";
    /// A stored refresh token longer than this is rejected as hostile.
    const MAX_TOKEN_LEN: usize = 16 * 1024;

    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        static kSecAttrAccessible: CFStringRef;
    }

    macro_rules! security_string {
        ($symbol:path) => {
            // SAFETY: every accepted symbol is an immutable process-lifetime
            // Security.framework CFString constant.
            static_string(unsafe { $symbol })
        };
    }

    fn static_string(raw: CFStringRef) -> CFType {
        // SAFETY: callers pass immutable process-lifetime Core Foundation string
        // constants, so wrapping under the get rule is correct.
        unsafe { CFString::wrap_under_get_rule(raw).into_CFType() }
    }

    /// The production Keychain backend, bound to one access group.
    pub(super) struct MacosRefreshTokenBackend {
        group: &'static str,
    }

    impl MacosRefreshTokenBackend {
        pub(super) fn new() -> Result<Self, RefreshTokenError> {
            Ok(Self {
                group: crate::configured_app_group()
                    .map_err(|_error| RefreshTokenError::OperationFailed)?,
            })
        }
    }

    impl RefreshTokenBackend for MacosRefreshTokenBackend {
        fn add(
            &self,
            account: &AccountId,
            token: &Zeroizing<String>,
        ) -> Result<AddOutcome, RefreshTokenError> {
            add(&TokenQuery::new(self.group, account), token)
        }

        fn update(
            &self,
            account: &AccountId,
            token: &Zeroizing<String>,
        ) -> Result<UpdateOutcome, RefreshTokenError> {
            update(&TokenQuery::new(self.group, account), token)
        }

        fn load(
            &self,
            account: &AccountId,
        ) -> Result<Option<Zeroizing<String>>, RefreshTokenError> {
            copy(&TokenQuery::new(self.group, account))
        }

        fn delete(&self, account: &AccountId) -> Result<DeleteOutcome, RefreshTokenError> {
            delete(&TokenQuery::new(self.group, account))
        }
    }

    /// One refresh-token item identity, fixed to `TOKEN_SERVICE` by construction.
    ///
    /// No constructor accepts a service, so a `TokenQuery` can never name the
    /// installation root key; the mutation functions accept only a `TokenQuery`.
    struct TokenQuery<'a> {
        group: &'a str,
        account: &'a str,
    }

    impl<'a> TokenQuery<'a> {
        fn new(group: &'a str, account: &'a AccountId) -> Self {
            Self {
                group,
                account: account.as_str(),
            }
        }

        /// Builds the item dictionary. `data` present ⇒ an insert attributes set
        /// (adds accessibility and the value); `returning` ⇒ a read query.
        fn dictionary(
            &self,
            data: Option<&CFData>,
            returning: bool,
        ) -> CFDictionary<CFType, CFType> {
            debug_assert_eq!(TOKEN_SERVICE, "app.tersa.mac.oauth-refresh-token.v1");
            let service = CFString::new(TOKEN_SERVICE);
            let account = CFString::new(self.account);
            let group = CFString::new(self.group);
            let mut pairs = vec![
                (
                    security_string!(item::kSecClass),
                    security_string!(item::kSecClassGenericPassword),
                ),
                (security_string!(item::kSecAttrService), service.as_CFType()),
                (security_string!(item::kSecAttrAccount), account.as_CFType()),
                (
                    security_string!(item::kSecAttrAccessGroup),
                    group.as_CFType(),
                ),
                (
                    security_string!(item::kSecAttrSynchronizable),
                    CFBoolean::false_value().as_CFType(),
                ),
                (
                    security_string!(item::kSecUseDataProtectionKeychain),
                    CFBoolean::true_value().as_CFType(),
                ),
            ];
            if let Some(data) = data {
                pairs.push((
                    security_string!(kSecAttrAccessible),
                    security_string!(access_control::kSecAttrAccessibleWhenUnlockedThisDeviceOnly),
                ));
                pairs.push((security_string!(item::kSecValueData), data.as_CFType()));
            }
            if returning {
                pairs.extend([
                    (
                        security_string!(item::kSecReturnData),
                        CFBoolean::true_value().as_CFType(),
                    ),
                    (
                        security_string!(item::kSecReturnAttributes),
                        CFBoolean::true_value().as_CFType(),
                    ),
                    (
                        security_string!(item::kSecMatchLimit),
                        CFNumber::from(2).as_CFType(),
                    ),
                ]);
            }
            CFDictionary::from_CFType_pairs(&pairs)
        }
    }

    /// The update attributes — only the new value, never identity or policy.
    fn value_data_attributes(data: &CFData) -> CFDictionary<CFType, CFType> {
        CFDictionary::from_CFType_pairs(&[(
            security_string!(item::kSecValueData),
            data.as_CFType(),
        )])
    }

    fn add(query: &TokenQuery, token: &Zeroizing<String>) -> Result<AddOutcome, RefreshTokenError> {
        let bytes = token.as_bytes();
        // SAFETY: the no-copy CFData borrows `bytes` only until it is dropped at
        // the end of this function; kCFAllocatorNull frees nothing, and the CFData
        // is a local that never escapes, so the borrowed pointer cannot outlive
        // `token`. (The FFI is inlined rather than passed to a closure precisely
        // so the no-copy value can never reach safe caller code.)
        let data_ref = unsafe {
            CFDataCreateWithBytesNoCopy(
                kCFAllocatorDefault,
                bytes.as_ptr(),
                bytes.len().to_CFIndex(),
                kCFAllocatorNull,
            )
        };
        if data_ref.is_null() {
            return Err(RefreshTokenError::OperationFailed);
        }
        // SAFETY: CFDataCreateWithBytesNoCopy returned a non-null +1 object.
        let data = unsafe { CFData::wrap_under_create_rule(data_ref) };
        let attributes = query.dictionary(Some(&data), false);
        // SAFETY: `attributes` and `data` are live throughout this synchronous
        // call and dropped before this function returns; no result is requested.
        let status = unsafe {
            keychain_item::SecItemAdd(attributes.as_concrete_TypeRef(), std::ptr::null_mut())
        };
        match status {
            base::errSecSuccess => Ok(AddOutcome::Added),
            base::errSecDuplicateItem => Ok(AddOutcome::Duplicate),
            _ => Err(RefreshTokenError::OperationFailed),
        }
    }

    fn update(
        query: &TokenQuery,
        token: &Zeroizing<String>,
    ) -> Result<UpdateOutcome, RefreshTokenError> {
        let bytes = token.as_bytes();
        // SAFETY: same no-copy contract as `add` — the CFData is a local dropped
        // at the end of this function and never escapes.
        let data_ref = unsafe {
            CFDataCreateWithBytesNoCopy(
                kCFAllocatorDefault,
                bytes.as_ptr(),
                bytes.len().to_CFIndex(),
                kCFAllocatorNull,
            )
        };
        if data_ref.is_null() {
            return Err(RefreshTokenError::OperationFailed);
        }
        // SAFETY: CFDataCreateWithBytesNoCopy returned a non-null +1 object.
        let data = unsafe { CFData::wrap_under_create_rule(data_ref) };
        let match_query = query.dictionary(None, false);
        let attributes = value_data_attributes(&data);
        // SAFETY: both retained dictionaries and `data` are live throughout this
        // synchronous call and dropped before return; the attributes carry only
        // the new value, so `SecItemUpdate` preserves the item's accessibility.
        let status = unsafe {
            keychain_item::SecItemUpdate(
                match_query.as_concrete_TypeRef(),
                attributes.as_concrete_TypeRef(),
            )
        };
        match status {
            base::errSecSuccess => Ok(UpdateOutcome::Updated),
            base::errSecItemNotFound => Ok(UpdateOutcome::Missing),
            _ => Err(RefreshTokenError::OperationFailed),
        }
    }

    fn delete(query: &TokenQuery) -> Result<DeleteOutcome, RefreshTokenError> {
        let match_query = query.dictionary(None, false);
        // SAFETY: the retained query dictionary is valid for this synchronous call.
        let status = unsafe { keychain_item::SecItemDelete(match_query.as_concrete_TypeRef()) };
        match status {
            base::errSecSuccess => Ok(DeleteOutcome::Deleted),
            base::errSecItemNotFound => Ok(DeleteOutcome::NotFound),
            _ => Err(RefreshTokenError::OperationFailed),
        }
    }

    fn copy(query: &TokenQuery) -> Result<Option<Zeroizing<String>>, RefreshTokenError> {
        let match_query = query.dictionary(None, true);
        let mut raw: CFTypeRef = std::ptr::null();
        // SAFETY: the retained query dictionary is valid for this synchronous
        // call and `raw` is a writable out-parameter initialized to null.
        let status = unsafe {
            keychain_item::SecItemCopyMatching(match_query.as_concrete_TypeRef(), &mut raw)
        };
        if status == base::errSecItemNotFound {
            return Ok(None);
        }
        if status != base::errSecSuccess || raw.is_null() {
            return Err(RefreshTokenError::OperationFailed);
        }
        // SAFETY: a successful SecItemCopyMatching result follows the create rule
        // and is non-null as checked above.
        let result = unsafe { CFType::wrap_under_create_rule(raw) };
        decode(result).map(Some)
    }

    fn decode(result: CFType) -> Result<Zeroizing<String>, RefreshTokenError> {
        let array = result
            .downcast_into::<CFArray>()
            .ok_or(RefreshTokenError::Invalid)?;
        if array.len() != 1 {
            return Err(RefreshTokenError::Invalid);
        }
        let raw = array.get_all_values()[0];
        // SAFETY: `raw` is retained by `array` for the duration of this decode.
        let dictionary = unsafe { CFType::wrap_under_get_rule(raw) }
            .downcast_into::<CFDictionary>()
            .ok_or(RefreshTokenError::Invalid)?;
        let data = dictionary
            .find(security_string!(item::kSecValueData).as_CFTypeRef())
            .ok_or(RefreshTokenError::Invalid)?;
        // SAFETY: the dictionary retains its non-null values while borrowed.
        let data = unsafe { data.as_ref() }.ok_or(RefreshTokenError::Invalid)?;
        // SAFETY: the value stays retained by `dictionary` during decode.
        let data = unsafe { CFType::wrap_under_get_rule(data) }
            .downcast_into::<CFData>()
            .ok_or(RefreshTokenError::Invalid)?;
        let length = usize::try_from(data.len()).map_err(|_negative| RefreshTokenError::Invalid)?;
        if length == 0 || length > MAX_TOKEN_LEN {
            return Err(RefreshTokenError::Invalid);
        }
        let mut bytes = Zeroizing::new(vec![0_u8; length]);
        // SAFETY: the validated source range is exactly `length` bytes and the
        // destination owns exactly `length` writable bytes. CFDataGetBytes copies
        // directly into the zeroizing destination.
        unsafe {
            core_foundation::data::CFDataGetBytes(
                data.as_concrete_TypeRef(),
                CFRange::init(0, length.to_CFIndex()),
                bytes.as_mut_ptr(),
            );
        }
        // Validate UTF-8 by borrow, then move the one owned copy into a zeroizing
        // String — no non-zeroizing intermediate of the token ever exists.
        let text = core::str::from_utf8(&bytes)
            .map_err(|_invalid| RefreshTokenError::Invalid)?
            .to_owned();
        Ok(Zeroizing::new(text))
    }
}

#[cfg(test)]
mod tests {
    #![expect(
        clippy::unwrap_used,
        reason = "in-memory fake locks and setup assert success before behavior"
    )]

    use std::collections::HashMap;
    use std::sync::Mutex;

    use tersa_platform::secure_storage::AccountId;
    use zeroize::Zeroizing;

    use super::{
        AddOutcome, DeleteOutcome, RefreshTokenBackend, RefreshTokenError, UpdateOutcome,
        delete_refresh_token, load_refresh_token, store_refresh_token,
    };

    fn account(value: &str) -> AccountId {
        AccountId::new(value).unwrap_or_else(|error| panic!("invalid test account: {error}"))
    }

    fn secret(value: &str) -> Zeroizing<String> {
        Zeroizing::new(value.to_owned())
    }

    /// An in-memory fake exercising the portable store/load/delete logic.
    #[derive(Default)]
    struct FakeBackend {
        items: Mutex<HashMap<String, String>>,
        force: Mutex<Option<ForcedOutcome>>,
    }

    #[derive(Clone, Copy)]
    enum ForcedOutcome {
        UpdateMissing,
        DeleteError,
    }

    impl FakeBackend {
        fn force(&self, outcome: ForcedOutcome) {
            *self.force.lock().unwrap() = Some(outcome);
        }

        fn stored(&self, account: &AccountId) -> Option<String> {
            self.items.lock().unwrap().get(account.as_str()).cloned()
        }
    }

    impl RefreshTokenBackend for FakeBackend {
        fn add(
            &self,
            account: &AccountId,
            token: &Zeroizing<String>,
        ) -> Result<AddOutcome, RefreshTokenError> {
            let mut items = self.items.lock().unwrap();
            if items.contains_key(account.as_str()) {
                return Ok(AddOutcome::Duplicate);
            }
            items.insert(account.as_str().to_owned(), (**token).clone());
            Ok(AddOutcome::Added)
        }

        fn update(
            &self,
            account: &AccountId,
            token: &Zeroizing<String>,
        ) -> Result<UpdateOutcome, RefreshTokenError> {
            if matches!(
                *self.force.lock().unwrap(),
                Some(ForcedOutcome::UpdateMissing)
            ) {
                *self.force.lock().unwrap() = None;
                // Model the item vanishing between the insert attempt and the
                // update, so the store's retried insert re-creates it.
                self.items.lock().unwrap().remove(account.as_str());
                return Ok(UpdateOutcome::Missing);
            }
            let mut items = self.items.lock().unwrap();
            if !items.contains_key(account.as_str()) {
                return Ok(UpdateOutcome::Missing);
            }
            items.insert(account.as_str().to_owned(), (**token).clone());
            Ok(UpdateOutcome::Updated)
        }

        fn load(
            &self,
            account: &AccountId,
        ) -> Result<Option<Zeroizing<String>>, RefreshTokenError> {
            Ok(self.stored(account).map(Zeroizing::new))
        }

        fn delete(&self, account: &AccountId) -> Result<DeleteOutcome, RefreshTokenError> {
            if matches!(
                *self.force.lock().unwrap(),
                Some(ForcedOutcome::DeleteError)
            ) {
                return Err(RefreshTokenError::OperationFailed);
            }
            if self
                .items
                .lock()
                .unwrap()
                .remove(account.as_str())
                .is_some()
            {
                Ok(DeleteOutcome::Deleted)
            } else {
                Ok(DeleteOutcome::NotFound)
            }
        }
    }

    #[test]
    fn stores_then_loads_a_token() {
        let backend = FakeBackend::default();
        let id = account("default");
        store_refresh_token(&backend, &id, &secret("refresh-one")).unwrap();
        assert_eq!(
            load_refresh_token(&backend, &id).unwrap().as_deref(),
            Some(&"refresh-one".to_owned())
        );
    }

    #[test]
    fn rotates_an_existing_token_in_place() {
        let backend = FakeBackend::default();
        let id = account("default");
        store_refresh_token(&backend, &id, &secret("refresh-one")).unwrap();
        store_refresh_token(&backend, &id, &secret("refresh-two")).unwrap();
        assert_eq!(backend.stored(&id).as_deref(), Some("refresh-two"));
    }

    #[test]
    fn insures_the_add_duplicate_then_missing_race_with_one_retry() {
        let backend = FakeBackend::default();
        let id = account("default");
        // Seed an item so the first insert attempt reports a duplicate.
        store_refresh_token(&backend, &id, &secret("stale")).unwrap();
        // Force the update to report the item vanished (the insert->duplicate->
        // deleted race); the store must recover with exactly one retried insert.
        backend.force(ForcedOutcome::UpdateMissing);
        store_refresh_token(&backend, &id, &secret("refresh-two")).unwrap();
        assert_eq!(backend.stored(&id).as_deref(), Some("refresh-two"));
    }

    #[test]
    fn delete_is_idempotent_and_ok_when_missing() {
        let backend = FakeBackend::default();
        let id = account("default");
        delete_refresh_token(&backend, &id).unwrap();
        store_refresh_token(&backend, &id, &secret("refresh-one")).unwrap();
        delete_refresh_token(&backend, &id).unwrap();
        assert!(backend.stored(&id).is_none());
    }

    #[test]
    fn delete_surfaces_a_non_missing_failure() {
        let backend = FakeBackend::default();
        let id = account("default");
        backend.force(ForcedOutcome::DeleteError);
        assert_eq!(
            delete_refresh_token(&backend, &id),
            Err(RefreshTokenError::OperationFailed)
        );
    }

    #[test]
    fn error_debug_is_redacted() {
        assert_eq!(
            format!("{:?}", RefreshTokenError::OperationFailed),
            "RefreshTokenError([REDACTED])"
        );
    }
}
