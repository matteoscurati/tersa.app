// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! macOS Data Protection Keychain root-key and fixed App Group capabilities.
//!
//! The production constructors use only the signing-time application-group
//! value. They deliberately offer no runtime configuration or fallback.

#![deny(unsafe_code)]

use std::fmt;
use std::path::{Path, PathBuf};

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use tersa_platform::secure_storage::{
    AccountId, AccountProfileLocator, InstallationRootKeyProvisioner, KeyStorageError,
    ProfileStorageError, ProvisionOutcome,
};
use zeroize::Zeroize;

// Rust guideline compliant 1.0.

#[cfg(target_os = "macos")]
const SERVICE: &str = "app.tersa.mac.storage-root.v1";
#[cfg(target_os = "macos")]
const ACCOUNT: &str = "default";
const ROOT_SALT: &[u8] = b"tersa.app/macos/root-key/v1";
const HKDF_PREFIX: &[u8] = b"tersa.app/macos/hkdf-sha256/v1";
const DATABASE_PURPOSE: &[u8] = b"sqlcipher/account-database/v1";
const PROFILE_PREFIX: &[&str] = &["profiles", "default", "accounts"];

#[cfg_attr(test, derive(Eq, PartialEq))]
struct SecretKey([u8; 32]);

impl SecretKey {
    #[cfg(test)]
    fn new(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    fn zeroed() -> Self {
        Self([0; 32])
    }

    fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    fn as_mut_bytes(&mut self) -> &mut [u8; 32] {
        &mut self.0
    }

    fn zeroize_now(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for SecretKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretKey([REDACTED])")
    }
}

impl Drop for SecretKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

/// Provisions only the fixed installation root key.
pub struct DataProtectionRootKeyProvisioner {
    backend: ProductionBackend,
}

impl fmt::Debug for DataProtectionRootKeyProvisioner {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DataProtectionRootKeyProvisioner([REDACTED])")
    }
}

/// Locates only the fixed default profile in the configured App Group.
pub struct AppGroupProfileLocator {
    locator: ProductionContainerLocator,
}

impl fmt::Debug for AppGroupProfileLocator {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AppGroupProfileLocator([REDACTED])")
    }
}

impl DataProtectionRootKeyProvisioner {
    /// Creates the fixed production provisioner.
    ///
    /// # Errors
    ///
    /// Returns a redacted error when the signing-time App Group is absent.
    pub fn new() -> Result<Self, KeyStorageError> {
        Ok(Self {
            backend: ProductionBackend::new()?,
        })
    }
}

impl AppGroupProfileLocator {
    /// Creates the fixed production profile locator.
    ///
    /// # Errors
    ///
    /// Returns a redacted error when the signing-time App Group is absent.
    pub fn new() -> Result<Self, ProfileStorageError> {
        Ok(Self {
            locator: ProductionContainerLocator::new()?,
        })
    }
}

impl InstallationRootKeyProvisioner for DataProtectionRootKeyProvisioner {
    fn provision_installation_root_key(&self) -> Result<ProvisionOutcome, KeyStorageError> {
        provision_installation_root_key(&self.backend)
    }
}

fn provision_installation_root_key(
    backend: &impl RootKeyBackend,
) -> Result<ProvisionOutcome, KeyStorageError> {
    if backend.copy()?.is_some() {
        return Ok(ProvisionOutcome::Existing);
    }

    let mut candidate = backend.random_key()?;
    match backend.add(&candidate)? {
        AddResult::Added => {
            candidate.zeroize_now();
            backend.candidate_zeroized_before_reread(&candidate);
            backend.copy()?.ok_or(KeyStorageError::Invalid)?;
            Ok(ProvisionOutcome::Created)
        }
        AddResult::Duplicate => {
            candidate.zeroize_now();
            backend.candidate_zeroized_before_reread(&candidate);
            backend.copy()?.ok_or(KeyStorageError::Invalid)?;
            Ok(ProvisionOutcome::Existing)
        }
    }
}

impl AccountProfileLocator for AppGroupProfileLocator {
    fn account_database_path(
        &self,
        account_id: &AccountId,
    ) -> Result<PathBuf, ProfileStorageError> {
        account_database_path(&self.locator, account_id)
    }
}

fn account_database_path(
    locator: &impl ContainerLocator,
    account_id: &AccountId,
) -> Result<PathBuf, ProfileStorageError> {
    let container = locator.container()?;
    if !container.is_dir() || !is_readable_directory(&container) {
        return Err(ProfileStorageError::Unavailable);
    }
    let digest = hex_digest(account_id);
    Ok(PROFILE_PREFIX
        .iter()
        .fold(container, |path, part| path.join(part))
        .join(digest)
        .join("mail.sqlite3"))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "PR 32 validates private derivation; PR 33 will compose it directly with database opening without exporting key bytes."
    )
)]
enum AccountKeyPurpose {
    SqlCipherAccountDatabaseV1,
}

#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "PR 32 validates private derivation; PR 33 will compose it directly with database opening without exporting key bytes."
    )
)]
fn derive_account_key(
    root: &SecretKey,
    account_id: &AccountId,
    purpose: AccountKeyPurpose,
) -> Result<SecretKey, KeyStorageError> {
    let purpose = match purpose {
        AccountKeyPurpose::SqlCipherAccountDatabaseV1 => DATABASE_PURPOSE,
    };
    let info = framed_info(account_id, purpose)?;
    let hkdf = Hkdf::<Sha256>::new(Some(ROOT_SALT), root.as_bytes());
    let mut output = SecretKey::zeroed();
    hkdf.expand(&info, output.as_mut_bytes())
        .map_err(|_invalid_length| KeyStorageError::Invalid)?;
    Ok(output)
}

fn framed_info(account: &AccountId, purpose: &[u8]) -> Result<Vec<u8>, KeyStorageError> {
    let account = account.as_str().as_bytes();
    let account_len = u16::try_from(account.len()).map_err(|_too_long| KeyStorageError::Invalid)?;
    let purpose_len = u16::try_from(purpose.len()).map_err(|_too_long| KeyStorageError::Invalid)?;
    let mut result = Vec::with_capacity(HKDF_PREFIX.len() + 4 + account.len() + purpose.len());
    result.extend_from_slice(HKDF_PREFIX);
    result.extend_from_slice(&account_len.to_be_bytes());
    result.extend_from_slice(account);
    result.extend_from_slice(&purpose_len.to_be_bytes());
    result.extend_from_slice(purpose);
    Ok(result)
}

fn hex_digest(account: &AccountId) -> String {
    let digest = Sha256::digest(account.as_str().as_bytes());
    hex_encode(&digest)
}

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut encoded = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        encoded.push(char::from(HEX[usize::from(byte >> 4)]));
        encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
    }
    encoded
}

fn is_readable_directory(path: &Path) -> bool {
    std::fs::read_dir(path).is_ok()
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[cfg_attr(
    all(not(target_os = "macos"), not(test)),
    expect(
        dead_code,
        reason = "Non-macOS builds retain the portable capability shape but fail before constructing a Keychain add result."
    )
)]
enum AddResult {
    Added,
    Duplicate,
}

trait RootKeyBackend: Send + Sync {
    fn copy(&self) -> Result<Option<SecretKey>, KeyStorageError>;
    fn random_key(&self) -> Result<SecretKey, KeyStorageError>;
    fn add(&self, candidate: &SecretKey) -> Result<AddResult, KeyStorageError>;

    fn candidate_zeroized_before_reread(&self, _candidate: &SecretKey) {}
}

trait ContainerLocator: Send + Sync {
    fn container(&self) -> Result<PathBuf, ProfileStorageError>;
}

/// Internal fixed production Keychain implementation.
#[derive(Debug)]
struct ProductionBackend {
    group: &'static str,
}

impl ProductionBackend {
    fn new() -> Result<Self, KeyStorageError> {
        Ok(Self {
            group: configured_group(option_env!("TERSA_MACOS_APP_GROUP"))?,
        })
    }
}

impl RootKeyBackend for ProductionBackend {
    fn copy(&self) -> Result<Option<SecretKey>, KeyStorageError> {
        macos_keychain::copy(self.group)
    }
    fn random_key(&self) -> Result<SecretKey, KeyStorageError> {
        macos_keychain::random()
    }
    fn add(&self, candidate: &SecretKey) -> Result<AddResult, KeyStorageError> {
        macos_keychain::add(self.group, candidate)
    }
}

/// Internal fixed production App Group container implementation.
#[derive(Debug)]
struct ProductionContainerLocator {
    group: &'static str,
}
impl ProductionContainerLocator {
    fn new() -> Result<Self, ProfileStorageError> {
        Ok(Self {
            group: configured_profile_group(option_env!("TERSA_MACOS_APP_GROUP"))?,
        })
    }
}

fn configured_group(group: Option<&'static str>) -> Result<&'static str, KeyStorageError> {
    group
        .filter(|value| !value.is_empty())
        .ok_or(KeyStorageError::Unavailable)
}

fn configured_profile_group(
    group: Option<&'static str>,
) -> Result<&'static str, ProfileStorageError> {
    group
        .filter(|value| !value.is_empty())
        .ok_or(ProfileStorageError::Unavailable)
}
impl ContainerLocator for ProductionContainerLocator {
    fn container(&self) -> Result<PathBuf, ProfileStorageError> {
        macos_container::lookup(self.group)
    }
}

#[cfg(target_os = "macos")]
#[expect(
    unsafe_code,
    clippy::borrow_as_ptr,
    reason = "Security.framework and Core Foundation expose this add-only Keychain contract only through audited C FFI."
)]
mod macos_keychain {
    use super::{AddResult, KeyStorageError, SecretKey};
    use core_foundation::array::CFArray;
    use core_foundation::base::{
        CFEqual, CFIndexConvertible, CFRange, CFType, CFTypeRef, TCFType, kCFAllocatorDefault,
        kCFAllocatorNull,
    };
    use core_foundation::boolean::CFBoolean;
    use core_foundation::data::{CFData, CFDataCreateWithBytesNoCopy, CFDataGetBytes};
    use core_foundation::dictionary::CFDictionary;
    use core_foundation::number::CFNumber;
    use core_foundation::string::{CFString, CFStringRef};
    use security_framework_sys::{access_control, base, item, keychain_item, random};
    use std::ffi::c_void;

    // security-framework-sys 2.17.0 omits only this stable dictionary-key
    // symbol. All other Security constants come from the audited sys crate.
    #[link(name = "Security", kind = "framework")]
    unsafe extern "C" {
        static kSecAttrAccessible: CFStringRef;
    }

    macro_rules! security_string {
        ($symbol:path) => {
            // SAFETY: Every accepted symbol is an immutable process-lifetime
            // Security.framework CFString constant.
            static_string(unsafe { $symbol })
        };
    }

    pub(super) fn copy(group: &str) -> Result<Option<SecretKey>, KeyStorageError> {
        let query = record_dictionary(group, None, true);
        let mut raw: CFTypeRef = std::ptr::null();
        // SAFETY: The retained query dictionary is valid for the synchronous
        // call and `raw` is a writable out-parameter initialized to null.
        let status =
            unsafe { keychain_item::SecItemCopyMatching(query.as_concrete_TypeRef(), &mut raw) };
        if status == base::errSecItemNotFound {
            return Ok(None);
        }
        if status != base::errSecSuccess || raw.is_null() {
            return Err(KeyStorageError::OperationFailed);
        }
        // SAFETY: A successful SecItemCopyMatching result follows the Core
        // Foundation create rule and is non-null as checked above.
        let result = unsafe { CFType::wrap_under_create_rule(raw) };
        decode_copy_result(result, group).map(Some)
    }
    pub(super) fn random() -> Result<SecretKey, KeyStorageError> {
        let mut key = SecretKey::zeroed();
        // SAFETY: The secret output owns exactly 32 writable bytes for the
        // duration of the synchronous Security.framework call.
        let status = unsafe {
            random::SecRandomCopyBytes(
                random::kSecRandomDefault,
                key.as_bytes().len(),
                key.as_mut_bytes().as_mut_ptr().cast::<c_void>(),
            )
        };
        if status == 0 {
            Ok(key)
        } else {
            Err(KeyStorageError::OperationFailed)
        }
    }
    pub(super) fn add(group: &str, candidate: &SecretKey) -> Result<AddResult, KeyStorageError> {
        let status = add_no_copy(group, candidate)?;
        match status {
            base::errSecSuccess => Ok(AddResult::Added),
            base::errSecDuplicateItem => Ok(AddResult::Duplicate),
            _ => Err(KeyStorageError::OperationFailed),
        }
    }

    fn record_dictionary(
        group: &str,
        data: Option<&CFData>,
        returning: bool,
    ) -> CFDictionary<CFType, CFType> {
        record_dictionary_with_optional_attributes(
            group,
            data,
            returning,
            Some(security_string!(item::kSecClassGenericPassword)),
            None,
        )
    }

    fn add_no_copy(group: &str, candidate: &SecretKey) -> Result<i32, KeyStorageError> {
        // SAFETY: This function constructs the borrowing CFData and dictionary,
        // performs the synchronous SecItemAdd call, and drops both before its
        // borrow of `candidate` can end. No object containing the no-copy
        // pointer is returned. kCFAllocatorNull never frees Rust-owned bytes.
        let data_ref = unsafe {
            CFDataCreateWithBytesNoCopy(
                kCFAllocatorDefault,
                candidate.as_bytes().as_ptr(),
                candidate.as_bytes().len().to_CFIndex(),
                kCFAllocatorNull,
            )
        };
        if data_ref.is_null() {
            return Err(KeyStorageError::OperationFailed);
        }
        // SAFETY: CFDataCreateWithBytesNoCopy returned a non-null +1 object.
        let data = unsafe { CFData::wrap_under_create_rule(data_ref) };
        let attributes = record_dictionary(group, Some(&data), false);
        // SAFETY: `attributes`, `data`, and `candidate` are live throughout
        // this synchronous call. The no-copy values are dropped before this
        // function returns, so the raw pointer cannot escape this scope.
        Ok(unsafe {
            keychain_item::SecItemAdd(attributes.as_concrete_TypeRef(), std::ptr::null_mut())
        })
    }

    fn record_dictionary_with_optional_attributes(
        group: &str,
        data: Option<&CFData>,
        returning: bool,
        class: Option<CFType>,
        synchronizable: Option<CFType>,
    ) -> CFDictionary<CFType, CFType> {
        let service = CFString::new(super::SERVICE);
        let account = CFString::new(super::ACCOUNT);
        let group = CFString::new(group);
        let accessible_key = security_string!(kSecAttrAccessible);
        let accessible =
            security_string!(access_control::kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly);
        let data_protection_key = security_string!(item::kSecUseDataProtectionKeychain);
        let pairs = vec![
            (security_string!(item::kSecAttrService), service.as_CFType()),
            (security_string!(item::kSecAttrAccount), account.as_CFType()),
            (
                security_string!(item::kSecAttrAccessGroup),
                group.as_CFType(),
            ),
            (accessible_key, accessible.as_CFType()),
            (data_protection_key, CFBoolean::true_value().as_CFType()),
        ];
        let mut pairs = pairs;
        if let Some(class) = class {
            pairs.push((security_string!(item::kSecClass), class));
        }
        if let Some(synchronizable) = synchronizable {
            pairs.push((
                security_string!(item::kSecAttrSynchronizable),
                synchronizable,
            ));
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
        if let Some(data) = data {
            pairs.push((security_string!(item::kSecValueData), data.as_CFType()));
        }
        CFDictionary::from_CFType_pairs(&pairs)
    }

    fn static_string(raw: CFStringRef) -> CFType {
        // SAFETY: Callers pass immutable process-lifetime Core Foundation
        // string constants, so wrapping under the get rule is correct.
        unsafe { CFString::wrap_under_get_rule(raw).into_CFType() }
    }

    fn decode_copy_result(result: CFType, group: &str) -> Result<SecretKey, KeyStorageError> {
        let array = result
            .downcast_into::<CFArray>()
            .ok_or(KeyStorageError::Invalid)?;
        if array.len() != 1 {
            return Err(KeyStorageError::Invalid);
        }
        let raw = array.get_all_values()[0];
        // SAFETY: `raw` is retained by `array` for the duration of this decode.
        let dictionary = unsafe { CFType::wrap_under_get_rule(raw) }
            .downcast_into::<CFDictionary>()
            .ok_or(KeyStorageError::Invalid)?;
        decode_record(&dictionary, group)
    }

    fn decode_record(dictionary: &CFDictionary, group: &str) -> Result<SecretKey, KeyStorageError> {
        let service = CFString::new(super::SERVICE);
        let account = CFString::new(super::ACCOUNT);
        let group = CFString::new(group);
        let required = [
            (security_string!(item::kSecAttrService), service.as_CFType()),
            (security_string!(item::kSecAttrAccount), account.as_CFType()),
            (
                security_string!(item::kSecAttrAccessGroup),
                group.as_CFType(),
            ),
            (
                security_string!(kSecAttrAccessible),
                security_string!(access_control::kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly),
            ),
        ];
        for (key, value) in required {
            let actual = dictionary
                .find(key.as_CFTypeRef())
                .ok_or(KeyStorageError::Invalid)?;
            // SAFETY: Both arguments are live Core Foundation objects.
            if unsafe { CFEqual(*actual, value.as_CFTypeRef()) } == 0 {
                return Err(KeyStorageError::Invalid);
            }
        }
        validate_optional_attribute(
            dictionary,
            &security_string!(item::kSecClass),
            &security_string!(item::kSecClassGenericPassword),
        )?;
        validate_optional_attribute(
            dictionary,
            &security_string!(item::kSecAttrSynchronizable),
            &CFBoolean::false_value().as_CFType(),
        )?;
        let data = dictionary
            .find(security_string!(item::kSecValueData).as_CFTypeRef())
            .ok_or(KeyStorageError::Invalid)?;
        // SAFETY: The dictionary retains its non-null values while borrowed.
        let data = unsafe { data.as_ref() };
        let data = data.ok_or(KeyStorageError::Invalid)?;
        // SAFETY: The value remains retained by `dictionary` during decode.
        let data = unsafe { CFType::wrap_under_get_rule(data) }
            .downcast_into::<CFData>()
            .ok_or(KeyStorageError::Invalid)?;
        if data.len() != 32 {
            return Err(KeyStorageError::Invalid);
        }
        let mut bytes = SecretKey::zeroed();
        // SAFETY: The validated source range is exactly 32 bytes and `bytes`
        // owns exactly 32 writable bytes. CFDataGetBytes performs the sole
        // copy directly into the zeroizing destination.
        unsafe {
            CFDataGetBytes(
                data.as_concrete_TypeRef(),
                CFRange::init(0, 32),
                bytes.as_mut_bytes().as_mut_ptr(),
            );
        }
        Ok(bytes)
    }

    fn validate_optional_attribute(
        dictionary: &CFDictionary,
        key: &CFType,
        expected: &CFType,
    ) -> Result<(), KeyStorageError> {
        let Some(actual) = dictionary.find(key.as_CFTypeRef()) else {
            return Ok(());
        };
        // SAFETY: Both arguments are live Core Foundation objects.
        if unsafe { CFEqual(*actual, expected.as_CFTypeRef()) } == 0 {
            return Err(KeyStorageError::Invalid);
        }
        Ok(())
    }

    #[cfg(test)]
    #[expect(
        clippy::unwrap_used,
        reason = "Focused Core Foundation boundary tests fail immediately when a required fixture value is absent."
    )]
    mod tests {
        use super::*;

        fn assert_dictionary_value(
            dictionary: &CFDictionary<CFType, CFType>,
            key: &CFType,
            expected: &CFType,
        ) {
            let actual = dictionary.find(key.as_CFTypeRef()).unwrap();
            // SAFETY: The dictionary value and expected fixture are live Core
            // Foundation objects for the duration of this assertion.
            let equal = unsafe { CFEqual(actual.as_CFTypeRef(), expected.as_CFTypeRef()) };
            assert_ne!(equal, 0);
        }

        fn fixture_record(
            group: &str,
            data: Option<&[u8]>,
            class: Option<CFType>,
            synchronizable: Option<CFType>,
        ) -> CFDictionary<CFType, CFType> {
            let data = data.map(CFData::from_buffer);
            record_dictionary_with_optional_attributes(
                group,
                data.as_ref(),
                false,
                class,
                synchronizable,
            )
        }

        fn exact_fixture_record(group: &str, data: Option<&[u8]>) -> CFDictionary<CFType, CFType> {
            fixture_record(
                group,
                data,
                Some(security_string!(item::kSecClassGenericPassword)),
                Some(CFBoolean::false_value().as_CFType()),
            )
        }

        #[test]
        fn copy_query_omits_synchronizable_and_fixes_data_protection_group_and_limit() {
            let group = "TEAM.app.tersa.shared";
            let query = record_dictionary(group, None, true);
            assert_dictionary_value(
                &query,
                &security_string!(item::kSecAttrAccessGroup),
                &CFString::new(group).as_CFType(),
            );
            assert_dictionary_value(
                &query,
                &security_string!(item::kSecUseDataProtectionKeychain),
                &CFBoolean::true_value().as_CFType(),
            );
            assert!(
                query
                    .find(security_string!(item::kSecAttrSynchronizable).as_CFTypeRef())
                    .is_none()
            );
            assert_dictionary_value(
                &query,
                &security_string!(item::kSecMatchLimit),
                &CFNumber::from(2).as_CFType(),
            );
            assert_dictionary_value(
                &query,
                &security_string!(item::kSecReturnData),
                &CFBoolean::true_value().as_CFType(),
            );
            assert_dictionary_value(
                &query,
                &security_string!(item::kSecReturnAttributes),
                &CFBoolean::true_value().as_CFType(),
            );
        }

        #[test]
        fn add_dictionary_omits_synchronizable_and_uses_data_protection_keychain() {
            let data = CFData::from_buffer(&[7; 32]);
            let dictionary = record_dictionary("TEAM.app.tersa.shared", Some(&data), false);
            assert!(
                dictionary
                    .find(security_string!(item::kSecAttrSynchronizable).as_CFTypeRef())
                    .is_none()
            );
            assert_dictionary_value(
                &dictionary,
                &security_string!(item::kSecUseDataProtectionKeychain),
                &CFBoolean::true_value().as_CFType(),
            );
            assert_dictionary_value(
                &dictionary,
                &security_string!(item::kSecValueData),
                &CFData::from_buffer(&[7; 32]).as_CFType(),
            );
        }

        #[test]
        fn copy_decoder_accepts_one_exact_record_and_rejects_ambiguous_or_malformed_results() {
            let group = "TEAM.app.tersa.shared";
            let record = exact_fixture_record(group, Some(&[7; 32]));
            let one = CFArray::from_CFTypes(&[record.as_CFType()]);
            assert_eq!(
                *decode_copy_result(one.as_CFType(), group)
                    .unwrap()
                    .as_bytes(),
                [7; 32]
            );

            let first = exact_fixture_record(group, Some(&[7; 32]));
            let second = exact_fixture_record(group, Some(&[8; 32]));
            let duplicate = CFArray::from_CFTypes(&[first.as_CFType(), second.as_CFType()]);
            assert_eq!(
                decode_copy_result(duplicate.as_CFType(), group),
                Err(KeyStorageError::Invalid)
            );
            assert_eq!(
                decode_copy_result(CFString::new("not-an-array").as_CFType(), group),
                Err(KeyStorageError::Invalid)
            );
        }

        #[test]
        fn copy_decoder_rejects_wrong_attributes_and_secret_lengths() {
            let group = "TEAM.app.tersa.shared";
            let wrong_group = exact_fixture_record("OTHER.app.tersa.shared", Some(&[7; 32]));
            let wrong_group = CFArray::from_CFTypes(&[wrong_group.as_CFType()]);
            assert_eq!(
                decode_copy_result(wrong_group.as_CFType(), group),
                Err(KeyStorageError::Invalid)
            );

            let short = exact_fixture_record(group, Some(&[7; 31]));
            let short = CFArray::from_CFTypes(&[short.as_CFType()]);
            assert_eq!(
                decode_copy_result(short.as_CFType(), group),
                Err(KeyStorageError::Invalid)
            );

            let missing_data = exact_fixture_record(group, None);
            let missing_data = CFArray::from_CFTypes(&[missing_data.as_CFType()]);
            assert_eq!(
                decode_copy_result(missing_data.as_CFType(), group),
                Err(KeyStorageError::Invalid)
            );
        }

        #[test]
        fn copy_decoder_allows_omitted_class_and_synchronizable_but_rejects_mismatch() {
            let group = "TEAM.app.tersa.shared";
            let omitted = fixture_record(group, Some(&[7; 32]), None, None);
            let omitted = CFArray::from_CFTypes(&[omitted.as_CFType()]);
            assert_eq!(
                *decode_copy_result(omitted.as_CFType(), group)
                    .unwrap()
                    .as_bytes(),
                [7; 32]
            );

            let wrong_class = fixture_record(
                group,
                Some(&[7; 32]),
                Some(CFString::new("wrong-class").as_CFType()),
                None,
            );
            let wrong_class = CFArray::from_CFTypes(&[wrong_class.as_CFType()]);
            assert_eq!(
                decode_copy_result(wrong_class.as_CFType(), group),
                Err(KeyStorageError::Invalid)
            );

            let wrong_sync = fixture_record(
                group,
                Some(&[7; 32]),
                None,
                Some(CFBoolean::true_value().as_CFType()),
            );
            let wrong_sync = CFArray::from_CFTypes(&[wrong_sync.as_CFType()]);
            assert_eq!(
                decode_copy_result(wrong_sync.as_CFType(), group),
                Err(KeyStorageError::Invalid)
            );
        }
    }
}
#[cfg(not(target_os = "macos"))]
mod macos_keychain {
    use super::{AddResult, KeyStorageError, SecretKey};
    pub(super) fn copy(_: &str) -> Result<Option<SecretKey>, KeyStorageError> {
        Err(KeyStorageError::Unavailable)
    }
    pub(super) fn random() -> Result<SecretKey, KeyStorageError> {
        Err(KeyStorageError::Unavailable)
    }
    pub(super) fn add(_: &str, _: &SecretKey) -> Result<AddResult, KeyStorageError> {
        Err(KeyStorageError::Unavailable)
    }
}
#[cfg(target_os = "macos")]
mod macos_container {
    use super::ProfileStorageError;
    use objc2_foundation::{NSFileManager, NSString};
    use std::path::PathBuf;
    pub(super) fn lookup(group: &str) -> Result<PathBuf, ProfileStorageError> {
        let group = NSString::from_str(group);
        let url = NSFileManager::defaultManager()
            .containerURLForSecurityApplicationGroupIdentifier(&group)
            .ok_or(ProfileStorageError::Unavailable)?;
        if !url.isFileURL() {
            return Err(ProfileStorageError::Unavailable);
        }
        let path = url.path().ok_or(ProfileStorageError::Unavailable)?;
        Ok(PathBuf::from(path.to_string()))
    }
}
#[cfg(not(target_os = "macos"))]
mod macos_container {
    use super::ProfileStorageError;
    use std::path::PathBuf;
    pub(super) fn lookup(_: &str) -> Result<PathBuf, ProfileStorageError> {
        Err(ProfileStorageError::Unavailable)
    }
}

#[cfg(test)]
#[expect(
    clippy::cast_possible_truncation,
    clippy::unwrap_used,
    reason = "Test fixtures use bounded indices and fail immediately on poisoned locks or unexpected results."
)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{Arc, Barrier, Mutex};

    fn account_id() -> AccountId {
        AccountId::new("acct-test-1").unwrap()
    }

    struct FakeLocator(Result<PathBuf, ProfileStorageError>);
    impl ContainerLocator for FakeLocator {
        fn container(&self) -> Result<PathBuf, ProfileStorageError> {
            self.0.clone()
        }
    }

    #[derive(Default)]
    struct Fake {
        item: Mutex<Option<[u8; 32]>>,
        random: Mutex<[u8; 32]>,
        calls: Mutex<Vec<&'static str>>,
        duplicate_on_add: bool,
        zeroized_before_reread: Mutex<bool>,
    }
    impl RootKeyBackend for Fake {
        fn copy(&self) -> Result<Option<SecretKey>, KeyStorageError> {
            self.calls.lock().unwrap().push("copy");
            Ok(self.item.lock().unwrap().map(SecretKey::new))
        }
        fn random_key(&self) -> Result<SecretKey, KeyStorageError> {
            self.calls.lock().unwrap().push("random");
            Ok(SecretKey::new(*self.random.lock().unwrap()))
        }
        fn add(&self, c: &SecretKey) -> Result<AddResult, KeyStorageError> {
            self.calls.lock().unwrap().push("add");
            let mut item = self.item.lock().unwrap();
            if self.duplicate_on_add {
                *item = Some([9; 32]);
                Ok(AddResult::Duplicate)
            } else if item.is_some() {
                Ok(AddResult::Duplicate)
            } else {
                *item = Some(*c.as_bytes());
                Ok(AddResult::Added)
            }
        }
        fn candidate_zeroized_before_reread(&self, candidate: &SecretKey) {
            assert_eq!(candidate.as_bytes(), &[0; 32]);
            *self.zeroized_before_reread.lock().unwrap() = true;
            self.calls.lock().unwrap().push("zeroized");
        }
    }

    #[derive(Clone)]
    struct ConcurrentFake {
        item: Arc<Mutex<Option<[u8; 32]>>>,
        first_copy: Arc<AtomicBool>,
        initial_copy_barrier: Arc<Barrier>,
        candidate: [u8; 32],
    }

    impl RootKeyBackend for ConcurrentFake {
        fn copy(&self) -> Result<Option<SecretKey>, KeyStorageError> {
            if !self.first_copy.swap(true, Ordering::SeqCst) {
                let snapshot = *self.item.lock().unwrap();
                self.initial_copy_barrier.wait();
                return Ok(snapshot.map(SecretKey::new));
            }
            Ok(self.item.lock().unwrap().map(SecretKey::new))
        }

        fn random_key(&self) -> Result<SecretKey, KeyStorageError> {
            Ok(SecretKey::new(self.candidate))
        }

        fn add(&self, candidate: &SecretKey) -> Result<AddResult, KeyStorageError> {
            let mut item = self.item.lock().unwrap();
            if item.is_some() {
                Ok(AddResult::Duplicate)
            } else {
                *item = Some(*candidate.as_bytes());
                Ok(AddResult::Added)
            }
        }
    }
    #[test]
    fn hkdf_known_answer_and_info() {
        let root = SecretKey::new(core::array::from_fn(|i| i as u8));
        assert_eq!(
            hex_encode(&framed_info(&account_id(), DATABASE_PURPOSE).unwrap()),
            "74657273612e6170702f6d61636f732f686b64662d7368613235362f7631000b616363742d746573742d31001d73716c6369706865722f6163636f756e742d64617461626173652f7631"
        );
        assert_eq!(
            hex_encode(
                derive_account_key(
                    &root,
                    &account_id(),
                    AccountKeyPurpose::SqlCipherAccountDatabaseV1
                )
                .unwrap()
                .as_bytes()
            ),
            "c822b72b2aaad045b983307618e4ea580ab2c1a219dcf379b229661f68f8c148"
        );
    }
    #[test]
    fn existing_item_skips_rng_and_add() {
        let fake = Fake::default();
        *fake.item.lock().unwrap() = Some([7; 32]);
        assert_eq!(
            provision_installation_root_key(&fake),
            Ok(ProvisionOutcome::Existing)
        );
        assert_eq!(*fake.calls.lock().unwrap(), vec!["copy"]);
    }
    #[test]
    fn success_rereads_after_add() {
        let fake = Fake::default();
        assert_eq!(
            provision_installation_root_key(&fake),
            Ok(ProvisionOutcome::Created)
        );
        assert_eq!(
            *fake.calls.lock().unwrap(),
            vec!["copy", "random", "add", "zeroized", "copy"]
        );
    }
    #[test]
    fn duplicate_loser_zeroizes_before_reread() {
        let fake = Fake {
            duplicate_on_add: true,
            ..Fake::default()
        };
        assert_eq!(
            provision_installation_root_key(&fake),
            Ok(ProvisionOutcome::Existing)
        );
        assert_eq!(
            *fake.calls.lock().unwrap(),
            vec!["copy", "random", "add", "zeroized", "copy"]
        );
        assert!(*fake.zeroized_before_reread.lock().unwrap());
    }

    #[test]
    fn simultaneous_provisioners_converge_on_one_stored_winner() {
        let item = Arc::new(Mutex::new(None));
        let barrier = Arc::new(Barrier::new(2));
        let first = ConcurrentFake {
            item: Arc::clone(&item),
            first_copy: Arc::new(AtomicBool::new(false)),
            initial_copy_barrier: Arc::clone(&barrier),
            candidate: [1; 32],
        };
        let second = ConcurrentFake {
            item: Arc::clone(&item),
            first_copy: Arc::new(AtomicBool::new(false)),
            initial_copy_barrier: barrier,
            candidate: [2; 32],
        };

        let first = std::thread::spawn(move || provision_installation_root_key(&first));
        let second = std::thread::spawn(move || provision_installation_root_key(&second));
        let mut outcomes = [
            first.join().unwrap().unwrap(),
            second.join().unwrap().unwrap(),
        ];
        outcomes.sort_by_key(|outcome| match outcome {
            ProvisionOutcome::Created => 0,
            ProvisionOutcome::Existing => 1,
        });

        assert_eq!(
            outcomes,
            [ProvisionOutcome::Created, ProvisionOutcome::Existing]
        );
        let winner = *item.lock().unwrap();
        assert!(winner == Some([1; 32]) || winner == Some([2; 32]));
    }
    #[test]
    fn digest_is_fixed() {
        assert_eq!(
            hex_digest(&account_id()),
            "1a0b66a4c753580e7b1710d6e6057933d031fc6d5ebfd4ff3994f4b02641fc47"
        );
    }
    #[test]
    fn fixed_profile_layout_requires_an_existing_readable_directory() {
        let directory = std::env::temp_dir();
        let locator = FakeLocator(Ok(directory.clone()));
        assert_eq!(
            account_database_path(&locator, &account_id()).unwrap(),
            directory.join("profiles/default/accounts/1a0b66a4c753580e7b1710d6e6057933d031fc6d5ebfd4ff3994f4b02641fc47/mail.sqlite3")
        );
        let missing = FakeLocator(Ok(directory.join("tersa-missing-container")));
        assert_eq!(
            account_database_path(&missing, &account_id()),
            Err(ProfileStorageError::Unavailable)
        );
        let no_config = FakeLocator(Err(ProfileStorageError::Unavailable));
        assert_eq!(
            account_database_path(&no_config, &account_id()),
            Err(ProfileStorageError::Unavailable)
        );
    }

    #[test]
    fn profile_locator_rejects_non_directories_without_fallback() {
        let path = std::env::temp_dir().join(format!(
            "tersa-keychain-profile-file-{}",
            std::process::id()
        ));
        std::fs::write(&path, b"not a container").unwrap();
        let locator = FakeLocator(Ok(path.clone()));
        assert_eq!(
            account_database_path(&locator, &account_id()),
            Err(ProfileStorageError::Unavailable)
        );
        std::fs::remove_file(path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn profile_locator_rejects_unreadable_directories() {
        use std::os::unix::fs::PermissionsExt;

        let path = std::env::temp_dir().join(format!(
            "tersa-keychain-unreadable-container-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&path);
        std::fs::create_dir(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000)).unwrap();
        let locator = FakeLocator(Ok(path.clone()));
        assert_eq!(
            account_database_path(&locator, &account_id()),
            Err(ProfileStorageError::Unavailable)
        );
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        std::fs::remove_dir(path).unwrap();
    }

    #[test]
    fn production_group_configuration_fails_closed() {
        assert_eq!(configured_group(None), Err(KeyStorageError::Unavailable));
        assert_eq!(
            configured_group(Some("")),
            Err(KeyStorageError::Unavailable)
        );
        assert_eq!(
            configured_group(Some("TEAM.app.tersa.shared")),
            Ok("TEAM.app.tersa.shared")
        );
        assert_eq!(
            configured_profile_group(None),
            Err(ProfileStorageError::Unavailable)
        );
        assert_eq!(
            configured_profile_group(Some("TEAM.app.tersa.shared")),
            Ok("TEAM.app.tersa.shared")
        );
    }
    #[test]
    fn framing_rejects_oversized_purpose_and_separates_segments() {
        assert_eq!(
            framed_info(&account_id(), &vec![0; usize::from(u16::MAX) + 1]),
            Err(KeyStorageError::Invalid)
        );
        let account_ab = AccountId::new("ab").unwrap();
        let account_a = AccountId::new("a").unwrap();
        assert_ne!(
            framed_info(&account_ab, b"c").unwrap(),
            framed_info(&account_a, b"bc").unwrap()
        );
    }
    #[test]
    fn errors_and_capabilities_are_redacted() {
        assert_eq!(
            format!("{:?}", KeyStorageError::Invalid),
            "KeyStorageError([REDACTED])"
        );
        assert_eq!(
            format!("{:?}", ProfileStorageError::Invalid),
            "ProfileStorageError([REDACTED])"
        );
        let secret = SecretKey::new([0xAB; 32]);
        let formatted = format!("{secret:?}");
        assert_eq!(formatted, "SecretKey([REDACTED])");
        assert!(!formatted.contains("171"));
        assert!(!formatted.contains("AB"));
        assert!(!formatted.contains("ab"));
    }
}
