//! Making, reloading, and using an enclave key, through Security.framework.
//!
//! Every call here returns a `+1` reference or null with an error out-parameter. Each reference is
//! wrapped in an owning `CFType` the moment it arrives, and each null becomes an [`Error`] before
//! anything reads it: a null handed on to the next call is how a damaged blob turns into a crash.

use core::ptr;
use core::time::Duration;

use core_foundation::base::{CFOptionFlags, CFType, CFTypeRef, TCFType as _};
use core_foundation::boolean::CFBoolean;
use core_foundation::data::CFData;
use core_foundation::dictionary::{CFDictionary, CFMutableDictionary};
use core_foundation::error::CFErrorRef;
use core_foundation::number::CFNumber;
use core_foundation::string::{CFString, CFStringRef};
use security_framework_sys::access_control::{
    SecAccessControlCreateWithFlags, kSecAccessControlBiometryCurrentSet,
    kSecAccessControlPrivateKeyUsage, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
};
use security_framework_sys::base::SecKeyRef;
use security_framework_sys::item::{
    kSecAttrAccessControl, kSecAttrIsPermanent, kSecAttrKeyClass, kSecAttrKeyClassPrivate,
    kSecAttrKeyClassPublic, kSecAttrKeySizeInBits, kSecAttrKeyType,
    kSecAttrKeyTypeECSECPrimeRandom, kSecAttrTokenID, kSecAttrTokenIDSecureEnclave,
    kSecPrivateKeyAttrs, kSecUseAuthenticationContext,
};
use security_framework_sys::key::{
    SecKeyCopyAttributes, SecKeyCopyExternalRepresentation, SecKeyCopyKeyExchangeResult,
    SecKeyCopyPublicKey, SecKeyCreateRandomKey, SecKeyCreateWithData,
    kSecKeyAlgorithmECDHKeyExchangeStandard,
};
use zeroize::Zeroizing;

use crate::context::Context;
use crate::error::{Error, OsError};
use crate::{PUBLIC_KEY_LEN, Policy, SECRET_LEN};

/// The attribute that holds an enclave key's blob: the key, wrapped by the enclave so only this Mac's
/// enclave can use it. It is `kSecAttrTokenOID`, which the public headers do not export; CryptoKit's
/// `dataRepresentation` is the same bytes.
const TOKEN_OBJECT: &str = "toid";

/// LocalAuthentication's codes for a person who said no: the touch did not match, they cancelled,
/// or the system cancelled the dialog (the screen locked with it up).
const DECLINED: [isize; 3] = [-1, -2, -4];
/// LocalAuthentication's codes for a context invalidated by its own program: `-9` when it is pulled
/// while the dialog is up, `-10` when it is pulled before the evaluation starts. Only
/// [`Key::agree`]'s deadline invalidates a context while it is in use, so either one after the
/// deadline fired is a timeout; without it, the system's own failure, never a cancel.
const PULLED: [isize; 2] = [-9, -10];
/// LocalAuthentication's code for "a person is needed, and this context may not ask".
const NOT_INTERACTIVE: isize = -1004;

impl Policy {
    /// The access control flags this policy pins. Never `userPresence`, `biometryAny`, or a watch:
    /// each lets the login password or a newly enrolled finger in.
    pub(crate) const fn flags(self) -> CFOptionFlags {
        match self {
            Self::BiometryCurrentSet => {
                kSecAccessControlPrivateKeyUsage | kSecAccessControlBiometryCurrentSet
            }
        }
    }
}

/// Make a new key in this Mac's Secure Enclave under `policy`, and return its blob and its public key
/// (65 bytes, uncompressed X9.63). Nothing is asked of anyone, and nothing is put in the keychain:
/// the key is not permanent, so the blob is its only home.
///
/// Before returning, the key is reloaded from its blob and asked for an agreement with nobody allowed
/// to answer. It must refuse for want of a person; a key that opens anyway guards nothing, and is
/// refused here as [`Error::Unguarded`] rather than handed out. That self-test refuses a key with no
/// access control, and nothing finer: a key that let the login password or a newly enrolled finger in
/// would pass it too. Which access control a key gets is pinned by `policy` alone, and the crate's
/// source test holds `Policy::BiometryCurrentSet` to its two flags.
pub fn create(policy: Policy) -> Result<(Vec<u8>, [u8; PUBLIC_KEY_LEN]), Error> {
    let mut error: CFErrorRef = ptr::null_mut();
    // SAFETY: the protection class is a static `CFString`, the flags are plain bits, and the error
    // out-parameter is a valid pointer to null.
    let access = unsafe {
        SecAccessControlCreateWithFlags(
            ptr::null(),
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly.cast(),
            policy.flags(),
            &raw mut error,
        )
    };
    let access = owned(access.cast_const().cast(), error).map_err(Error::AccessControl)?;

    let mut private = CFMutableDictionary::<CFType, CFType>::new();
    let mut attributes = ec_attributes();
    // SAFETY: every pointer handed to `string` here is the address of a Security.framework static.
    unsafe {
        private.set(
            string(&raw const kSecAttrIsPermanent),
            CFBoolean::false_value().as_CFType(),
        );
        private.set(string(&raw const kSecAttrAccessControl), access);
        attributes.set(
            string(&raw const kSecAttrTokenID),
            string(&raw const kSecAttrTokenIDSecureEnclave),
        );
        attributes.set(
            string(&raw const kSecPrivateKeyAttrs),
            private.to_immutable().as_CFType(),
        );
    }

    let mut error: CFErrorRef = ptr::null_mut();
    // SAFETY: the attributes are a live dictionary and the error out-parameter is valid.
    let made =
        unsafe { SecKeyCreateRandomKey(attributes.as_concrete_TypeRef().cast(), &raw mut error) };
    let made = owned(made.cast_const().cast(), error).map_err(Error::Create)?;

    // SAFETY: `made` is a live `SecKey`; the call returns a +1 dictionary or null.
    let held = unsafe { SecKeyCopyAttributes(sec_key(&made)) };
    if held.is_null() {
        return Err(Error::NoBlob);
    }
    // SAFETY: `held` is a non-null +1 dictionary this function owns.
    let held: CFDictionary<CFType, CFType> = unsafe { CFDictionary::wrap_under_create_rule(held) };
    let Some(blob) = held.find(CFString::new(TOKEN_OBJECT).as_CFType()) else {
        return Err(Error::NoBlob);
    };
    let Some(blob) = blob.downcast::<CFData>() else {
        return Err(Error::NoBlob);
    };
    let public = public_of(&made)?;

    // The self-test: the key as it will be used, from its blob, must refuse with nobody to ask.
    load(blob.bytes(), &public)?.check()?;
    Ok((blob.bytes().to_vec(), public))
}

/// Reload a key from its `blob`, and check it is the key whose public key is `public`. Nothing is
/// asked of anyone: a reload is a handle, and only an agreement needs the enclave's permission.
///
/// A blob made on another Mac may load and then fail at first use; [`Key::check`] tells.
pub fn load(blob: &[u8], public: &[u8; PUBLIC_KEY_LEN]) -> Result<Key, Error> {
    let key = Key {
        blob: CFData::from_buffer(blob),
    };
    let reloaded = key.reload(None)?;
    if public_of(&reloaded)? != *public {
        return Err(Error::OtherKey);
    }
    Ok(key)
}

/// An enclave key, by its blob. It holds no context and no handle between operations: each
/// operation reloads the key under a context of its own.
pub struct Key {
    blob: CFData,
}

impl Key {
    /// Agree a secret with `peer` (a P-256 public key, uncompressed X9.63): the x-coordinate of the
    /// shared point, as ECDH defines it. This is the one call that asks for a touch, with `reason`
    /// in the dialog. Each call asks again.
    ///
    /// The dialog stays up at most `wait`: then this call closes it itself and fails as
    /// [`Error::TimedOut`]. Nothing outside the call can reach the dialog, and it does not close when
    /// the program that asked exits, so the bound has to be here.
    pub fn agree(
        &self,
        peer: &[u8; PUBLIC_KEY_LEN],
        reason: &str,
        wait: Duration,
    ) -> Result<Zeroizing<[u8; SECRET_LEN]>, Error> {
        // The dialog shows the reason as the whole of why it asks; an empty one asks with no why.
        if reason.trim().is_empty() {
            return Err(Error::NoReason);
        }
        let context = Context::asking(reason)?;
        let key = self.reload(Some(&context))?;
        let peer = public_key(peer)?;
        let (agreed, fired) = context.within(wait, || exchange(&key, &peer))?;
        // A touch in the last instant, after the deadline fired, still agreed: it is kept.
        agreed.map_err(|error| past(error, fired))
    }

    /// Ask for an agreement with nobody allowed to answer: `Ok` when the enclave refuses only for want
    /// of a person, which says the key is this Mac's, still alive, and guarded. A blob from another
    /// Mac or a damaged one fails as [`Error::Load`]; a key that answers anyway fails as
    /// [`Error::Unguarded`]. Never shows a dialog.
    pub fn check(&self) -> Result<(), Error> {
        let context = Context::silent()?;
        let key = self.reload(Some(&context))?;
        // Any valid point serves as the peer: the enclave refuses before it looks at it.
        let peer = public_key(&public_of(&key)?)?;
        match exchange(&key, &peer) {
            Err(Error::NotInteractive(_)) => Ok(()),
            Ok(_) => Err(Error::Unguarded),
            Err(error) => Err(error),
        }
    }

    /// The key, reloaded from its blob, bound to `context` when one is given.
    fn reload(&self, context: Option<&Context>) -> Result<CFType, Error> {
        let mut attributes = ec_attributes();
        attributes.set(
            CFString::new(TOKEN_OBJECT).as_CFType(),
            self.blob.as_CFType(),
        );
        // SAFETY: every pointer handed to `string` here is the address of a Security.framework static.
        unsafe {
            attributes.set(
                string(&raw const kSecAttrKeyClass),
                string(&raw const kSecAttrKeyClassPrivate),
            );
            attributes.set(
                string(&raw const kSecAttrTokenID),
                string(&raw const kSecAttrTokenIDSecureEnclave),
            );
            if let Some(context) = context {
                attributes.set(
                    string(&raw const kSecUseAuthenticationContext),
                    context.as_cf_type().clone(),
                );
            }
        }
        let mut error: CFErrorRef = ptr::null_mut();
        // SAFETY: the data argument is empty because the token and its object id name the key; the
        // attributes are a live dictionary and the error out-parameter is valid.
        let reloaded = unsafe {
            SecKeyCreateWithData(
                CFData::from_buffer(&[]).as_concrete_TypeRef(),
                attributes.as_concrete_TypeRef().cast(),
                &raw mut error,
            )
        };
        owned(reloaded.cast_const().cast(), error).map_err(Error::Load)
    }
}

/// ECDH between the enclave key and `peer`, through the enclave.
fn exchange(key: &CFType, peer: &CFType) -> Result<Zeroizing<[u8; SECRET_LEN]>, Error> {
    let parameters = CFDictionary::<CFType, CFType>::from_CFType_pairs(&[]);
    let mut error: CFErrorRef = ptr::null_mut();
    // SAFETY: both keys are live `SecKey`s, the algorithm is a static `CFString`, the parameters are
    // a live empty dictionary, and the error out-parameter is valid.
    let shared = unsafe {
        SecKeyCopyKeyExchangeResult(
            sec_key(key),
            kSecKeyAlgorithmECDHKeyExchangeStandard,
            sec_key(peer),
            parameters.as_concrete_TypeRef(),
            &raw mut error,
        )
    };
    if shared.is_null() {
        return Err(read(OsError::take(error)));
    }
    // SAFETY: `shared` is a non-null +1 `CFData` this function owns.
    let shared = unsafe { CFData::wrap_under_create_rule(shared) };
    // The system's own copy is freed by the system, unwiped; this one is wiped on drop.
    let mut secret = Zeroizing::new([0; SECRET_LEN]);
    if shared.bytes().len() != SECRET_LEN {
        return Err(Error::SecretLength {
            found: shared.bytes().len(),
        });
    }
    secret.copy_from_slice(shared.bytes());
    Ok(secret)
}

/// What an agreement's refusal says, by its domain and code.
fn read(os: OsError) -> Error {
    let local_authentication =
        |codes: &[isize]| codes.iter().any(|&code| os.is_local_authentication(code));
    if local_authentication(&DECLINED) {
        Error::Declined(os)
    } else if local_authentication(&[NOT_INTERACTIVE]) {
        Error::NotInteractive(os)
    } else if os.is_token() {
        // A damaged blob, or another Mac's, loads and then fails here, before any dialog.
        Error::Load(os)
    } else {
        Error::Agree(os)
    }
}

/// An agreement's refusal once its deadline is known: a pulled context after the deadline fired is
/// the wait running out. Any other refusal keeps its own reading, a cancel in the last instant
/// included.
fn past(error: Error, fired: bool) -> Error {
    match error {
        Error::Agree(os)
            if fired && PULLED.iter().any(|&code| os.is_local_authentication(code)) =>
        {
            Error::TimedOut(os)
        }
        error => error,
    }
}

/// A key's public half, uncompressed X9.63.
fn public_of(key: &CFType) -> Result<[u8; PUBLIC_KEY_LEN], Error> {
    // SAFETY: `key` is a live `SecKey`; the call returns a +1 key or null.
    let public = unsafe { SecKeyCopyPublicKey(sec_key(key)) };
    // A damaged blob can reload and still have no public half: null here, never passed on.
    let public = owned(public.cast_const().cast(), ptr::null_mut()).map_err(Error::Load)?;
    let mut error: CFErrorRef = ptr::null_mut();
    // SAFETY: `public` is a live `SecKey` and the error out-parameter is valid.
    let bytes = unsafe { SecKeyCopyExternalRepresentation(sec_key(&public), &raw mut error) };
    let bytes = owned(bytes.cast(), error).map_err(Error::Load)?;
    let Some(bytes) = bytes.downcast::<CFData>() else {
        return Err(Error::OtherKey);
    };
    <[u8; PUBLIC_KEY_LEN]>::try_from(bytes.bytes()).map_err(|_| Error::OtherKey)
}

/// A P-256 public key from its uncompressed X9.63 bytes.
fn public_key(bytes: &[u8; PUBLIC_KEY_LEN]) -> Result<CFType, Error> {
    let mut attributes = ec_attributes();
    // SAFETY: every pointer handed to `string` here is the address of a Security.framework static.
    unsafe {
        attributes.set(
            string(&raw const kSecAttrKeyClass),
            string(&raw const kSecAttrKeyClassPublic),
        );
    }
    let mut error: CFErrorRef = ptr::null_mut();
    // SAFETY: the data and the attributes are live, and the error out-parameter is valid.
    let public = unsafe {
        SecKeyCreateWithData(
            CFData::from_buffer(bytes).as_concrete_TypeRef(),
            attributes.as_concrete_TypeRef().cast(),
            &raw mut error,
        )
    };
    owned(public.cast_const().cast(), error).map_err(Error::Peer)
}

/// The attributes every key here shares: a 256-bit key on the NIST P-256 curve.
fn ec_attributes() -> CFMutableDictionary<CFType, CFType> {
    let mut attributes = CFMutableDictionary::<CFType, CFType>::new();
    // SAFETY: every pointer handed to `string` here is the address of a Security.framework static.
    unsafe {
        attributes.set(
            string(&raw const kSecAttrKeyType),
            string(&raw const kSecAttrKeyTypeECSECPrimeRandom),
        );
        attributes.set(
            string(&raw const kSecAttrKeySizeInBits),
            CFNumber::from(256_i32).as_CFType(),
        );
    }
    attributes
}

/// A `+1` reference a call returned, owned; or, for null, the error the call wrote.
fn owned(reference: CFTypeRef, error: CFErrorRef) -> Result<CFType, OsError> {
    if reference.is_null() {
        return Err(OsError::take(error));
    }
    // SAFETY: a non-null result of a Security.framework `Create` or `Copy` call is a +1 reference
    // the caller owns; `CFType` releases it once on drop. Any error written alongside is null.
    Ok(unsafe { CFType::wrap_under_create_rule(reference) })
}

/// One of Security.framework's exported `CFString` constants, as a dictionary key or value.
///
/// # Safety
///
/// `constant` must be the address of one of the framework's exported `CFString` statics, which it
/// initialises before any code of ours runs and never writes again.
unsafe fn string(constant: *const CFStringRef) -> CFType {
    // SAFETY: the caller vouches that `constant` is such a static; the `CFString` it names lives for
    // the process, and the get rule retains it for the wrapper's life.
    unsafe { CFString::wrap_under_get_rule(*constant) }.as_CFType()
}

/// The `SecKeyRef` an owned `CFType` holds. Every caller passes a reference that a `SecKey` call made.
fn sec_key(key: &CFType) -> SecKeyRef {
    key.as_CFTypeRef().cast_mut().cast()
}

#[cfg(test)]
#[path = "key_tests.rs"]
mod key_tests;
