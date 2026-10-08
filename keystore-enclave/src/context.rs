//! The `LAContext` an enclave operation asks a person through.
//!
//! One context per operation, made inside it and invalidated when it drops, so a touch given for one
//! operation can never be spent on a second: macOS lets a context answer again for as long as its
//! reuse window allows, and a context that no longer exists answers nothing. The reuse window is
//! left at its default of zero.
//!
//! A context can also be pulled while it asks: [`Context::within`] invalidates it at a deadline from a
//! thread of its own, which closes the dialog and returns the blocked operation with an error.

use core::ffi::{c_char, c_void};
use core::time::Duration;
use std::sync::mpsc::{self, RecvTimeoutError};
use std::thread;

use core_foundation::base::{CFType, CFTypeRef, TCFType as _};
use core_foundation::string::CFString;

use crate::error::Error;

type Id = *mut c_void;
type Sel = *mut c_void;

// Linked for the `LAContext` class; nothing in it is called by symbol. The four selectors below are
// sent by hand through `objc_msgSend`, which avoids a dependency; a fifth is the point to take
// `objc2` instead. The deadline sends one of the four, `invalidate`, from a thread of its own.
#[link(name = "LocalAuthentication", kind = "framework")]
unsafe extern "C" {}

#[link(name = "objc")]
unsafe extern "C" {
    fn objc_getClass(name: *const c_char) -> Id;
    fn sel_registerName(name: *const c_char) -> Sel;
    fn objc_msgSend();
}

/// An `LAContext`, owned: released when it drops, and invalidated first.
pub(crate) struct Context(CFType);

impl Context {
    /// A context that shows `reason` in the Touch ID dialog. macOS frames it as `<program> is trying
    /// to <reason>`, so the caller writes it as a line a person reads.
    pub(crate) fn asking(reason: &str) -> Result<Self, Error> {
        let context = Self::new()?;
        let reason = CFString::new(reason);
        // SAFETY: `setLocalizedReason:` takes one object, and a `CFString` is toll-free bridged to the
        // `NSString` it expects. The context and the string are both alive for the call.
        unsafe {
            send_object(
                context.id(),
                c"setLocalizedReason:".as_ptr(),
                reason.as_CFTypeRef() as Id,
            );
        }
        Ok(context)
    }

    /// A context that may not ask anyone: an operation that needs a person fails at once with
    /// LocalAuthentication's `-1004` instead of showing a dialog.
    pub(crate) fn silent() -> Result<Self, Error> {
        let context = Self::new()?;
        // SAFETY: `setInteractionNotAllowed:` takes one `BOOL`, which is a one-byte `bool` on arm64
        // and a `signed char` on x86_64; either way `true` crosses as the byte 1.
        unsafe { send_bool(context.id(), c"setInteractionNotAllowed:".as_ptr(), true) };
        Ok(context)
    }

    fn new() -> Result<Self, Error> {
        // SAFETY: `objc_getClass` takes a NUL-terminated name and returns the class or nil; the
        // framework is linked above, so the class is registered by the time this runs.
        let class = unsafe { objc_getClass(c"LAContext".as_ptr()) };
        if class.is_null() {
            return Err(Error::NoContext);
        }
        // SAFETY: `+new` takes no arguments and returns a +1 instance, or nil.
        let context = unsafe { send(class, c"new".as_ptr()) };
        if context.is_null() {
            return Err(Error::NoContext);
        }
        // SAFETY: `context` is a +1 object this function owns; `CFType` releases it once on drop, and
        // `CFRelease` releases any Objective-C object.
        Ok(Self(unsafe {
            CFType::wrap_under_create_rule(context as CFTypeRef)
        }))
    }

    /// Run `operation`, which asks through this context, and invalidate the context if it has not
    /// returned after `wait`. Invalidating closes the dialog, and the operation then returns at once
    /// with LocalAuthentication's `-9` (or `-10`, when the deadline beat the dialog up). Returns the
    /// operation's result, and whether the deadline fired.
    ///
    /// The deadline is a scoped thread waiting on a channel: the operation's return drops the
    /// sender, which wakes the timer with nothing to do, and the scope joins it before this returns,
    /// so no thread and no dialog outlives the call.
    pub(crate) fn within<T>(
        &self,
        wait: Duration,
        operation: impl FnOnce() -> T,
    ) -> Result<(T, bool), Error> {
        let cancel = Cancel(self);
        thread::scope(|scope| {
            // Made inside the scope, so an operation that unwinds drops the sender on its way out and
            // the join below it does not sit out the rest of the wait.
            let (finished, deadline) = mpsc::channel::<()>();
            let timer = thread::Builder::new()
                .name("Touch ID deadline".to_owned())
                .spawn_scoped(scope, move || match deadline.recv_timeout(wait) {
                    Err(RecvTimeoutError::Timeout) => {
                        cancel.invalidate();
                        true
                    }
                    Ok(()) | Err(RecvTimeoutError::Disconnected) => false,
                })
                // Refused before the dialog: a touch with no deadline is the wait this exists to end.
                .map_err(Error::Timer)?;
            let done = operation();
            drop(finished);
            // The timer sleeps and sends one message, so it does not panic; if it did, the deadline is
            // read as fired, which names a timeout only for the codes an invalidate alone produces.
            let fired = timer.join().unwrap_or(true);
            Ok((done, fired))
        })
    }

    /// Invalidate the context early, for the deadline: a dialog it shows closes, an evaluation in
    /// flight fails, and it never answers again. The drop invalidates it again, which is a no-op.
    fn invalidate(&self) {
        // SAFETY: `-invalidate` takes no arguments and is valid on a live context, which `self`
        // borrows.
        unsafe { send_void(self.id(), c"invalidate".as_ptr()) };
    }

    /// The context, for the attribute that hands it to a key.
    pub(crate) fn as_cf_type(&self) -> &CFType {
        &self.0
    }

    fn id(&self) -> Id {
        self.0.as_CFTypeRef().cast_mut()
    }
}

impl Drop for Context {
    fn drop(&mut self) {
        // SAFETY: `-invalidate` takes no arguments and is valid on a live context, a second time
        // included; the release that follows (the field's own drop) is the last use.
        unsafe { send_void(self.id(), c"invalidate".as_ptr()) };
    }
}

/// A context lent to the deadline's timer thread, for the one message it sends: `invalidate`.
struct Cancel<'a>(&'a Context);

impl Cancel<'_> {
    // A method, not `cancel.0`, so the timer's closure captures the whole `Cancel` and its `Send`,
    // never the bare `&Context`, which is not.
    fn invalidate(&self) {
        self.0.invalidate();
    }
}

// SAFETY: the timer thread does one thing through this, `-[LAContext invalidate]`, which is the
// message made to be sent while an evaluation started through the context is in flight on another
// thread: it is how an evaluation is cancelled. On macOS it closes the Touch ID dialog and returns the
// blocked `SecKeyCopyKeyExchangeResult` with `-9` about 10 ms after the send. The borrow is live for
// every use: the timer is a scoped thread, joined before `within` returns and so before the context
// can drop. Nothing else crosses: no retain, no release, no other message.
unsafe impl Send for Cancel<'_> {}

/// `objc_msgSend` as a call of no arguments returning an object.
///
/// # Safety
///
/// `receiver` must be a live object or class that answers `selector` with that signature.
unsafe fn send(receiver: Id, selector: *const c_char) -> Id {
    // SAFETY: `objc_msgSend` is called through a pointer cast to the method's own signature, which is
    // how it is always called; the caller vouches for the receiver and the selector.
    unsafe {
        let call = core::mem::transmute::<
            unsafe extern "C" fn(),
            unsafe extern "C" fn(Id, Sel) -> Id,
        >(objc_msgSend);
        call(receiver, sel_registerName(selector))
    }
}

/// `objc_msgSend` as a call of no arguments and no result.
///
/// # Safety
///
/// As [`send`], for a selector that returns nothing.
unsafe fn send_void(receiver: Id, selector: *const c_char) {
    // SAFETY: as in `send`, for this signature.
    unsafe {
        let call = core::mem::transmute::<unsafe extern "C" fn(), unsafe extern "C" fn(Id, Sel)>(
            objc_msgSend,
        );
        call(receiver, sel_registerName(selector));
    }
}

/// `objc_msgSend` as a call of one object argument and no result.
///
/// # Safety
///
/// As [`send`], for a selector taking one object.
unsafe fn send_object(receiver: Id, selector: *const c_char, argument: Id) {
    // SAFETY: as in `send`, for this signature.
    unsafe {
        let call = core::mem::transmute::<unsafe extern "C" fn(), unsafe extern "C" fn(Id, Sel, Id)>(
            objc_msgSend,
        );
        call(receiver, sel_registerName(selector), argument);
    }
}

/// `objc_msgSend` as a call of one `BOOL` argument and no result.
///
/// # Safety
///
/// As [`send`], for a selector taking one `BOOL`.
unsafe fn send_bool(receiver: Id, selector: *const c_char, argument: bool) {
    // SAFETY: as in `send`, for this signature.
    unsafe {
        let call = core::mem::transmute::<
            unsafe extern "C" fn(),
            unsafe extern "C" fn(Id, Sel, bool),
        >(objc_msgSend);
        call(receiver, sel_registerName(selector), argument);
    }
}
