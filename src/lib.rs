#![deny(missing_docs, dead_code)]
//! This crate implements device cookies, a method to prevent login bruteforce attacks as described
//! by OWASP: https://www.owasp.org/index.php/Slow_Down_Online_Guessing_Attacks_with_Device_Cookies

use ring::hmac;
use std::{
    fmt::Display,
    time::{Duration, Instant},
};

/// Test module
#[cfg(test)]
mod tests;

/// A device cookie containing the identity, nonce and signature.
#[derive(PartialEq, Eq, Clone, Debug, Hash)]
pub struct DeviceCookie {
    identity: String,
    nonce: u64,
    signature: Vec<u8>,
}

impl DeviceCookie {
    /// The identity of the device cookie.
    #[inline]
    pub fn identity(&self) -> &str {
        &self.identity
    }

    /// The nonce of the device cookie.
    #[inline]
    pub fn nonce(&self) -> u64 {
        self.nonce
    }

    /// The signature of the device cookie: This is calculated as `hmac(key, "<identity>,<nonce>"`
    #[inline]
    pub fn signature(&self) -> &[u8] {
        &self.signature
    }
}

/// Describes a login message. Each login message has something, that identifies the user that is
/// trying to log in.
pub trait LoginMessage {
    /// The associated type of the user's identity.
    type Identity: Display;
    /// A way to obtain the identity of a login message. This is what identifies a unique user,
    /// e.g. a username or email address.
    fn identity(&self) -> &Self::Identity;
}

/// The result of an login attempt. This allows us to use any type as the result of a login
/// attempt, as long as it can be evaluated to a boolean value.
pub trait LoginResult {
    /// Check if the login was valid.
    fn is_valid(&self) -> bool;
}

impl LoginResult for bool {
    fn is_valid(&self) -> bool {
        *self
    }
}

impl<E> LoginResult for Result<bool, E> {
    fn is_valid(&self) -> bool {
        match self {
            Ok(valid) => *valid,
            Err(_) => false,
        }
    }
}

/// This trait implements the login logic as described by OWASP. It should be possible to implement
/// this trait for any concievable backed, e.g. databases, memory caches or simple file based
/// solutions.
pub trait Provider {
    /// The associated type of the login message.
    type LoginMessage: LoginMessage;
    /// The result of an login attempt.
    type LoginResult: LoginResult;
    /// Iterator over all failures for an identity.
    type IdentFailIterator: IntoIterator<Item = Instant>;
    /// Iterator over all failures for a cookie.
    type CookieFailIterator: IntoIterator<Item = Instant>;

    /// The number of allowed tries per user or cookie.
    fn tries(&self) -> usize;
    /// The time for how long a user or device cookie is blocked from logging in, if it exceeds
    /// `self.tries()` failed logins.
    fn time(&self) -> Duration;
    /// The secret key used to sign a newly created device cookie.
    fn key(&self) -> &[u8];
    /// Given a login message, check if it is valid or not.
    fn validate_login(&self, msg: &Self::LoginMessage) -> Self::LoginResult;
    /// Returns all failed login attempts for a given identity
    fn failures_for_identity(
        &self,
        identity: &<Self::LoginMessage as LoginMessage>::Identity,
    ) -> Option<Self::IdentFailIterator>;
    /// Get the number of invalid login attempts for a given identity.
    fn tries_for_identity(
        &self,
        identity: &<Self::LoginMessage as LoginMessage>::Identity,
    ) -> usize {
        self.failures_for_identity(identity)
            .map(|failed| {
                failed
                    .into_iter()
                    .filter(|when| when.elapsed() <= self.time())
                    .count()
            })
            .unwrap_or(0)
    }
    /// Logs a failed login attempt for the given identity.
    fn log_for_identity(
        &mut self,
        identity: &<Self::LoginMessage as LoginMessage>::Identity,
        when: Instant,
    );
    /// Returns all failed login attempts for a given identity
    fn failures_for_cookie(&self, cookie: &DeviceCookie) -> Option<Self::CookieFailIterator>;
    /// Get the number of invalid login attempts for a given device cookie.
    fn tries_for_cookie(&self, cookie: &DeviceCookie) -> usize {
        self.failures_for_cookie(cookie)
            .map(|failed| {
                failed
                    .into_iter()
                    .filter(|when| when.elapsed() <= self.time())
                    .count()
            })
            .unwrap_or(0)
    }
    /// Logs a failed login attempt for the given cookie.
    fn log_for_cookie(&mut self, cookie: &DeviceCookie, now: Instant);
    /// Resets the failed login attempts for the given device cookie.
    fn reset_for_cookie(&mut self, identity: &DeviceCookie);
    /// Check if a device cookie is valid for the identity stored inside.
    fn valid_cookie_for_identity(&self, cookie: &DeviceCookie) -> bool {
        let key = hmac::Key::new(hmac::HMAC_SHA512, self.key());
        hmac::verify(
            &key,
            format!("{},{}", cookie.identity(), cookie.nonce()).as_bytes(),
            &cookie.signature,
        )
        .is_ok()
    }

    /// Creates a signed cookie for a given identity and nonce. This uses `HMAC SHA512` to sign the
    /// data. The nonce should be generated by a CSRNG.
    fn sign_cookie(
        &self,
        identity: &<Self::LoginMessage as LoginMessage>::Identity,
        nonce: u64,
    ) -> DeviceCookie {
        let key = hmac::Key::new(hmac::HMAC_SHA512, self.key());
        DeviceCookie {
            identity: identity.to_string(),
            nonce,
            signature: hmac::sign(&key, format!("{},{}", identity, nonce).as_bytes())
                .as_ref()
                .to_vec(),
        }
    }

    /// Performs a login attempt for the given login message and an optional device cookie.
    fn perform_login(
        &mut self,
        msg: Self::LoginMessage,
        cookie: Option<DeviceCookie>,
    ) -> LoginStatus {
        if let Some(cookie) = cookie.filter(|cookie| self.valid_cookie_for_identity(cookie)) {
            let tries = self.tries_for_cookie(&cookie);
            if tries < self.tries() {
                if self.validate_login(&msg).is_valid() {
                    self.reset_for_cookie(&cookie);
                    LoginStatus::Valid(
                        // TODO: generate random nonce
                        self.sign_cookie(msg.identity(), 0),
                    )
                } else {
                    self.log_for_cookie(&cookie, Instant::now());
                    LoginStatus::Invalid
                }
            } else {
                self.log_for_cookie(&cookie, Instant::now());
                LoginStatus::Blocked
            }
        } else {
            let tries = self.tries_for_identity(msg.identity());
            if tries < self.tries() {
                if self.validate_login(&msg).is_valid() {
                    // self.set_for_identity(msg.identity(), 0, Instant::now());
                    LoginStatus::Valid(
                        // TODO: generate random nonce
                        self.sign_cookie(msg.identity(), 0),
                    )
                } else {
                    self.log_for_identity(msg.identity(), Instant::now());
                    LoginStatus::Invalid
                }
            } else {
                self.log_for_identity(msg.identity(), Instant::now());
                LoginStatus::Blocked
            }
        }
    }
}

/// The status of a login attempt.
#[derive(PartialEq, Clone, Debug)]
pub enum LoginStatus {
    /// Valid login. This contains the newly generated device cookie to be passed to the user.
    Valid(DeviceCookie),
    /// Invalid login.
    Invalid,
    /// The user or device cookie has been blocked.
    Blocked,
}

impl LoginStatus {
    /// Checks if the current status represents a valid login attempt.
    pub fn is_valid(&self) -> bool {
        match self {
            LoginStatus::Valid(_) => true,
            _ => false,
        }
    }
}
