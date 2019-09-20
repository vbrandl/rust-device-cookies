use crate::{DeviceCookie, LoginMessage, LoginStatus, Provider};
use proptest::prelude::*;
use std::{
    collections::{HashMap, HashSet},
    time::{Duration, Instant},
};

struct UserPass {
    user: String,
    pass: String,
}

impl LoginMessage for UserPass {
    type Identity = String;
    fn identity(&self) -> &Self::Identity {
        &self.user
    }
}

struct InMemoryProvider {
    limit: usize,
    time: Duration,
    key: Vec<u8>,
    // failed_attempts_cookie: HashMap<DeviceCookie, HashSet<(Instant, String)>>,
    failed_attempts_cookie: HashMap<DeviceCookie, HashSet<Instant>>,
    failed_attempts_identity: HashMap<String, HashSet<Instant>>,
}

impl Provider for InMemoryProvider {
    type LoginMessage = UserPass;
    type LoginResult = bool;
    type IdentFailIterator = HashSet<Instant>;
    type CookieFailIterator = HashSet<Instant>;

    fn tries(&self) -> usize {
        self.limit
    }

    fn key(&self) -> &[u8] {
        &self.key
    }

    fn time(&self) -> Duration {
        self.time
    }

    fn validate_login(&self, msg: &Self::LoginMessage) -> Self::LoginResult {
        msg.user == "foo" && msg.pass == "bar"
    }

    fn failures_for_cookie(&self, cookie: &DeviceCookie) -> Option<Self::CookieFailIterator> {
        self.failed_attempts_cookie
            .get(cookie)
            .map(|failed| failed.clone())
    }

    fn log_for_cookie(&mut self, cookie: &DeviceCookie, now: Instant) {
        self.failed_attempts_cookie
            .entry(cookie.clone())
            .or_insert(HashSet::new())
            .insert(now);
    }

    fn reset_for_cookie(&mut self, cookie: &DeviceCookie) {
        self.failed_attempts_cookie.remove(cookie);
    }

    fn failures_for_identity(
        &self,
        identity: &<Self::LoginMessage as LoginMessage>::Identity,
    ) -> Option<Self::IdentFailIterator> {
        self.failed_attempts_identity
            .get(identity)
            .map(|failed| failed.clone())
    }

    fn log_for_identity(
        &mut self,
        identity: &<Self::LoginMessage as LoginMessage>::Identity,
        now: Instant,
    ) {
        self.failed_attempts_identity
            .entry(identity.clone())
            .or_insert(HashSet::new())
            .insert(now);
    }

    fn reset_for_identity(&mut self, identity: &<Self::LoginMessage as LoginMessage>::Identity) {
        self.failed_attempts_identity.remove(identity);
    }
}

impl InMemoryProvider {
    fn new(limit: usize, time: Duration, key: Vec<u8>) -> Self {
        Self {
            limit,
            time,
            failed_attempts_identity: HashMap::new(),
            failed_attempts_cookie: HashMap::new(),
            key,
        }
    }
}

fn invalid_login() -> UserPass {
    UserPass {
        user: "foo".to_string(),
        pass: "invalid_pass".to_string(),
    }
}

fn valid_login() -> UserPass {
    UserPass {
        user: "foo".to_string(),
        pass: "bar".to_string(),
    }
}

fn invalid_cookie() -> DeviceCookie {
    DeviceCookie {
        identity: "foo".to_string(),
        nonce: 0,
        signature: vec![],
    }
}

#[test]
fn valid_login_blocked_after_limit_without_cookie() {
    let mut provider = InMemoryProvider::new(2, Duration::from_secs(60), vec![1, 2, 3]);
    assert_eq!(
        LoginStatus::Invalid,
        provider.perform_login(invalid_login(), None)
    );
    assert_eq!(
        LoginStatus::Invalid,
        provider.perform_login(invalid_login(), None)
    );
    assert_eq!(
        LoginStatus::Blocked,
        provider.perform_login(valid_login(), None)
    );
}

#[test]
fn valid_login_resets_tries_without_cookie() {
    let mut provider = InMemoryProvider::new(3, Duration::from_secs(60), vec![1, 2, 3]);
    assert_eq!(
        LoginStatus::Invalid,
        provider.perform_login(invalid_login(), None)
    );
    assert_eq!(
        LoginStatus::Invalid,
        provider.perform_login(invalid_login(), None)
    );
    assert!(provider.perform_login(valid_login(), None).is_valid());
    assert_eq!(
        LoginStatus::Invalid,
        provider.perform_login(invalid_login(), None)
    );
    assert_eq!(
        LoginStatus::Invalid,
        provider.perform_login(invalid_login(), None)
    );
    assert_eq!(
        LoginStatus::Invalid,
        provider.perform_login(invalid_login(), None)
    );
    assert_eq!(
        LoginStatus::Blocked,
        provider.perform_login(valid_login(), None)
    );
}

#[test]
fn valid_login_blocked_after_limit_with_cookie() {
    let mut provider = InMemoryProvider::new(2, Duration::from_secs(60), vec![1, 2, 3]);
    if let LoginStatus::Valid(cookie) = provider.perform_login(valid_login(), None) {
        assert_eq!(
            LoginStatus::Invalid,
            provider.perform_login(invalid_login(), Some(cookie.clone()))
        );
        assert_eq!(
            LoginStatus::Invalid,
            provider.perform_login(invalid_login(), Some(cookie.clone()))
        );
        assert_eq!(
            LoginStatus::Blocked,
            provider.perform_login(valid_login(), Some(cookie))
        );
    } else {
        panic!()
    }
}

#[test]
fn valid_login_resets_tries_with_cookie() {
    let mut provider = InMemoryProvider::new(3, Duration::from_secs(60), vec![1, 2, 3]);
    if let LoginStatus::Valid(cookie) = provider.perform_login(valid_login(), None) {
        assert_eq!(
            LoginStatus::Invalid,
            provider.perform_login(invalid_login(), Some(cookie.clone()))
        );
        assert_eq!(
            LoginStatus::Invalid,
            provider.perform_login(invalid_login(), Some(cookie.clone()))
        );
        assert!(provider
            .perform_login(valid_login(), Some(cookie.clone()))
            .is_valid());
        assert_eq!(
            LoginStatus::Invalid,
            provider.perform_login(invalid_login(), Some(cookie.clone()))
        );
        assert_eq!(
            LoginStatus::Invalid,
            provider.perform_login(invalid_login(), Some(cookie.clone()))
        );
        assert_eq!(
            LoginStatus::Invalid,
            provider.perform_login(invalid_login(), Some(cookie.clone()))
        );
        assert_eq!(
            LoginStatus::Blocked,
            provider.perform_login(valid_login(), Some(cookie.clone()))
        );
    } else {
        panic!()
    }
}

#[test]
fn login_with_cookie_possible_after_blocking() {
    let mut provider = InMemoryProvider::new(3, Duration::from_secs(60), vec![1, 2, 3]);
    if let LoginStatus::Valid(cookie) = provider.perform_login(valid_login(), None) {
        assert_eq!(0, provider.tries_for_identity(invalid_login().identity()));
        assert_eq!(
            LoginStatus::Invalid,
            provider.perform_login(invalid_login(), None)
        );
        assert_eq!(1, provider.tries_for_identity(invalid_login().identity()));
        assert_eq!(
            LoginStatus::Invalid,
            provider.perform_login(invalid_login(), None)
        );
        assert_eq!(2, provider.tries_for_identity(invalid_login().identity()));
        assert_eq!(
            LoginStatus::Invalid,
            provider.perform_login(invalid_login(), None)
        );
        assert_eq!(3, provider.tries_for_identity(invalid_login().identity()));
        assert_eq!(
            LoginStatus::Blocked,
            provider.perform_login(valid_login(), None)
        );
        assert_eq!(4, provider.tries_for_identity(invalid_login().identity()));
        assert!(provider
            .perform_login(valid_login(), Some(cookie))
            .is_valid());
    } else {
        panic!()
    }
}

#[test]
fn login_with_invalid_cookie_not_possible_after_blocking() {
    let mut provider = InMemoryProvider::new(3, Duration::from_secs(60), vec![1, 2, 3]);
    assert_eq!(
        LoginStatus::Invalid,
        provider.perform_login(invalid_login(), None)
    );
    assert_eq!(
        LoginStatus::Invalid,
        provider.perform_login(invalid_login(), None)
    );
    assert_eq!(
        LoginStatus::Invalid,
        provider.perform_login(invalid_login(), None)
    );
    assert_eq!(
        LoginStatus::Blocked,
        provider.perform_login(valid_login(), None)
    );
    assert_eq!(
        LoginStatus::Blocked,
        provider.perform_login(valid_login(), Some(invalid_cookie()))
    );
}

#[test]
fn invalid_cookie_cannot_be_verified() {
    let provider = InMemoryProvider::new(3, Duration::from_secs(60), vec![1, 2, 3]);
    assert!(!provider.valid_cookie_for_identity(&invalid_cookie()));
}

proptest! {
    #[test]
    fn signed_cookie_can_be_validated(identity: String, nonce: u64) {
        let provider = InMemoryProvider::new(3, Duration::from_secs(60), vec![1,2,3]);
        let cookie = provider.sign_cookie(&identity, nonce);
        assert!(provider.valid_cookie_for_identity(&cookie));
    }

    #[test]
    fn signed_cookie_cannot_be_validated_with_different_key(identity: String, nonce: u64) {
        let creation_provider = InMemoryProvider::new(3, Duration::from_secs(60), vec![1,2,3]);
        let validation_provider = InMemoryProvider::new(3, Duration::from_secs(60), vec![3,2,1]);
        let cookie = creation_provider.sign_cookie(&identity, nonce);
        assert!(!validation_provider.valid_cookie_for_identity(&cookie));
    }
}

#[test]
fn unblock_after_lock_time_without_cookie() {
    let cooldown = Duration::from_secs(1);
    let mut provider = InMemoryProvider::new(3, cooldown, vec![1, 2, 3]);
    assert_eq!(
        LoginStatus::Invalid,
        provider.perform_login(invalid_login(), None)
    );
    assert_eq!(
        LoginStatus::Invalid,
        provider.perform_login(invalid_login(), None)
    );
    assert_eq!(
        LoginStatus::Invalid,
        provider.perform_login(invalid_login(), None)
    );
    assert_eq!(
        LoginStatus::Blocked,
        provider.perform_login(valid_login(), None)
    );
    std::thread::sleep(cooldown);
    assert!(provider.perform_login(valid_login(), None).is_valid());
}

#[test]
fn unblock_after_lock_time_without_invalid_cookie() {
    let cooldown = Duration::from_secs(1);
    let mut provider = InMemoryProvider::new(3, cooldown, vec![1, 2, 3]);
    assert_eq!(
        LoginStatus::Invalid,
        provider.perform_login(invalid_login(), Some(invalid_cookie()))
    );
    assert_eq!(
        LoginStatus::Invalid,
        provider.perform_login(invalid_login(), Some(invalid_cookie()))
    );
    assert_eq!(
        LoginStatus::Invalid,
        provider.perform_login(invalid_login(), Some(invalid_cookie()))
    );
    assert_eq!(
        LoginStatus::Blocked,
        provider.perform_login(valid_login(), Some(invalid_cookie()))
    );
    std::thread::sleep(cooldown);
    assert!(provider
        .perform_login(valid_login(), Some(invalid_cookie()))
        .is_valid());
}

#[test]
fn unblock_after_lock_time_without_valid_cookie() {
    let cooldown = Duration::from_secs(1);
    let mut provider = InMemoryProvider::new(3, cooldown, vec![1, 2, 3]);
    if let LoginStatus::Valid(cookie) = provider.perform_login(valid_login(), None) {
        assert_eq!(
            LoginStatus::Invalid,
            provider.perform_login(invalid_login(), Some(cookie.clone()))
        );
        assert_eq!(
            LoginStatus::Invalid,
            provider.perform_login(invalid_login(), Some(cookie.clone()))
        );
        assert_eq!(
            LoginStatus::Invalid,
            provider.perform_login(invalid_login(), Some(cookie.clone()))
        );
        assert_eq!(
            LoginStatus::Blocked,
            provider.perform_login(valid_login(), Some(cookie.clone()))
        );
        std::thread::sleep(cooldown);
        assert!(provider
            .perform_login(valid_login(), Some(cookie))
            .is_valid());
    } else {
        panic!()
    }
}

#[test]
fn multiple_logins_without_cookie_dont_block() {
    let mut provider = InMemoryProvider::new(3, Duration::from_secs(60), vec![1, 2, 3]);
    assert!(provider.perform_login(valid_login(), None).is_valid());
    assert!(provider.perform_login(valid_login(), None).is_valid());
    assert!(provider.perform_login(valid_login(), None).is_valid());
    assert!(provider.perform_login(valid_login(), None).is_valid());
    assert!(provider.perform_login(valid_login(), None).is_valid());
}

#[test]
fn multiple_logins_with_cookie_dont_block() {
    let mut provider = InMemoryProvider::new(3, Duration::from_secs(60), vec![1, 2, 3]);
    if let LoginStatus::Valid(cookie) = provider.perform_login(valid_login(), None) {
        assert!(provider
            .perform_login(valid_login(), Some(cookie.clone()))
            .is_valid());
        assert!(provider
            .perform_login(valid_login(), Some(cookie.clone()))
            .is_valid());
        assert!(provider
            .perform_login(valid_login(), Some(cookie.clone()))
            .is_valid());
        assert!(provider
            .perform_login(valid_login(), Some(cookie.clone()))
            .is_valid());
        assert!(provider
            .perform_login(valid_login(), Some(cookie))
            .is_valid());
    } else {
        panic!()
    }
}

#[test]
fn cookies_contain_random_nonce() {
    let mut provider = InMemoryProvider::new(3, Duration::from_secs(60), vec![1, 2, 3]);
    // compare 3 cookies to make accidental collisions less likely
    if let (LoginStatus::Valid(cookie1), LoginStatus::Valid(cookie2), LoginStatus::Valid(cookie3)) = (
        provider.perform_login(valid_login(), None),
        provider.perform_login(valid_login(), None),
        provider.perform_login(valid_login(), None),
    ) {
        assert!(cookie1 != cookie2 || cookie1 != cookie3 || cookie2 != cookie3);
    } else {
        panic!()
    }
}
