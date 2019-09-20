# Device Cookies

**WARNING**: This is a work in progress and I am still working on the API.

This crate provides a trait and default implementation for [device cookies][0]
for Rust.

Device cookies try to solve the problem of login bruteforce. A naive bruteforce
detection would define two numbers `N` and `M` which describe the number of
allowed login attempts and the duration for how long the account gets logged,
after `N` failed login attempts. This approach enables an attacker to block the
actual user from logging in by simply sending a few invalid login messages.
Device cookies solve this DoS problem by issuing device and user specific
cookies after a successful login. If a user can provide a valid device cookie as
a proof that he logged in successfully in the past, he gets `N` login attempts
per valid cookie, even if the account is locked.

For a better explanation read [the OWASP article][0] or check this flowchart:

TODO: decision flowchart

The crate provides a `Provider` trait, that already implements the blocking
logic and can be plugged in front of any kind of authentication backend (e.g.
databases, memory caches, LDAP, ...).


[0]: https://www.owasp.org/index.php/Slow_Down_Online_Guessing_Attacks_with_Device_Cookies
