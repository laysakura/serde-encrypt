//! serde_encrypt::error::Error implements std::error::Error in `std` feature.

#![cfg(feature = "std")]

mod test_util;

// https://rust-lang.github.io/api-guidelines/interoperability.html#error-types-are-meaningful-and-well-behaved-c-good-err
#[test]
fn test_api_guidelines_c_good_err() {
    use std::fmt::Display;

    fn assert_error<T: std::error::Error + Send + Sync + 'static>() {}
    assert_error::<serde_encrypt::error::Error>();

    fn assert_display<T: Display>() {}
    assert_display::<serde_encrypt::error::Error>();
}
