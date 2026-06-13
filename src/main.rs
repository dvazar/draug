//! Thin entry point: parse configuration, then hand off to the library.
//! All logic lives in the `draug` library crate so it can be tested
//! independently of the binary.

fn main() {
    let config = draug::Config::from_args();
    std::process::exit(draug::run(config));
}
