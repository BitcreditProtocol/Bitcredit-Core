fn main() {
    let version = std::env::var("CARGO_PKG_VERSION").unwrap();
    println!("cargo:rustc-env=CRATE_VERSION={version}");
}
