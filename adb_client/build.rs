fn main() {
    println!("cargo:rerun-if-changed=../native/macos_adb_interface.c");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("macos") {
        cc::Build::new()
            .file("../native/macos_adb_interface.c")
            .compile("macos_adb_interface");
        println!("cargo:rustc-link-lib=framework=IOKit");
        println!("cargo:rustc-link-lib=framework=CoreFoundation");
    }
}
