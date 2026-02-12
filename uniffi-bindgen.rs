// uniffi-bindgen.rs - Binary for generating language bindings

fn main() {
    // This binary is used to generate Kotlin and Swift bindings
    // from the uniffi UDL file.
    //
    // Usage:
    //   cargo run --bin uniffi-bindgen generate src/cosmic_ext_connect_core.udl --language kotlin --out-dir ./bindings/kotlin
    //   cargo run --bin uniffi-bindgen generate src/cosmic_ext_connect_core.udl --language swift --out-dir ./bindings/swift

    uniffi::uniffi_bindgen_main()
}
