// build.rs - uniffi code generation

fn main() {
    // Generate uniffi scaffolding code
    // This will be called during the build process to generate
    // the FFI bindings from the UDL (uniffi interface definition language) file

    uniffi::generate_scaffolding("./src/cosmic_connect_core.udl").unwrap();

    println!("cargo:rerun-if-changed=src/cosmic_connect_core.udl");
    println!("cargo:rerun-if-changed=build.rs");
}
