fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Use a vendored protoc unless the user provides one.
    if std::env::var_os("PROTOC").is_none() {
        let protoc = protoc_bin_vendored::protoc_bin_path().expect("vendored protoc available");
        std::env::set_var("PROTOC", protoc);
    }
    println!("cargo:rerun-if-changed=proto");
    tonic_build::configure().compile_protos(&["proto/df2b/v1/agent.proto"], &["proto"])?;
    Ok(())
}
