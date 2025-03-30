fn main() {
    prost_build::compile_protos(&["src/proto/crx3.proto"], &["src/proto"])
        .expect("Failed to compile protos");
    println!("cargo:rerun-if-changed=src/proto/crx3.proto");
}
