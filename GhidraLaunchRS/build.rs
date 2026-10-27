// build.rs

extern crate embed_resource;

fn main() {
    println!("cargo:rerun-if-changed=../Resources/Resource.rc");
    println!("cargo:rerun-if-changed=../Resources/Resource.h");
    println!("cargo:rerun-if-changed=../Resources/Version.h");
    println!("cargo:rerun-if-changed=../Resources/Ghidra.ico");
    embed_resource::compile("..\\Resources\\Resource.rc", embed_resource::NONE)
        .manifest_required()
        .expect("failed to compile Windows resources");
}
