// build.rs

fn main() {
    for file in [
        "Resource.rc",
        "Resource.h",
        "Version.h",
        "Ghidra.ico",
        "application.manifest",
    ] {
        println!("cargo:rerun-if-changed=../Resources/{file}");
    }
    // GHIDRA_LAUNCH_RS selects this variant's InternalName/OriginalFilename in Resource.rc
    embed_resource::compile("..\\Resources\\Resource.rc", ["GHIDRA_LAUNCH_RS"])
        .manifest_required()
        .expect("failed to compile Windows resources");
}
