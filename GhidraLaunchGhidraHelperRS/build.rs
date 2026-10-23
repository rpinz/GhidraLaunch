fn main() {
    println!("cargo:rerun-if-changed=GhidraLaunchGhidraHelperRS.rc");
    println!("cargo:rerun-if-changed=../Resources/Version.h");

    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() == Ok("windows") {
        embed_resource::compile_for(
            "GhidraLaunchGhidraHelperRS.rc",
            ["GhidraLaunchGhidraHelperRS"],
            embed_resource::ParamsIncludeDirs(&["../Resources"]),
        )
        .manifest_required()
        .expect("failed to compile Ghidra helper Windows resources");
    }
}
