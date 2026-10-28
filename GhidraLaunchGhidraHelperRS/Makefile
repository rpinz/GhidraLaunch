# Cargo builds into the workspace target directory (..\target); bin\<Configuration> holds the
# packaged copies. Clean only this package so the launcher's outputs survive.
all: debug

debug:
	cargo build --locked --manifest-path Cargo.toml && (if exist bin\Debug (ver >nul) else (mkdir bin\Debug)) && copy /y ..\target\debug\GhidraLaunchGhidraHelperRS.exe bin\Debug\GhidraLaunchGhidraHelperRS.exe && copy /y ..\target\debug\GhidraLaunchGhidraHelperRS.pdb bin\Debug\GhidraLaunchGhidraHelperRS.pdb

release:
	cargo build --release --locked --manifest-path Cargo.toml && (if exist bin\Release (ver >nul) else (mkdir bin\Release)) && copy /y ..\target\release\GhidraLaunchGhidraHelperRS.exe bin\Release\GhidraLaunchGhidraHelperRS.exe && copy /y ..\target\release\GhidraLaunchGhidraHelperRS.pdb bin\Release\GhidraLaunchGhidraHelperRS.pdb

clean:
	cargo clean -p ghidra_launch_helper --manifest-path Cargo.toml && (if exist bin\Debug\GhidraLaunchGhidraHelperRS.exe (del /q bin\Debug\GhidraLaunchGhidraHelperRS.exe)) && (if exist bin\Debug\GhidraLaunchGhidraHelperRS.pdb (del /q bin\Debug\GhidraLaunchGhidraHelperRS.pdb)) && (if exist bin\Release\GhidraLaunchGhidraHelperRS.exe (del /q bin\Release\GhidraLaunchGhidraHelperRS.exe)) && (if exist bin\Release\GhidraLaunchGhidraHelperRS.pdb (del /q bin\Release\GhidraLaunchGhidraHelperRS.pdb))
