all: debug

debug:
	cargo build --locked && if not exist bin\Debug mkdir bin\Debug && copy /y target\debug\GhidraLaunchGhidraHelperRS.exe bin\Debug\GhidraLaunchGhidraHelperRS.exe

release:
	cargo build --release --locked && if not exist bin\Release mkdir bin\Release && copy /y target\release\GhidraLaunchGhidraHelperRS.exe bin\Release\GhidraLaunchGhidraHelperRS.exe

clean:
	cargo clean && if exist bin\Debug\GhidraLaunchGhidraHelperRS.exe del /q bin\Debug\GhidraLaunchGhidraHelperRS.exe && if exist bin\Release\GhidraLaunchGhidraHelperRS.exe del /q bin\Release\GhidraLaunchGhidraHelperRS.exe
