using System;
using System.IO;

// Test-only cached-uninstaller failure. No registry or payload operations.
internal static class LegacyFailureGate
{
    private static int Main(string[] args)
    {
        if (args.Length != 1) return 2;
        if (!File.Exists(args[0])) return 0;
        Console.Error.WriteLine("Intentional legacy-uninstall failure: " + args[0]);
        return 1;
    }
}
