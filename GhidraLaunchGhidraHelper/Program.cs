using System;
using System.IO;
using System.IO.Compression;
using System.Security.Cryptography;

namespace GhidraLaunchGhidraHelper
{
    // Extracts the Ghidra release zip (as downloaded and verified by download.sh/download.ps1,
    // and chained as an install-time download payload in GhidraLaunchSetup/Bundle.wxs) into a
    // flat directory containing ghidraRun.bat directly, matching the GHIDRA_HOME contract used
    // by both launchers. Invoked from the Burn chain as an ExePackage's Install/UninstallCommand.
    internal static class Program
    {
        // Name of the marker file written into the destination directory recording the SHA-256
        // of the source zip, so repeated/repair installs with an unchanged zip are a fast no-op.
        private const string MarkerFileName = ".ghidralaunch-source.sha256";

        private static int Main(string[] args)
        {
            if (args.Length == 3 && string.Equals(args[0], "extract", StringComparison.OrdinalIgnoreCase))
            {
                return Extract(args[1], args[2]) ? 0 : 1;
            }

            if (args.Length == 2 && string.Equals(args[0], "remove", StringComparison.OrdinalIgnoreCase))
            {
                return Remove(args[1]) ? 0 : 1;
            }

            Console.Error.WriteLine("Usage: GhidraLaunchGhidraHelper extract <zipPath> <destDir>");
            Console.Error.WriteLine("       GhidraLaunchGhidraHelper remove <destDir>");
            return 2;
        }

        private static bool Extract(string zipPath, string destDir)
        {
            if (!File.Exists(zipPath))
            {
                Console.Error.WriteLine($"Ghidra zip not found: {zipPath}");
                return false;
            }

            string hash = ComputeSha256(zipPath);
            string markerPath = Path.Combine(destDir, MarkerFileName);

            if (Directory.Exists(destDir) && File.Exists(markerPath))
            {
                string existing = File.ReadAllText(markerPath).Trim();
                if (string.Equals(existing, hash, StringComparison.OrdinalIgnoreCase))
                {
                    Console.WriteLine($"Ghidra already extracted at {destDir} (unchanged); skipping.");
                    return true;
                }
            }

            string tempDir = Path.Combine(Path.GetTempPath(), "GhidraLaunchExtract-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(tempDir);
            try
            {
                ZipFile.ExtractToDirectory(zipPath, tempDir);

                string sourceRoot = FindSourceRoot(tempDir);

                if (Directory.Exists(destDir))
                {
                    Directory.Delete(destDir, recursive: true);
                }

                Directory.CreateDirectory(Path.GetDirectoryName(destDir) ?? destDir);
                Directory.Move(sourceRoot, destDir);

                File.WriteAllText(Path.Combine(destDir, MarkerFileName), hash);
                Console.WriteLine($"Extracted Ghidra to {destDir}.");
                return true;
            }
            finally
            {
                if (Directory.Exists(tempDir))
                {
                    Directory.Delete(tempDir, recursive: true);
                }
            }
        }

        // Ghidra release zips contain a single top-level "ghidra_x.y_PUBLIC" folder; strip it so
        // ghidraRun.bat ends up directly inside destDir (the GHIDRA_HOME contract).
        private static string FindSourceRoot(string extractedDir)
        {
            string[] topEntries = Directory.GetFileSystemEntries(extractedDir);
            if (topEntries.Length == 1 && Directory.Exists(topEntries[0]))
            {
                return topEntries[0];
            }

            return extractedDir;
        }

        private static bool Remove(string destDir)
        {
            if (Directory.Exists(destDir))
            {
                Directory.Delete(destDir, recursive: true);
                Console.WriteLine($"Removed {destDir}.");
            }

            return true;
        }

        private static string ComputeSha256(string path)
        {
            using (var sha256 = SHA256.Create())
            using (var stream = File.OpenRead(path))
            {
                byte[] hash = sha256.ComputeHash(stream);
                return BitConverter.ToString(hash).Replace("-", string.Empty).ToLowerInvariant();
            }
        }
    }
}
