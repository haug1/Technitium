using System;
using System.Collections.Generic;
using System.IO;

namespace DnsServerCore.Configuration
{
    // Callers serialize changes and pass only server-owned configuration file names.
    internal static class ConfigurationJournal
    {
        private const string PendingName = ".manifest-pending";
        private const string StagingName = ".manifest-staging";

        private static readonly HashSet<string> _configurationFiles = new(StringComparer.Ordinal)
        {
            "dns.config", "log.config", "self-signed-cert.pfx", "blocklist.config", "webservice.config", "auth.config"
        };

        internal static void Recover(string configFolder)
        {
            string pending = Path.Combine(configFolder, PendingName);
            string staging = Path.Combine(configFolder, StagingName);
            if (Directory.Exists(staging))
                Directory.Delete(staging, true);

            if (!Directory.Exists(pending))
                return;

            foreach (string fileName in _configurationFiles)
                Restore(configFolder, pending, fileName);

            string zoneEntries = Path.Combine(pending, "zones");
            if (Directory.Exists(zoneEntries))
            {
                foreach (string entry in Directory.EnumerateDirectories(zoneEntries))
                {
                    string name = Path.GetFileName(entry);
                    if (IsZoneFileName(name))
                        Restore(configFolder, pending, Path.Combine("zones", name));
                }
            }

            Directory.Move(pending, staging);
        }

        internal static void Persist(string configFolder, Action write, params string[] fileNames)
        {
            string pending = Path.Combine(configFolder, PendingName);
            string staging = Path.Combine(configFolder, StagingName);
            if (Directory.Exists(pending))
                throw new IOException("An interrupted manifest write must be recovered before applying again.");

            if (Directory.Exists(staging))
                Directory.Delete(staging, true);
            if (OperatingSystem.IsWindows())
                Directory.CreateDirectory(staging);
            else
                Directory.CreateDirectory(staging, UnixFileMode.UserRead | UnixFileMode.UserWrite | UnixFileMode.UserExecute);

            foreach (string fileName in new HashSet<string>(fileNames, StringComparer.Ordinal))
            {
                if (!_configurationFiles.Contains(fileName) &&
                    (!string.Equals(Path.GetDirectoryName(fileName), "zones", StringComparison.Ordinal) || !IsZoneFileName(Path.GetFileName(fileName))))
                    throw new ArgumentException("Unsupported configuration journal path.", nameof(fileNames));

                string entry = Path.Combine(staging, fileName);
                Directory.CreateDirectory(entry);
                string target = Path.Combine(configFolder, fileName);
                if (File.Exists(target))
                    CopyAndFlush(target, Path.Combine(entry, "previous"));
            }

            Directory.Move(staging, pending);
            try
            {
                write();
                // Rename before cleanup so a partially deleted journal is never replayed.
                Directory.Move(pending, staging);
            }
            catch
            {
                Recover(configFolder);
                throw;
            }
        }

        private static void Restore(string configFolder, string pending, string fileName)
        {
            string entry = Path.Combine(pending, fileName);
            if (!Directory.Exists(entry))
                return;

            string target = Path.Combine(configFolder, fileName);
            string snapshot = Path.Combine(entry, "previous");
            if (File.Exists(snapshot))
            {
                Directory.CreateDirectory(Path.GetDirectoryName(target));
                string temporary = Path.Combine(entry, "restore");
                CopyAndFlush(snapshot, temporary);
                File.Move(temporary, target, true);
            }
            else if (Directory.Exists(Path.GetDirectoryName(target)))
            {
                File.Delete(target);
            }
        }

        private static bool IsZoneFileName(string name)
        {
            return name.EndsWith(".zone", StringComparison.Ordinal) &&
                name.IndexOfAny(Path.GetInvalidFileNameChars()) == -1 &&
                !name.Contains('*') && !name.Contains('\\') && !name.Contains('/');
        }

        private static void CopyAndFlush(string source, string destination)
        {
            File.Copy(source, destination, true);
            using var file = new FileStream(destination, FileMode.Open, FileAccess.Write);
            file.Flush(flushToDisk: true);
        }
    }
}
