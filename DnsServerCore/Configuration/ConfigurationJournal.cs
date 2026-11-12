using System;
using System.IO;

namespace DnsServerCore.Configuration
{
    // Callers serialize changes and pass only server-owned configuration file names.
    internal static class ConfigurationJournal
    {
        private const string PendingName = ".manifest-pending";
        private const string StagingName = ".manifest-staging";

        internal static void Recover(string configFolder, params string[] fileNames)
        {
            string pending = Path.Combine(configFolder, PendingName);
            string staging = Path.Combine(configFolder, StagingName);
            if (Directory.Exists(staging))
                Directory.Delete(staging, true);

            if (!Directory.Exists(pending))
                return;

            foreach (string fileName in fileNames)
            {
                string entry = Path.Combine(pending, fileName);
                if (!Directory.Exists(entry))
                    continue;

                string target = Path.Combine(configFolder, fileName);
                string snapshot = Path.Combine(entry, "previous");
                if (File.Exists(snapshot))
                {
                    string temporary = Path.Combine(entry, "restore");
                    CopyAndFlush(snapshot, temporary);
                    File.Move(temporary, target, true);
                }
                else
                {
                    File.Delete(target);
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

            foreach (string fileName in fileNames)
            {
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
                Recover(configFolder, fileNames);
                throw;
            }
        }

        private static void CopyAndFlush(string source, string destination)
        {
            File.Copy(source, destination, true);
            using var file = new FileStream(destination, FileMode.Open, FileAccess.Write);
            file.Flush(flushToDisk: true);
        }
    }
}
