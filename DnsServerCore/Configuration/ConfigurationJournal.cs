using System;
using System.Collections.Generic;
using System.IO;
using System.Threading.Tasks;

namespace DnsServerCore.Configuration
{
    // Callers serialize changes and pass only server-owned configuration file names.
    internal static class ConfigurationJournal
    {
        private const string PendingName = ".manifest-pending";
        private const string StagingName = ".manifest-staging";
        private const string AppActivationPendingName = ".manifest-app-activation-pending";
        private const string AppActivationStagingName = ".manifest-app-activation-staging";

        private static readonly HashSet<string> _configurationFiles = new(StringComparer.Ordinal)
        {
            "dns.config", "log.config", "self-signed-cert.pfx", "blocklist.config", "webservice.config", "auth.config", "allowed.config", "blocked.config", Dns.ZoneManagers.AuthZoneManager.ManifestOwnershipFile, Auth.AuthManager.LdapOwnershipFile, Auth.AuthManager.SsoOwnershipFile, Auth.AuthManager.GroupOwnershipFile, Auth.AuthManager.UserOwnershipFile, Auth.AuthManager.PermissionOwnershipFile, ConfigurationStaticSessions.FileName
        };

        internal static void Recover(string configFolder)
        {
            Recover(configFolder, PendingName, StagingName);
            Recover(configFolder, AppActivationPendingName, AppActivationStagingName);
        }

        private static void Recover(string configFolder, string pendingName, string stagingName)
        {
            string pending = Path.Combine(configFolder, pendingName);
            string staging = Path.Combine(configFolder, stagingName);
            if (Directory.Exists(staging))
                Directory.Delete(staging, true);

            if (!Directory.Exists(pending))
                return;

            foreach (string fileName in _configurationFiles)
                Restore(configFolder, pending, fileName);

            RestoreResourceFiles("zones");
            RestoreResourceFiles("scopes");
            string apps = Path.Combine(pending, "apps");
            if (Directory.Exists(apps))
            {
                foreach (string directory in Directory.EnumerateDirectories(apps))
                    RestoreResourceFiles(Path.Combine("apps", Path.GetFileName(directory)));
            }

            Directory.Move(pending, staging);

            void RestoreResourceFiles(string directory)
            {
                string entries = Path.Combine(pending, directory);
                if (!Directory.Exists(entries))
                    return;

                foreach (string entry in Directory.EnumerateDirectories(entries))
                {
                    string relativePath = Path.Combine(directory, Path.GetFileName(entry));
                    if (IsResourceFile(relativePath))
                        Restore(configFolder, pending, relativePath);
                }
            }
        }

        internal static void Persist(string configFolder, Action write, params string[] fileNames)
        {
            string pending = Path.Combine(configFolder, PendingName);
            string staging = Path.Combine(configFolder, StagingName);
            Begin(configFolder, pending, staging, fileNames);
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

        internal static async Task ActivateAppsAsync(string configFolder, string[] fileNames, Func<Task> activate)
        {
            if (fileNames.Length == 0)
                return;

            Begin(configFolder, Path.Combine(configFolder, AppActivationPendingName),
                Path.Combine(configFolder, AppActivationStagingName), fileNames);
            try
            {
                await activate();
            }
            finally
            {
                // Apps may write their config while initializing. Preserve the original until
                // the main manifest transaction commits the declared values.
                Recover(configFolder, AppActivationPendingName, AppActivationStagingName);
            }
        }

        private static void Begin(string configFolder, string pending, string staging, string[] fileNames)
        {
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
                if (!_configurationFiles.Contains(fileName) && !IsResourceFile(fileName))
                    throw new ArgumentException("Unsupported configuration journal path.", nameof(fileNames));

                string entry = Path.Combine(staging, fileName);
                Directory.CreateDirectory(entry);
                string target = Path.Combine(configFolder, fileName);
                if (File.Exists(target))
                    CopyAndFlush(target, Path.Combine(entry, "previous"));
            }

            Directory.Move(staging, pending);
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

        private static bool IsResourceFile(string path)
        {
            string directory = Path.GetDirectoryName(path);
            string name = Path.GetFileName(path);
            if (name.IndexOfAny(Path.GetInvalidFileNameChars()) != -1)
                return false;

            if (directory is not null && Path.GetDirectoryName(directory) == "apps")
                return ConfigurationApplications.IsSafeName(Path.GetFileName(directory)) && name == Dns.Applications.DnsApplication.ConfigurationFileName;

            return directory switch
            {
                "zones" => name.EndsWith(".zone", StringComparison.Ordinal) &&
                    !name.Contains('*') && !name.Contains('\\') && !name.Contains('/'),
                "scopes" => name == Dhcp.DhcpServer.ManifestOwnershipFile ||
                    (name.Length > ".scope".Length && name.EndsWith(".scope", StringComparison.Ordinal)),
                _ => false
            };
        }

        private static void CopyAndFlush(string source, string destination)
        {
            File.Copy(source, destination, true);
            using var file = new FileStream(destination, FileMode.Open, FileAccess.Write);
            file.Flush(flushToDisk: true);
        }
    }
}
