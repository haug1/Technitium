using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.Json;
using DnsServerCore.Cluster;

namespace DnsServerCore.Configuration
{
    internal static class ConfigurationClusterOptions
    {
        internal const string Path = "/cluster";
        internal const string OwnershipFile = "cluster-ownership.config";

        internal readonly record struct Settings(ushort HeartbeatRefresh, ushort HeartbeatRetry, ushort ConfigRefresh, ushort ConfigRetry);
        internal readonly record struct Candidate(Settings Current, Settings Desired, int NodeId, ClusterNodeType NodeType, IReadOnlyList<string> CurrentOwnership, string[] DesiredOwnership)
        {
            internal bool ValuesChanged => Current != Desired;
            internal bool OwnershipChanged => !CurrentOwnership.SequenceEqual(DesiredOwnership);
        }

        internal static bool IsDeclared(ConfigurationManifest manifest) => manifest is not null &&
            manifest.Settings.TryGetProperty("cluster", out _);

        private static bool IsInterval(string name) => name is
            "heartbeatRefreshSeconds" or "heartbeatRetrySeconds" or "configRefreshSeconds" or "configRetrySeconds";

        internal static void CheckApplySupport(JsonElement section)
        {
            foreach (JsonProperty field in section.EnumerateObject())
            {
                if (field.Name == "bootstrap")
                {
                    foreach (JsonProperty input in field.Value.EnumerateObject())
                    {
                        if (input.Name != "role")
                            throw new InvalidDataException($"{Path}/bootstrap/{input.Name}: Cluster join from a manifest is not implemented.");
                    }
                }
                else if (field.Name is not ("domain" or "node") && !IsInterval(field.Name))
                {
                    throw new InvalidDataException($"{Path}/{field.Name}: This cluster setting is not implemented.");
                }
            }
        }

        internal sealed record PrimaryBootstrap(string Domain, IPAddress[] Addresses, Settings Options, string[] Ownership);

        internal static PrimaryBootstrap PrepareStartupBootstrap(ConfigurationManifest manifest, ClusterManager cluster, Auth.User admin)
        {
            if (cluster.ClusterInitialized || !IsDeclared(manifest))
                return null;

            JsonElement section = manifest.Settings.GetProperty("cluster");
            if (!section.TryGetProperty("bootstrap", out JsonElement bootstrap) ||
                !bootstrap.TryGetProperty("role", out JsonElement role) || role.GetString() != "Primary")
                return null;

            if (manifest.Settings.EnumerateObject().Any(field => field.Name is not ("schemaVersion" or "$schema" or "cluster")))
                throw new InvalidDataException("/cluster/bootstrap: Initialize the Primary in a cluster-only startup manifest before applying other settings.");

            string domain = section.TryGetProperty("domain", out JsonElement declaredDomain) ? declaredDomain.GetString() : null;
            if (string.IsNullOrWhiteSpace(domain))
                throw new InvalidDataException("/cluster/domain: A domain is required to initialize a Primary.");

            IPAddress[] addresses = ReadAddresses(section);
            if (addresses is null || addresses.Length == 0)
                throw new InvalidDataException("/cluster/node/addresses: Advertised addresses are required to initialize a Primary.");

            if (admin is null || admin.Disabled)
                throw new InvalidDataException("/cluster/bootstrap: An enabled local administrator is required.");

            domain = cluster.PreparePrimaryInitialization(domain, addresses, admin);
            Settings options = ReadOptions(section, ClusterManager.DefaultManifestOptions);
            return new PrimaryBootstrap(domain, addresses, options, GetDeclaredIntervals(section));
        }

        private static IPAddress[] ReadAddresses(JsonElement section)
        {
            if (!section.TryGetProperty("node", out JsonElement node) ||
                !node.TryGetProperty("addresses", out JsonElement addresses))
                return null;
            if (addresses.ValueKind == JsonValueKind.Null)
                throw new InvalidDataException("/cluster/node/addresses: Supply a list of advertised addresses.");
            return addresses.EnumerateArray().Select(value => IPAddress.Parse(value.GetString())).Distinct().ToArray();
        }

        private static string[] GetDeclaredIntervals(JsonElement section) => section.ValueKind == JsonValueKind.Object
            ? section.EnumerateObject().Select(field => field.Name).Where(IsInterval).Order(StringComparer.Ordinal).ToArray() : [];

        internal static Candidate? Prepare(ConfigurationManifest manifest, ClusterManager cluster)
        {
            if (manifest is null || (!IsDeclared(manifest) && cluster.ManagedOptionNames.Count == 0))
                return null;

            bool declared = manifest.Settings.TryGetProperty("cluster", out JsonElement section);
            if (declared)
                CheckApplySupport(section);

            bool hasDomain = declared && section.TryGetProperty("domain", out _);
            bool hasBootstrap = declared && section.TryGetProperty("bootstrap", out _);
            if (!cluster.ClusterInitialized)
            {
                if (hasBootstrap || hasDomain)
                    throw new InvalidDataException($"{Path}: Initialize or join the declared cluster before applying its topology.");
                throw new InvalidDataException($"{Path}: Only an initialized Primary node can apply cluster options.");
            }

            ClusterNode self = cluster.GetSelfNode();
            if (hasDomain)
            {
                string name = section.GetProperty("domain").GetString();
                if (name is null || !string.Equals(ConfigurationManifest.CanonicalDnsName(name, $"{Path}/domain", allowRoot: false),
                    cluster.ClusterDomain, StringComparison.OrdinalIgnoreCase))
                    throw new InvalidDataException($"{Path}/domain: The declared domain does not match the current cluster.");
            }

            if (hasBootstrap && section.GetProperty("bootstrap").TryGetProperty("role", out JsonElement role) &&
                !string.Equals(role.GetString(), self.Type.ToString(), StringComparison.Ordinal))
                throw new InvalidDataException($"{Path}/bootstrap/role: The declared role does not match the current node.");

            IPAddress[] addresses = declared ? ReadAddresses(section) : null;
            if (addresses is not null && !new HashSet<IPAddress>(self.IPAddresses).SetEquals(addresses))
                throw new InvalidDataException("/cluster/node/addresses: The declared addresses do not match the current node.");

            string[] ownership = GetDeclaredIntervals(section);
            IReadOnlyList<string> currentOwnership = cluster.ManagedOptionNames;
            if ((ownership.Length != 0 || currentOwnership.Count != 0) && self.Type != ClusterNodeType.Primary)
                throw new InvalidDataException($"{Path}: Only an initialized Primary node can apply cluster options.");

            Settings current = cluster.GetManifestOptions();
            return new Candidate(current, ReadOptions(section, current), self.Id, self.Type, currentOwnership, ownership);
        }

        private static Settings ReadOptions(JsonElement section, Settings current)
        {
            Settings defaults = ClusterManager.DefaultManifestOptions;
            var desired = new Settings(
                Read("heartbeatRefreshSeconds", current.HeartbeatRefresh, defaults.HeartbeatRefresh),
                Read("heartbeatRetrySeconds", current.HeartbeatRetry, defaults.HeartbeatRetry),
                Read("configRefreshSeconds", current.ConfigRefresh, defaults.ConfigRefresh),
                Read("configRetrySeconds", current.ConfigRetry, defaults.ConfigRetry));
            try
            {
                ClusterManager.ValidateClusterOptions(desired);
            }
            catch (ArgumentException ex)
            {
                throw new InvalidDataException($"{Path}/configRefreshSeconds: The configuration refresh interval must be greater than the heartbeat refresh interval.", ex);
            }
            return desired;

            ushort Read(string field, ushort value, ushort defaultValue) => section.ValueKind == JsonValueKind.Object && section.TryGetProperty(field, out JsonElement setting)
                ? setting.ValueKind == JsonValueKind.Null ? defaultValue : setting.GetUInt16() : value;
        }

        internal static JsonElement Export(Settings options) => JsonSerializer.SerializeToElement(new
        {
            heartbeatRefreshSeconds = options.HeartbeatRefresh,
            heartbeatRetrySeconds = options.HeartbeatRetry,
            configRefreshSeconds = options.ConfigRefresh,
            configRetrySeconds = options.ConfigRetry
        });

        internal static void WriteSnapshot(Utf8JsonWriter writer, Candidate candidate)
        {
            writer.WriteStartObject("manifestClusterOptions");
            writer.WriteNumber("node", candidate.NodeId);
            writer.WriteString("role", candidate.NodeType.ToString());
            writer.WritePropertyName("current");
            Export(candidate.Current).WriteTo(writer);
            writer.WritePropertyName("desired");
            Export(candidate.Desired).WriteTo(writer);
            writer.WritePropertyName("currentOwnership");
            JsonSerializer.Serialize(writer, candidate.CurrentOwnership);
            writer.WriteEndObject();
        }

        internal static void Compare(JsonElement snapshot, List<ConfigurationChange> changes)
        {
            JsonElement current = snapshot.GetProperty("current");
            foreach (JsonProperty field in snapshot.GetProperty("desired").EnumerateObject())
            {
                if (!JsonElement.DeepEquals(field.Value, current.GetProperty(field.Name)))
                    changes.Add(new ConfigurationChange($"{Path}/{field.Name}", ConfigurationChangeKind.Update, false));
            }
        }
    }
}
