using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using DnsServerCore.Cluster;

namespace DnsServerCore.Configuration
{
    internal static class ConfigurationClusterOptions
    {
        internal const string Path = "/cluster";
        internal const string OwnershipFile = "cluster-ownership.config";

        internal readonly record struct Settings(ushort HeartbeatRefresh, ushort HeartbeatRetry, ushort ConfigRefresh, ushort ConfigRetry);
        internal readonly record struct Candidate(Settings Current, Settings Desired, int NodeId, IReadOnlyList<string> CurrentOwnership, string[] DesiredOwnership)
        {
            internal bool ValuesChanged => Current != Desired;
            internal bool OwnershipChanged => !CurrentOwnership.SequenceEqual(DesiredOwnership);
        }

        internal static bool IsDeclared(ConfigurationManifest manifest) => manifest is not null &&
            manifest.Settings.TryGetProperty("cluster", out _);

        internal static bool Supports(string name) => name is
            "heartbeatRefreshSeconds" or "heartbeatRetrySeconds" or "configRefreshSeconds" or "configRetrySeconds";

        internal static Candidate? Prepare(ConfigurationManifest manifest, ClusterManager cluster)
        {
            if (manifest is null || (!IsDeclared(manifest) && cluster.ManagedOptionNames.Count == 0))
                return null;

            bool declared = manifest.Settings.TryGetProperty("cluster", out JsonElement section);
            string[] ownership = declared ? section.EnumerateObject().Select(field => field.Name).Order(StringComparer.Ordinal).ToArray() : [];
            foreach (string field in ownership)
            {
                if (!Supports(field))
                    throw new InvalidDataException($"{Path}/{field}: This cluster setting is not implemented.");
            }
            if (!cluster.ClusterInitialized || cluster.GetSelfNode().Type != ClusterNodeType.Primary)
                throw new InvalidDataException($"{Path}: Only an initialized Primary node can apply cluster options.");

            Settings current = cluster.GetManifestOptions();
            var desired = new Settings(
                Read("heartbeatRefreshSeconds", current.HeartbeatRefresh, 30),
                Read("heartbeatRetrySeconds", current.HeartbeatRetry, 10),
                Read("configRefreshSeconds", current.ConfigRefresh, 900),
                Read("configRetrySeconds", current.ConfigRetry, 60));
            try
            {
                ClusterManager.ValidateClusterOptions(desired);
            }
            catch (ArgumentException ex)
            {
                throw new InvalidDataException($"{Path}/configRefreshSeconds: The configuration refresh interval must be greater than the heartbeat refresh interval.", ex);
            }
            return new Candidate(current, desired, cluster.GetSelfNode().Id, cluster.ManagedOptionNames, ownership);

            ushort Read(string field, ushort value, ushort defaultValue) => declared && section.TryGetProperty(field, out JsonElement setting)
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
