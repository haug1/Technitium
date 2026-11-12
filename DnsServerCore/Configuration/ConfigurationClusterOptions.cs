using System;
using System.Collections.Generic;
using System.IO;
using System.Text.Json;
using DnsServerCore.Cluster;

namespace DnsServerCore.Configuration
{
    internal static class ConfigurationClusterOptions
    {
        internal const string Path = "/cluster";

        internal readonly record struct Settings(ushort HeartbeatRefresh, ushort HeartbeatRetry, ushort ConfigRefresh, ushort ConfigRetry);
        internal readonly record struct Candidate(Settings Current, Settings Desired, int NodeId)
        {
            internal bool Changed => Current != Desired;
        }

        internal static bool IsDeclared(ConfigurationManifest manifest) => manifest is not null &&
            manifest.Settings.TryGetProperty("cluster", out _);

        internal static bool Supports(string name) => name is
            "heartbeatRefreshSeconds" or "heartbeatRetrySeconds" or "configRefreshSeconds" or "configRetrySeconds";

        internal static Candidate? Prepare(ConfigurationManifest manifest, ClusterManager cluster)
        {
            if (!IsDeclared(manifest))
                return null;

            JsonElement section = manifest.Settings.GetProperty("cluster");
            foreach (JsonProperty field in section.EnumerateObject())
            {
                if (!Supports(field.Name))
                    throw new InvalidDataException($"{Path}/{field.Name}: This cluster setting is not implemented.");
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
            return new Candidate(current, desired, cluster.GetSelfNode().Id);

            ushort Read(string field, ushort value, ushort defaultValue) => section.TryGetProperty(field, out JsonElement setting)
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
