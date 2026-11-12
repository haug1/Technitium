using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using DnsServerCore.Dns;
using DnsServerCore.Dns.Zones;
using TechnitiumLibrary.Net.Dns;

namespace DnsServerCore.Configuration
{
    internal static class ConfigurationZonePrimary
    {
        internal readonly record struct Changes(NameServerAddress[] Servers, DnsTransportProtocol? Protocol, string TsigKey, bool? Validate)
        {
            internal void Apply(AuthZoneInfo zone)
            {
                if (Protocol.HasValue)
                    zone.PrimaryZoneTransferProtocol = Protocol.Value;
                if (Servers is not null)
                    zone.PrimaryNameServerAddresses = Servers;
                if (TsigKey is not null)
                    zone.PrimaryZoneTransferTsigKeyName = TsigKey.Length == 0 ? null : TsigKey;
                if (Validate.HasValue)
                    zone.ValidateZone = Validate.Value;
            }

            internal IEnumerable<string> Fields()
            {
                if (Servers is not null) yield return "servers";
                if (Protocol.HasValue) yield return "transferProtocol";
                if (TsigKey is not null) yield return "tsigKey";
                if (Validate.HasValue) yield return "validateZone";
            }
        }

        internal static Changes Prepare(JsonElement declaration, AuthZoneType type, AuthZoneInfo current,
            IReadOnlyDictionary<string, TsigKey> keys, string path)
        {
            bool declared = declaration.TryGetProperty("primary", out JsonElement options);
            if (type != AuthZoneType.Secondary)
            {
                if (declared)
                    throw new InvalidDataException($"{path}/primary: Primary transfer settings require a Secondary zone.");
                return default;
            }

            if (declaration.TryGetProperty("records", out _))
                throw new InvalidDataException($"{path}/records: Secondary records are maintained by zone transfer.");
            if (declaration.TryGetProperty("updates", out JsonElement updates) && updates.TryGetProperty("securityPolicies", out _))
                throw new InvalidDataException($"{path}/updates/securityPolicies: Secondary zones inherit update authorization from the primary.");
            if (!declared)
                return default;

            DnsTransportProtocol previousProtocol = current?.PrimaryZoneTransferProtocol ?? DnsTransportProtocol.Tcp;
            DnsTransportProtocol protocol = options.TryGetProperty("transferProtocol", out JsonElement transport)
                ? Enum.Parse<DnsTransportProtocol>(transport.GetString() ?? nameof(DnsTransportProtocol.Tcp)) : previousProtocol;
            if (protocol is not (DnsTransportProtocol.Tcp or DnsTransportProtocol.Tls or DnsTransportProtocol.Quic))
                throw new InvalidDataException($"{path}/primary/transferProtocol: Expected Tcp, Tls, or Quic.");
            if (protocol == DnsTransportProtocol.Quic)
                DnsServer.ValidateQuicSupport();

            NameServerAddress[] servers = null;
            if (options.TryGetProperty("servers", out JsonElement serversValue))
            {
                servers = serversValue.ValueKind == JsonValueKind.Null ? [] : serversValue.EnumerateArray().Select((entry, index) =>
                {
                    string serverPath = $"{path}/primary/servers/{index}";
                    if (entry.TryGetProperty("transport", out JsonElement explicitTransport) && explicitTransport.GetString() != protocol.ToString())
                        throw new InvalidDataException($"{serverPath}/transport: Use the zone's transfer protocol.");
                    string address = entry.GetProperty("address").GetString();
                    if (System.Text.Encoding.UTF8.GetByteCount(address.Trim()) > byte.MaxValue)
                        throw new InvalidDataException($"{serverPath}/address: Maximum address length is 255 UTF-8 bytes.");
                    return ParseAddress(address, protocol, serverPath);
                }).ToArray();
            }
            else if (protocol != previousProtocol && current?.PrimaryNameServerAddresses is { } previousServers)
            {
                servers = previousServers.Select(server => ParseAddress(server.ToString(), protocol, path + "/primary/servers")).ToArray();
            }
            if (servers is not null && protocol == previousProtocol && SameServers(servers, current?.PrimaryNameServerAddresses))
                servers = null;

            string key = null;
            if (options.TryGetProperty("tsigKey", out JsonElement keyValue))
            {
                key = keyValue.ValueKind == JsonValueKind.Null ? string.Empty :
                    ConfigurationManifest.CanonicalDnsName(keyValue.GetString(), path + "/primary/tsigKey", allowRoot: false);
                if (key.Length != 0 && keys?.ContainsKey(key) != true)
                    throw new InvalidDataException($"{path}/primary/tsigKey: No matching TSIG key is configured.");
                if (string.Equals(key, current?.PrimaryZoneTransferTsigKeyName ?? "", StringComparison.OrdinalIgnoreCase))
                    key = null;
            }

            bool? validate = options.TryGetProperty("validateZone", out JsonElement validateValue)
                ? validateValue.ValueKind == JsonValueKind.True : null;
            if (validate == (current?.ValidateZone ?? false))
                validate = null;
            return new Changes(servers, protocol == previousProtocol ? null : protocol, key, validate);
        }

        internal static NameServerAddress ParseAddress(string address, DnsTransportProtocol protocol, string path)
        {
            try
            {
                NameServerAddress server = NameServerAddress.Parse(address);
                return server.Protocol == protocol ? server : server.Clone(protocol);
            }
            catch (Exception ex) when (ex is ArgumentException or FormatException or DnsClientException or NotSupportedException)
            {
                throw new InvalidDataException($"{path}: Invalid primary name server address for the transfer protocol.");
            }
        }

        internal static bool SameServers(IReadOnlyList<NameServerAddress> first, IReadOnlyList<NameServerAddress> second) =>
            (first ?? []).Select(server => (server.Protocol, server.ToString()))
                .SequenceEqual((second ?? []).Select(server => (server.Protocol, server.ToString())));

        internal static void CheckRestoreOwnership(string path, IEnumerable<string> fields, AuthZoneInfo current, AuthZoneInfo candidate)
        {
            foreach (string field in fields)
            {
                bool changed = field switch
                {
                    "primary/servers" => !SameServers(current.PrimaryNameServerAddresses, candidate.PrimaryNameServerAddresses),
                    "primary/transferProtocol" => current.PrimaryZoneTransferProtocol != candidate.PrimaryZoneTransferProtocol,
                    "primary/tsigKey" => !string.Equals(current.PrimaryZoneTransferTsigKeyName ?? "", candidate.PrimaryZoneTransferTsigKeyName ?? "", StringComparison.OrdinalIgnoreCase),
                    "primary/validateZone" => current.ValidateZone != candidate.ValidateZone,
                    _ => false
                };
                if (changed)
                    throw new InvalidDataException($"{path}/{field}: Primary transfer settings are managed by the configuration manifest.");
            }
        }

        internal static JsonObject Export(AuthZoneInfo zone) => JsonSerializer.SerializeToNode(new
        {
            servers = (zone.PrimaryNameServerAddresses ?? []).Select(server => new { address = server.ToString() }),
            transferProtocol = zone.PrimaryZoneTransferProtocol.ToString(),
            tsigKey = string.IsNullOrEmpty(zone.PrimaryZoneTransferTsigKeyName) ? null : zone.PrimaryZoneTransferTsigKeyName,
            validateZone = zone.ValidateZone
        }).AsObject();
    }
}
