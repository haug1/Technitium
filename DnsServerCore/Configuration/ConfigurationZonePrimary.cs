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
        internal static bool IsReplicated(AuthZoneType type) =>
            type is AuthZoneType.Secondary or AuthZoneType.SecondaryForwarder or AuthZoneType.SecondaryCatalog or AuthZoneType.Stub;

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
            if (!IsReplicated(type))
            {
                if (type == AuthZoneType.Catalog && declaration.TryGetProperty("records", out _))
                    throw new InvalidDataException($"{path}/records: Catalog records are generated from catalog settings and membership.");
                if (declared)
                    throw new InvalidDataException($"{path}/primary: Primary server settings require a secondary or stub zone.");
                return default;
            }

            if (declaration.TryGetProperty("records", out _))
                throw new InvalidDataException($"{path}/records: This zone obtains its records from its primary servers.");
            if (type == AuthZoneType.SecondaryCatalog)
            {
                foreach (JsonProperty field in declaration.EnumerateObject())
                {
                    if (ConfigurationZonePolicies.IsPolicy(field.Name))
                        throw new InvalidDataException($"{path}/{field.Name}: Secondary catalog policies are inherited from the catalog.");
                }
            }
            if (type is AuthZoneType.Stub or AuthZoneType.SecondaryForwarder &&
                (declaration.TryGetProperty("transfer", out _) || declaration.TryGetProperty("notify", out _)))
                throw new InvalidDataException($"{path}: This zone type does not support transfer or notify policies.");
            if (type == AuthZoneType.Stub && declaration.TryGetProperty("updates", out _))
                throw new InvalidDataException($"{path}/updates: Stub zones do not support update policies.");
            if (type is AuthZoneType.Stub or AuthZoneType.SecondaryForwarder &&
                UsesZoneNameServers(declaration, "query"))
                throw new InvalidDataException($"{path}/query/mode: This zone type cannot use its name servers for query access.");
            if (type is AuthZoneType.Secondary or AuthZoneType.SecondaryForwarder && UsesZoneNameServers(declaration, "updates"))
                throw new InvalidDataException($"{path}/updates/mode: This zone type cannot use its name servers for update access.");
            if (declaration.TryGetProperty("updates", out JsonElement updates) && updates.TryGetProperty("securityPolicies", out _))
                throw new InvalidDataException($"{path}/updates/securityPolicies: Secondary zones inherit update authorization from the primary.");
            if (!declared)
            {
                if (type is AuthZoneType.SecondaryForwarder or AuthZoneType.SecondaryCatalog && current is null)
                    throw new InvalidDataException($"{path}/primary/servers: This zone type requires at least one primary server.");
                return default;
            }

            bool stub = type == AuthZoneType.Stub;
            if (stub && (options.TryGetProperty("transferProtocol", out _) || options.TryGetProperty("tsigKey", out _)))
                throw new InvalidDataException($"{path}/primary: Stub zones use UDP and do not use a transfer TSIG key.");
            if (type != AuthZoneType.Secondary && options.TryGetProperty("validateZone", out _))
                throw new InvalidDataException($"{path}/primary/validateZone: Zone validation requires a Secondary zone.");

            DnsTransportProtocol previousProtocol = stub ? DnsTransportProtocol.Udp :
                current?.PrimaryZoneTransferProtocol ?? DnsTransportProtocol.Tcp;
            DnsTransportProtocol protocol = options.TryGetProperty("transferProtocol", out JsonElement transport)
                ? Enum.Parse<DnsTransportProtocol>(transport.GetString() ?? nameof(DnsTransportProtocol.Tcp)) : previousProtocol;
            if (!stub && protocol is not (DnsTransportProtocol.Tcp or DnsTransportProtocol.Tls or DnsTransportProtocol.Quic))
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
                    var server = ParseAddress(address, protocol, serverPath);
                    if (stub && server.Port != 53)
                        throw new InvalidDataException($"{serverPath}/address: Stub zone primary servers must use port 53.");
                    return server;
                }).ToArray();
            }
            else if (protocol != previousProtocol && current?.PrimaryNameServerAddresses is { } previousServers)
            {
                servers = previousServers.Select(server => ParseAddress(server.ToString(), protocol, path + "/primary/servers")).ToArray();
            }
            if (type is AuthZoneType.SecondaryForwarder or AuthZoneType.SecondaryCatalog &&
                (servers ?? current?.PrimaryNameServerAddresses) is not { Count: > 0 })
                throw new InvalidDataException($"{path}/primary/servers: This zone type requires at least one primary server.");
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
            if (validate.HasValue && validate == (current?.ValidateZone ?? false))
                validate = null;
            return new Changes(servers, protocol == previousProtocol ? null : protocol, key, validate);

            static bool UsesZoneNameServers(JsonElement zone, string name) =>
                zone.TryGetProperty(name, out JsonElement policy) && policy.TryGetProperty("mode", out JsonElement mode) &&
                mode.GetString() is "AllowOnlyZoneNameServers" or "AllowZoneNameServersAndUseSpecifiedNetworkACL";
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

        internal static JsonObject Export(AuthZoneInfo zone)
        {
            var result = new JsonObject
            {
                ["servers"] = JsonSerializer.SerializeToNode((zone.PrimaryNameServerAddresses ?? []).Select(server => new { address = server.ToString() }))
            };
            if (zone.Type != AuthZoneType.Stub)
            {
                result["transferProtocol"] = zone.PrimaryZoneTransferProtocol.ToString();
                result["tsigKey"] = string.IsNullOrEmpty(zone.PrimaryZoneTransferTsigKeyName) ? null : zone.PrimaryZoneTransferTsigKeyName;
            }
            if (zone.Type == AuthZoneType.Secondary)
                result["validateZone"] = zone.ValidateZone;
            return result;
        }
    }
}
