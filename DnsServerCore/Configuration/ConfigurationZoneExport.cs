using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using DnsServerCore.Auth;
using DnsServerCore.Dns;
using DnsServerCore.Dns.ResourceRecords;
using DnsServerCore.Dns.ZoneManagers;
using DnsServerCore.Dns.Zones;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Configuration
{
    internal static class ConfigurationZoneExport
    {
        internal static JsonObject Export(DnsServer dns, Func<string, bool> isClusterInfrastructure, Func<string, bool> canView,
            Func<string, Permission> getPermission, ISet<string> missingInputs)
        {
            var result = new JsonObject();
            foreach (AuthZoneInfo zone in dns.AuthZoneManager.GetAllZones().OrderBy(zone => zone.Name, StringComparer.Ordinal))
            {
                if (!canView(zone.Name))
                    continue;

                string name = zone.Name.Length == 0 ? "." : zone.Name;
                string path = ConfigurationPlan.AppendPath("/zones", name);
                if (isClusterInfrastructure(zone.Name) ||
                    (zone.ApexZone is not (PrimaryZone { DnssecStatus: AuthZoneDnssecStatus.Unsigned } or ForwarderZone) &&
                        !ConfigurationZonePrimary.IsReplicated(zone.Type)) ||
                    (zone.CatalogZoneName is string catalog && (!AuthZoneManager.SupportsManifestCatalogMembership(zone.Type) ||
                        isClusterInfrastructure(catalog) || !canView(catalog) || dns.AuthZoneManager.GetAuthZoneInfo(catalog)?.Type != AuthZoneType.Catalog)))
                {
                    missingInputs.Add(path);
                    continue;
                }

                var declaration = JsonSerializer.SerializeToNode(new
                {
                    type = zone.Type.ToString(),
                    enabled = !zone.Disabled,
                    query = new { mode = zone.QueryAccess.ToString(), networkAcl = zone.QueryAccessNetworkACL?.Select(rule => rule.ToString()) ?? [] },
                    transfer = new
                    {
                        mode = zone.ZoneTransfer.ToString(),
                        networkAcl = zone.ZoneTransferNetworkACL?.Select(rule => rule.ToString()) ?? [],
                        tsigKeys = (zone.ZoneTransferTsigKeyNames ?? Enumerable.Empty<string>()).OrderBy(key => key, StringComparer.Ordinal)
                    },
                    notify = new { mode = zone.Notify.ToString(), nameServers = zone.NotifyNameServers?.Select(address => address.ToString()) ?? [] },
                    updates = new { mode = zone.Update.ToString(), networkAcl = zone.UpdateNetworkACL?.Select(rule => rule.ToString()) ?? [] }
                }).AsObject();

                if (AuthZoneManager.SupportsManifestCatalogMembership(zone.Type))
                {
                    var catalogDeclaration = new JsonObject
                    {
                        ["name"] = zone.CatalogZoneName, ["overrideQueryAccess"] = zone.OverrideCatalogQueryAccess
                    };
                    if (zone.Type != AuthZoneType.Stub)
                        catalogDeclaration["overrideZoneTransfer"] = zone.OverrideCatalogZoneTransfer;
                    if (zone.Type is AuthZoneType.Primary or AuthZoneType.Forwarder)
                        catalogDeclaration["overrideNotify"] = zone.OverrideCatalogNotify;
                    if (zone.CatalogZoneName is not null || catalogDeclaration.Any(field => field.Key != "name" && field.Value.GetValue<bool>()))
                        declaration["catalog"] = catalogDeclaration;
                }
                if (zone.ZoneTransferTsigKeyNames?.Any(key => dns.TsigKeys?.ContainsKey(key) != true) == true)
                {
                    declaration["transfer"].AsObject().Remove("tsigKeys");
                    missingInputs.Add(path + "/transfer/tsigKeys");
                }
                if (zone.Type == AuthZoneType.Catalog)
                {
                    declaration.Remove("updates");
                    declaration["notify"].AsObject()["secondaryCatalogNameServers"] =
                        JsonSerializer.SerializeToNode((zone.NotifySecondaryCatalogNameServers ?? []).Select(address => address.ToString()));
                }
                else if (ConfigurationZonePrimary.IsReplicated(zone.Type))
                {
                    var primary = ConfigurationZonePrimary.Export(zone);
                    if (zone.Type != AuthZoneType.Stub && zone.PrimaryZoneTransferTsigKeyName is { Length: > 0 } key &&
                        dns.TsigKeys?.ContainsKey(key) != true)
                    {
                        primary.Remove("tsigKey");
                        missingInputs.Add(path + "/primary/tsigKey");
                    }
                    declaration["primary"] = primary;
                    if (zone.Type is AuthZoneType.Stub or AuthZoneType.SecondaryForwarder)
                    {
                        declaration.Remove("transfer");
                        declaration.Remove("notify");
                    }
                    if (zone.Type is AuthZoneType.Stub or AuthZoneType.SecondaryCatalog)
                        declaration.Remove("updates");
                    if (zone.Type == AuthZoneType.SecondaryCatalog)
                    {
                        declaration.Remove("query");
                        declaration.Remove("transfer");
                        declaration.Remove("notify");
                    }
                }
                else if (zone.UpdateSecurityPolicies?.Keys.Any(key => dns.TsigKeys?.ContainsKey(key) != true) == true)
                    missingInputs.Add(path + "/updates/securityPolicies");
                else
                    declaration["updates"].AsObject()["securityPolicies"] = ConfigurationZoneUpdatePolicies.Write(zone.UpdateSecurityPolicies);

                if (getPermission?.Invoke(zone.Name) is Permission permission)
                    declaration["permissions"] = ConfigurationPermissions.ExportGrants(permission);

                if (!ConfigurationZonePrimary.IsReplicated(zone.Type) && zone.Type != AuthZoneType.Catalog)
                {
                    var records = new List<DnsResourceRecord>();
                    dns.AuthZoneManager.ListAllZoneRecords(zone.Name, records);
                    JsonArray exportedRecords = ExportRecords(zone.Name, dns.ServerDomain, path, records, missingInputs);
                    if (exportedRecords is not null)
                        declaration.Add("records", exportedRecords);
                }
                result.Add(name, declaration);
            }
            return result;
        }

        private static JsonArray ExportRecords(string zone, string serverDomain, string path, List<DnsResourceRecord> records, ISet<string> missingInputs)
        {
            var entries = new List<(string Owner, ushort Type, string Hex, uint Ttl, bool Disabled, string Comments, uint ExpiryTtl,
                string[] Glue, bool? UseSerialDateScheme, bool AutoIpv4Hint, bool AutoIpv6Hint, JsonObject Data, string MissingInput)>();
            foreach (DnsResourceRecord record in records)
            {
                if (ConfigurationPlan.IsLeaseRecord(record) ||
                    (record.Type != DnsResourceRecordType.SOA &&
                        ConfigurationPlan.IsGeneratedRecord(zone, serverDomain, record.Name, record.Type, record.RDATA)))
                    continue;

                var info = record.Tag as GenericRecordInfo;
                if (record.Class != DnsClass.IN)
                {
                    missingInputs.Add(path + "/records");
                    return null;
                }

                using var wire = new MemoryStream();
                DnsResourceRecordData data = record.RDATA;
                bool autoIpv4 = info is SVCBRecordInfo { AutoIpv4Hint: true };
                bool autoIpv6 = info is SVCBRecordInfo { AutoIpv6Hint: true };
                if (data is DnsSOARecordData soa)
                    data = new DnsSOARecordData(soa.PrimaryNameServer, soa.ResponsiblePerson, 0, soa.Refresh, soa.Retry, soa.Expire, soa.Minimum);
                else if (data is DnsSVCBRecordData svc)
                    data = ConfigurationPlan.WithoutAutomaticHints(svc, autoIpv4, autoIpv6);
                string sortKey, missingInput = null;
                JsonObject declaration;
                string owner = record.Name.ToLowerInvariant();
                if (data is DnsApplicationRecordData application)
                {
                    declaration = new JsonObject { ["app"] = new JsonObject { ["name"] = application.AppName, ["classPath"] = application.ClassPath } };
                    sortKey = string.Empty;
                    if (application.Data.Length > 0)
                        missingInput = "/data/app/configuration";
                }
                else if (data is DnsForwarderRecordData forwarder)
                {
                    if (forwarder.Protocol is not (DnsTransportProtocol.Udp or DnsTransportProtocol.Tcp or DnsTransportProtocol.Tls or
                        DnsTransportProtocol.Https or DnsTransportProtocol.Quic) ||
                        forwarder.NameServer?.DoHEndPoint is Uri uri && (uri.UserInfo.Length != 0 || uri.Query.Length != 0 || uri.Fragment.Length != 0))
                    {
                        missingInputs.Add(path + "/records");
                        return null;
                    }
                    var proxy = new JsonObject { ["type"] = forwarder.ProxyType.ToString() };
                    if (forwarder.ProxyType is DnsForwarderRecordProxyType.Http or DnsForwarderRecordProxyType.Socks5)
                    {
                        proxy["address"] = forwarder.ProxyAddress;
                        proxy["port"] = forwarder.ProxyPort;
                        if (!string.IsNullOrEmpty(forwarder.ProxyUsername))
                            proxy["username"] = forwarder.ProxyUsername;
                        if (!string.IsNullOrEmpty(forwarder.ProxyPassword))
                            missingInput = "/data/forwarder/proxy/password";
                    }
                    declaration = new JsonObject
                    {
                        ["forwarder"] = new JsonObject
                        {
                            ["address"] = forwarder.Forwarder, ["transport"] = forwarder.Protocol.ToString(),
                            ["priority"] = forwarder.Priority, ["dnssecValidation"] = forwarder.DnssecValidation, ["proxy"] = proxy
                        }
                    };
                    sortKey = declaration.ToJsonString();
                }
                else
                {
                    data.WriteTo(wire);
                    string hex = Convert.ToHexString(wire.GetBuffer().AsSpan(sizeof(ushort), (int)wire.Length - sizeof(ushort)));
                    try
                    {
                        if (!ConfigurationManifest.ReadRawZoneRecordData(zone, owner, record.Type, hex, path + "/records").RDATA.Equals(data))
                        {
                            missingInputs.Add(path + "/records");
                            return null;
                        }
                    }
                    catch (InvalidDataException)
                    {
                        missingInputs.Add(path + "/records");
                        return null;
                    }
                    declaration = new JsonObject { ["rawHex"] = hex };
                    sortKey = hex;
                }

                string[] glue = null;
                if (record.RDATA is DnsNSRecordData ns)
                {
                    IReadOnlyList<DnsResourceRecord> glueRecords = (info as NSRecordInfo)?.GlueRecords ?? [];
                    if (glueRecords.Any(address => address.Class != DnsClass.IN || address.OriginalTtlValue != record.OriginalTtlValue ||
                        !address.Name.Equals(ns.NameServer, StringComparison.OrdinalIgnoreCase) ||
                        address.Type is not (DnsResourceRecordType.A or DnsResourceRecordType.AAAA)) ||
                        (glueRecords.Count > 0 && owner == zone && (zone.Length == 0 ||
                            ns.NameServer.Equals(zone, StringComparison.OrdinalIgnoreCase) ||
                            ns.NameServer.EndsWith("." + zone, StringComparison.OrdinalIgnoreCase))))
                    {
                        missingInputs.Add(path + "/records");
                        return null;
                    }
                    glue = glueRecords.Select(address => address.RDATA.ToString()).ToArray();
                }

                entries.Add((owner, (ushort)record.Type, sortKey, record.OriginalTtlValue, info?.Disabled ?? false,
                    info?.Comments ?? string.Empty, info?.ExpiryTtl ?? 0u, glue,
                    record.Type == DnsResourceRecordType.SOA ? info is SOARecordInfo { UseSoaSerialDateScheme: true } : null,
                    autoIpv4, autoIpv6, declaration, missingInput));
            }

            var exported = new JsonArray();
            foreach (var entry in entries.OrderBy(entry => entry.Owner, StringComparer.Ordinal).ThenBy(entry => entry.Type)
                         .ThenBy(entry => entry.Hex, StringComparer.Ordinal))
            {
                var record = new JsonObject
                {
                    ["owner"] = entry.Owner == zone ? "@" : entry.Owner,
                    ["type"] = (int)entry.Type,
                    ["data"] = entry.Data,
                    ["ttl"] = entry.Ttl,
                    ["disabled"] = entry.Disabled,
                    ["comments"] = entry.Comments,
                    ["expiryTtl"] = entry.ExpiryTtl
                };
                if (entry.Glue is not null)
                    record["glue"] = JsonSerializer.SerializeToNode(entry.Glue);
                if (entry.UseSerialDateScheme.HasValue)
                    record["useSerialDateScheme"] = entry.UseSerialDateScheme.Value;
                if (entry.AutoIpv4Hint)
                    record["autoIpv4Hint"] = true;
                if (entry.AutoIpv6Hint)
                    record["autoIpv6Hint"] = true;
                if (entry.MissingInput is not null)
                    missingInputs.Add($"{path}/records/{exported.Count}{entry.MissingInput}");
                exported.Add(record);
            }
            return exported;
        }
    }
}
