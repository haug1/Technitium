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
            Func<AuthZoneInfo, bool> canExportClusterCatalogMember, Func<string, Permission> getPermission, ISet<string> missingInputs)
        {
            var result = new JsonObject();
            foreach (AuthZoneInfo zone in dns.AuthZoneManager.GetAllZones().OrderBy(zone => zone.Name, StringComparer.Ordinal))
            {
                if (!canView(zone.Name))
                    continue;

                string catalog = zone.CatalogZoneName;
                AuthZoneType? catalogType = catalog is null ? null : dns.AuthZoneManager.GetAuthZoneInfo(catalog)?.Type;
                string name = zone.Name.Length == 0 ? "." : zone.Name;
                string path = ConfigurationPlan.AppendPath("/zones", name);
                Permission permission = getPermission?.Invoke(zone.Name);
                if (isClusterInfrastructure(zone.Name))
                {
                    if (OperatorGrants(permission).Any())
                        result.Add(name, new JsonObject { ["permissions"] = ConfigurationPermissions.ExportGrants(permission, includeBuiltInZoneGroups: false) });
                    continue;
                }
                if (catalogType == AuthZoneType.SecondaryCatalog)
                {
                    Permission catalogPermission = canView(catalog) ? getPermission?.Invoke(catalog) : null;
                    if (permission is not null && !OperatorGrants(permission).SequenceEqual(OperatorGrants(catalogPermission)))
                        result.Add(name, new JsonObject { ["permissions"] = ConfigurationPermissions.ExportGrants(permission) });
                    continue;
                }
                if ((zone.ApexZone is not (PrimaryZone or ForwarderZone) &&
                        !ConfigurationZonePrimary.IsReplicated(zone.Type)) ||
                    (catalog is not null && (!AuthZoneManager.SupportsManifestCatalogMembership(zone.Type) ||
                        (isClusterInfrastructure(catalog) && !canExportClusterCatalogMember(zone)) ||
                        !canView(catalog) || catalogType != AuthZoneType.Catalog)))
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

                if (zone.ApexZone is PrimaryZone { DnssecStatus: not AuthZoneDnssecStatus.Unsigned })
                    declaration["dnssec"] = ConfigurationZoneDnssec.Export(zone, path, missingInputs);

                if (permission is not null)
                    declaration["permissions"] = ConfigurationPermissions.ExportGrants(permission);

                if (!ConfigurationZonePrimary.IsReplicated(zone.Type) && zone.Type != AuthZoneType.Catalog)
                {
                    var records = new List<DnsResourceRecord>();
                    dns.AuthZoneManager.ListAllZoneRecords(zone.Name, records);
                    uint defaultNsTtl = dns.AuthZoneManager.DefaultNsRecordTtl;
                    bool replaceApexNameServers = false;
                    if (zone.Type == AuthZoneType.Primary)
                    {
                        var apexNameServers = records.Where(record => record.Type == DnsResourceRecordType.NS &&
                            record.Name.Equals(zone.Name, StringComparison.OrdinalIgnoreCase)).ToArray();
                        if (canExportClusterCatalogMember(zone))
                        {
                            declaration["catalog"]["apexNameServerTtl"] = apexNameServers.FirstOrDefault()?.OriginalTtlValue ?? defaultNsTtl;
                            records.RemoveAll(record => record.Type == DnsResourceRecordType.NS && record.Name.Equals(zone.Name, StringComparison.OrdinalIgnoreCase));
                        }
                        else
                        {
                            replaceApexNameServers = apexNameServers.Length == 0 ||
                                apexNameServers.Any(record => !ConfigurationPlan.IsGeneratedRecord(zone.Name, dns.ServerDomain, record.Name, record.Type, record.RDATA) ||
                                    HasCustomizedNameServer(zone.Name, record, defaultNsTtl, records));
                        }
                    }
                    JsonArray exportedRecords = ExportRecords(zone.Name, dns.ServerDomain, defaultNsTtl, replaceApexNameServers, path, records, missingInputs);
                    if (exportedRecords is not null)
                    {
                        declaration.Add("records", exportedRecords);
                        if (replaceApexNameServers)
                            declaration.Add("replaceApexNameServers", true);
                    }
                }
                result.Add(name, declaration);
            }
            return result;
        }

        private static IEnumerable<(bool Group, string Name, PermissionFlag Flags)> OperatorGrants(Permission permission)
        {
            if (permission is null)
                return [];
            return permission.UserPermissions.Select(grant => (false, grant.Key.Username, grant.Value))
                .Concat(permission.GroupPermissions.Where(grant => grant.Key.Name is not (Group.ADMINISTRATORS or Group.DNS_ADMINISTRATORS))
                    .Select(grant => (true, grant.Key.Name.ToLowerInvariant(), grant.Value)))
                .OrderBy(grant => grant.Item1).ThenBy(grant => grant.Item2, StringComparer.Ordinal);
        }

        private static bool HasCustomizedNameServer(string zone, DnsResourceRecord record, uint defaultNsTtl, List<DnsResourceRecord> records)
        {
            var info = record.Tag as GenericRecordInfo;
            return record.OriginalTtlValue != defaultNsTtl || info?.Disabled == true ||
                !string.IsNullOrEmpty(info?.Comments) || info?.ExpiryTtl > 0 ||
                (info is NSRecordInfo { GlueRecords.Count: > 0 } && !HasRedundantApexGlue(zone, record, records));
        }

        private static bool HasRedundantApexGlue(string zone, DnsResourceRecord record, List<DnsResourceRecord> records) =>
            record.Name.Equals(zone, StringComparison.OrdinalIgnoreCase) && record.RDATA is DnsNSRecordData ns &&
            AuthZoneManager.DomainBelongsToZone(zone, ns.NameServer) &&
            record.Tag is NSRecordInfo { GlueRecords.Count: > 0 } metadata &&
            metadata.GlueRecords.All(address => address.Class == DnsClass.IN &&
                address.Name.Equals(ns.NameServer, StringComparison.OrdinalIgnoreCase) &&
                address.Type is DnsResourceRecordType.A or DnsResourceRecordType.AAAA &&
                records.Any(candidate => candidate.Class == DnsClass.IN &&
                    candidate.Name.Equals(address.Name, StringComparison.OrdinalIgnoreCase) && candidate.Type == address.Type &&
                    candidate.RDATA.Equals(address.RDATA) && candidate.OriginalTtlValue == address.OriginalTtlValue &&
                    candidate.Tag is not GenericRecordInfo { Disabled: true } && !ConfigurationPlan.IsLeaseRecord(candidate)));

        private static JsonArray ExportRecords(string zone, string serverDomain, uint defaultNsTtl, bool replaceApexNameServers, string path, List<DnsResourceRecord> records, ISet<string> missingInputs)
        {
            var entries = new List<(string Owner, ushort Type, string Hex, uint Ttl, bool Disabled, string Comments, uint ExpiryTtl,
                JsonArray Glue, bool? UseSerialDateScheme, bool AutoIpv4Hint, bool AutoIpv6Hint, JsonObject Data, List<string> MissingInputs)>();
            foreach (DnsResourceRecord record in records)
            {
                var info = record.Tag as GenericRecordInfo;
                bool preserveNameServer = record.Type == DnsResourceRecordType.NS &&
                    (replaceApexNameServers && record.Name.Equals(zone, StringComparison.OrdinalIgnoreCase) ||
                        HasCustomizedNameServer(zone, record, defaultNsTtl, records));
                if (ConfigurationPlan.IsLeaseRecord(record) ||
                    (record.Type != DnsResourceRecordType.SOA &&
                        !preserveNameServer &&
                        ConfigurationPlan.IsGeneratedRecord(zone, serverDomain, record.Name, record.Type, record.RDATA)))
                    continue;

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
                string sortKey;
                var recordInputs = new List<string>();
                JsonObject declaration;
                string owner = record.Name.ToLowerInvariant();
                if (data is DnsApplicationRecordData application)
                {
                    declaration = new JsonObject { ["app"] = new JsonObject { ["name"] = application.AppName, ["classPath"] = application.ClassPath } };
                    sortKey = string.Empty;
                    if (application.Data.Length > 0)
                        recordInputs.Add("/data/app/configuration");
                }
                else if (data is DnsForwarderRecordData forwarder)
                {
                    if (forwarder.Protocol is not (DnsTransportProtocol.Udp or DnsTransportProtocol.Tcp or DnsTransportProtocol.Tls or
                        DnsTransportProtocol.Https or DnsTransportProtocol.Quic))
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
                            recordInputs.Add("/data/forwarder/proxy/password");
                    }
                    var forwarderSettings = new JsonObject
                    {
                        ["address"] = forwarder.Forwarder, ["transport"] = forwarder.Protocol.ToString(),
                        ["priority"] = forwarder.Priority, ["dnssecValidation"] = forwarder.DnssecValidation, ["proxy"] = proxy
                    };
                    declaration = new JsonObject { ["forwarder"] = forwarderSettings };
                    sortKey = declaration.ToJsonString();
                    if (forwarder.NameServer?.DoHEndPoint is Uri uri &&
                        (uri.UserInfo.Length != 0 || uri.Query.Length != 0 || uri.Fragment.Length != 0))
                    {
                        forwarderSettings.Remove("address");
                        recordInputs.Add("/data/forwarder/address");
                    }
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

                JsonArray glue = null;
                if (record.RDATA is DnsNSRecordData ns)
                {
                    IReadOnlyList<DnsResourceRecord> glueRecords = (info as NSRecordInfo)?.GlueRecords ?? [];
                    bool inZoneApex = owner == zone && AuthZoneManager.DomainBelongsToZone(zone, ns.NameServer);
                    if (inZoneApex)
                    {
                        // Zone-file import attaches copies of the authoritative addresses to the apex NS.
                        if (glueRecords.Count > 0 && !HasRedundantApexGlue(zone, record, records))
                        {
                            missingInputs.Add(path + "/records");
                            return null;
                        }
                    }
                    else
                    {
                        if (glueRecords.Any(address => address.Class != DnsClass.IN ||
                            !address.Name.Equals(ns.NameServer, StringComparison.OrdinalIgnoreCase) ||
                            address.Type is not (DnsResourceRecordType.A or DnsResourceRecordType.AAAA)))
                        {
                            missingInputs.Add(path + "/records");
                            return null;
                        }
                        glue = new JsonArray();
                        foreach (DnsResourceRecord address in glueRecords)
                        {
                            string ip = address.RDATA.ToString();
                            glue.Add(address.OriginalTtlValue == record.OriginalTtlValue
                                ? JsonValue.Create(ip) : new JsonObject { ["address"] = ip, ["ttl"] = address.OriginalTtlValue });
                        }
                    }
                }

                entries.Add((owner, (ushort)record.Type, sortKey, record.OriginalTtlValue, info?.Disabled ?? false,
                    info?.Comments ?? string.Empty, info?.ExpiryTtl ?? 0u, glue,
                    record.Type == DnsResourceRecordType.SOA ? info is SOARecordInfo { UseSoaSerialDateScheme: true } : null,
                    autoIpv4, autoIpv6, declaration, recordInputs));
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
                    record["glue"] = entry.Glue;
                if (entry.UseSerialDateScheme.HasValue)
                    record["useSerialDateScheme"] = entry.UseSerialDateScheme.Value;
                if (entry.AutoIpv4Hint)
                    record["autoIpv4Hint"] = true;
                if (entry.AutoIpv6Hint)
                    record["autoIpv6Hint"] = true;
                foreach (string input in entry.MissingInputs)
                    missingInputs.Add($"{path}/records/{exported.Count}{input}");
                exported.Add(record);
            }
            return exported;
        }
    }
}
