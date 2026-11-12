using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.Json;
using System.Text.Json.Nodes;
using DnsServerCore.Auth;
using DnsServerCore.Dns;
using DnsServerCore.Dns.ResourceRecords;
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
                if (isClusterInfrastructure(zone.Name) || zone.ApexZone is not PrimaryZone { DnssecStatus: AuthZoneDnssecStatus.Unsigned } || zone.CatalogZoneName is not null)
                {
                    missingInputs.Add(path);
                    continue;
                }

                var declaration = JsonSerializer.SerializeToNode(new
                {
                    type = nameof(AuthZoneType.Primary),
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

                if (zone.ZoneTransferTsigKeyNames?.Any(key => dns.TsigKeys?.ContainsKey(key) != true) == true)
                {
                    declaration["transfer"].AsObject().Remove("tsigKeys");
                    missingInputs.Add(path + "/transfer/tsigKeys");
                }
                if (zone.UpdateSecurityPolicies?.Keys.Any(key => dns.TsigKeys?.ContainsKey(key) != true) == true)
                    missingInputs.Add(path + "/updates/securityPolicies");
                else
                    declaration["updates"].AsObject()["securityPolicies"] = ConfigurationZoneUpdatePolicies.Write(zone.UpdateSecurityPolicies);

                if (getPermission?.Invoke(zone.Name) is Permission permission)
                    declaration["permissions"] = ConfigurationPermissions.ExportGrants(permission);

                var records = new List<DnsResourceRecord>();
                dns.AuthZoneManager.ListAllZoneRecords(zone.Name, records);
                JsonArray exportedRecords = ExportRecords(zone.Name, dns.ServerDomain, path, records, missingInputs);
                if (exportedRecords is not null)
                    declaration.Add("records", exportedRecords);
                result.Add(name, declaration);
            }
            return result;
        }

        private static JsonArray ExportRecords(string zone, string serverDomain, string path, List<DnsResourceRecord> records, ISet<string> missingInputs)
        {
            var entries = new List<(string Owner, ushort Type, string Hex, uint Ttl, bool Disabled, string Comments, uint ExpiryTtl, string[] Glue)>();
            foreach (DnsResourceRecord record in records)
            {
                if (ConfigurationPlan.IsLeaseRecord(record) ||
                    ConfigurationPlan.IsGeneratedRecord(zone, serverDomain, record.Name, record.Type, record.RDATA))
                    continue;

                var info = record.Tag as GenericRecordInfo;
                if (record.Class != DnsClass.IN || record.Type is DnsResourceRecordType.APP or DnsResourceRecordType.FWD ||
                    info is SVCBRecordInfo { AutoIpv4Hint: true } or SVCBRecordInfo { AutoIpv6Hint: true })
                {
                    missingInputs.Add(path + "/records");
                    return null;
                }

                using var wire = new MemoryStream();
                record.RDATA.WriteTo(wire);
                string hex = Convert.ToHexString(wire.GetBuffer().AsSpan(sizeof(ushort), (int)wire.Length - sizeof(ushort)));
                string owner = record.Name.ToLowerInvariant();
                try
                {
                    if (!ConfigurationManifest.ReadRawZoneRecordData(zone, owner, record.Type, hex, path + "/records").RDATA.Equals(record.RDATA))
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

                entries.Add((owner, (ushort)record.Type, hex, record.OriginalTtlValue, info?.Disabled ?? false,
                    info?.Comments ?? string.Empty, info?.ExpiryTtl ?? 0u, glue));
            }

            var exported = new JsonArray();
            foreach (var entry in entries.OrderBy(entry => entry.Owner, StringComparer.Ordinal).ThenBy(entry => entry.Type)
                         .ThenBy(entry => entry.Hex, StringComparer.Ordinal))
            {
                var record = new JsonObject
                {
                    ["owner"] = entry.Owner == zone ? "@" : entry.Owner,
                    ["type"] = (int)entry.Type,
                    ["data"] = new JsonObject { ["rawHex"] = entry.Hex },
                    ["ttl"] = entry.Ttl,
                    ["disabled"] = entry.Disabled,
                    ["comments"] = entry.Comments,
                    ["expiryTtl"] = entry.ExpiryTtl
                };
                if (entry.Glue is not null)
                    record["glue"] = JsonSerializer.SerializeToNode(entry.Glue);
                exported.Add(record);
            }
            return exported;
        }
    }
}
