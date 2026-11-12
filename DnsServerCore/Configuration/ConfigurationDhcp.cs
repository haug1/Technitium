using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using DnsServerCore.Dhcp;
using DnsServerCore.Dhcp.Options;
using TechnitiumLibrary.Net;

namespace DnsServerCore.Configuration
{
    internal static class ConfigurationDhcp
    {
        private const string ScopesPath = "/dhcp/scopes";

        private static readonly JsonObject _defaultOptions = WriteScopeOptions(new Scope("defaults", true,
            IPAddress.Parse("192.0.2.1"), IPAddress.Parse("192.0.2.2"), IPAddress.Parse("255.255.255.0"), null, null)
            { IgnoreClientIdentifierOption = true });

        private sealed record Reservation(IPAddress Address, string HostName, string Comments);

        private sealed record ScopeState(IPAddress Start, IPAddress End, IPAddress Mask, bool Enabled);

        internal static void Validate(JsonElement manifest)
        {
            if (!manifest.TryGetProperty("dhcp", out JsonElement dhcp) ||
                !dhcp.TryGetProperty("scopes", out JsonElement scopes) || scopes.ValueKind == JsonValueKind.Null)
                return;

            foreach (JsonProperty declaration in scopes.EnumerateObject())
            {
                string path = ConfigurationPlan.AppendPath(ScopesPath, declaration.Name);
                try
                {
                    Scope.ValidateScopeName(declaration.Name);
                }
                catch (DhcpServerException)
                {
                    throw new InvalidDataException($"{path}: Invalid scope name.");
                }

                if (string.IsNullOrWhiteSpace(declaration.Name))
                    throw new InvalidDataException($"{path}: A scope name is required.");

                JsonElement scope = declaration.Value;
                if (scope.ValueKind == JsonValueKind.Null)
                    continue;

                ReadDeclaredOptions(scope, path);
                IPAddress start = ReadAddress(scope, "startingAddress");
                IPAddress end = ReadAddress(scope, "endingAddress");
                IPAddress mask = ReadAddress(scope, "subnetMask");
                ValidateNetwork(path, start, end, mask);

                if (scope.TryGetProperty("exclusions", out JsonElement exclusions))
                    ReadExclusions(exclusions, path + "/exclusions", start, end);

                if (scope.TryGetProperty("reservations", out JsonElement reservations) && reservations.ValueKind == JsonValueKind.Object)
                {
                    var identifiers = new HashSet<string>(StringComparer.Ordinal);
                    var addresses = new HashSet<IPAddress>();
                    foreach (JsonProperty reservation in reservations.EnumerateObject())
                    {
                        string entryPath = ConfigurationPlan.AppendPath(path + "/reservations", reservation.Name);
                        if (!identifiers.Add(ReadHardwareAddress(reservation.Name, entryPath)))
                            throw new InvalidDataException($"{entryPath}: Duplicate reservation hardware address.");

                        IPAddress address = reservation.Value.ValueKind == JsonValueKind.Object
                            ? ReadAddress(reservation.Value, "address") : null;
                        if (address is null)
                            continue;
                        if (!addresses.Add(address))
                            throw new InvalidDataException($"{entryPath}/address: Duplicate reservation address.");
                        CheckRange(entryPath + "/address", address, start, end);
                    }
                }
            }
        }

        internal sealed class ScopeSnapshot : IDisposable
        {
            private readonly Dictionary<string, Scope> _scopes = new(StringComparer.Ordinal);
            private readonly List<Scope> _copies = [];

            internal IReadOnlyDictionary<string, Scope> Scopes => _scopes;

            internal ScopeSnapshot(JsonElement declarations, IReadOnlyDictionary<string, Scope> scopes)
            {
                try
                {
                    foreach (var (name, scope) in scopes)
                    {
                        Scope captured = scope;
                        if (declarations.ValueKind == JsonValueKind.Null || declarations.TryGetProperty(name, out _))
                        {
                            captured = scope.CloneForManifest();
                            _copies.Add(captured);
                        }
                        _scopes.Add(name, captured);
                    }
                }
                catch
                {
                    Dispose();
                    throw;
                }
            }

            public void Dispose()
            {
                foreach (Scope scope in _copies)
                    scope.Dispose();
            }
        }

        internal static void WriteSnapshot(Utf8JsonWriter writer, JsonElement declarations, IReadOnlyDictionary<string, Scope> scopes)
        {
            writer.WriteStartObject("manifestDhcpScopes");
            DateTime now = DateTime.UtcNow;
            foreach ((string name, Scope scope) in scopes.OrderBy(entry => entry.Key, StringComparer.Ordinal))
            {
                writer.WriteStartObject(name);
                writer.WriteString("startingAddress", scope.StartingAddress.ToString());
                writer.WriteString("endingAddress", scope.EndingAddress.ToString());
                writer.WriteString("subnetMask", scope.SubnetMask.ToString());
                writer.WriteBoolean("enabled", scope.Enabled);

                if (declarations.ValueKind == JsonValueKind.Object && !declarations.TryGetProperty(name, out _))
                {
                    writer.WriteEndObject();
                    continue;
                }

                Lease[] activeLeases = scope.Leases.Values.Where(lease => lease.LeaseExpires > now)
                    .OrderBy(lease => lease.Address.ConvertIpToNumber()).ThenBy(lease => BitConverter.ToString(lease.HardwareAddress), StringComparer.Ordinal)
                    .ToArray();
                writer.WriteStartArray("activeLeases");
                foreach (Lease lease in activeLeases)
                {
                    writer.WriteStartObject();
                    writer.WriteString("hardwareAddress", BitConverter.ToString(lease.HardwareAddress));
                    writer.WriteString("address", lease.Address.ToString());
                    writer.WriteBoolean("dynamic", lease.Type == LeaseType.Dynamic);
                    writer.WriteEndObject();
                }
                writer.WriteEndArray();

                writer.WriteStartObject("reservations");
                foreach (Lease reservation in scope.ReservedLeases.OrderBy(lease => BitConverter.ToString(lease.HardwareAddress), StringComparer.Ordinal))
                {
                    writer.WriteStartObject(BitConverter.ToString(reservation.HardwareAddress));
                    writer.WriteString("address", reservation.Address.ToString());
                    writer.WriteString("hostName", reservation.HostName);
                    writer.WriteString("comments", reservation.Comments);
                    writer.WriteEndObject();
                }
                writer.WriteEndObject();

                writer.WritePropertyName("options");
                WriteScopeOptions(scope).WriteTo(writer);
                writer.WritePropertyName("exclusions");
                WriteExclusions(scope.Exclusions).WriteTo(writer);
                writer.WriteEndObject();
            }
            writer.WriteEndObject();
        }

        internal static void Compare(JsonElement dhcp, JsonElement snapshot, List<ConfigurationChange> changes)
        {
            if (!dhcp.TryGetProperty("scopes", out JsonElement scopes))
                return;
            if (scopes.ValueKind == JsonValueKind.Null)
            {
                foreach (JsonProperty scope in snapshot.EnumerateObject())
                    PreviewRemoval(scope.Name, scope.Value, changes);
                return;
            }

            var candidates = new Dictionary<string, ScopeState>(StringComparer.Ordinal);
            foreach (JsonProperty entry in snapshot.EnumerateObject())
            {
                JsonElement scope = entry.Value;
                candidates.Add(entry.Name, new ScopeState(ReadAddress(scope, "startingAddress"), ReadAddress(scope, "endingAddress"),
                    ReadAddress(scope, "subnetMask"), scope.GetProperty("enabled").GetBoolean()));
            }

            var changedRanges = new List<string>();
            foreach (JsonProperty entry in scopes.EnumerateObject())
            {
                string path = ConfigurationPlan.AppendPath(ScopesPath, entry.Name);
                if (entry.Value.ValueKind == JsonValueKind.Null)
                {
                    if (candidates.Remove(entry.Name))
                        PreviewRemoval(entry.Name, snapshot.GetProperty(entry.Name), changes);
                    continue;
                }

                JsonElement scope = entry.Value;
                candidates.TryGetValue(entry.Name, out ScopeState previous);
                IPAddress start = ReadAddress(scope, "startingAddress") ?? previous?.Start;
                IPAddress end = ReadAddress(scope, "endingAddress") ?? previous?.End;
                IPAddress mask = ReadAddress(scope, "subnetMask") ?? previous?.Mask;
                if (start is null || end is null || mask is null)
                    throw new InvalidDataException($"{path}: Starting address, ending address, and subnet mask are required to create a scope.");

                foreach (string field in new[] { "startingAddress", "endingAddress", "subnetMask" })
                {
                    if (scope.TryGetProperty(field, out JsonElement value) && value.ValueKind == JsonValueKind.Null)
                        throw new InvalidDataException($"{path}/{field}: This field has no default address.");
                }

                bool enabled = scope.TryGetProperty("enabled", out JsonElement enabledValue)
                    ? enabledValue.ValueKind == JsonValueKind.Null || enabledValue.GetBoolean()
                    : previous?.Enabled ?? true;
                var candidate = new ScopeState(start, end, mask, enabled);
                bool rangeChanged = previous is null || !start.Equals(previous.Start) || !end.Equals(previous.End) || !mask.Equals(previous.Mask);
                if (rangeChanged)
                {
                    ValidateNetwork(path, start, end, mask);
                    changedRanges.Add(entry.Name);
                }

                snapshot.TryGetProperty(entry.Name, out JsonElement currentScope);
                if (rangeChanged || scope.TryGetProperty("reservations", out _))
                    CompareReservations(scope, currentScope, path, start, end, rangeChanged, changes);

                if (rangeChanged && previous is not null)
                {
                    foreach (JsonElement lease in currentScope.GetProperty("activeLeases").EnumerateArray())
                        CheckRange(path, ReadAddress(lease, "address"), start, end);
                }

                if (scope.TryGetProperty("exclusions", out JsonElement exclusions))
                {
                    var desired = ReadExclusions(exclusions, path + "/exclusions", start, end);
                    if (previous is not null)
                    {
                        var currentExclusions = ReadExclusions(currentScope.GetProperty("exclusions"), path + "/exclusions", null, null);
                        if (!desired.SequenceEqual(currentExclusions))
                        {
                            foreach (JsonElement lease in currentScope.GetProperty("activeLeases").EnumerateArray())
                            {
                                if (!lease.TryGetProperty("dynamic", out JsonElement dynamic) || !dynamic.GetBoolean())
                                    continue;
                                uint address = ReadAddress(lease, "address").ConvertIpToNumber();
                                if (desired.Any(range => range.Start <= address && address <= range.End) &&
                                    !currentExclusions.Any(range => range.Start <= address && address <= range.End))
                                    throw new InvalidDataException($"{path}/exclusions: The exclusion would displace an active dynamic lease.");
                            }
                            changes.Add(new ConfigurationChange(path + "/exclusions", ConfigurationChangeKind.Update, false));
                        }
                    }
                }
                else if (rangeChanged && previous is not null)
                {
                    ReadExclusions(currentScope.GetProperty("exclusions"), path + "/exclusions", start, end);
                }

                if (previous is not null)
                    CompareOptions(scope, currentScope, path, changes);

                candidates[entry.Name] = candidate;
                if (previous is null)
                    changes.Add(new ConfigurationChange(path, ConfigurationChangeKind.Add, false));
                else
                {
                    AddUpdate("startingAddress", !start.Equals(previous.Start));
                    AddUpdate("endingAddress", !end.Equals(previous.End));
                    AddUpdate("subnetMask", !mask.Equals(previous.Mask));
                    AddUpdate("enabled", enabled != previous.Enabled);
                }

                void AddUpdate(string field, bool changed)
                {
                    if (changed)
                        changes.Add(new ConfigurationChange(path + "/" + field, ConfigurationChangeKind.Update, false));
                }
            }

            foreach (string name in changedRanges)
            {
                ScopeState scope = candidates[name];
                uint first = scope.Start.ConvertIpToNumber();
                uint last = scope.End.ConvertIpToNumber();
                if (candidates.Any(other => other.Key != name &&
                    first <= other.Value.End.ConvertIpToNumber() && other.Value.Start.ConvertIpToNumber() <= last))
                    throw new InvalidDataException($"{ConfigurationPlan.AppendPath(ScopesPath, name)}: The range overlaps another DHCP scope.");
            }
        }

        internal static void ValidatePersistableScopes(ConfigurationManifest manifest,
            IReadOnlyDictionary<string, Scope> current, LogManager log, DhcpServer dhcpServer)
        {
            if (!manifest.Settings.TryGetProperty("dhcp", out JsonElement dhcp) ||
                !dhcp.TryGetProperty("scopes", out JsonElement scopes) || scopes.ValueKind == JsonValueKind.Null)
                return;

            foreach (JsonProperty declaration in scopes.EnumerateObject())
            {
                if (declaration.Value.ValueKind == JsonValueKind.Null)
                    continue;
                current.TryGetValue(declaration.Name, out Scope existing);
                using Scope candidate = PrepareScope(declaration.Name, declaration.Value, existing, log, dhcpServer);
            }
        }

        internal static Scope PrepareScope(string name, JsonElement settings, Scope existing, LogManager log, DhcpServer dhcpServer)
        {
            string path = ConfigurationPlan.AppendPath(ScopesPath, name);
            IPAddress start = ReadAddress(settings, "startingAddress") ?? existing?.StartingAddress;
            IPAddress end = ReadAddress(settings, "endingAddress") ?? existing?.EndingAddress;
            IPAddress mask = ReadAddress(settings, "subnetMask") ?? existing?.SubnetMask;
            bool enabled = settings.TryGetProperty("enabled", out JsonElement enabledValue)
                ? enabledValue.ValueKind != JsonValueKind.False : existing?.Enabled ?? true;
            Scope candidate = null;
            try
            {
                candidate = existing is null
                    ? new Scope(name, enabled, start, end, mask, log, dhcpServer) { IgnoreClientIdentifierOption = true }
                    : existing.CloneForManifest();
                if (existing is not null)
                {
                    if (!start.Equals(existing.StartingAddress) || !end.Equals(existing.EndingAddress) || !mask.Equals(existing.SubnetMask))
                        candidate.ChangeNetwork(start, end, mask);
                    candidate.SetEnabled(enabled);
                }

                ApplyOptions(candidate, ReadDeclaredOptions(settings, path), path);
                if (settings.TryGetProperty("exclusions", out JsonElement exclusions))
                    candidate.Exclusions = ReadExclusions(exclusions, path + "/exclusions", start, end).Select(range =>
                        new Exclusion(IPAddressExtensions.ConvertNumberToIp(range.Start), IPAddressExtensions.ConvertNumberToIp(range.End))).ToArray();
                if (settings.TryGetProperty("reservations", out JsonElement reservations))
                    ApplyReservations(candidate, reservations, path + "/reservations");

                candidate.WriteTo(Stream.Null);
                return candidate;
            }
            catch (Exception ex)
            {
                candidate?.Dispose();
                if (ex is ArgumentException or OverflowException or DhcpServerException)
                    throw new InvalidDataException($"{path}: The scope settings cannot be stored in the DHCP configuration.");
                throw;
            }
        }

        private static void ApplyReservations(Scope scope, JsonElement declarations, string path)
        {
            if (declarations.ValueKind == JsonValueKind.Null)
            {
                scope.ClearManifestReservations();
                return;
            }

            var existing = scope.ReservedLeases.ToLookup(lease => BitConverter.ToString(lease.HardwareAddress), StringComparer.Ordinal);
            foreach (JsonProperty entry in declarations.EnumerateObject())
            {
                string entryPath = ConfigurationPlan.AppendPath(path, entry.Name);
                string key = ReadHardwareAddress(entry.Name, entryPath);
                byte[] mac = Lease.ParseHardwareAddress(key);
                var identifier = new ClientIdentifierOption((byte)DhcpMessageHardwareAddressType.Ethernet, mac);
                Lease previous = null;
                foreach (Lease reservation in existing[key])
                {
                    if (!reservation.ClientIdentifier.Equals(identifier) || previous is not null)
                        throw new InvalidDataException($"{entryPath}: The existing reservation cannot be identified by an Ethernet MAC address alone.");
                    previous = reservation;
                }

                if (entry.Value.ValueKind == JsonValueKind.Null)
                {
                    scope.SetManifestReservation(mac, null, null, null);
                    continue;
                }
                IPAddress address = ReadAddress(entry.Value, "address") ?? previous?.Address;
                string hostName = entry.Value.TryGetProperty("hostName", out JsonElement host) ? host.GetString() : previous?.HostName;
                string comments = entry.Value.TryGetProperty("comments", out JsonElement comment) ? comment.GetString() : previous?.Comments;
                scope.SetManifestReservation(mac, address, hostName, comments);
            }
        }

        private static void ApplyOptions(Scope scope, JsonObject options, string path)
        {
            JsonObject lease = options["leaseTime"]?.AsObject();
            scope.LeaseTimeDays = (ushort)Number(lease, "days", scope.LeaseTimeDays);
            scope.LeaseTimeHours = (byte)Number(lease, "hours", scope.LeaseTimeHours);
            scope.LeaseTimeMinutes = (byte)Number(lease, "minutes", scope.LeaseTimeMinutes);
            scope.OfferDelayTime = (ushort)Number(options, "offerDelayMs", scope.OfferDelayTime);
            JsonObject ping = options["pingCheck"]?.AsObject();
            scope.PingCheckEnabled = Flag(ping, "enabled", scope.PingCheckEnabled);
            scope.PingCheckTimeout = (ushort)Number(ping, "timeoutMs", scope.PingCheckTimeout);
            scope.PingCheckRetries = (byte)Number(ping, "retries", scope.PingCheckRetries);
            scope.DomainName = Text(options, "domainName", scope.DomainName);
            if (options.TryGetPropertyValue("domainSearchList", out JsonNode domains))
                scope.DomainSearchList = Strings(domains);
            JsonObject updates = options["dnsUpdates"]?.AsObject();
            scope.DnsUpdates = Flag(updates, "enabled", scope.DnsUpdates);
            scope.DnsOverwriteForDynamicLease = Flag(updates, "overwriteDynamicRecords", scope.DnsOverwriteForDynamicLease);
            scope.DnsTtl = Number(updates, "ttl", scope.DnsTtl);
            JsonObject boot = options["boot"]?.AsObject();
            scope.ServerAddress = Address(boot, "serverAddress", scope.ServerAddress);
            scope.ServerHostName = Text(boot, "serverHostName", scope.ServerHostName);
            scope.BootFileName = Text(boot, "fileName", scope.BootFileName);
            scope.RouterAddress = Address(options, "routerAddress", scope.RouterAddress);

            if (options["dns"] is JsonObject dns)
            {
                bool local = Flag(dns, "useThisServer", scope.UseThisDnsServer);
                var servers = dns.TryGetPropertyValue("servers", out JsonNode dnsServers) ? Addresses(dnsServers) : scope.DnsServers;
                if (!local && servers?.Count >= byte.MaxValue)
                    throw new InvalidDataException($"{path}/dns/servers: At most 254 explicit DNS servers can be stored.");
                scope.SetManifestDnsServers(local, servers);
            }
            if (options.TryGetPropertyValue("winsServers", out JsonNode wins))
                scope.WinsServers = Addresses(wins);
            if (options["ntp"] is JsonObject ntp)
            {
                if (ntp.TryGetPropertyValue("servers", out JsonNode servers))
                    scope.NtpServers = Addresses(servers);
                if (ntp.TryGetPropertyValue("serverDomainNames", out JsonNode names))
                    scope.NtpServerDomainNames = Strings(names);
            }
            if (options.TryGetPropertyValue("staticRoutes", out JsonNode routes))
                scope.StaticRoutes = routes?.AsArray().Select(route => new ClasslessStaticRouteOption.Route(
                    IPAddress.Parse(route["destination"].GetValue<string>()), IPAddress.Parse(route["subnetMask"].GetValue<string>()),
                    IPAddress.Parse(route["router"].GetValue<string>()))).ToArray();
            if (options.TryGetPropertyValue("vendorInfo", out JsonNode vendor))
            {
                var effective = new Dictionary<string, VendorSpecificInformationOption>(StringComparer.Ordinal);
                if (vendor is not null)
                {
                    if (scope.VendorInfo is not null)
                    {
                        foreach (var (identifier, option) in scope.VendorInfo)
                            effective.Add(identifier, option);
                    }
                    foreach (var (identifier, option) in vendor.AsObject())
                    {
                        if (option is null)
                            effective.Remove(identifier);
                        else
                            effective[identifier] = new VendorSpecificInformationOption(option.GetValue<string>());
                    }
                }
                scope.VendorInfo = effective;
            }
            if (options.TryGetPropertyValue("capwapAcIpAddresses", out JsonNode capwap))
                scope.CAPWAPAcIpAddresses = Addresses(capwap);
            if (options.TryGetPropertyValue("tftpServerAddresses", out JsonNode tftp))
                scope.TftpServerAddresses = Addresses(tftp);
            if (options.TryGetPropertyValue("genericOptions", out JsonNode generic))
                scope.GenericOptions = generic?.AsArray().Select(option => new DhcpOption((DhcpOptionCode)Number(option.AsObject(), "code", 0),
                    option["value"].GetValue<string>())).ToArray();

            scope.AllowOnlyReservedLeases = Flag(options, "allowOnlyReservedLeases", scope.AllowOnlyReservedLeases);
            scope.BlockLocallyAdministeredMacAddresses = Flag(options, "blockLocallyAdministeredMacAddresses", scope.BlockLocallyAdministeredMacAddresses);
            scope.IgnoreClientIdentifierOption = Flag(options, "ignoreClientIdentifierOption", scope.IgnoreClientIdentifierOption);

            static bool Flag(JsonObject parent, string name, bool fallback) => parent?[name]?.GetValue<bool>() ?? fallback;
            static uint Number(JsonObject parent, string name, uint fallback) => parent?[name] is JsonNode value
                ? decimal.ToUInt32(JsonSerializer.SerializeToElement(value).GetDecimal()) : fallback;
            static string Text(JsonObject parent, string name, string fallback) =>
                parent is not null && parent.TryGetPropertyValue(name, out JsonNode value) ? value?.GetValue<string>() : fallback;
            static IPAddress Address(JsonObject parent, string name, IPAddress fallback) =>
                parent is not null && parent.TryGetPropertyValue(name, out JsonNode value)
                    ? value is null ? null : IPAddress.Parse(value.GetValue<string>()) : fallback;
            static string[] Strings(JsonNode value) => value?.AsArray().Select(item => item.GetValue<string>()).ToArray();
            static IPAddress[] Addresses(JsonNode value) => Strings(value)?.Select(IPAddress.Parse).ToArray();
        }

        private static void PreviewRemoval(string name, JsonElement current, List<ConfigurationChange> changes)
        {
            string path = ConfigurationPlan.AppendPath(ScopesPath, name);
            if (current.GetProperty("activeLeases").GetArrayLength() != 0)
                throw new InvalidDataException($"{path}: A scope with active leases cannot be removed.");
            changes.Add(new ConfigurationChange(path, ConfigurationChangeKind.Remove, false));
        }

        internal static JsonObject ExportScopes(IReadOnlyDictionary<string, Scope> scopes, ISet<string> missingInputs)
        {
            var exported = new JsonObject();
            foreach (var (name, scope) in scopes.OrderBy(entry => entry.Key, StringComparer.Ordinal))
            {
                var reservations = new JsonObject();
                var reservedAddresses = new HashSet<IPAddress>();
                bool representable = true;
                foreach (Lease reservation in scope.ReservedLeases.OrderBy(lease => BitConverter.ToString(lease.HardwareAddress), StringComparer.Ordinal))
                {
                    string mac = BitConverter.ToString(reservation.HardwareAddress);
                    if (reservation.HardwareAddress.Length != 6 || reservations.ContainsKey(mac) ||
                        !reservedAddresses.Add(reservation.Address) || !Scope.IsAddressInRange(reservation.Address, scope.StartingAddress, scope.EndingAddress) ||
                        !reservation.ClientIdentifier.Equals(new ClientIdentifierOption((byte)DhcpMessageHardwareAddressType.Ethernet, reservation.HardwareAddress)))
                    {
                        representable = false;
                        break;
                    }
                    reservations.Add(mac, new JsonObject
                    {
                        ["address"] = reservation.Address.ToString(),
                        ["hostName"] = reservation.HostName,
                        ["comments"] = reservation.Comments
                    });
                }
                if (!representable)
                {
                    missingInputs.Add(ConfigurationPlan.AppendPath(ScopesPath, name));
                    continue;
                }

                JsonObject settings = WriteScopeOptions(scope);
                settings["enabled"] = scope.Enabled;
                settings["startingAddress"] = scope.StartingAddress.ToString();
                settings["endingAddress"] = scope.EndingAddress.ToString();
                settings["subnetMask"] = scope.SubnetMask.ToString();
                settings["exclusions"] = WriteExclusions(scope.Exclusions);
                settings["reservations"] = reservations;
                exported.Add(name, settings);
            }
            return exported;
        }

        private static JsonObject WriteScopeOptions(Scope scope)
        {
            var vendorInfo = new JsonObject();
            if (scope.VendorInfo is not null)
            {
                foreach (var (identifier, option) in scope.VendorInfo.OrderBy(entry => entry.Key, StringComparer.Ordinal))
                    vendorInfo.Add(identifier, BitConverter.ToString(option.Information).Replace('-', ':'));
            }

            return JsonSerializer.SerializeToNode(new
            {
                leaseTime = new { days = scope.LeaseTimeDays, hours = scope.LeaseTimeHours, minutes = scope.LeaseTimeMinutes },
                offerDelayMs = scope.OfferDelayTime,
                pingCheck = new { enabled = scope.PingCheckEnabled, timeoutMs = scope.PingCheckTimeout, retries = scope.PingCheckRetries },
                domainName = string.IsNullOrEmpty(scope.DomainName) ? null : NormalizeStoredName(scope.DomainName),
                domainSearchList = scope.DomainSearchList?.Select(NormalizeStoredName) ?? [],
                dnsUpdates = new { enabled = scope.DnsUpdates, overwriteDynamicRecords = scope.DnsOverwriteForDynamicLease, ttl = scope.DnsTtl },
                boot = new { serverAddress = scope.ServerAddress?.ToString(), serverHostName = scope.ServerHostName, fileName = scope.BootFileName },
                routerAddress = scope.RouterAddress?.ToString(),
                dns = new { useThisServer = scope.UseThisDnsServer, servers = WriteAddresses(scope.UseThisDnsServer ? null : scope.DnsServers) },
                winsServers = WriteAddresses(scope.WinsServers),
                ntp = new { servers = WriteAddresses(scope.NtpServers), serverDomainNames = scope.NtpServerDomainNames?.Select(NormalizeStoredName) ?? [] },
                staticRoutes = scope.StaticRoutes?.Select(route => new
                {
                    destination = route.Destination.ToString(),
                    subnetMask = route.SubnetMask.ToString(),
                    router = route.Router.ToString()
                }) ?? [],
                vendorInfo,
                capwapAcIpAddresses = WriteAddresses(scope.CAPWAPAcIpAddresses),
                tftpServerAddresses = WriteAddresses(scope.TftpServerAddresses),
                genericOptions = scope.GenericOptions?.Select(option => new { code = (byte)option.Code, value = Convert.ToHexString(option.RawValue) }) ?? [],
                allowOnlyReservedLeases = scope.AllowOnlyReservedLeases,
                blockLocallyAdministeredMacAddresses = scope.BlockLocallyAdministeredMacAddresses,
                ignoreClientIdentifierOption = scope.IgnoreClientIdentifierOption
            }).AsObject();

            static string NormalizeStoredName(string name) => name.TrimEnd('.').ToLowerInvariant();

            static IEnumerable<string> WriteAddresses(IEnumerable<IPAddress> addresses) =>
                addresses?.Select(address => address.ToString()) ?? [];
        }

        private static JsonObject ReadDeclaredOptions(JsonElement scope, string path)
        {
            var options = new JsonObject();
            foreach (JsonProperty field in scope.EnumerateObject())
            {
                if (!_defaultOptions.ContainsKey(field.Name))
                    continue;
                string fieldPath = ConfigurationPlan.AppendPath(path, field.Name);
                if (field.Name == "vendorInfo")
                {
                    options.Add(field.Name, ReadVendorInformation(field.Value, fieldPath));
                    continue;
                }

                JsonNode defaults = _defaultOptions[field.Name];
                if (defaults is JsonObject group)
                {
                    var normalized = new JsonObject();
                    foreach (JsonProperty option in field.Value.EnumerateObject())
                        normalized.Add(option.Name, NormalizeOption(option.Value, group[option.Name], field.Name + "/" + option.Name,
                            ConfigurationPlan.AppendPath(fieldPath, option.Name)));
                    options.Add(field.Name, normalized);
                }
                else
                {
                    options.Add(field.Name, NormalizeOption(field.Value, defaults, field.Name, fieldPath));
                }
            }
            return options;
        }

        private static JsonNode NormalizeOption(JsonElement value, JsonNode defaultValue, string name, string path)
        {
            if (value.ValueKind == JsonValueKind.Null)
                return defaultValue?.DeepClone();

            switch (name)
            {
                case "domainName":
                    return JsonValue.Create(ConfigurationManifest.CanonicalDnsName(value.GetString(), path, allowRoot: false));
                case "domainSearchList":
                case "ntp/serverDomainNames":
                    return JsonSerializer.SerializeToNode(value.EnumerateArray().Select((item, index) =>
                        ConfigurationManifest.CanonicalDnsName(item.GetString(), $"{path}/{index}", allowRoot: false)));
                case "boot/serverAddress":
                case "routerAddress":
                    return JsonValue.Create(IPAddress.Parse(value.GetString()).ToString());
                case "dns/servers":
                case "winsServers":
                case "ntp/servers":
                case "capwapAcIpAddresses":
                case "tftpServerAddresses":
                    return JsonSerializer.SerializeToNode(value.EnumerateArray().Select(item => IPAddress.Parse(item.GetString()).ToString()));
                case "boot/serverHostName":
                case "boot/fileName":
                    string text = value.GetString();
                    if (text.Length > (name == "boot/fileName" ? 127 : 63) || Encoding.UTF8.GetByteCount(text) > byte.MaxValue)
                        throw new InvalidDataException($"{path}: The value exceeds the DHCP field size.");
                    break;
                case "genericOptions":
                    var generic = new JsonArray();
                    foreach (JsonElement option in value.EnumerateArray())
                    {
                        byte code = decimal.ToByte(option.GetProperty("code").GetDecimal());
                        string payload = option.GetProperty("value").GetString();
                        if (payload.Length > short.MaxValue * 2)
                            throw new InvalidDataException($"{path}/{generic.Count}/value: The encoded DHCP option exceeds 32767 bytes.");
                        generic.Add(new JsonObject { ["code"] = code, ["value"] = payload.ToUpperInvariant() });
                    }
                    return generic;
                case "staticRoutes":
                    var routes = new JsonArray();
                    foreach (JsonElement route in value.EnumerateArray())
                    {
                        IPAddress mask = ReadAddress(route, "subnetMask");
                        ValidateNetwork($"{path}/{routes.Count}", null, null, mask);
                        routes.Add(new JsonObject
                        {
                            ["destination"] = ReadAddress(route, "destination").ToString(),
                            ["subnetMask"] = mask.ToString(),
                            ["router"] = ReadAddress(route, "router").ToString()
                        });
                    }
                    return routes;
            }
            return JsonNode.Parse(value.GetRawText());
        }

        private static JsonObject ReadVendorInformation(JsonElement value, string path)
        {
            if (value.ValueKind == JsonValueKind.Null)
                return null;

            var result = new JsonObject();
            foreach (JsonProperty entry in value.EnumerateObject())
            {
                string entryPath = ConfigurationPlan.AppendPath(path, entry.Name);
                if (Encoding.UTF8.GetByteCount(entry.Name) > byte.MaxValue)
                    throw new InvalidDataException($"{entryPath}: The vendor identifier exceeds 255 UTF-8 bytes.");

                if (entry.Value.ValueKind == JsonValueKind.Null)
                {
                    result.Add(entry.Name, null);
                    continue;
                }
                try
                {
                    var option = new VendorSpecificInformationOption(entry.Value.GetString());
                    result.Add(entry.Name, BitConverter.ToString(option.Information).Replace('-', ':'));
                }
                catch (Exception ex) when (ex is ArgumentException or FormatException or OverflowException)
                {
                    throw new InvalidDataException($"{entryPath}: Invalid hexadecimal vendor information.");
                }
            }
            if (result.Count(entry => entry.Value is not null) > byte.MaxValue)
                throw new InvalidDataException($"{path}: At most 255 vendor identifiers are supported.");
            return result;
        }

        private static void CompareOptions(JsonElement scope, JsonElement current, string path, List<ConfigurationChange> changes)
        {
            JsonObject desired = ReadDeclaredOptions(scope, path);
            if (desired.Count == 0)
                return;

            JsonNode previous = JsonNode.Parse(current.GetProperty("options").GetRawText());
            foreach (var (name, candidate) in desired)
            {
                string optionPath = ConfigurationPlan.AppendPath(path, name);
                if (name == "vendorInfo")
                {
                    JsonObject existing = previous[name].AsObject();
                    if (candidate is null)
                    {
                        foreach (var (identifier, _) in existing)
                            changes.Add(new ConfigurationChange(ConfigurationPlan.AppendPath(optionPath, identifier), ConfigurationChangeKind.Remove, false));
                        continue;
                    }
                    JsonObject entries = candidate.AsObject();
                    int retained = existing.Count(entry => !entries.ContainsKey(entry.Key));
                    if (retained + entries.Count(entry => entry.Value is not null) > byte.MaxValue)
                        throw new InvalidDataException($"{optionPath}: At most 255 vendor identifiers are supported.");
                    foreach (var (identifier, value) in entries)
                    {
                        bool exists = existing.TryGetPropertyValue(identifier, out JsonNode oldValue);
                        if (!JsonNode.DeepEquals(oldValue, value))
                            changes.Add(new ConfigurationChange(ConfigurationPlan.AppendPath(optionPath, identifier),
                                !exists ? ConfigurationChangeKind.Add : value is null ? ConfigurationChangeKind.Remove : ConfigurationChangeKind.Update, false));
                    }
                    continue;
                }
                if (candidate is JsonObject group)
                {
                    foreach (var (field, value) in group)
                    {
                        if (name == "dns" && field == "servers" &&
                            (group["useThisServer"]?.GetValue<bool>() ?? previous[name]["useThisServer"].GetValue<bool>()))
                            continue;
                        AddUpdate(ConfigurationPlan.AppendPath(optionPath, field), previous[name][field], value);
                    }
                }
                else
                {
                    AddUpdate(optionPath, previous[name], candidate);
                }
            }

            void AddUpdate(string optionPath, JsonNode oldValue, JsonNode value)
            {
                if (!JsonNode.DeepEquals(oldValue, value))
                    changes.Add(new ConfigurationChange(optionPath, ConfigurationChangeKind.Update, false));
            }
        }

        private static JsonArray WriteExclusions(IReadOnlyCollection<Exclusion> exclusions)
        {
            var result = new JsonArray();
            if (exclusions is not null)
            {
                foreach (Exclusion entry in exclusions.OrderBy(item => item.StartingAddress.ConvertIpToNumber()).ThenBy(item => item.EndingAddress.ConvertIpToNumber()))
                    result.Add(new JsonObject { ["startingAddress"] = entry.StartingAddress.ToString(), ["endingAddress"] = entry.EndingAddress.ToString() });
            }
            return result;
        }

        private static (uint Start, uint End)[] ReadExclusions(JsonElement value, string path, IPAddress start, IPAddress end)
        {
            if (value.ValueKind == JsonValueKind.Null)
                return [];

            var ranges = new SortedSet<(uint Start, uint End)>();
            int index = 0;
            foreach (JsonElement exclusion in value.EnumerateArray())
            {
                string entryPath = $"{path}/{index++}";
                IPAddress first = ReadAddress(exclusion, "startingAddress");
                IPAddress last = ReadAddress(exclusion, "endingAddress");
                try
                {
                    _ = new Exclusion(first, last);
                }
                catch (ArgumentException)
                {
                    throw new InvalidDataException($"{entryPath}/endingAddress: Exclusion end must be at or after its start.");
                }
                CheckRange(entryPath + "/startingAddress", first, start, end);
                CheckRange(entryPath + "/endingAddress", last, start, end);
                ranges.Add((first.ConvertIpToNumber(), last.ConvertIpToNumber()));
            }
            return ranges.ToArray();
        }

        private static void CompareReservations(JsonElement scope, JsonElement current, string scopePath,
            IPAddress start, IPAddress end, bool rangeChanged, List<ConfigurationChange> changes)
        {
            string path = scopePath + "/reservations";
            bool exists = current.ValueKind == JsonValueKind.Object;
            var reservations = new Dictionary<string, Reservation>(StringComparer.Ordinal);
            var activeLeases = new List<(string HardwareAddress, IPAddress Address)>();
            if (exists)
            {
                foreach (JsonProperty entry in current.GetProperty("reservations").EnumerateObject())
                {
                    JsonElement value = entry.Value;
                    reservations.Add(entry.Name, new Reservation(ReadAddress(value, "address"),
                        value.GetProperty("hostName").GetString(), value.GetProperty("comments").GetString()));
                }
                foreach (JsonElement lease in current.GetProperty("activeLeases").EnumerateArray())
                    activeLeases.Add((lease.GetProperty("hardwareAddress").GetString(), ReadAddress(lease, "address")));
            }

            var changedAddresses = new Dictionary<string, string>(StringComparer.Ordinal);
            if (scope.TryGetProperty("reservations", out JsonElement desired))
            {
                if (desired.ValueKind == JsonValueKind.Null)
                {
                    foreach ((string key, Reservation reservation) in reservations)
                    {
                        string entryPath = ConfigurationPlan.AppendPath(path, key);
                        CheckRemoval(key, reservation, entryPath);
                        changes.Add(new ConfigurationChange(entryPath, ConfigurationChangeKind.Remove, false));
                    }
                    reservations.Clear();
                }
                else
                {
                    foreach (JsonProperty entry in desired.EnumerateObject())
                    {
                        string entryPath = ConfigurationPlan.AppendPath(path, entry.Name);
                        string key = ReadHardwareAddress(entry.Name, entryPath);
                        reservations.TryGetValue(key, out Reservation previous);
                        if (entry.Value.ValueKind == JsonValueKind.Null)
                        {
                            if (reservations.Remove(key))
                            {
                                CheckRemoval(key, previous, entryPath);
                                changes.Add(new ConfigurationChange(entryPath, ConfigurationChangeKind.Remove, false));
                            }
                            continue;
                        }

                        JsonElement value = entry.Value;
                        IPAddress address = value.TryGetProperty("address", out _) ? ReadAddress(value, "address") : previous?.Address;
                        if (address is null)
                            throw new InvalidDataException($"{entryPath}/address: A reservation requires an IPv4 address.");
                        string host = value.TryGetProperty("hostName", out JsonElement hostName) ? hostName.GetString() : previous?.HostName;
                        string comments = value.TryGetProperty("comments", out JsonElement comment) ? comment.GetString() : previous?.Comments;
                        var candidate = new Reservation(address, host, comments);
                        if (candidate == previous)
                            continue;

                        if (previous is null || !previous.Address.Equals(address))
                        {
                            if (previous is not null)
                                CheckRemoval(key, previous, entryPath);
                            CheckRange(entryPath + "/address", address, start, end);
                            if (activeLeases.Any(lease => lease.Address.Equals(address) && lease.HardwareAddress != key))
                                throw new InvalidDataException($"{entryPath}/address: The address belongs to an active lease for another client.");
                            if (activeLeases.Any(lease => lease.HardwareAddress == key && !lease.Address.Equals(address)))
                                throw new InvalidDataException($"{entryPath}/address: This client has an active lease at a different address.");
                            changedAddresses.Add(key, entryPath);
                        }
                        reservations[key] = candidate;
                        if (exists)
                            changes.Add(new ConfigurationChange(entryPath, previous is null ? ConfigurationChangeKind.Add : ConfigurationChangeKind.Update, false));
                    }
                }
            }

            if (rangeChanged)
            {
                foreach ((string key, Reservation reservation) in reservations)
                    CheckRange(ConfigurationPlan.AppendPath(path, key) + "/address", reservation.Address, start, end);
            }

            foreach ((string key, string entryPath) in changedAddresses)
            {
                if (reservations.Any(other => other.Key != key && other.Value.Address.Equals(reservations[key].Address)))
                    throw new InvalidDataException($"{entryPath}/address: The address is reserved for another client.");
            }

            void CheckRemoval(string key, Reservation previous, string entryPath)
            {
                if (activeLeases.Any(lease => lease.HardwareAddress == key && lease.Address.Equals(previous.Address)))
                    throw new InvalidDataException($"{entryPath}: This reservation has an active lease.");
            }
        }

        private static string ReadHardwareAddress(string key, string path)
        {
            byte[] hardwareAddress;
            try
            {
                hardwareAddress = Lease.ParseHardwareAddress(key);
            }
            catch (Exception ex) when (ex is FormatException or OverflowException)
            {
                throw new InvalidDataException($"{path}: Invalid Ethernet hardware address.");
            }

            if (hardwareAddress.Length != 6)
                throw new InvalidDataException($"{path}: An Ethernet hardware address must have six bytes.");
            return BitConverter.ToString(hardwareAddress);
        }

        private static IPAddress ReadAddress(JsonElement value, string field)
        {
            return value.TryGetProperty(field, out JsonElement address) && address.ValueKind == JsonValueKind.String
                ? IPAddress.Parse(address.GetString()) : null;
        }

        private static void ValidateNetwork(string path, IPAddress start, IPAddress end, IPAddress mask)
        {
            if (mask is not null)
            {
                uint hostBits = ~mask.ConvertIpToNumber();
                if ((hostBits & (hostBits + 1)) != 0)
                    throw new InvalidDataException($"{path}/subnetMask: Expected a contiguous IPv4 subnet mask.");
            }

            if (start is null || end is null)
                return;
            if (start.ConvertIpToNumber() >= end.ConvertIpToNumber())
                throw new InvalidDataException($"{path}/endingAddress: Scope end must be greater than its start.");
            if (mask is null)
                return;

            try
            {
                (_, uint broadcast) = Scope.ValidateNetwork(start, end, mask);
                if (end.ConvertIpToNumber() >= broadcast)
                    throw new InvalidDataException($"{path}/endingAddress: Scope end must be inside the starting address subnet.");
            }
            catch (ArgumentException ex)
            {
                throw new InvalidDataException($"{path}/{ex.ParamName}: Scope addresses must be usable host addresses.");
            }
        }

        private static void CheckRange(string path, IPAddress address, IPAddress start, IPAddress end)
        {
            if ((start is not null && address.ConvertIpToNumber() < start.ConvertIpToNumber()) ||
                (end is not null && address.ConvertIpToNumber() > end.ConvertIpToNumber()))
                throw new InvalidDataException($"{path}: An address is outside the DHCP scope range.");
        }
    }
}
