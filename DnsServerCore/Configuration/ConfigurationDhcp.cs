using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text.Json;
using DnsServerCore.Dhcp;
using TechnitiumLibrary.Net;

namespace DnsServerCore.Configuration
{
    internal static class ConfigurationDhcp
    {
        private const string ScopesPath = "/dhcp/scopes";

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

                IPAddress start = ReadAddress(scope, "startingAddress");
                IPAddress end = ReadAddress(scope, "endingAddress");
                IPAddress mask = ReadAddress(scope, "subnetMask");
                ValidateNetwork(path, start, end, mask);

                if (scope.TryGetProperty("exclusions", out JsonElement exclusions) && exclusions.ValueKind == JsonValueKind.Array)
                {
                    int index = 0;
                    foreach (JsonElement exclusion in exclusions.EnumerateArray())
                    {
                        string entryPath = $"{path}/exclusions/{index++}";
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
                    }
                }

                if (scope.TryGetProperty("reservations", out JsonElement reservations) && reservations.ValueKind == JsonValueKind.Object)
                {
                    var identifiers = new HashSet<string>(StringComparer.Ordinal);
                    var addresses = new HashSet<IPAddress>();
                    foreach (JsonProperty reservation in reservations.EnumerateObject())
                    {
                        string entryPath = ConfigurationPlan.AppendPath(path + "/reservations", reservation.Name);
                        byte[] hardwareAddress;
                        try
                        {
                            hardwareAddress = Lease.ParseHardwareAddress(reservation.Name);
                        }
                        catch (Exception ex) when (ex is FormatException or OverflowException)
                        {
                            throw new InvalidDataException($"{entryPath}: Invalid Ethernet hardware address.");
                        }

                        if (hardwareAddress.Length != 6)
                            throw new InvalidDataException($"{entryPath}: An Ethernet hardware address must have six bytes.");
                        if (!identifiers.Add(Convert.ToHexString(hardwareAddress)))
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

                if (declarations.ValueKind != JsonValueKind.Object || !declarations.TryGetProperty(name, out _))
                {
                    writer.WriteEndObject();
                    continue;
                }

                var addresses = new SortedSet<uint>();
                bool hasActiveLeases = false;
                foreach (Lease lease in scope.Leases.Values)
                {
                    if (lease.LeaseExpires > now)
                    {
                        hasActiveLeases = true;
                        addresses.Add(lease.Address.ConvertIpToNumber());
                    }
                }
                writer.WriteBoolean("hasActiveLeases", hasActiveLeases);
                foreach (Lease reservation in scope.ReservedLeases)
                    addresses.Add(reservation.Address.ConvertIpToNumber());
                if (scope.Exclusions is not null)
                {
                    foreach (Exclusion exclusion in scope.Exclusions)
                    {
                        addresses.Add(exclusion.StartingAddress.ConvertIpToNumber());
                        addresses.Add(exclusion.EndingAddress.ConvertIpToNumber());
                    }
                }
                writer.WriteStartArray("protectedAddresses");
                foreach (uint address in addresses)
                    writer.WriteNumberValue(address);
                writer.WriteEndArray();
                writer.WriteEndObject();
            }
            writer.WriteEndObject();
        }

        internal static void Compare(JsonElement dhcp, JsonElement snapshot, List<ConfigurationChange> changes)
        {
            if (!dhcp.TryGetProperty("scopes", out JsonElement scopes))
                return;
            if (scopes.ValueKind == JsonValueKind.Null)
                throw new InvalidDataException($"{ScopesPath}: Preview of resetting all scopes is not implemented.");

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
                    {
                        if (snapshot.GetProperty(entry.Name).GetProperty("hasActiveLeases").GetBoolean())
                            throw new InvalidDataException($"{path}: A scope with active leases cannot be removed.");
                        changes.Add(new ConfigurationChange(path, ConfigurationChangeKind.Remove, false));
                    }
                    continue;
                }

                JsonElement scope = entry.Value;
                foreach (JsonProperty field in scope.EnumerateObject())
                {
                    if (field.Name is not ("startingAddress" or "endingAddress" or "subnetMask" or "enabled"))
                        throw new InvalidDataException($"{ConfigurationPlan.AppendPath(path, field.Name)}: Planning for this scope setting is not implemented.");
                }

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
                if (previous is null || !start.Equals(previous.Start) || !end.Equals(previous.End) || !mask.Equals(previous.Mask))
                {
                    ValidateNetwork(path, start, end, mask);
                    changedRanges.Add(entry.Name);

                    if (previous is not null)
                    {
                        foreach (JsonElement address in snapshot.GetProperty(entry.Name).GetProperty("protectedAddresses").EnumerateArray())
                        {
                            if (!Scope.IsAddressInRange(IPAddressExtensions.ConvertNumberToIp(address.GetUInt32()), start, end))
                                throw new InvalidDataException($"{path}: The new range excludes an existing lease, reservation, or exclusion.");
                        }
                    }
                }

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
