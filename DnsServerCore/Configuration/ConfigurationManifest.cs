using DnsServerCore.Dns;
using DnsServerCore.Dns.ZoneManagers;
using Json.Schema;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Configuration
{
    public sealed class ConfigurationManifest
    {
        public const string DefaultFileName = "technitium.json";
        public const int CurrentSchemaVersion = 1;

        private static readonly UTF8Encoding _secretFileEncoding = new(encoderShouldEmitUTF8Identifier: true, throwOnInvalidBytes: true);
        private static readonly Lazy<JsonSchema> _schema = new(LoadSchema);

        private ConfigurationManifest(string filePath, JsonElement settings)
        {
            FilePath = filePath;
            Settings = settings;
        }

        public string FilePath { get; }

        // Keep explicit nulls so callers can distinguish a reset from an omitted setting.
        public JsonElement Settings { get; }

        public static ConfigurationManifest Load(string filePath)
        {
            string fullPath = Path.GetFullPath(filePath);
            using FileStream stream = File.OpenRead(fullPath);
            using JsonDocument document = ParseDocument(stream);
            return FromDocument(document, fullPath);
        }

        internal static ConfigurationManifest LoadForStartup(string configFolder)
        {
            ConfigurationManifest manifest;
            try
            {
                manifest = Load(Path.Combine(configFolder, DefaultFileName));
            }
            catch (FileNotFoundException)
            {
                return null;
            }

            ConfigurationPlan.CheckApplySupport(manifest);
            manifest.ValidateReferences();
            return manifest;
        }

        internal static async Task<ConfigurationManifest> ReadAsync(Stream stream, CancellationToken cancellationToken)
        {
            try
            {
                using JsonDocument document = await JsonDocument.ParseAsync(stream, cancellationToken: cancellationToken);
                return FromDocument(document, null);
            }
            catch (JsonException ex)
            {
                throw InvalidJson(ex);
            }
        }

        private static ConfigurationManifest FromDocument(JsonDocument document, string filePath)
        {
            JsonElement root = document.RootElement;

            if (root.ValueKind != JsonValueKind.Object)
                throw new InvalidDataException("The manifest must be a JSON object.");

            CheckDuplicateProperties(root, "");
            if (!root.TryGetProperty("schemaVersion", out JsonElement version))
                throw new InvalidDataException("/schemaVersion: A schema version is required.");

            if ((version.ValueKind != JsonValueKind.Number) || !version.TryGetDecimal(out decimal value) || (value != CurrentSchemaVersion))
                throw new InvalidDataException("/schemaVersion: Unsupported schema version.");

            ValidateSchema(root);
            CheckDnsNameKeys(root, "zones", "", allowRoot: true);
            ValidateZoneRecords(root);
            ConfigurationZonePolicies.Validate(root);
            ConfigurationDhcp.Validate(root);
            if (root.TryGetProperty("dns", out JsonElement dns))
            {
                CheckDnsNameKeys(dns, "tsigKeys", "/dns", allowRoot: false);
                if (dns.TryGetProperty("serverDomain", out JsonElement serverDomain))
                    ReadServerDomain(serverDomain);
                if (dns.TryGetProperty("localEndpoints", out JsonElement endpoints))
                    ReadDnsLocalEndPoints(endpoints);
                if (dns.TryGetProperty("sourceNetworks", out JsonElement sourceNetworks))
                {
                    if (sourceNetworks.TryGetProperty("ipv4", out JsonElement ipv4))
                        ReadNetworks(ipv4, "/dns/sourceNetworks/ipv4", AddressFamily.InterNetwork);
                    if (sourceNetworks.TryGetProperty("ipv6", out JsonElement ipv6))
                        ReadNetworks(ipv6, "/dns/sourceNetworks/ipv6", AddressFamily.InterNetworkV6);
                }
                if (dns.TryGetProperty("clientSubnet", out JsonElement clientSubnet))
                {
                    if (clientSubnet.TryGetProperty("ipv4Override", out JsonElement ipv4Override))
                        ReadNetwork(ipv4Override.GetString(), "/dns/clientSubnet/ipv4Override", AddressFamily.InterNetwork);
                    if (clientSubnet.TryGetProperty("ipv6Override", out JsonElement ipv6Override))
                        ReadNetwork(ipv6Override.GetString(), "/dns/clientSubnet/ipv6Override", AddressFamily.InterNetworkV6);
                }
                if (dns.TryGetProperty("recursion", out JsonElement recursion) && recursion.TryGetProperty("networkAcl", out JsonElement recursionAcl))
                    ReadNetworkAcl(recursionAcl, "/dns/recursion/networkAcl");
                if (dns.TryGetProperty("authoritative", out JsonElement authoritative))
                {
                    if (authoritative.TryGetProperty("defaultResponsiblePerson", out JsonElement responsiblePerson))
                        ReadDefaultResponsiblePerson(responsiblePerson);
                    if (authoritative.TryGetProperty("zoneTransferAllowedNetworks", out JsonElement transfer))
                        ReadNetworks(transfer, "/dns/authoritative/zoneTransferAllowedNetworks");
                    if (authoritative.TryGetProperty("notifyAllowedNetworks", out JsonElement notify))
                        ReadNetworks(notify, "/dns/authoritative/notifyAllowedNetworks");
                }
            }

            if (root.TryGetProperty("web", out JsonElement web))
            {
                if (web.TryGetProperty("realIpHeader", out JsonElement realIp))
                    ReadWebHeader(realIp, realIp: true);
                if (web.TryGetProperty("frameAncestors", out JsonElement frameAncestors))
                    ReadWebHeader(frameAncestors, realIp: false);
                if (web.TryGetProperty("reverseProxyAcl", out JsonElement reverseProxyAcl))
                    ReadWebReverseProxyAcl(reverseProxyAcl);
                if (web.TryGetProperty("httpUnixSocket", out JsonElement httpSocket))
                    ReadWebUnixSocket(httpSocket, "/web/httpUnixSocket");
                if (web.TryGetProperty("tlsUnixSocket", out JsonElement tlsSocket))
                    ReadWebUnixSocket(tlsSocket, "/web/tlsUnixSocket");
            }

            if (root.TryGetProperty("blocklists", out JsonElement blocklists) && blocklists.TryGetProperty("sources", out JsonElement sources))
                ReadBlockListSources(sources);

            return new ConfigurationManifest(filePath, root.Clone());
        }

        internal string GetServerDomain()
        {
            return Settings.TryGetProperty("dns", out JsonElement dns) && dns.TryGetProperty("serverDomain", out JsonElement domain)
                ? ReadServerDomain(domain) : null;
        }

        public string GetServerDomainEnvironmentWarning()
        {
            string declared = GetServerDomain();
            if (declared is null)
                return null;

            const string variable = DnsServer.ServerDomainEnvironmentVariable;
            string environment = Environment.GetEnvironmentVariable(variable);
            if (string.IsNullOrEmpty(environment))
                return null;

            try
            {
                if (string.Equals(declared, DnsServer.NormalizeServerDomain(environment), StringComparison.Ordinal))
                    return null;
            }
            catch (Exception ex) when (ex is ArgumentException or FormatException or DnsServerException or DnsClientException)
            {
                // An invalid legacy value is also overridden by the manifest.
            }

            return $"/dns/serverDomain: The manifest overrides {variable}.";
        }

        internal static string ReadServerDomain(JsonElement value)
        {
            if (value.ValueKind == JsonValueKind.Null)
                return DnsServer.DefaultServerDomain;

            try
            {
                return DnsServer.NormalizeServerDomain(value.GetString());
            }
            catch (Exception ex) when (ex is ArgumentException or FormatException or DnsServerException or DnsClientException)
            {
                throw new InvalidDataException("/dns/serverDomain: Invalid DNS server domain name.");
            }
        }

        internal static DnsWebService.WebUnixSocket ReadWebUnixSocket(JsonElement value, string path)
        {
            if (value.ValueKind == JsonValueKind.Null)
                return new DnsWebService.WebUnixSocket(false, "");

            bool? enabled = value.TryGetProperty("enabled", out JsonElement enable) ? enable.ValueKind != JsonValueKind.Null && enable.GetBoolean() : null;
            string socketPath = value.TryGetProperty("path", out JsonElement socket) ? ReadWebUnixSocketPath(socket, path + "/path") : null;
            return new DnsWebService.WebUnixSocket(enabled, socketPath);
        }

        internal static string ReadWebUnixSocketPath(JsonElement value, string path)
        {
            string socket = value.GetString();
            if (string.IsNullOrWhiteSpace(socket))
                return "";

            try
            {
                if (!Path.IsPathFullyQualified(socket) || socket.Contains('\0'))
                    throw new ArgumentException();
                _ = new UnixDomainSocketEndPoint(socket);
                return socket;
            }
            catch (Exception ex) when (ex is ArgumentException or PlatformNotSupportedException)
            {
                throw new InvalidDataException($"{path}: Invalid absolute Unix socket path.");
            }
        }

        internal static NetworkAccessControl[] ReadWebReverseProxyAcl(JsonElement value)
        {
            if (value.ValueKind == JsonValueKind.Null)
                return DnsWebService.CreateDefaultReverseProxyAcl();

            return ReadNetworkAcl(value, "/web/reverseProxyAcl");
        }

        internal static NetworkAccessControl[] ReadNetworkAcl(JsonElement value, string path)
        {
            if (value.ValueKind == JsonValueKind.Null)
                return [];

            var rules = new NetworkAccessControl[value.GetArrayLength()];
            for (int i = 0; i < rules.Length; i++)
            {
                string entry = value[i].GetString();
                int slash = entry.IndexOf('/');
                if (!NetworkAccessControl.TryParse(entry, out rules[i]) ||
                    (slash >= 0 && (!byte.TryParse(entry.AsSpan(slash + 1), out byte prefix) || prefix != rules[i].NetworkAddress.PrefixLength)))
                    throw new InvalidDataException($"{DisplayPath(path)}/{i}: Invalid network ACL rule.");
            }
            return rules;
        }

        internal static string ReadWebHeader(JsonElement value, bool realIp)
        {
            try
            {
                return DnsWebService.NormalizeWebHeader(value.GetString(), realIp);
            }
            catch (ArgumentException)
            {
                string name = realIp ? "realIpHeader" : "frameAncestors";
                throw new InvalidDataException($"/web/{name}: Invalid web header name or value.");
            }
        }

        internal static IReadOnlyList<string> ReadBlockListSources(JsonElement value)
        {
            if (value.ValueKind == JsonValueKind.Null)
                return [];

            try
            {
                return BlockListZoneManager.NormalizeBlockListUrls(value.EnumerateArray().Select(item => item.GetString()).ToArray());
            }
            catch (ArgumentException)
            {
                throw new InvalidDataException("/blocklists/sources: Invalid source URL or comment.");
            }
        }

        internal static NetworkAddress[] ReadNetworks(JsonElement value, string path, AddressFamily? family = null)
        {
            if (value.ValueKind == JsonValueKind.Null)
                return [];

            var networks = new NetworkAddress[value.GetArrayLength()];
            for (int i = 0; i < networks.Length; i++)
                networks[i] = ReadNetwork(value[i].GetString(), $"{path}/{i}", family);
            return networks.Distinct().ToArray();
        }

        internal static NetworkAddress ReadNetwork(string entry, string path, AddressFamily? family = null)
        {
            if (entry is null)
                return null;

            int slash = entry.IndexOf('/');
            if (!NetworkAddress.TryParse(entry, out NetworkAddress network) ||
                (slash >= 0 && (!byte.TryParse(entry.AsSpan(slash + 1), out byte prefix) || prefix != network.PrefixLength)))
                throw new InvalidDataException($"{path}: Invalid network address or prefix.");
            if (family.HasValue && network.AddressFamily != family.Value)
                throw new InvalidDataException($"{path}: Network address uses the wrong IP family.");
            return network;
        }

        internal static string ReadDefaultResponsiblePerson(JsonElement value)
        {
            try
            {
                return DnsServer.NormalizeDefaultResponsiblePerson(value.GetString() ?? "");
            }
            catch (Exception ex) when (ex is ArgumentException or FormatException)
            {
                throw new InvalidDataException("/dns/authoritative/defaultResponsiblePerson: Invalid email address.");
            }
        }

        internal IReadOnlyList<IPEndPoint> GetDnsLocalEndPoints()
        {
            return Settings.TryGetProperty("dns", out JsonElement dns) && dns.TryGetProperty("localEndpoints", out JsonElement endpoints)
                ? ReadDnsLocalEndPoints(endpoints)
                : null;
        }

        internal static IReadOnlyList<IPEndPoint> ReadDnsLocalEndPoints(JsonElement value)
        {
            if (value.ValueKind == JsonValueKind.Null || value.GetArrayLength() == 0)
                return DnsServer.NormalizeLocalEndPoints(null);

            var endpoints = new IPEndPoint[value.GetArrayLength()];
            var seen = new HashSet<string>(StringComparer.Ordinal);
            for (int index = 0; index < endpoints.Length; index++)
            {
                string address = value[index].GetString();
                int colon = address.LastIndexOf(':');
                bool hasPort = (colon >= 0) && ((colon == address.IndexOf(':')) || (address[colon - 1] == ']'));
                if ((hasPort && !ushort.TryParse(address.AsSpan(colon + 1), out _)) ||
                    !InterfaceEndPoint.TryParse(address, out InterfaceEndPoint endpoint))
                    throw new InvalidDataException($"/dns/localEndpoints/{index}: Invalid DNS listener endpoint.");

                endpoints[index] = endpoint;
            }

            try
            {
                DnsServer.NormalizeLocalEndPoints(endpoints, useDefaultPort: true);
            }
            catch (ArgumentException)
            {
                throw new InvalidDataException("/dns/localEndpoints: Port 853 is reserved for DNS-over-TLS.");
            }

            for (int index = 0; index < endpoints.Length; index++)
            {
                if (!seen.Add(endpoints[index].ToString()))
                    throw new InvalidDataException($"/dns/localEndpoints/{index}: Duplicate DNS listener endpoint.");
            }

            return endpoints;
        }

        public void ValidateReferences()
        {
            ValidateReferences(Settings, "");
        }

        private void ValidateReferences(JsonElement element, string path)
        {
            if (element.ValueKind == JsonValueKind.Object)
            {
                if (IsReferencePath(path) && (element.TryGetProperty("environment", out _) || element.TryGetProperty("file", out _)))
                {
                    ResolveReference(element, path);
                    return;
                }

                foreach (JsonProperty property in element.EnumerateObject())
                    ValidateReferences(property.Value, AppendPath(path, property.Name));
            }
            else if (element.ValueKind == JsonValueKind.Array)
            {
                int index = 0;
                foreach (JsonElement item in element.EnumerateArray())
                    ValidateReferences(item, path + "/" + index++);
            }
        }

        internal string ResolveReference(JsonElement reference, string path)
        {
            string secret;
            if (reference.TryGetProperty("environment", out JsonElement variable))
            {
                try
                {
                    secret = Environment.GetEnvironmentVariable(variable.GetString());
                }
                catch (ArgumentException)
                {
                    throw new InvalidDataException($"{DisplayPath(path)}: Invalid environment reference.");
                }

                if (string.IsNullOrEmpty(secret))
                    throw new InvalidDataException($"{DisplayPath(path)}: Referenced environment value is missing or empty.");

                return secret;
            }

            if (FilePath is null)
                throw new InvalidDataException($"{DisplayPath(path)}: File references require a local manifest file.");

            string resolvedPath;
            try
            {
                resolvedPath = Path.GetFullPath(reference.GetProperty("file").GetString(), Path.GetDirectoryName(FilePath));
            }
            catch (ArgumentException)
            {
                throw new InvalidDataException($"{DisplayPath(path)}: Invalid file reference.");
            }

            try
            {
                using var file = new StreamReader(resolvedPath, _secretFileEncoding, detectEncodingFromByteOrderMarks: false);
                secret = file.ReadToEnd();
            }
            catch (DecoderFallbackException)
            {
                throw new InvalidDataException($"{DisplayPath(path)}: Referenced file is not valid text.");
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or NotSupportedException)
            {
                throw new InvalidDataException($"{DisplayPath(path)}: Referenced file is missing or inaccessible.");
            }

            if (secret.Length == 0)
                throw new InvalidDataException($"{DisplayPath(path)}: Referenced file is empty.");

            return secret;
        }

        private static bool IsReferencePath(string path)
        {
            return path.Split('/') switch
            {
                ["", "web", "certificate", "password"] => true,
                ["", "dns", "listeners", "certificate", "password"] => true,
                ["", "dns", "proxy", "password"] => true,
                ["", "dns", "tsigKeys", _, "secret"] => true,
                ["", "auth", "users", _, "password"] => true,
                ["", "auth", "users", _, "totp", "enrollment"] => true,
                ["", "auth", "staticSessions", _, "token"] => true,
                ["", "auth", "sso", "clientSecret"] => true,
                ["", "auth", "ldap", "bindPassword"] => true,
                ["", "cluster", "bootstrap", "password" or "totp"] => true,
                ["", "zones", _, "dnssec", "keys", _, "privateKey"] => true,
                ["", "zones", _, "records", _, "data", "forwarder", "proxy", "password"] => true,
                ["", "zones", _, "records", _, "data", "app", "configuration", ..] => true,
                ["", "apps", "packages", _, "source"] => true,
                ["", "apps", "packages", _, "configuration", ..] => true,
                _ => false
            };
        }

        private static void CheckDnsNameKeys(JsonElement parent, string propertyName, string path, bool allowRoot)
        {
            if (!parent.TryGetProperty(propertyName, out JsonElement entries) || (entries.ValueKind == JsonValueKind.Null))
                return;

            var names = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            foreach (JsonProperty entry in entries.EnumerateObject())
            {
                string entryPath = AppendPath(path + "/" + propertyName, entry.Name);
                string name = CanonicalDnsName(entry.Name, entryPath, allowRoot);

                if (!names.Add(name))
                    throw new InvalidDataException($"{DisplayPath(entryPath)}: Duplicate canonical DNS name.");
            }
        }

        internal static string CanonicalDnsName(string value, string path, bool allowRoot)
        {
            string name = value.TrimEnd('.');
            try
            {
                if (DnsClient.IsDomainNameUnicode(name))
                    name = DnsClient.ConvertDomainNameToAscii(name);
            }
            catch (ArgumentException)
            {
                throw new InvalidDataException($"{DisplayPath(path)}: Invalid DNS name.");
            }

            if ((!allowRoot && name.Length == 0) || !DnsClient.IsDomainNameValid(name))
                throw new InvalidDataException($"{DisplayPath(path)}: Invalid DNS name.");

            return name.ToLowerInvariant();
        }

        private static void ValidateZoneRecords(JsonElement root)
        {
            if (!root.TryGetProperty("zones", out JsonElement zones))
                return;

            foreach (JsonProperty zone in zones.EnumerateObject())
            {
                if (zone.Value.ValueKind != JsonValueKind.Object || !zone.Value.TryGetProperty("records", out JsonElement records) ||
                    records.ValueKind != JsonValueKind.Array)
                    continue;

                string zonePath = AppendPath("/zones", zone.Name);
                string zoneName = CanonicalDnsName(zone.Name, zonePath, allowRoot: true);
                int index = 0;
                foreach (JsonElement record in records.EnumerateArray())
                {
                    string recordPath = $"{zonePath}/records/{index++}";
                    (string owner, DnsResourceRecordType type) = ReadZoneRecordIdentity(zoneName, record, recordPath);
                    JsonElement data = record.GetProperty("data");
                    if (data.TryGetProperty("zoneFile", out JsonElement zoneFile))
                        ReadZoneFileRecordData(zoneName, owner, type, zoneFile.GetString(), recordPath + "/data/zoneFile");
                    if (data.TryGetProperty("rawHex", out JsonElement rawHex))
                        ReadRawZoneRecordData(zoneName, owner, type, rawHex.GetString(), recordPath + "/data/rawHex");
                    if (data.TryGetProperty("forwarder", out _) && type != DnsResourceRecordType.FWD)
                        throw new InvalidDataException($"{DisplayPath(recordPath + "/data/forwarder")}: Forwarder data requires an FWD record.");
                    if (data.TryGetProperty("app", out _) && type != DnsResourceRecordType.APP)
                        throw new InvalidDataException($"{DisplayPath(recordPath + "/data/app")}: App data requires an APP record.");
                    if (data.TryGetProperty("txtBase64", out JsonElement segments))
                    {
                        if (type != DnsResourceRecordType.TXT)
                            throw new InvalidDataException($"{DisplayPath(recordPath + "/data/txtBase64")}: Base64 TXT data requires a TXT record.");
                        int segmentIndex = 0;
                        byte[] decoded = new byte[255];
                        foreach (JsonElement segment in segments.EnumerateArray())
                        {
                            if (!Convert.TryFromBase64String(segment.GetString(), decoded, out _))
                                throw new InvalidDataException($"{DisplayPath(recordPath + $"/data/txtBase64/{segmentIndex}")}: Expected base64 text for a segment of at most 255 bytes.");
                            segmentIndex++;
                        }
                    }
                }
            }
        }

        internal static (string Owner, DnsResourceRecordType Type) ReadZoneRecordIdentity(string zoneName, JsonElement record, string path)
        {
            string owner = record.GetProperty("owner").GetString();
            owner = owner == "@" ? zoneName : CanonicalDnsName(owner, path + "/owner", allowRoot: true);
            if (!AuthZoneManager.DomainBelongsToZone(zoneName, owner))
                throw new InvalidDataException($"{DisplayPath(path + "/owner")}: Record owner must belong to its zone.");

            JsonElement value = record.GetProperty("type");
            if (value.ValueKind == JsonValueKind.Number)
                return (owner, (DnsResourceRecordType)decimal.ToUInt16(value.GetDecimal()));
            if (Enum.TryParse(value.GetString(), out DnsResourceRecordType type))
                return (owner, type);
            throw new InvalidDataException($"{DisplayPath(path + "/type")}: Unknown record type. Use a numeric type code for unrecognized types.");
        }

        internal static DnsResourceRecord ReadRawZoneRecordData(string zoneName, string owner, DnsResourceRecordType type, string hex, string path)
        {
            string genericData = FormattableString.Invariant($@"\# {hex.Length / 2} {hex}");
            return ReadZoneFileRecordData(zoneName, owner, type, genericData, path);
        }

        internal static DnsResourceRecord ReadZoneFileRecordData(string zoneName, string owner, DnsResourceRecordType type, string data, string path)
        {
            // The parser only reads this in-memory record. Relative names in its RDATA use the enclosing zone as their origin.
            string typeCode = ((ushort)type).ToString(CultureInfo.InvariantCulture);
            using var input = new StringReader($"{owner}. 0 IN TYPE{typeCode} {data}");
            List<DnsResourceRecord> records;
            try
            {
                records = ZoneFile.ReadZoneFileFromAsync(input, zoneName).GetAwaiter().GetResult();
            }
            catch (Exception ex) when (ex is FormatException or ArgumentException or OverflowException or IOException or NotSupportedException or InvalidOperationException or DnsClientException)
            {
                throw new InvalidDataException($"{DisplayPath(path)}: Invalid zone-file record data.");
            }

            if (records.Count != 1 || records[0].Type != type || records[0].Class != DnsClass.IN ||
                !records[0].Name.Equals(owner, StringComparison.OrdinalIgnoreCase))
                throw new InvalidDataException($"{DisplayPath(path)}: Expected data for exactly one record.");

            return records[0];
        }

        private static JsonDocument ParseDocument(Stream stream)
        {
            try
            {
                return JsonDocument.Parse(stream);
            }
            catch (JsonException ex)
            {
                throw InvalidJson(ex);
            }
        }

        private static InvalidDataException InvalidJson(JsonException ex)
        {
            // Parser messages can contain fragments of the supplied manifest.
            return new InvalidDataException($"Invalid JSON at line {ex.LineNumber.GetValueOrDefault() + 1}, byte {ex.BytePositionInLine.GetValueOrDefault() + 1}.");
        }

        private static JsonSchema LoadSchema()
        {
            using Stream stream = typeof(ConfigurationManifest).Assembly.GetManifestResourceStream("Technitium.Configuration.Schema.json")
                ?? throw new InvalidOperationException("The configuration schema resource is missing.");
            using var reader = new StreamReader(stream);
            return JsonSchema.FromText(reader.ReadToEnd());
        }

        private static void ValidateSchema(JsonElement root)
        {
            EvaluationResults result = _schema.Value.Evaluate(root, new EvaluationOptions
            {
                OutputFormat = OutputFormat.List,
                RequireFormatValidation = true
            });
            if (result.IsValid)
                return;

            // A failed branch of a nullable value often reports a second type error.
            // Prefer specific checks and discard enclosing errors when a child has one.
            var failures = result.Details.Where(detail => !detail.IsValid)
                .GroupBy(detail => detail.InstanceLocation.ToString(), StringComparer.Ordinal)
                .ToArray();

            var messages = new List<string>();
            foreach (var failure in failures.OrderBy(group => group.Key, StringComparer.Ordinal))
            {
                string path = failure.Key;
                var keywords = failure.SelectMany(detail => detail.Errors?.Keys.AsEnumerable() ?? Enumerable.Empty<string>())
                    .ToHashSet(StringComparer.Ordinal);

                string message;
                if (failure.Any(detail => detail.EvaluationPath.ToString().EndsWith("/additionalProperties", StringComparison.Ordinal)
                    && (detail.Errors?.Keys.All(string.IsNullOrEmpty) != false)))
                {
                    message = "Unknown setting.";
                }
                else if (failures.Any(other => other.Key.StartsWith(path + "/", StringComparison.Ordinal)))
                {
                    continue;
                }
                else if (keywords.Contains("format"))
                {
                    message = "Value has an invalid format.";
                }
                else if (keywords.Contains("maximum") || keywords.Contains("minimum"))
                {
                    message = "Value is outside the supported range.";
                }
                else
                {
                    message = "Value does not match the configuration schema.";
                }

                // Report only paths and fixed descriptions. Schema messages can contain input values.
                messages.Add($"{DisplayPath(path)}: {message}");
            }

            throw new InvalidDataException(messages.Count == 0
                ? "/: Manifest does not match the configuration schema."
                : string.Join(Environment.NewLine, messages.Take(20)));
        }

        private static void CheckDuplicateProperties(JsonElement element, string path)
        {
            if (element.ValueKind == JsonValueKind.Object)
            {
                var names = new HashSet<string>(StringComparer.Ordinal);
                foreach (JsonProperty property in element.EnumerateObject())
                {
                    string childPath = AppendPath(path, property.Name);
                    if (!names.Add(property.Name))
                        throw new InvalidDataException($"{DisplayPath(childPath)}: Duplicate setting.");
                    CheckDuplicateProperties(property.Value, childPath);
                }
            }
            else if (element.ValueKind == JsonValueKind.Array)
            {
                int index = 0;
                foreach (JsonElement item in element.EnumerateArray())
                    CheckDuplicateProperties(item, path + "/" + index++);
            }
        }

        private static string AppendPath(string path, string name)
        {
            return path + "/" + name.Replace("~", "~0", StringComparison.Ordinal).Replace("/", "~1", StringComparison.Ordinal);
        }

        private static string DisplayPath(string path)
        {
            return path.Length == 0 ? "/" : JsonEncodedText.Encode(path).ToString();
        }
    }
}
