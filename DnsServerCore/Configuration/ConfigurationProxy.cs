using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using TechnitiumLibrary.Net.Proxy;

namespace DnsServerCore.Configuration
{
    internal static class ConfigurationProxy
    {
        private const string Path = "/dns/proxy";
        private const string PasswordPath = Path + "/password";

        [Flags]
        internal enum Fields : ulong
        {
            Type = 1UL << 14,
            Address = 1UL << 15,
            Port = 1UL << 16,
            Username = 1UL << 17,
            Password = 1UL << 18,
            Bypass = 1UL << 19,
            All = Type | Address | Port | Username | Password | Bypass
        }

        private static readonly (Fields Field, string Name)[] _fields =
            [(Fields.Type, "type"), (Fields.Address, "address"), (Fields.Port, "port"),
             (Fields.Username, "username"), (Fields.Password, "password"), (Fields.Bypass, "bypass")];

        internal readonly record struct Candidate(Fields Managed, NetProxy Proxy);

        internal static bool TryGetDeclaration(ConfigurationManifest manifest, out JsonElement proxy)
        {
            proxy = default;
            return manifest is not null && manifest.Settings.TryGetProperty("dns", out JsonElement dns) &&
                dns.TryGetProperty("proxy", out proxy);
        }

        internal static string ResolvePassword(ConfigurationManifest manifest, JsonElement reference)
        {
            string password = reference.ValueKind == JsonValueKind.Null ? null : manifest.ResolveReference(reference, PasswordPath);
            if (password is not null && Encoding.UTF8.GetByteCount(password) > byte.MaxValue)
                throw new InvalidDataException($"{PasswordPath}: The resolved password exceeds 255 UTF-8 bytes.");
            return password;
        }

        internal static Candidate Prepare(ConfigurationManifest manifest, NetProxy current)
        {
            if (!TryGetDeclaration(manifest, out JsonElement desired))
                return default;

            Fields managed = 0;
            foreach (var (field, name) in _fields)
            {
                if (desired.TryGetProperty(name, out _))
                    managed |= field;
            }
            if (managed == 0)
                return default;

            NetProxyType type = desired.TryGetProperty("type", out JsonElement typeValue)
                ? Enum.Parse<NetProxyType>(typeValue.GetString() ?? nameof(NetProxyType.None))
                : current?.Type ?? NetProxyType.None;
            string address = ReadEffectiveString("address", current?.Address);
            string username = ReadEffectiveString("username", current?.Credential?.UserName);
            int? port = desired.TryGetProperty("port", out JsonElement portValue)
                ? portValue.ValueKind == JsonValueKind.Null ? null : decimal.ToInt32(portValue.GetDecimal())
                : current?.Port;
            string password = desired.TryGetProperty("password", out JsonElement reference)
                ? ResolvePassword(manifest, reference) : current?.Credential?.Password;
            string[] bypass = desired.TryGetProperty("bypass", out JsonElement rules) ? ReadBypassRules(rules) : null;
            NetProxy proxy = Build(desired, type, address, port, username, password, bypass, current?.BypassList);
            return new Candidate(managed, Differences(current, proxy) == 0 ? current : proxy);

            string ReadEffectiveString(string field, string fallback)
            {
                return desired.TryGetProperty(field, out JsonElement value) ? value.GetString() : fallback;
            }
        }

        internal static Fields Differences(NetProxy current, NetProxy candidate)
        {
            Fields fields = 0;
            if (current?.Type != candidate?.Type)
                fields |= Fields.Type;
            if (current?.Address != candidate?.Address)
                fields |= Fields.Address;
            if (current?.Port != candidate?.Port)
                fields |= Fields.Port;
            if ((current?.Credential?.UserName ?? "") != (candidate?.Credential?.UserName ?? ""))
                fields |= Fields.Username;
            if ((current?.Credential?.Password ?? "") != (candidate?.Credential?.Password ?? ""))
                fields |= Fields.Password;
            if (!(current?.BypassList ?? []).Select(item => item.Value)
                .SequenceEqual((candidate?.BypassList ?? []).Select(item => item.Value), StringComparer.Ordinal))
                fields |= Fields.Bypass;
            return fields;
        }

        internal static IEnumerable<string> Paths(Fields fields)
        {
            foreach (var (field, name) in _fields)
            {
                if ((fields & field) != 0)
                    yield return Path + "/" + name;
            }
        }

        internal static void WritePasswordSnapshot(Utf8JsonWriter writer, string password, NetProxy current, byte[] key)
        {
            writer.WriteStartObject("manifestProxyPassword");
            writer.WriteString("current", Fingerprint(current?.Credential?.Password));
            writer.WriteString("desired", Fingerprint(password));
            writer.WriteBoolean("currentSet", !string.IsNullOrEmpty(current?.Credential?.Password));
            writer.WriteBoolean("desiredSet", !string.IsNullOrEmpty(password));
            writer.WriteEndObject();

            string Fingerprint(string value)
            {
                return string.IsNullOrEmpty(value) ? null : Convert.ToHexString(HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(value)));
            }
        }

        internal static void Compare(JsonElement desired, JsonElement snapshot, List<ConfigurationChange> changes)
        {
            if (!desired.EnumerateObject().Any())
                return;

            snapshot.TryGetProperty("proxy", out JsonElement current);
            string currentType = ReadString(current, "type") ?? nameof(NetProxyType.None);
            string type = desired.TryGetProperty("type", out JsonElement typeValue)
                ? typeValue.GetString() ?? nameof(NetProxyType.None) : currentType;
            string address = EffectiveString("address");
            string username = EffectiveString("username");
            int? port = desired.TryGetProperty("port", out JsonElement portValue)
                ? portValue.ValueKind == JsonValueKind.Null ? null : decimal.ToInt32(portValue.GetDecimal())
                : current.TryGetPort();
            bool hasPassword = snapshot.TryGetProperty("manifestProxyPassword", out JsonElement password);
            bool declaresPassword = desired.TryGetProperty("password", out _);
            if (declaresPassword && !hasPassword)
                throw new InvalidDataException($"{PasswordPath}: A server preview is required to resolve proxy credentials.");

            string[] bypass = desired.TryGetProperty("bypass", out JsonElement rules) ? ReadBypassRules(rules) : null;
            string passwordPlaceholder = hasPassword && password.GetProperty(declaresPassword ? "desiredSet" : "currentSet").GetBoolean() ? "set" : null;
            NetProxy candidate = Build(desired, Enum.Parse<NetProxyType>(type), address, port, username, passwordPlaceholder, bypass, null);

            bool disabling = candidate is null && currentType != nameof(NetProxyType.None);
            foreach (var (_, name) in _fields)
            {
                if (!disabling && !desired.TryGetProperty(name, out _))
                    continue;

                bool changed = name switch
                {
                    "type" => currentType != type,
                    "address" => ReadString(current, "address") != candidate?.Address,
                    "port" => current.TryGetPort() != candidate?.Port,
                    "username" => (ReadString(current, "username") ?? "") != (candidate?.Credential?.UserName ?? ""),
                    "password" => hasPassword && !JsonElement.DeepEquals(password.GetProperty("current"), password.GetProperty("desired")),
                    "bypass" => !ReadBypass(current).SequenceEqual(bypass ?? [], StringComparer.Ordinal),
                    _ => throw new InvalidDataException($"{Path}: Unknown proxy setting.")
                };
                if (changed)
                    changes.Add(new ConfigurationChange(Path + "/" + name, ConfigurationChangeKind.Update, false));
            }

            string EffectiveString(string field)
            {
                return desired.TryGetProperty(field, out JsonElement value) ? value.GetString() : ReadString(current, field);
            }
        }

        private static string[] ReadBypassRules(JsonElement rules)
        {
            return rules.ValueKind == JsonValueKind.Null ? [] : rules.EnumerateArray().Select(value => value.GetString()).ToArray();
        }

        private static NetProxy Build(JsonElement desired, NetProxyType type, string address, int? port, string username,
            string password, string[] bypass, IReadOnlyCollection<NetProxyBypassItem> currentBypass)
        {
            if (type == NetProxyType.None)
            {
                foreach (JsonProperty field in desired.EnumerateObject())
                {
                    if (field.Name != "type" && field.Value.ValueKind != JsonValueKind.Null &&
                        !(field.Name == "bypass" && field.Value.GetArrayLength() == 0))
                        throw new InvalidDataException($"{Path}/{field.Name}: This setting requires an enabled proxy.");
                }
                return null;
            }

            if (string.IsNullOrWhiteSpace(address) || Encoding.UTF8.GetByteCount(address) > byte.MaxValue)
                throw new InvalidDataException($"{Path}/address: An enabled proxy requires an address of at most 255 UTF-8 bytes.");
            if (port is null or < 1 or > 65535)
                throw new InvalidDataException($"{Path}/port: An enabled proxy requires a port from 1 to 65535.");
            if (username is not null && Encoding.UTF8.GetByteCount(username) > byte.MaxValue)
                throw new InvalidDataException($"{Path}/username: Maximum username length is 255 UTF-8 bytes.");
            if (!string.IsNullOrEmpty(password) && string.IsNullOrEmpty(username))
                throw new InvalidDataException($"{PasswordPath}: A password requires a proxy username.");

            NetProxy proxy;
            try
            {
                proxy = NetProxy.CreateProxy(type, address, port.Value,
                    string.IsNullOrEmpty(username) ? null : new NetworkCredential(username, password));
            }
            catch (Exception ex) when (ex is ArgumentException or FormatException or NotSupportedException)
            {
                throw new InvalidDataException($"{Path}/address: Invalid proxy address.");
            }

            if (bypass is null)
            {
                if (currentBypass is not null)
                    proxy.BypassList = currentBypass;
                return proxy;
            }
            if (bypass.Length > byte.MaxValue)
                throw new InvalidDataException($"{Path}/bypass: At most 255 bypass entries are supported.");
            var items = new NetProxyBypassItem[bypass.Length];
            for (int i = 0; i < bypass.Length; i++)
            {
                try
                {
                    if (Encoding.UTF8.GetByteCount(bypass[i]) > byte.MaxValue)
                        throw new ArgumentException();
                    items[i] = new NetProxyBypassItem(bypass[i]);
                }
                catch (Exception ex) when (ex is ArgumentException or FormatException or NetProxyException)
                {
                    throw new InvalidDataException($"{Path}/bypass/{i}: Invalid proxy bypass entry.");
                }
            }
            proxy.BypassList = items;
            return proxy;
        }

        private static int? TryGetPort(this JsonElement element)
        {
            return element.ValueKind == JsonValueKind.Object && element.TryGetProperty("port", out JsonElement port) ? port.GetInt32() : null;
        }

        private static string ReadString(JsonElement element, string field)
        {
            return element.ValueKind == JsonValueKind.Object && element.TryGetProperty(field, out JsonElement value)
                ? value.GetString() : null;
        }

        private static IEnumerable<string> ReadBypass(JsonElement element)
        {
            return element.ValueKind == JsonValueKind.Object && element.TryGetProperty("bypass", out JsonElement rules)
                ? rules.EnumerateArray().Select(value => value.GetString()) : [];
        }
    }
}
