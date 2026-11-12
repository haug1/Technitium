using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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

        internal static bool TryGetPasswordReference(ConfigurationManifest manifest, out JsonElement password)
        {
            password = default;
            return manifest is not null && manifest.Settings.TryGetProperty("dns", out JsonElement dns) &&
                dns.TryGetProperty("proxy", out JsonElement proxy) && proxy.TryGetProperty("password", out password);
        }

        internal static void WritePasswordSnapshot(Utf8JsonWriter writer, ConfigurationManifest manifest, JsonElement reference,
            NetProxy current, byte[] key)
        {
            string password = reference.ValueKind == JsonValueKind.Null ? null : manifest.ResolveReference(reference, PasswordPath);
            if (password is not null && Encoding.UTF8.GetByteCount(password) > byte.MaxValue)
                throw new InvalidDataException($"{PasswordPath}: The resolved password exceeds 255 UTF-8 bytes.");

            writer.WriteStartObject("manifestProxyPassword");
            writer.WriteString("current", Fingerprint(current?.Credential?.Password));
            writer.WriteString("desired", Fingerprint(password));
            writer.WriteBoolean("desiredSet", !string.IsNullOrEmpty(password));
            writer.WriteEndObject();

            string Fingerprint(string value)
            {
                return string.IsNullOrEmpty(value) ? null : Convert.ToHexString(HMACSHA256.HashData(key, Encoding.UTF8.GetBytes(value)));
            }
        }

        internal static void Compare(JsonElement desired, JsonElement snapshot, List<ConfigurationChange> changes)
        {
            snapshot.TryGetProperty("proxy", out JsonElement current);
            string currentType = ReadString(current, "type") ?? nameof(NetProxyType.None);
            string type = desired.TryGetProperty("type", out JsonElement typeValue)
                ? typeValue.GetString() ?? nameof(NetProxyType.None) : currentType;
            string address = EffectiveString("address");
            string username = EffectiveString("username");
            int? port = desired.TryGetProperty("port", out JsonElement portValue)
                ? portValue.ValueKind == JsonValueKind.Null ? null : decimal.ToInt32(portValue.GetDecimal())
                : current.ValueKind == JsonValueKind.Object ? current.GetProperty("port").GetInt32() : null;
            bool hasPassword = snapshot.TryGetProperty("manifestProxyPassword", out JsonElement password);
            if (desired.TryGetProperty("password", out _) && !hasPassword)
                throw new InvalidDataException($"{PasswordPath}: A server preview is required to resolve proxy credentials.");

            string[] bypass = null;
            if (desired.TryGetProperty("bypass", out JsonElement rules))
            {
                bypass = rules.ValueKind == JsonValueKind.Null ? [] : rules.EnumerateArray().Select(value => value.GetString()).ToArray();
                for (int i = 0; i < bypass.Length; i++)
                {
                    try
                    {
                        if (Encoding.UTF8.GetByteCount(bypass[i]) > byte.MaxValue)
                            throw new ArgumentException();
                        _ = new NetProxyBypassItem(bypass[i]);
                    }
                    catch (Exception ex) when (ex is ArgumentException or FormatException)
                    {
                        throw new InvalidDataException($"{Path}/bypass/{i}: Invalid proxy bypass entry.");
                    }
                }
            }

            if (type == nameof(NetProxyType.None))
            {
                foreach (JsonProperty field in desired.EnumerateObject())
                {
                    if (field.Name != "type" && field.Value.ValueKind != JsonValueKind.Null &&
                        !(field.Name == "bypass" && field.Value.GetArrayLength() == 0))
                        throw new InvalidDataException($"{Path}/{field.Name}: This setting requires an enabled proxy.");
                }
            }
            else
            {
                if (string.IsNullOrWhiteSpace(address) || Encoding.UTF8.GetByteCount(address) > byte.MaxValue)
                    throw new InvalidDataException($"{Path}/address: An enabled proxy requires an address of at most 255 UTF-8 bytes.");
                if (port is null or < 1 or > 65535)
                    throw new InvalidDataException($"{Path}/port: An enabled proxy requires a port from 1 to 65535.");
                try
                {
                    _ = NetProxy.CreateProxy(Enum.Parse<NetProxyType>(type), address, port.Value);
                }
                catch (Exception ex) when (ex is ArgumentException or FormatException or NotSupportedException)
                {
                    throw new InvalidDataException($"{Path}/address: Invalid proxy address.");
                }
                if (username is not null && Encoding.UTF8.GetByteCount(username) > byte.MaxValue)
                    throw new InvalidDataException($"{Path}/username: Maximum username length is 255 UTF-8 bytes.");
                if (hasPassword && password.GetProperty("desiredSet").GetBoolean() && string.IsNullOrEmpty(username))
                    throw new InvalidDataException($"{PasswordPath}: A password requires a proxy username.");
            }

            foreach (JsonProperty field in desired.EnumerateObject())
            {
                bool changed = field.Name switch
                {
                    "type" => currentType != type,
                    "address" => ReadString(current, "address") != address,
                    "port" => current.ValueKind == JsonValueKind.Object ? current.GetProperty("port").GetInt32() != port : port.HasValue,
                    "username" => ReadString(current, "username") != username,
                    "password" => !JsonElement.DeepEquals(password.GetProperty("current"), password.GetProperty("desired")),
                    "bypass" => !ReadBypass(current).SequenceEqual(bypass, StringComparer.Ordinal),
                    _ => throw new InvalidDataException($"{Path}: Unknown proxy setting.")
                };
                if (changed)
                    changes.Add(new ConfigurationChange(Path + "/" + field.Name, ConfigurationChangeKind.Update, false));
            }

            string EffectiveString(string field)
            {
                return desired.TryGetProperty(field, out JsonElement value) ? value.GetString() : ReadString(current, field);
            }
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
