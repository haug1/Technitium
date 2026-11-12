using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Text;
using System.Text.Json;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net;

namespace DnsServerCore.Configuration
{
    internal static class ConfigurationDomainLists
    {
        internal static string[] Read(ConfigurationManifest manifest, string field)
        {
            return manifest is not null && manifest.Settings.TryGetProperty(field, out JsonElement entries)
                ? Read(entries, "/" + field) : null;
        }

        internal static string[] Read(JsonElement entries, string path)
        {
            if (entries.ValueKind == JsonValueKind.Null)
                return [];

            var names = new SortedSet<string>(StringComparer.Ordinal);
            int index = 0;
            foreach (JsonElement entry in entries.EnumerateArray())
                names.Add(Normalize(entry.GetString(), $"{path}/{index++}"));
            return names.ToArray();
        }

        internal static string Normalize(string name, string path)
        {
            name = name.Trim();
            if (IPAddress.TryParse(name, out IPAddress address))
                return address.GetReverseDomain();
            return ConfigurationManifest.CanonicalDnsName(name, path, allowRoot: name == ".");
        }

        internal static void Compare(JsonElement desired, string path, JsonElement snapshot, List<ConfigurationChange> changes)
        {
            if (!snapshot.TryGetProperty(path[1..], out JsonElement current))
                throw new InvalidDataException($"{path}: The server did not return the domain list.");

            var previous = current.EnumerateArray().Select(item => item.GetString()).ToHashSet(StringComparer.Ordinal);
            var next = Read(desired, path).ToHashSet(StringComparer.Ordinal);
            foreach (string name in previous.Except(next))
                changes.Add(new ConfigurationChange(ConfigurationPlan.AppendPath(path, name.Length == 0 ? "." : name), ConfigurationChangeKind.Remove, false));
            foreach (string name in next.Except(previous))
                changes.Add(new ConfigurationChange(ConfigurationPlan.AppendPath(path, name.Length == 0 ? "." : name), ConfigurationChangeKind.Add, false));
        }

        internal enum Ownership : byte
        {
            None,
            Local,
            Primary
        }

        internal static (string[] Names, Ownership Owner) ReadStore(Stream stream, string format)
        {
            if (Encoding.ASCII.GetString(stream.ReadExactly(2)) != format || stream.ReadByte() != 1)
                throw new InvalidDataException("Invalid DNS domain list file format.");

            using var reader = new BinaryReader(stream, Encoding.UTF8, leaveOpen: true);
            int count = reader.ReadInt32();
            if (count < 0)
                throw new InvalidDataException("Invalid DNS domain list count.");
            var names = new List<string>();
            for (int i = 0; i < count; i++)
                names.Add(stream.ReadShortString());
            int ownership = stream.ReadByte();
            return (names.ToArray(), ownership switch
            {
                (int)Ownership.Local => Ownership.Local,
                (int)Ownership.Primary => Ownership.Primary,
                _ => Ownership.None
            });
        }

        internal static void WriteStore(Stream stream, string format, IReadOnlyList<string> names, Ownership ownership)
        {
            using var writer = new BinaryWriter(stream, Encoding.UTF8, leaveOpen: true);
            writer.Write(Encoding.ASCII.GetBytes(format));
            writer.Write((byte)1);
            writer.Write(names.Count);
            foreach (string name in names)
                stream.WriteShortString(name);
            if (ownership != Ownership.None)
                writer.Write((byte)ownership);
        }

        internal static void RejectManagedChange(string path)
        {
            throw new InvalidDataException($"{path}: Domain list is managed by the configuration manifest.");
        }
    }
}
