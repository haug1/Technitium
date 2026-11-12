using DnsServerCore.Configuration;
using System;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;

namespace DnsServerApp
{
    internal static class ConfigurationCommand
    {
        private static readonly JsonSerializerOptions _exportOptions = new() { WriteIndented = true };

        public static async Task<int> RunAsync(string[] args)
        {
            try
            {
                switch (args[1])
                {
                    case "validate" when args.Length <= 3:
                        LoadManifest(args.Length == 3 ? args[2] : ConfigurationManifest.DefaultFileName);
                        Console.WriteLine("Manifest structure and references are valid.");
                        return 0;

                    case "plan" when args.Length == 4:
                        await WritePlanAsync(LoadManifest(args[2]), ParseServerUrl(args[3]));
                        return 0;

                    case "apply" when args.Length == 5:
                        await ApplyAsync(LoadManifest(args[2]), ParseServerUrl(args[3]), args[4]);
                        Console.WriteLine("Configuration applied.");
                        return 0;

                    case "export" when args.Length == 3:
                        JsonElement snapshot = await ReadServerResponseAsync(ParseServerUrl(args[2]), "/api/settings/get");
                        Console.WriteLine(ConfigurationPlan.Export(snapshot).ToJsonString(_exportOptions));
                        Console.Error.WriteLine("Partial export of supported settings. Supply blocklist sources separately if needed.");
                        return 0;

                    default:
                        Console.Error.WriteLine("Usage: DnsServerApp config validate [manifest]");
                        Console.Error.WriteLine("       DnsServerApp config plan <manifest> <server-url>");
                        Console.Error.WriteLine("       DnsServerApp config apply <manifest> <server-url> <revision>");
                        Console.Error.WriteLine("       DnsServerApp config export <server-url>");
                        return 2;
                }
            }
            catch (InvalidDataException ex)
            {
                Console.Error.WriteLine(ex.Message);
                return 1;
            }
            catch (Exception ex) when (ex is HttpRequestException or OperationCanceledException or JsonException)
            {
                Console.Error.WriteLine("Could not read current settings from the server.");
                return 1;
            }
            catch (Exception ex) when (ex is IOException or UnauthorizedAccessException or ArgumentException)
            {
                Console.Error.WriteLine("Could not open the configuration manifest.");
                return 1;
            }
        }

        private static ConfigurationManifest LoadManifest(string path)
        {
            ConfigurationManifest manifest = ConfigurationManifest.Load(path);
            manifest.ValidateReferences();
            return manifest;
        }

        private static Uri ParseServerUrl(string value)
        {
            if (!Uri.TryCreate(value, UriKind.Absolute, out Uri? uri)
                || ((uri.Scheme != Uri.UriSchemeHttps) && ((uri.Scheme != Uri.UriSchemeHttp) || !uri.IsLoopback))
                || (uri.UserInfo.Length > 0) || (uri.Query.Length > 0) || (uri.Fragment.Length > 0) || (uri.AbsolutePath != "/"))
                throw new InvalidDataException("Use a server origin with HTTPS or loopback HTTP.");

            return uri;
        }

        private static async Task WritePlanAsync(ConfigurationManifest manifest, Uri serverUrl)
        {
            using var content = new StringContent(manifest.Settings.GetRawText(), Encoding.UTF8, "application/json");
            JsonElement preview = await ReadServerResponseAsync(serverUrl, "/api/settings/config/plan", content);
            JsonElement changes = preview.GetProperty("changes");
            if (changes.GetArrayLength() == 0)
                Console.WriteLine("No setting changes.");

            foreach (JsonElement change in changes.EnumerateArray())
            {
                string restart = change.GetProperty("restartWebService").GetBoolean() ? " (web service restart)" : "";
                Console.WriteLine($"{change.GetProperty("kind").GetString()} {change.GetProperty("path").GetString()}{restart}");
            }

            Console.WriteLine($"Revision {preview.GetProperty("revision").GetString()}");
        }

        private static async Task ApplyAsync(ConfigurationManifest manifest, Uri serverUrl, string revision)
        {
            if ((revision.Length != 64) || !Array.TrueForAll(revision.ToCharArray(), char.IsAsciiHexDigit))
                throw new InvalidDataException("Supply the revision printed by config plan.");

            using var content = new StringContent(manifest.Settings.GetRawText(), Encoding.UTF8, "application/json");
            await ReadServerResponseAsync(serverUrl, "/api/settings/config/apply", content, revision.ToUpperInvariant());
        }

        private static async Task<JsonElement> ReadServerResponseAsync(Uri serverUrl, string apiPath, HttpContent? content = null, string? revision = null)
        {
            string? token = Environment.GetEnvironmentVariable("TECHNITIUM_CONFIG_API_TOKEN");
            if (string.IsNullOrWhiteSpace(token))
                throw new InvalidDataException("Set TECHNITIUM_CONFIG_API_TOKEN to a token with Settings view permission.");
            if ((token.Length != 64) || !Array.TrueForAll(token.ToCharArray(), char.IsAsciiHexDigit))
                throw new InvalidDataException("TECHNITIUM_CONFIG_API_TOKEN must contain a server-generated API token.");

            using var client = new HttpClient(new SocketsHttpHandler { AllowAutoRedirect = false, UseProxy = false })
            {
                BaseAddress = serverUrl,
                Timeout = TimeSpan.FromSeconds(15)
            };
            client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);
            using var request = new HttpRequestMessage(content is null ? HttpMethod.Get : HttpMethod.Post, apiPath)
            {
                Content = content
            };
            if (revision is not null)
                request.Headers.IfMatch.Add(new EntityTagHeaderValue("\"" + revision + "\""));
            using HttpResponseMessage response = await client.SendAsync(request);
            response.EnsureSuccessStatusCode();

            using Stream responseStream = await response.Content.ReadAsStreamAsync();
            using JsonDocument document = await JsonDocument.ParseAsync(responseStream);
            JsonElement root = document.RootElement;
            if ((root.ValueKind != JsonValueKind.Object) || !root.TryGetProperty("status", out JsonElement status)
                || (status.ValueKind != JsonValueKind.String)
                || !status.ValueEquals("ok") || !root.TryGetProperty("response", out JsonElement current))
                throw new InvalidDataException("The server rejected the request for current settings.");

            return current.Clone();
        }
    }
}
