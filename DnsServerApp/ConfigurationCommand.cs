using DnsServerCore.Configuration;
using System;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;
using System.Threading.Tasks;

namespace DnsServerApp
{
    internal static class ConfigurationCommand
    {
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

                    default:
                        Console.Error.WriteLine("Usage: DnsServerApp config validate [manifest]");
                        Console.Error.WriteLine("       DnsServerApp config plan <manifest> <server-url>");
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
            using HttpResponseMessage response = await client.GetAsync("/api/settings/get");
            response.EnsureSuccessStatusCode();

            using Stream responseStream = await response.Content.ReadAsStreamAsync();
            using JsonDocument document = await JsonDocument.ParseAsync(responseStream);
            JsonElement root = document.RootElement;
            if ((root.ValueKind != JsonValueKind.Object) || !root.TryGetProperty("status", out JsonElement status)
                || (status.ValueKind != JsonValueKind.String)
                || !status.ValueEquals("ok") || !root.TryGetProperty("response", out JsonElement current))
                throw new InvalidDataException("The server rejected the request for current settings.");

            var changes = ConfigurationPlan.Create(manifest, current);
            if (changes.Count == 0)
                Console.WriteLine("No setting changes.");

            foreach (ConfigurationChange change in changes)
            {
                string restart = change.RestartWebService ? " (web service restart)" : "";
                Console.WriteLine($"{change.Kind} {change.Path}{restart}");
            }
        }
    }
}
