using DnsServerCore.Configuration;
using System;
using System.IO;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading;
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
                        ConfigurationManifest manifest = LoadManifest(args.Length == 3 ? args[2] : ConfigurationManifest.DefaultFileName);
                        string? domainWarning = manifest.GetServerDomainEnvironmentWarning();
                        if (domainWarning is not null)
                            Console.Error.WriteLine(domainWarning);
                        Console.WriteLine("Manifest structure and references are valid.");
                        return 0;

                    case "plan" when args.Length == 4:
                        await WritePlanAsync(LoadManifest(args[2]), ParseServerUrl(args[3]));
                        return 0;

                    case "apply" when args.Length == 5 || (args.Length == 7 && args[5] == "--wait"):
                        return await ApplyAsync(LoadManifest(args[2]), ParseServerUrl(args[3]), args[4],
                            args.Length == 7 ? ParseServerUrl(args[6]) : null);

                    case "status" when args.Length == 4:
                        return await ReadApplyStatusAsync(ParseServerUrl(args[2]), args[3]);

                    case "export" when args.Length == 3 || (args.Length == 4 && args[3] == "--include-preview-only"):
                        bool includePreviewOnly = args.Length == 4;
                        JsonElement snapshot = await ReadServerResponseAsync(ParseServerUrl(args[2]), "/api/settings/get");
                        Console.WriteLine(ConfigurationPlan.Export(snapshot, includePreviewOnly).ToJsonString(_exportOptions));
                        Console.Error.WriteLine(includePreviewOnly
                            ? "Partial export includes preview-only settings."
                            : "Partial export includes settings supported by config apply.");
                        if (snapshot.TryGetProperty("blockListUrls", out JsonElement sources) &&
                            sources.ValueKind == JsonValueKind.Array && sources.GetArrayLength() > 0)
                            Console.Error.WriteLine("Blocklist sources were omitted because URLs can contain credentials. Supply blocklists.sources separately.");
                        return 0;

                    default:
                        Console.Error.WriteLine("Usage: DnsServerApp config validate [manifest]");
                        Console.Error.WriteLine("       DnsServerApp config plan <manifest> <server-url>");
                        Console.Error.WriteLine("       DnsServerApp config apply <manifest> <server-url> <revision> [--wait <result-url>]");
                        Console.Error.WriteLine("       DnsServerApp config status <server-url> <operation-id>");
                        Console.Error.WriteLine("       DnsServerApp config export <server-url> [--include-preview-only]");
                        return 2;
                }
            }
            catch (InvalidDataException ex)
            {
                Console.Error.WriteLine(ex.Message);
                return 1;
            }
            catch (Exception ex) when (ex is HttpRequestException or SocketException or OperationCanceledException or JsonException)
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
            if (preview.TryGetProperty("warnings", out JsonElement warnings))
            {
                foreach (JsonElement warning in warnings.EnumerateArray())
                    Console.Error.WriteLine(warning.GetString());
            }

            JsonElement changes = preview.GetProperty("changes");
            if (changes.GetArrayLength() == 0)
                Console.WriteLine("No setting changes.");

            foreach (JsonElement change in changes.EnumerateArray())
            {
                string restart = change.GetProperty("restartWebService").GetBoolean() ? " (web service restart)" : "";
                if (change.TryGetProperty("restartDnsService", out JsonElement restartDns) && restartDns.GetBoolean())
                    restart += " (DNS service restart)";
                Console.WriteLine($"{change.GetProperty("kind").GetString()} {change.GetProperty("path").GetString()}{restart}");
            }

            Console.WriteLine($"Revision {preview.GetProperty("revision").GetString()}");
        }

        private static async Task<int> ApplyAsync(ConfigurationManifest manifest, Uri serverUrl, string revision, Uri? resultUrl)
        {
            if ((revision.Length != 64) || !Array.TrueForAll(revision.ToCharArray(), char.IsAsciiHexDigit))
                throw new InvalidDataException("Supply the revision printed by config plan.");

            using var content = new StringContent(manifest.Settings.GetRawText(), Encoding.UTF8, "application/json");
            JsonElement response = await ReadServerResponseAsync(serverUrl, "/api/settings/config/apply", content, revision.ToUpperInvariant());
            if (!response.TryGetProperty("operationId", out JsonElement id))
            {
                Console.WriteLine("Configuration applied.");
                return 0;
            }

            string operationId = id.GetString() ?? "";
            Console.WriteLine($"Configuration apply is pending. Operation {operationId}");
            if (resultUrl is not null)
                return await WaitForApplyAsync(serverUrl, resultUrl, operationId);

            Console.WriteLine("Use config status with the server origin and operation ID to check the result.");
            return 0;
        }

        private static async Task<int> ReadApplyStatusAsync(Uri serverUrl, string operationId)
        {
            JsonElement result = await GetApplyStatusAsync(serverUrl, operationId);
            return PrintApplyStatus(result);
        }

        private static async Task<JsonElement> GetApplyStatusAsync(Uri serverUrl, string operationId, CancellationToken cancellationToken = default)
        {
            if (!Guid.TryParseExact(operationId, "N", out Guid id))
                throw new InvalidDataException("Supply the operation ID printed by config apply.");

            JsonElement result = await ReadServerResponseAsync(serverUrl, "/api/settings/config/status?operationId=" + id.ToString("N"), cancellationToken: cancellationToken);
            if (result.ValueKind != JsonValueKind.Object || !result.TryGetProperty("state", out JsonElement state) ||
                state.ValueKind != JsonValueKind.String ||
                (state.ValueEquals("failed") && (!result.TryGetProperty("message", out JsonElement message) || message.ValueKind != JsonValueKind.String)))
                throw new InvalidDataException("The server returned an invalid configuration apply status.");

            return result;
        }

        private static async Task<int> WaitForApplyAsync(Uri originalUrl, Uri resultUrl, string operationId)
        {
            Uri[] origins = originalUrl.Equals(resultUrl) ? [originalUrl] : [resultUrl, originalUrl];
            using var timeout = new CancellationTokenSource(TimeSpan.FromSeconds(45));
            try
            {
                while (!timeout.IsCancellationRequested)
                {
                    foreach (Uri origin in origins)
                    {
                        using var attempt = CancellationTokenSource.CreateLinkedTokenSource(timeout.Token);
                        attempt.CancelAfter(TimeSpan.FromSeconds(2));
                        try
                        {
                            JsonElement result = await GetApplyStatusAsync(origin, operationId, attempt.Token);
                            if (result.GetProperty("state").GetString() != "pending")
                                return PrintApplyStatus(result);
                        }
                        catch (Exception ex) when (ex is HttpRequestException or SocketException or OperationCanceledException or JsonException or InvalidDataException)
                        {
                            // The server may be switching listeners, or this origin may no longer serve the operation.
                        }
                    }

                    await Task.Delay(TimeSpan.FromMilliseconds(250), timeout.Token);
                }
            }
            catch (OperationCanceledException) when (timeout.IsCancellationRequested)
            { }

            Console.Error.WriteLine($"Timed out waiting for operation {operationId}. Use config status to check its outcome.");
            return 1;
        }

        private static int PrintApplyStatus(JsonElement result)
        {
            switch (result.GetProperty("state").GetString())
            {
                case "applied":
                    Console.WriteLine("Configuration applied.");
                    return 0;
                case "failed":
                    Console.Error.WriteLine(result.GetProperty("message").GetString());
                    return 1;
                case "pending":
                    Console.WriteLine("Configuration apply is pending.");
                    return 0;
                default:
                    throw new InvalidDataException("The server returned an unknown configuration apply state.");
            }
        }

        private static async Task<JsonElement> ReadServerResponseAsync(Uri serverUrl, string apiPath, HttpContent? content = null, string? revision = null, CancellationToken cancellationToken = default)
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
            using HttpResponseMessage response = await client.SendAsync(request, cancellationToken);
            response.EnsureSuccessStatusCode();

            using Stream responseStream = await response.Content.ReadAsStreamAsync(cancellationToken);
            using JsonDocument document = await JsonDocument.ParseAsync(responseStream, cancellationToken: cancellationToken);
            JsonElement root = document.RootElement;
            if ((root.ValueKind != JsonValueKind.Object) || !root.TryGetProperty("status", out JsonElement status)
                || (status.ValueKind != JsonValueKind.String)
                || !status.ValueEquals("ok") || !root.TryGetProperty("response", out JsonElement current))
                throw new InvalidDataException("The server rejected the request for current settings.");

            return current.Clone();
        }
    }
}
