# Repository Guidelines

## Project Structure

- `DnsServerCore/` implements DNS, DHCP, authentication, clustering, and the web API. The admin console lives in `www/` and the DNS-over-HTTPS landing page in `dohwww/` within that project.
- `DnsServerApp/` hosts the cross-platform server. `DnsServerWindowsService/`, `DnsServerSystemTrayApp/`, and `DnsServerWindowsSetup/` contain the Windows service, tray app, and installer.
- `DnsServerCore.HttpApi/` provides HTTP API types. `DnsServerCore.ApplicationCommon/` defines the DNS app interfaces. Individual plugins and their documentation live in `Apps/`.

## Build and Run

Use the .NET 10 SDK. Clone `TechnitiumLibrary` beside this checkout and build its ByteTree, Net, and Security.OTP projects in Release mode. The DNS server projects reference the sibling repository's compiled assemblies. Follow [build.md](build.md) for the dependency commands and Windows packaging instructions.

- `dotnet publish DnsServerApp/DnsServerApp.csproj -c Release` builds and publishes the server and its web assets.
- `dotnet run --project DnsServerApp/DnsServerApp.csproj -- --portable-app --stop-if-bind-fails /path/to/scratch-config` runs the server with an isolated configuration directory. Check the printed console URL and make sure the configured listener ports are available.

## Coding Style

Match surrounding code. C# uses four-space indentation, braces on separate lines, PascalCase for types and public members, and camelCase for locals and parameters. Follow the containing class's private-field convention, such as `_configFolder` in `DnsWebService`. Keep changes focused and avoid reformatting bundled web assets.

## Testing

Run `dotnet test DnsServerCore.Tests/DnsServerCore.Tests.csproj` after building the sibling library. Add tests for observable behavior and regressions using scratch configuration and controlled dependencies. For UI changes, exercise the affected screen and record the verification. See [build.md](build.md#regression-tests) for coverage commands.

## Commits and Pull Requests

Commit completed changes for every task and push the working branch to the private `origin` before reporting completion. Stage only the files changed for the task and verify the push succeeded. Use Conventional Commits for all new commits, such as `docs: update configuration guide`.

In pull requests, explain the behavior change, summarize verification, link relevant issues, and include screenshots for visible UI changes. Update [APIDOCS.md](APIDOCS.md) when API behavior changes and review [CONTRIBUTING.md](CONTRIBUTING.md) before submitting.
