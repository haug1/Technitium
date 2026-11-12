$ErrorActionPreference = 'Stop'
$repo = Split-Path -Parent $PSScriptRoot
$temp = Join-Path $env:RUNNER_TEMP ('technitium-startup-' + [guid]::NewGuid())
$password = [guid]::NewGuid().ToString('N')
$env:DNS_SERVER_ADMIN_PASSWORD = $password

function Get-LoopbackPort {
    $listener = [System.Net.Sockets.TcpListener]::new([System.Net.IPAddress]::Loopback, 0)
    try {
        $listener.Start()
        return $listener.LocalEndpoint.Port
    } finally {
        $listener.Stop()
    }
}

function Wait-Settings([int] $port) {
    $uri = "http://127.0.0.1:$port/api"
    $deadline = [DateTime]::UtcNow.AddSeconds(30)
    do {
        try {
            $login = Invoke-RestMethod "$uri/user/login" -NoProxy -TimeoutSec 2 -Method Post -Body @{
                user = 'admin'
                pass = $password
            }
            if ($login.status -eq 'ok') {
                $settings = Invoke-RestMethod "$uri/settings/get" -NoProxy -TimeoutSec 2 -Headers @{
                    Authorization = "Bearer $($login.token)"
                }
                if ($settings.status -eq 'ok') {
                    return $settings.response
                }
            }
        } catch {
            # The endpoint may still be starting.
        }
        Start-Sleep -Milliseconds 250
    } while ([DateTime]::UtcNow -lt $deadline)
    throw "Settings endpoint on port $port did not become available."
}

foreach ($kind in @('console', 'service')) {
    $folder = Join-Path $temp $kind
    New-Item -ItemType Directory -Path $folder -Force | Out-Null
    $manifest = Join-Path $folder 'technitium.json'
    $webPort = Get-LoopbackPort
    $dnsPort = Get-LoopbackPort
    $domain = "$kind.startup.test"
    @{
        schemaVersion = 1
        dns = @{
            serverDomain = $domain
            localEndpoints = @("127.0.0.1:$dnsPort")
            checkForUpdates = $false
        }
        web = @{ localAddresses = @('127.0.0.1'); httpPort = $webPort }
        logging = @{ folder = 'logs'; retentionDays = 47 }
        apps = @{ autoUpdate = $false }
    } | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $manifest

    $serviceName = "TechnitiumManifest-$([guid]::NewGuid().ToString('N'))"
    $registered = $false
    try {
        if ($kind -eq 'service') {
            $serviceExe = Join-Path $repo 'DnsServerWindowsService/bin/Debug/DnsService.exe'
            $binaryPath = '"{0}" "{1}"' -f $serviceExe, $folder
            New-Service -Name $serviceName -BinaryPathName $binaryPath -StartupType Manual | Out-Null
            $registered = $true
            $serviceEnvironment = @("DNS_SERVER_ADMIN_PASSWORD=$password")
            if ($env:DOTNET_ROOT) {
                $serviceEnvironment += "DOTNET_ROOT=$env:DOTNET_ROOT"
            }
            New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\$serviceName" -Name Environment `
                -PropertyType MultiString -Value $serviceEnvironment | Out-Null
        }

        foreach ($withManifest in @($true, $false)) {
            $process = $null
            try {
                if ($registered) {
                    Start-Service -Name $serviceName
                } else {
                    $consoleExe = Join-Path $repo 'DnsServerApp/bin/Debug/DnsServerApp.exe'
                    $arguments = '--portable-app --stop-if-bind-fails "{0}"' -f $folder
                    $process = Start-Process -FilePath $consoleExe -ArgumentList $arguments -PassThru
                }
                $settings = Wait-Settings $webPort
                if ($settings.dnsServerDomain -ne $domain -or $settings.maxLogFileDays -ne 47 -or
                    $settings.webServiceHttpPort -ne $webPort -or
                    $settings.dnsServerLocalEndPoints -notcontains "127.0.0.1:$dnsPort") {
                    throw "Unexpected effective settings for the $kind host (manifest present: $withManifest)."
                }
                if ($withManifest -and ($settings.managedSettings -notcontains '/dns/serverDomain')) {
                    throw "The $kind host did not report ownership of the startup manifest settings."
                }
                Write-Host "Verified $kind startup (manifest present: $withManifest)."
            } finally {
                if ($registered) {
                    $service = Get-Service -Name $serviceName
                    if ($service.Status -ne 'Stopped') {
                        Stop-Service -InputObject $service
                        $service.WaitForStatus('Stopped', [TimeSpan]::FromSeconds(15))
                    }
                } elseif ($process -and !$process.HasExited) {
                    Stop-Process -InputObject $process -Force
                    $process.WaitForExit()
                }
            }
            if ($withManifest) {
                Remove-Item -LiteralPath $manifest
            }
        }
    } catch {
        Get-ChildItem (Join-Path $folder 'logs') -Filter '*.log' -ErrorAction SilentlyContinue |
            ForEach-Object { Get-Content $_.FullName -Tail 30 }
        throw
    } finally {
        if ($registered) {
            Remove-Service -Name $serviceName
        }
    }
}
