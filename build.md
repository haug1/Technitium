# Build Instructions

## Linux development with Nix

On x86-64 or ARM64 Linux, run `nix develop` from the repository root. If flakes are disabled, run `nix --extra-experimental-features 'nix-command flakes' develop`. The shell provides the pinned .NET 10 SDK, MsQuic for DNS-over-QUIC and HTTP/3, and `dig` for DNS checks.

Inside the shell, build the sibling library checkout once and rebuild it after library changes. Skip the clone if you already have `../TechnitiumLibrary`.

```sh
git clone https://github.com/TechnitiumSoftware/TechnitiumLibrary.git ../TechnitiumLibrary
for project in TechnitiumLibrary.ByteTree TechnitiumLibrary.Net TechnitiumLibrary.Security.OTP; do
    dotnet build "../TechnitiumLibrary/$project/$project.csproj" -c Release || break
done
```

Build the server and run it with a scratch configuration directory. Reuse that directory on later runs to keep your local settings.

```sh
dotnet build DnsServerApp/DnsServerApp.csproj
scratch_config=$(mktemp -d)
DNS_SERVER_WEB_SERVICE_LOCAL_ADDRESSES=127.0.0.1 \
    dotnet run --no-build --project DnsServerApp/DnsServerApp.csproj -- \
    --portable-app --stop-if-bind-fails "$scratch_config"
```

Open the web console URL printed at startup. A fresh configuration uses DNS port 53, which must be available and may require bind privileges. Use the web console to change the DNS listener to a development port such as 5353 for subsequent runs with the same configuration directory.

## For Windows

To build the Technitium DNS Server Windows Setup, you need to install [Microsoft Visual Studio Community](https://visualstudio.microsoft.com/vs/) and [Inno Setup](https://jrsoftware.org/isinfo.php) on your computer. Once you have it installed, follow the steps below:

1. Open Visual Studio and use the "Clone a repository" option to clone the [TechnitiumLibrary](https://github.com/TechnitiumSoftware/TechnitiumLibrary) project using the `https://github.com/TechnitiumSoftware/TechnitiumLibrary.git` URL. Once the repository is cloned and opened in Visual Studio, select the build mode to "Release" from the dropdown box in the toolbar and use the Build > Build Solution menu to build it.

2. Open Visual Studio and use the "Clone a repository" option to clone the [DnsServer](https://github.com/TechnitiumSoftware/DnsServer) project using the `https://github.com/TechnitiumSoftware/DnsServer.git` URL in the same parent folder that you had cloned the TechnitiumLibrary repository in previous step. Once the repository is cloned and opened in Visual Studio, right click on the `DnsServerSystemTrayApp` project and click on the Publish menu to open the publish page. Click the Publish button on it to publish the project in `DnsServer\DnsServerWindowsSetup\publish` folder. Similarly, right click on the `DnsServerWindowsService` project and click on the Publish menu to open publish page and use the Publish button to publish the project in the same folder as that of the previous project.

3. Open the `DnsServer\DnsServerWindowsSetup\DnsServerSetup.iss` file in Inno Setup and click on the Build > Compile menu to generate a Windows setup in `DnsServerWindowsSetup\Release` folder that you can then use to install Technitium DNS Server on Windows.

## For Linux

Follow the instructions given below to build and install the DNS server from source. These instructions are written for Ubuntu and Raspberry Pi OS but, you can easily follow similar steps on your favorite distro.

1. Install prerequisites like curl and git.
```
sudo apt update
sudo apt install curl git -y
```

2. Follow the [install instructions](https://learn.microsoft.com/en-us/dotnet/core/install/linux-ubuntu-install?tabs=dotnet9&pivots=os-linux-ubuntu-2404) to be able to install ASP.NET Core SDK on your distro. Use the instructions given in the link to install the repository for other distros not shown in below examples:

- Ubuntu 24.04
```
sudo add-apt-repository ppa:dotnet/backports
sudo apt update
```

- Raspberry Pi OS
```
curl -sSL https://packages.microsoft.com/keys/microsoft.asc | sudo apt-key add -
sudo apt-add-repository https://packages.microsoft.com/debian/11/prod
sudo apt update
```

3. Install ASP.NET Core 10 SDK and `libmsquic` for DNS-over-QUIC support.
```
sudo apt install dotnet-sdk-10.0 libmsquic -y
```

Note! If you do not plan to use DNS-over-QUIC or HTTP/3 support, or you intend to just build a docker image then you can skip installing `libmsquic`.

4. Clone the source code for both [TechnitiumLibrary](https://github.com/TechnitiumSoftware/TechnitiumLibrary) and [DnsServer](https://github.com/TechnitiumSoftware/DnsServer) into the current folder.
```
git clone --depth 1 https://github.com/TechnitiumSoftware/TechnitiumLibrary.git TechnitiumLibrary
git clone --depth 1 https://github.com/TechnitiumSoftware/DnsServer.git DnsServer
```

5. Build the TechnitiumLibrary source.
```
dotnet build TechnitiumLibrary/TechnitiumLibrary.ByteTree/TechnitiumLibrary.ByteTree.csproj -c Release
dotnet build TechnitiumLibrary/TechnitiumLibrary.Net/TechnitiumLibrary.Net.csproj -c Release
dotnet build TechnitiumLibrary/TechnitiumLibrary.Security.OTP/TechnitiumLibrary.Security.OTP.csproj -c Release
```

6. Build the DnsServer source.
```
dotnet publish DnsServer/DnsServerApp/DnsServerApp.csproj -c Release
```

7. Install the DNS server as a systemd service.

Note! Skip this step if you wish to build and use docker image.

```
sudo mkdir -p /opt/technitium/dns
sudo cp -r DnsServer/DnsServerApp/bin/Release/publish/* /opt/technitium/dns
sudo cp /opt/technitium/dns/systemd.service /etc/systemd/system/dns.service
sudo systemctl stop systemd-resolved
sudo systemctl disable systemd-resolved
sudo systemctl enable dns.service
sudo systemctl start dns.service
sudo rm /etc/resolv.conf
echo "nameserver 127.0.0.1" | sudo tee /etc/resolv.conf
```

8. Build and run docker image.

Note! Skip this step if you have already installed the DNS server as a systemd service in previous step.

Note! Before proceeding to build a Docker image, it is required that you have installed `docker` on your computer.

Follow the commands given below to build a docker image for the DNS server.

```
cd DnsServer
sudo docker build -t technitium/dns-server:latest .
```

You can now run the image that you have built using `docker compose` as shown below. You should edit the `docker-compose.yml` file if you wish to edit the container's configuration before running it.

```
sudo systemctl stop systemd-resolved
sudo systemctl disable systemd-resolved
sudo docker compose up -d
```

9. Open the DNS server web console in a web browser using `http://<server-ip-address>:5380/` URL and set a login password to complete the installation.
