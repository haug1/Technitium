/*
Technitium DNS Server
Copyright (C) 2026  Shreyas Zare (shreyas@technitium.com)

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

*/

using DnsServerCore.Auth;
using DnsServerCore.Configuration;
using DnsServerCore.Cluster;
using DnsServerCore.Dhcp;
using DnsServerCore.Dns;
using DnsServerCore.Dns.Applications;
using DnsServerCore.Dns.Dnssec;
using DnsServerCore.Dns.Zones;
using DnsServerCore.Dns.ZoneManagers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.BearerToken;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.ResponseCompression;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.StaticFiles;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Primitives;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.IO.Compression;
using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;
using System.Reflection;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net.Proxy;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ClientConnection;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using TechnitiumLibrary.Net.Http.Client;

namespace DnsServerCore
{
    public sealed partial class DnsWebService : IAsyncDisposable, IDisposable
    {
        #region variables

        readonly static char[] commaSeparator = new char[] { ',' };
        static readonly IPEndPoint IPENDPOINT_ANY_0 = new IPEndPoint(IPAddress.Any, 0);

        readonly Version _currentVersion;
        readonly DateTime _uptimestamp = DateTime.UtcNow;
        readonly string _appFolder;
        readonly string _configFolder;

        readonly LogManager _log;
        readonly AuthManager _authManager;

        readonly WebServiceApi _api;
        readonly WebServiceDashboardApi _dashboardApi;
        readonly WebServiceZonesApi _zonesApi;
        readonly WebServiceOtherZonesApi _otherZonesApi;
        readonly WebServiceAppsApi _appsApi;
        readonly WebServiceSettingsApi _settingsApi;
        readonly WebServiceDhcpApi _dhcpApi;
        readonly WebServiceAuthApi _authApi;
        readonly WebServiceClusterApi _clusterApi;
        readonly WebServiceLogsApi _logsApi;

        WebApplication _webService;
        HttpClientNetworkHandler _ssoHttpHandler;
        HttpClient _ssoHttpClient;

        ClusterManager _clusterManager;
        DnsServer _dnsServer;
        DhcpServer _dhcpServer;

        //web service
        int _webServiceHttpPort = 5380;
        int _webServiceTlsPort = 53443;

        IReadOnlyList<IPAddress> _webServiceLocalAddresses = [IPAddress.Any, IPAddress.IPv6Any];

        bool _webServiceEnableHttpUnixSocket;
        string _webServiceHttpUnixSocket;

        bool _webServiceEnableTlsUnixSocket;
        string _webServiceTlsUnixSocket;

        bool _webServiceEnableTls;
        bool _webServiceEnableHttp3;
        bool _webServiceHttpToTlsRedirect;
        bool _webServiceUseSelfSignedTlsCertificate;

        IReadOnlyCollection<NetworkAccessControl> _webServiceReverseProxyAddresses = CreateDefaultReverseProxyAcl();

        internal static NetworkAccessControl[] CreateDefaultReverseProxyAcl()
        {
            return
            [
                new NetworkAccessControl(IPAddress.Parse("127.0.0.0"), 8),
                new NetworkAccessControl(IPAddress.Parse("10.0.0.0"), 8),
                new NetworkAccessControl(IPAddress.Parse("100.64.0.0"), 10),
                new NetworkAccessControl(IPAddress.Parse("169.254.0.0"), 16),
                new NetworkAccessControl(IPAddress.Parse("172.16.0.0"), 12),
                new NetworkAccessControl(IPAddress.Parse("192.168.0.0"), 16),
                new NetworkAccessControl(IPAddress.Parse("2000::"), 3, true),
                new NetworkAccessControl(IPAddress.IPv6Any, 0)
            ];
        }

        string _webServiceTlsCertificatePath;
        string _webServiceTlsCertificatePassword;
        bool _manifestOwnsRealIpHeader;
        bool _manifestOwnsFrameAncestors;
        bool _manifestOwnsReverseProxyAcl;
        // Null follows the legacy environment setting. An empty override selects the installed root.
        string _webRootOverride;
        bool _manifestOwnsWebRoot;
        string _activeWebRoot;
        ushort _managedWebListeners;
        private const byte ManagedWebAddresses = 8;
        private const byte ManagedWebHttpPort = 16;
        private const ushort ManagedWebTlsPort = 32;
        private const ushort ManagedWebTlsEnabled = 64;
        private const ushort ManagedWebHttp3 = 128;
        private const ushort ManagedWebRedirect = 256;
        private const ushort ManagedWebHttpSocketEnabled = 512;
        private const ushort ManagedWebHttpSocketPath = 1024;
        private const ushort ManagedWebTlsSocketEnabled = 2048;
        private const ushort ManagedWebTlsSocketPath = 4096;
        private const ushort ManagedWebHttpSocket = ManagedWebHttpSocketEnabled | ManagedWebHttpSocketPath;
        private const ushort ManagedWebTlsSocket = ManagedWebTlsSocketEnabled | ManagedWebTlsSocketPath;
        private const ushort ManagedWebSelfSigned = 8192;
        private const ushort ManagedWebCertificatePath = 16384;
        private const ushort ManagedWebCertificatePassword = 32768;
        private const ushort ManagedWebCertificateMask = ManagedWebSelfSigned | ManagedWebCertificatePath | ManagedWebCertificatePassword;
        private const ushort ManagedWebListenerMask = ManagedWebAddresses | ManagedWebHttpPort | ManagedWebTlsPort |
            ManagedWebTlsEnabled | ManagedWebHttp3 | ManagedWebRedirect | ManagedWebHttpSocket | ManagedWebTlsSocket | ManagedWebCertificateMask;
        internal readonly record struct WebUnixSocket(bool? Enabled, string Path)
        {
            internal bool HasValues => Enabled.HasValue || Path is not null;
        }

        internal readonly record struct WebListeners(IReadOnlyList<IPAddress> Addresses, int? HttpPort, int? TlsPort,
            bool? TlsEnabled = null, bool? Http3Enabled = null, bool? RedirectToTls = null, WebUnixSocket HttpSocket = default, WebUnixSocket TlsSocket = default)
        {
            internal bool HasValues => Addresses is not null || HttpPort.HasValue || TlsPort.HasValue ||
                TlsEnabled.HasValue || Http3Enabled.HasValue || RedirectToTls.HasValue || HttpSocket.HasValues || TlsSocket.HasValues;
        }
        internal readonly record struct WebLiveSettings(string RealIp, string FrameAncestors, IReadOnlyCollection<NetworkAccessControl> ReverseProxyAcl = null, WebListeners Listeners = default);
        string _webServiceRealIpHeader = "X-Real-IP";
        string _webServiceCspFrameAncestorsHeader = "'none'";

        Timer _tlsCertificateUpdateTimer;
        const int TLS_CERTIFICATE_UPDATE_TIMER_INITIAL_INTERVAL = 60000;
        const int TLS_CERTIFICATE_UPDATE_TIMER_INTERVAL = 60000;

        DateTime _webServiceCertificateLastModifiedOn;
        SslServerAuthenticationOptions _webServiceSslServerAuthenticationOptions;

        bool _ssoEnabled;

        List<string> _configDisabledZones;

        readonly Lock _saveLock = new Lock();
        bool _pendingSave;
        bool _manifestWebRestart;
        readonly Timer _saveTimer;
        const int SAVE_TIMER_INITIAL_INTERVAL = 5000;

        bool _isRunning;

        #endregion

        #region constructor

        public DnsWebService(bool isPortableApp, string configFolder = null, Uri updateCheckUri = null)
        {
            Assembly assembly = Assembly.GetExecutingAssembly();

            _currentVersion = assembly.GetName().Version;
            _appFolder = Path.GetDirectoryName(assembly.Location);

            if (configFolder is null)
                _configFolder = Path.Combine(_appFolder, "config");
            else
                _configFolder = Path.GetFullPath(configFolder);

            Directory.CreateDirectory(_configFolder);
            Directory.CreateDirectory(Path.Combine(_configFolder, "blocklists"));
            Directory.CreateDirectory(Path.Combine(_configFolder, "zones"));

            _log = new LogManager(isPortableApp, _configFolder);
            _authManager = new AuthManager(this, _configFolder, _log);

            _api = new WebServiceApi(this, updateCheckUri);
            _dashboardApi = new WebServiceDashboardApi(this);
            _zonesApi = new WebServiceZonesApi(this);
            _otherZonesApi = new WebServiceOtherZonesApi(this);
            _appsApi = new WebServiceAppsApi(this);
            _settingsApi = new WebServiceSettingsApi(this);
            _dhcpApi = new WebServiceDhcpApi(this);
            _authApi = new WebServiceAuthApi(this);
            _clusterApi = new WebServiceClusterApi(this);
            _logsApi = new WebServiceLogsApi(this);

            _saveTimer = new Timer(delegate (object state)
            {
                lock (_saveLock)
                {
                    if (_pendingSave && !_manifestWebRestart)
                    {
                        try
                        {
                            SaveConfigFileInternal();
                            _pendingSave = false;
                        }
                        catch (Exception ex)
                        {
                            _log.Write(ex);
                        }
                    }
                }
            });
        }

        #endregion

        #region IDisposable

        bool _disposed;

        public async ValueTask DisposeAsync()
        {
            if (_disposed)
                return;

            StopTlsCertificateUpdateTimer();

            lock (_saveLock)
            {
                _saveTimer?.Dispose();

                if (_pendingSave && !_manifestWebRestart)
                {
                    try
                    {
                        SaveConfigFileInternal();
                    }
                    catch (Exception ex)
                    {
                        _log.Write(ex);
                    }
                    finally
                    {
                        _pendingSave = false;
                    }
                }
            }

            await StopAsync();

            _authManager?.Dispose();

            if (_log is not null)
                await _log.DisposeAsync();

            _disposed = true;
        }

        public void Dispose()
        {
            DisposeAsync().Sync();
        }

        #endregion

        #region config

        private void LoadConfigFile(bool useLegacyServerDomain)
        {
            string webServiceConfigFile = Path.Combine(_configFolder, "webservice.config");

            try
            {
                using (FileStream fS = new FileStream(webServiceConfigFile, FileMode.Open, FileAccess.Read))
                {
                    ReadConfigFrom(fS, readOwnership: true);
                }

                _log.Write("Web Service config file was loaded: " + webServiceConfigFile);
            }
            catch (FileNotFoundException)
            {
                if (!TryLoadOldConfigFile())
                {
                    //old config file did not exist; read environment variables and generate new config
                    CreateForwarderZoneToDisableDnssecForNTP();

                    //web service
                    string strWebServiceLocalAddresses = Environment.GetEnvironmentVariable("DNS_SERVER_WEB_SERVICE_LOCAL_ADDRESSES");
                    if (!string.IsNullOrEmpty(strWebServiceLocalAddresses))
                        _webServiceLocalAddresses = strWebServiceLocalAddresses.Split(IPAddress.Parse, commaSeparator);

                    string strWebServiceHttpPort = Environment.GetEnvironmentVariable("DNS_SERVER_WEB_SERVICE_HTTP_PORT");
                    if (!string.IsNullOrEmpty(strWebServiceHttpPort))
                        _webServiceHttpPort = int.Parse(strWebServiceHttpPort);

                    string webServiceTlsPort = Environment.GetEnvironmentVariable("DNS_SERVER_WEB_SERVICE_HTTPS_PORT");
                    if (!string.IsNullOrEmpty(webServiceTlsPort))
                        _webServiceTlsPort = int.Parse(webServiceTlsPort);

                    UdpClientConnection.SocketPoolExcludedPorts = [(ushort)_webServiceTlsPort];

                    string webServiceEnableTls = Environment.GetEnvironmentVariable("DNS_SERVER_WEB_SERVICE_ENABLE_HTTPS");
                    if (!string.IsNullOrEmpty(webServiceEnableTls))
                        _webServiceEnableTls = bool.Parse(webServiceEnableTls);

                    string webServiceTlsCertificatePassword = Environment.GetEnvironmentVariable("DNS_SERVER_WEB_SERVICE_TLS_CERTIFICATE_PASSWORD");
                    if (!string.IsNullOrEmpty(webServiceTlsCertificatePassword))
                        _webServiceTlsCertificatePassword = webServiceTlsCertificatePassword;

                    string webServiceTlsCertificatePath = Environment.GetEnvironmentVariable("DNS_SERVER_WEB_SERVICE_TLS_CERTIFICATE_PATH");
                    if (!string.IsNullOrEmpty(webServiceTlsCertificatePath))
                    {
                        _webServiceTlsCertificatePath = webServiceTlsCertificatePath;

                        string webServiceTlsCertificateAbsolutePath = _log.ConvertToAbsolutePath(_webServiceTlsCertificatePath);

                        try
                        {
                            LoadWebServiceTlsCertificate(webServiceTlsCertificateAbsolutePath, _webServiceTlsCertificatePassword);
                        }
                        catch (Exception ex)
                        {
                            _log.Write("DNS Server encountered an error while loading Web Service TLS certificate: " + webServiceTlsCertificateAbsolutePath, ex);
                        }

                        StartTlsCertificateUpdateTimer();
                    }

                    string webServiceUseSelfSignedTlsCertificate = Environment.GetEnvironmentVariable("DNS_SERVER_WEB_SERVICE_USE_SELF_SIGNED_CERT");
                    if (!string.IsNullOrEmpty(webServiceUseSelfSignedTlsCertificate))
                    {
                        _webServiceUseSelfSignedTlsCertificate = bool.Parse(webServiceUseSelfSignedTlsCertificate);

                        if (useLegacyServerDomain && _webServiceUseSelfSignedTlsCertificate && !File.Exists(Path.Combine(_configFolder, "dns.config")))
                        {
                            //read DNS server domain name here to generate self signed cert
                            string serverDomain = Environment.GetEnvironmentVariable(DnsServer.ServerDomainEnvironmentVariable);
                            if (!string.IsNullOrEmpty(serverDomain))
                                _dnsServer.ServerDomain = serverDomain;
                        }

                        CheckAndLoadSelfSignedCertificate(false, false);
                    }

                    string webServiceHttpToTlsRedirect = Environment.GetEnvironmentVariable("DNS_SERVER_WEB_SERVICE_HTTP_TO_TLS_REDIRECT");
                    if (!string.IsNullOrEmpty(webServiceHttpToTlsRedirect))
                        _webServiceHttpToTlsRedirect = bool.Parse(webServiceHttpToTlsRedirect);

                    string webServiceReverseProxyAddresses = Environment.GetEnvironmentVariable("DNS_SERVER_WEB_SERVICE_REVERSE_PROXY_ADDRESSES");
                    if (!string.IsNullOrEmpty(webServiceReverseProxyAddresses))
                        _webServiceReverseProxyAddresses = webServiceReverseProxyAddresses.Split(NetworkAccessControl.Parse, ',');
                }

                lock (_saveLock)
                {
                    SaveConfigFileInternal();
                }
            }
            catch (Exception ex)
            {
                _log.Write("DNS Server encountered an error while loading Web Service config file: " + webServiceConfigFile, ex);
                _log.Write("Note: You may try deleting the Web Service config file to fix this issue. However, you will lose Web Service settings but, other data wont be affected.");
                throw;
            }
        }

        public void LoadConfig(Stream s)
        {
            lock (_saveLock)
            {
                ReadConfigFrom(s);

                SaveConfigFileInternal();
                _pendingSave = false;
            }
        }

        private void CreateForwarderZoneToDisableDnssecForNTP()
        {
            if (Environment.OSVersion.Platform == PlatformID.Unix)
            {
                //adding Negative Trust Anchor (NTA) for ntp.org so that systems with no real-time clock can sync time
                string ntpDomain = "ntp.org";
                string fwdRecordComments = "Negative Trust Anchor for ntp.org to allow systems with no real-time clock to sync time.";

                if (_dnsServer.AuthZoneManager.CreateForwarderZone(ntpDomain, DnsTransportProtocol.Udp, "this-server", false, DnsForwarderRecordProxyType.DefaultProxy, null, 0, null, null, fwdRecordComments) is not null)
                {
                    //set permissions
                    _authManager.SetPermission(PermissionSection.Zones, ntpDomain, _authManager.GetGroup(Group.ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                    _authManager.SetPermission(PermissionSection.Zones, ntpDomain, _authManager.GetGroup(Group.DNS_ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                    _authManager.SaveConfigFile();
                }
            }
        }

        private void SaveConfigFileInternal()
        {
            string tmpConfigFile = Path.Combine(_configFolder, "webservice.tmp");
            string configFile = Path.Combine(_configFolder, "webservice.config");

            using (FileStream fS = new FileStream(tmpConfigFile, FileMode.Create, FileAccess.Write))
            {
                WriteConfigTo(fS);
                fS.Flush(flushToDisk: true);
            }

            File.Move(tmpConfigFile, configFile, true);

            _log.Write("Web Service config file was saved: " + configFile);
        }

        public void SaveConfigFile()
        {
            lock (_saveLock)
            {
                if (_pendingSave)
                    return;

                _pendingSave = true;
                _saveTimer.Change(SAVE_TIMER_INITIAL_INTERVAL, Timeout.Infinite);
            }
        }

        private void InspectAndFixZonePermissions()
        {
            Permission permission = _authManager.GetPermission(PermissionSection.Zones);
            if (permission is null)
                throw new DnsWebServiceException("Failed to read 'Zones' permissions: auth.config file is probably corrupt.");

            bool saveConfig = false;

            IReadOnlyDictionary<string, Permission> subItemPermissions = permission.SubItemPermissions;

            //remove ghost permissions
            foreach (KeyValuePair<string, Permission> subItemPermission in subItemPermissions)
            {
                string zoneName = subItemPermission.Key;

                if (_dnsServer.AuthZoneManager.GetAuthZoneInfo(zoneName) is null)
                {
                    permission.RemoveAllSubItemPermissions(zoneName); //no such zone exists; remove permissions
                    saveConfig = true;
                }
            }

            //add missing admin permissions
            IReadOnlyList<AuthZoneInfo> zones = _dnsServer.AuthZoneManager.GetAllZones();
            Group admins = _authManager.GetGroup(Group.ADMINISTRATORS);
            if (admins is null)
                throw new DnsWebServiceException("Failed to find 'Administrators' group: auth.config file is probably corrupt.");

            Group dnsAdmins = _authManager.GetGroup(Group.DNS_ADMINISTRATORS);
            if (dnsAdmins is null)
                throw new DnsWebServiceException("Failed to find 'DNS Administrators' group: auth.config file is probably corrupt.");

            foreach (AuthZoneInfo zone in zones)
            {
                Permission zonePermission = _authManager.GetPermission(PermissionSection.Zones, zone.Name);

                if ((zonePermission is null) || !zonePermission.GroupPermissions.TryGetValue(admins, out PermissionFlag adminsPermission) || (adminsPermission != PermissionFlag.ViewModifyDelete))
                {
                    _authManager.SetPermission(PermissionSection.Zones, zone.Name, admins, PermissionFlag.ViewModifyDelete);
                    saveConfig = true;
                }

                if ((zonePermission is null) || !zonePermission.GroupPermissions.TryGetValue(dnsAdmins, out PermissionFlag dnsAdminsPermission) || (dnsAdminsPermission != PermissionFlag.ViewModifyDelete))
                {
                    _authManager.SetPermission(PermissionSection.Zones, zone.Name, dnsAdmins, PermissionFlag.ViewModifyDelete);
                    saveConfig = true;
                }
            }

            if (saveConfig)
                _authManager.SaveConfigFile();
        }

        private WebLiveSettings ReadConfigFrom(Stream s, bool readOwnership = false, bool apply = true)
        {
            if (Encoding.ASCII.GetString(s.ReadExactly(2)) != "WC") //format
                throw new InvalidDataException("Web Service config file format is invalid.");

            BinaryReader bR = new BinaryReader(s);

            int version = bR.ReadByte();
            if (version > 5)
                throw new InvalidDataException("Web Service config version not supported.");

            int httpPort = bR.ReadInt32();
            int tlsPort = bR.ReadInt32();
            int addressCount = bR.ReadByte();
            IPAddress[] addresses = addressCount == 0 ? [IPAddress.Any, IPAddress.IPv6Any] : new IPAddress[addressCount];
            for (int i = 0; i < addressCount; i++)
                addresses[i] = IPAddressExtensions.ReadFrom(bR);

            bool httpSocketEnabled = version >= 3 && bR.ReadBoolean();
            string httpSocket = version >= 3 ? s.ReadShortString() : "";
            bool tlsSocketEnabled = version >= 4 && bR.ReadBoolean();
            string tlsSocket = version >= 4 ? s.ReadShortString() : "";
            bool tlsEnabled = bR.ReadBoolean();
            bool http3Enabled = bR.ReadBoolean();
            bool redirectToTls = bR.ReadBoolean();
            bool selfSignedCertificate = bR.ReadBoolean();
            NetworkAccessControl[] proxyAddresses = version >= 2 ? AuthZoneInfo.ReadNetworkACLFrom(bR) ?? [] : CreateDefaultReverseProxyAcl();
            string certificatePath = s.ReadShortString();
            string certificatePassword = s.ReadShortString();
            var headers = new WebLiveSettings(s.ReadShortString(), version >= 3 ? s.ReadShortString() : "'none'", proxyAddresses, new WebListeners(addresses, httpPort, tlsPort, tlsEnabled, http3Enabled, redirectToTls,
                new WebUnixSocket(httpSocketEnabled, httpSocket), new WebUnixSocket(tlsSocketEnabled, tlsSocket)));
            if (!readOwnership)
                CheckManagedWebCertificate(selfSignedCertificate, certificatePath, certificatePassword);
            if (!apply)
            {
                CheckManifestWebTlsDependencies(tlsEnabled, selfSignedCertificate || certificatePath.Length > 0);
                return headers;
            }

            if (readOwnership || (_managedWebListeners & ManagedWebHttpPort) == 0)
                _webServiceHttpPort = httpPort;
            if (readOwnership || (_managedWebListeners & ManagedWebTlsPort) == 0)
                _webServiceTlsPort = tlsPort;
            if (readOwnership || (_managedWebListeners & ManagedWebAddresses) == 0)
                _webServiceLocalAddresses = addresses;
            if (readOwnership || (_managedWebListeners & ManagedWebHttpSocketEnabled) == 0)
                _webServiceEnableHttpUnixSocket = httpSocketEnabled;
            if (readOwnership || (_managedWebListeners & ManagedWebHttpSocketPath) == 0)
                _webServiceHttpUnixSocket = httpSocket.Length == 0 ? null : httpSocket;
            if (readOwnership || (_managedWebListeners & ManagedWebTlsSocketEnabled) == 0)
                _webServiceEnableTlsUnixSocket = tlsSocketEnabled;
            if (readOwnership || (_managedWebListeners & ManagedWebTlsSocketPath) == 0)
                _webServiceTlsUnixSocket = tlsSocket.Length == 0 ? null : tlsSocket;
            if (readOwnership || (_managedWebListeners & ManagedWebTlsEnabled) == 0)
                _webServiceEnableTls = tlsEnabled;
            if (readOwnership || (_managedWebListeners & ManagedWebHttp3) == 0)
                _webServiceEnableHttp3 = http3Enabled;
            if (readOwnership || (_managedWebListeners & ManagedWebRedirect) == 0)
                _webServiceHttpToTlsRedirect = redirectToTls;
            _webServiceUseSelfSignedTlsCertificate = selfSignedCertificate;

            _webServiceTlsCertificatePath = certificatePath;
            _webServiceTlsCertificatePassword = certificatePassword;

            if (_webServiceTlsCertificatePath.Length == 0)
                _webServiceTlsCertificatePath = null;

            if (_webServiceTlsCertificatePath is null)
            {
                StopTlsCertificateUpdateTimer();
            }
            else
            {
                string webServiceTlsCertificateAbsolutePath = _log.ConvertToAbsolutePath(_webServiceTlsCertificatePath);

                try
                {
                    LoadWebServiceTlsCertificate(webServiceTlsCertificateAbsolutePath, _webServiceTlsCertificatePassword);
                }
                catch (Exception ex)
                {
                    _log.Write("DNS Server encountered an error while loading Web Service TLS certificate: " + webServiceTlsCertificateAbsolutePath, ex);
                }

                StartTlsCertificateUpdateTimer();
            }

            CheckAndLoadSelfSignedCertificate(false, false);

            if (readOwnership)
            {
                int ownership = version >= 4 ? s.ReadByte() : -1;
                _manifestOwnsRealIpHeader = ownership >= 0 && (ownership & 1) != 0;
                _manifestOwnsFrameAncestors = ownership >= 0 && (ownership & 2) != 0;
                _manifestOwnsReverseProxyAcl = ownership >= 0 && (ownership & 4) != 0;
                int extendedOwnership = ownership >= 0 ? s.ReadByte() : -1;
                _managedWebListeners = (ushort)((Math.Max(0, ownership) | (Math.Max(0, extendedOwnership) << 8)) & ManagedWebListenerMask);
                _webRootOverride = version >= 5 ? bR.ReadString() : null;
                _manifestOwnsWebRoot = version >= 5 && bR.ReadBoolean();
            }
            if (readOwnership || !_manifestOwnsRealIpHeader)
                _webServiceRealIpHeader = headers.RealIp;
            if (readOwnership || !_manifestOwnsFrameAncestors)
                _webServiceCspFrameAncestorsHeader = headers.FrameAncestors;
            if (readOwnership || !_manifestOwnsReverseProxyAcl)
                _webServiceReverseProxyAddresses = proxyAddresses.Length == 0 ? null : proxyAddresses;

            return headers;
        }

        private void WriteConfigTo(Stream s)
        {
            BinaryWriter bW = new BinaryWriter(s);

            bW.Write(Encoding.ASCII.GetBytes("WC")); //format
            bW.Write((byte)(_webRootOverride is null ? 4 : 5)); //version

            bW.Write(_webServiceHttpPort);
            bW.Write(_webServiceTlsPort);

            {
                bW.Write(Convert.ToByte(_webServiceLocalAddresses.Count));

                foreach (IPAddress localAddress in _webServiceLocalAddresses)
                    localAddress.WriteTo(bW);
            }

            bW.Write(_webServiceEnableHttpUnixSocket);
            s.WriteShortString(_webServiceHttpUnixSocket ?? "");

            bW.Write(_webServiceEnableTlsUnixSocket);
            s.WriteShortString(_webServiceTlsUnixSocket ?? "");

            bW.Write(_webServiceEnableTls);
            bW.Write(_webServiceEnableHttp3);
            bW.Write(_webServiceHttpToTlsRedirect);
            bW.Write(_webServiceUseSelfSignedTlsCertificate);

            AuthZoneInfo.WriteNetworkACLTo(_webServiceReverseProxyAddresses, bW);

            if (_webServiceTlsCertificatePath is null)
                s.WriteShortString(string.Empty);
            else
                s.WriteShortString(_webServiceTlsCertificatePath);

            if (_webServiceTlsCertificatePassword is null)
                s.WriteShortString(string.Empty);
            else
                s.WriteShortString(_webServiceTlsCertificatePassword);

            s.WriteShortString(_webServiceRealIpHeader);
            s.WriteShortString(_webServiceCspFrameAncestorsHeader);
            if (_manifestOwnsRealIpHeader || _manifestOwnsFrameAncestors || _manifestOwnsReverseProxyAcl || _managedWebListeners != 0 || _webRootOverride is not null)
            {
                bW.Write((byte)((_manifestOwnsRealIpHeader ? 1 : 0) | (_manifestOwnsFrameAncestors ? 2 : 0) | (_manifestOwnsReverseProxyAcl ? 4 : 0) | _managedWebListeners));
                if (_managedWebListeners > byte.MaxValue || _webRootOverride is not null)
                    bW.Write((byte)(_managedWebListeners >> 8));
            }
            if (_webRootOverride is not null)
            {
                bW.Write(_webRootOverride);
                bW.Write(_manifestOwnsWebRoot);
            }
        }

        #endregion

        #region backup and restore config

        internal async Task BackupConfigAsync(Stream zipStream, bool authConfig, bool clusterConfig, bool webServiceSettings, bool dnsSettings, bool logSettings, bool zones, bool allowedZones, bool blockedZones, bool blockLists, bool apps, bool scopes, bool stats, bool logs, bool isConfigTransfer = false, DateTime ifModifiedSince = default, ICollection<string> includeZones = null)
        {
            await using (ZipArchive backupZip = new ZipArchive(zipStream, ZipArchiveMode.Create, true, Encoding.UTF8))
            {
                if (authConfig)
                {
                    string authConfigFile = Path.Combine(_configFolder, "auth.config");

                    if (File.Exists(authConfigFile) && (File.GetLastWriteTimeUtc(authConfigFile) > ifModifiedSince))
                        backupZip.CreateEntryFromFile(authConfigFile, "auth.config");
                }

                if (clusterConfig && !isConfigTransfer)
                {
                    string clusterConfigFile = Path.Combine(_configFolder, "cluster.config");

                    if (File.Exists(clusterConfigFile))
                        backupZip.CreateEntryFromFile(clusterConfigFile, "cluster.config");
                }

                if (webServiceSettings && !isConfigTransfer)
                {
                    string webServiceConfigFile = Path.Combine(_configFolder, "webservice.config");

                    if (File.Exists(webServiceConfigFile) && (File.GetLastWriteTimeUtc(webServiceConfigFile) > ifModifiedSince))
                        backupZip.CreateEntryFromFile(webServiceConfigFile, "webservice.config");

                    //backup web service cert
                    if (!isConfigTransfer && !string.IsNullOrEmpty(_webServiceTlsCertificatePath))
                    {
                        string webServiceTlsCertificatePath = _log.ConvertToAbsolutePath(_webServiceTlsCertificatePath);

                        if (File.Exists(webServiceTlsCertificatePath) && webServiceTlsCertificatePath.StartsWith(_configFolder.TrimEnd(['/', '\\']) + Path.DirectorySeparatorChar, Environment.OSVersion.Platform == PlatformID.Win32NT ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
                        {
                            string entryName = _log.ConvertToRelativePath(webServiceTlsCertificatePath).Replace('\\', '/');
                            backupZip.CreateEntryFromFile(webServiceTlsCertificatePath, entryName);
                        }
                    }
                }

                if (dnsSettings)
                {
                    string dnsConfigFile = Path.Combine(_configFolder, "dns.config");

                    if (File.Exists(dnsConfigFile) && (File.GetLastWriteTimeUtc(dnsConfigFile) > ifModifiedSince))
                        backupZip.CreateEntryFromFile(dnsConfigFile, "dns.config");

                    //backup optional protocols cert
                    if (!isConfigTransfer && !string.IsNullOrEmpty(_dnsServer.DnsTlsCertificatePath))
                    {
                        string dnsTlsCertificatePath = _log.ConvertToAbsolutePath(_dnsServer.DnsTlsCertificatePath);

                        if (File.Exists(dnsTlsCertificatePath) && dnsTlsCertificatePath.StartsWith(_configFolder.TrimEnd(['/', '\\']) + Path.DirectorySeparatorChar, Environment.OSVersion.Platform == PlatformID.Win32NT ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
                        {
                            string entryName = _log.ConvertToRelativePath(dnsTlsCertificatePath).Replace('\\', '/');
                            backupZip.CreateEntryFromFile(dnsTlsCertificatePath, entryName);
                        }
                    }
                }

                if (logSettings && !isConfigTransfer)
                {
                    string logConfigFile = Path.Combine(_configFolder, "log.config");

                    if (File.Exists(logConfigFile) && (File.GetLastWriteTimeUtc(logConfigFile) > ifModifiedSince))
                        backupZip.CreateEntryFromFile(logConfigFile, "log.config");
                }

                if (zones)
                {
                    if (isConfigTransfer)
                    {
                        //backup Primary zone DNSSEC private keys that are member zone of the cluster catalog zone
                        AuthZoneInfo clusterCatalogZoneInfo = _dnsServer.AuthZoneManager.GetAuthZoneInfo("cluster-catalog." + _clusterManager.ClusterDomain);
                        if ((clusterCatalogZoneInfo is not null) && (clusterCatalogZoneInfo.Type == AuthZoneType.Catalog))
                        {
                            IReadOnlyCollection<string> memberZoneNames = (clusterCatalogZoneInfo.ApexZone as CatalogZone).GetAllMemberZoneNames();

                            foreach (string memberZoneName in memberZoneNames)
                            {
                                AuthZoneInfo memberZoneInfo = _dnsServer.AuthZoneManager.GetAuthZoneInfo(memberZoneName);
                                if (memberZoneInfo is null)
                                    continue; //no such zone exists; ignore

                                if (memberZoneInfo.Type != AuthZoneType.Primary)
                                    continue; //not a Primary zone; ignore

                                if (memberZoneInfo.ApexZone.DnssecStatus == AuthZoneDnssecStatus.Unsigned)
                                    continue; //not a DNSSEC signed zone; ignore

                                IReadOnlyCollection<DnssecPrivateKey> dnssecPrivateKeys = memberZoneInfo.DnssecPrivateKeys;
                                bool includePrivateKeys = false;

                                if ((includeZones is not null) && includeZones.Contains(memberZoneInfo.Name))
                                {
                                    includePrivateKeys = true;
                                }
                                else
                                {
                                    foreach (DnssecPrivateKey dnssecPrivateKey in dnssecPrivateKeys)
                                    {
                                        if (dnssecPrivateKey.StateChangedOn > ifModifiedSince)
                                        {
                                            //found a changed key
                                            includePrivateKeys = true;
                                            break;
                                        }
                                    }
                                }

                                if (includePrivateKeys)
                                {
                                    using (MemoryStream mS = new MemoryStream(4096))
                                    {
                                        AuthZoneInfo.WriteDnssecPrivateKeysTo(dnssecPrivateKeys, new BinaryWriter(mS));

                                        mS.Position = 0;

                                        //create zip entry
                                        ZipArchiveEntry entry = backupZip.CreateEntry("zones/" + memberZoneName + ".keys", CompressionLevel.Optimal);
                                        await using (Stream entryStream = entry.Open())
                                        {
                                            await mS.CopyToAsync(entryStream);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    else
                    {
                        //backup zone files
                        string[] zoneFiles = Directory.GetFiles(Path.Combine(_configFolder, "zones"), "*.zone", SearchOption.TopDirectoryOnly);
                        foreach (string zoneFile in zoneFiles)
                        {
                            string entryName = "zones/" + Path.GetFileName(zoneFile);
                            backupZip.CreateEntryFromFile(zoneFile, entryName);
                        }
                    }
                }

                if (allowedZones)
                {
                    string allowedZonesFile = Path.Combine(_configFolder, "allowed.config");

                    if (File.Exists(allowedZonesFile) && (File.GetLastWriteTimeUtc(allowedZonesFile) > ifModifiedSince))
                        backupZip.CreateEntryFromFile(allowedZonesFile, "allowed.config");
                }

                if (blockedZones)
                {
                    string blockedZonesFile = Path.Combine(_configFolder, "blocked.config");

                    if (File.Exists(blockedZonesFile) && (File.GetLastWriteTimeUtc(blockedZonesFile) > ifModifiedSince))
                        backupZip.CreateEntryFromFile(blockedZonesFile, "blocked.config");
                }

                if (blockLists)
                {
                    string blockListConfigFile = Path.Combine(_configFolder, "blocklist.config");

                    if (File.Exists(blockListConfigFile) && (File.GetLastWriteTimeUtc(blockListConfigFile) > ifModifiedSince))
                        backupZip.CreateEntryFromFile(blockListConfigFile, "blocklist.config");

                    if (!isConfigTransfer)
                    {
                        string[] blockListFiles = Directory.GetFiles(Path.Combine(_configFolder, "blocklists"), "*", SearchOption.TopDirectoryOnly);
                        foreach (string blockListFile in blockListFiles)
                        {
                            string entryName = "blocklists/" + Path.GetFileName(blockListFile);
                            backupZip.CreateEntryFromFile(blockListFile, entryName);
                        }
                    }
                }

                if (apps)
                {
                    if (isConfigTransfer)
                    {
                        string[] appDirectories = Directory.GetDirectories(Path.Combine(_configFolder, "apps"), "*", SearchOption.TopDirectoryOnly);
                        foreach (string appDirectory in appDirectories)
                        {
                            string applicationName = Path.GetFileName(appDirectory);
                            string applicationZipFile = Path.Combine(appDirectory, applicationName + ".zip");
                            string configFile = Path.Combine(appDirectory, "dnsApp.config");
                            bool fileAdded = false;

                            if (File.Exists(applicationZipFile) && (File.GetLastWriteTimeUtc(applicationZipFile) > ifModifiedSince))
                            {
                                string entryName = "apps/" + applicationName + "/" + applicationName + ".zip";
                                backupZip.CreateEntryFromFile(applicationZipFile, entryName);
                                fileAdded = true;
                            }

                            if (File.Exists(configFile) && (File.GetLastWriteTimeUtc(configFile) > ifModifiedSince))
                            {
                                string entryName = "apps/" + applicationName + "/dnsApp.config";
                                backupZip.CreateEntryFromFile(configFile, entryName);
                                fileAdded = true;
                            }

                            if (!fileAdded)
                                _ = backupZip.CreateEntry("apps/" + applicationName + "/.exists", CompressionLevel.Optimal);
                        }
                    }
                    else
                    {
                        string[] appFiles = Directory.GetFiles(Path.Combine(_configFolder, "apps"), "*", SearchOption.AllDirectories);
                        foreach (string appFile in appFiles)
                        {
                            string entryName = appFile.Substring(_configFolder.Length);

                            if (Path.DirectorySeparatorChar != '/')
                                entryName = entryName.Replace(Path.DirectorySeparatorChar, '/');

                            entryName = entryName.TrimStart('/');

                            await CreateBackupEntryFromSharedFileAsync(backupZip, appFile, entryName);
                        }
                    }
                }

                if (scopes && !isConfigTransfer)
                {
                    string[] scopeFiles = Directory.GetFiles(Path.Combine(_configFolder, "scopes"), "*.scope", SearchOption.TopDirectoryOnly);
                    foreach (string scopeFile in scopeFiles)
                    {
                        string entryName = "scopes/" + Path.GetFileName(scopeFile);
                        backupZip.CreateEntryFromFile(scopeFile, entryName);
                    }
                }

                if (stats && !isConfigTransfer)
                {
                    string[] hourlyStatsFiles = Directory.GetFiles(Path.Combine(_configFolder, "stats"), "*.stat", SearchOption.TopDirectoryOnly);
                    foreach (string hourlyStatsFile in hourlyStatsFiles)
                    {
                        string entryName = "stats/" + Path.GetFileName(hourlyStatsFile);
                        backupZip.CreateEntryFromFile(hourlyStatsFile, entryName);
                    }

                    string[] dailyStatsFiles = Directory.GetFiles(Path.Combine(_configFolder, "stats"), "*.dstat", SearchOption.TopDirectoryOnly);
                    foreach (string dailyStatsFile in dailyStatsFiles)
                    {
                        string entryName = "stats/" + Path.GetFileName(dailyStatsFile);
                        backupZip.CreateEntryFromFile(dailyStatsFile, entryName);
                    }
                }

                if (logs && !isConfigTransfer)
                {
                    string[] logFiles = Directory.GetFiles(_log.LogFolderAbsolutePath, "*.log", SearchOption.TopDirectoryOnly);
                    foreach (string logFile in logFiles)
                    {
                        string entryName = "logs/" + Path.GetFileName(logFile);

                        if (logFile.Equals(_log.CurrentLogFile, StringComparison.OrdinalIgnoreCase))
                        {
                            await CreateBackupEntryFromSharedFileAsync(backupZip, logFile, entryName);
                        }
                        else
                        {
                            backupZip.CreateEntryFromFile(logFile, entryName);
                        }
                    }
                }
            }
        }

        private void CheckManagedDomainLists(ZipArchive backupZip, bool allowedZones, bool blockedZones, bool isConfigTransfer = false)
        {
            if (allowedZones && _dnsServer.AllowedZoneManager.ManifestOwnsList &&
                backupZip.GetEntry("allowed.config") is ZipArchiveEntry allowedEntry)
            {
                using Stream stream = allowedEntry.Open();
                _dnsServer.AllowedZoneManager.CheckRestoreManifestList(stream, isConfigTransfer);
            }
            if (blockedZones && _dnsServer.BlockedZoneManager.ManifestOwnsList &&
                backupZip.GetEntry("blocked.config") is ZipArchiveEntry blockedEntry)
            {
                using Stream stream = blockedEntry.Open();
                _dnsServer.BlockedZoneManager.CheckRestoreManifestList(stream, isConfigTransfer);
            }
        }

        internal async Task RestoreConfigAsync(Stream zipStream, bool authConfig, bool clusterConfig, bool webServiceSettings, bool dnsSettings, bool logSettings, bool zones, bool allowedZones, bool blockedZones, bool blockLists, bool apps, bool scopes, bool stats, bool logs, bool deleteExistingFiles, UserSession implantSession = null, bool isConfigTransfer = false)
        {
            await using (ZipArchive backupZip = new ZipArchive(zipStream, ZipArchiveMode.Read, false, Encoding.UTF8))
            {
                if (isConfigTransfer && authConfig && _authManager.HasManagedAuthSettings &&
                    backupZip.GetEntry("auth.config") is ZipArchiveEntry managedAuth)
                {
                    using Stream authConfiguration = managedAuth.Open();
                    _authManager.CheckManifestRestoreOwnership(authConfiguration);
                }

                if (isConfigTransfer)
                {
                    if (apps)
                        _dnsServer.DnsApplicationManager.CheckManifestRestore(backupZip, deleteExistingFiles, isConfigTransfer: true);
                    CheckManagedDomainLists(backupZip, allowedZones, blockedZones, isConfigTransfer: true);
                }

                if (isConfigTransfer && dnsSettings && (_dnsServer.HasManagedClusterDnsSettings || _dnsServer.HasManagedDnsListenerPolicy || _dnsServer.HasManagedDnsBindings || _dnsServer.HasManagedDnsCertificate || _dnsServer.HasManagedTsigKeys) &&
                    backupZip.GetEntry("dns.config") is ZipArchiveEntry dnsEntry)
                {
                    bool checkDnsBody;
                    using (Stream dnsConfiguration = dnsEntry.Open())
                        checkDnsBody = CheckRestoreManifestDnsSettings(dnsConfiguration, isConfigTransfer: true);
                    if (checkDnsBody)
                    {
                        using Stream dnsConfiguration = dnsEntry.Open();
                        _dnsServer.CheckRestoreManifestDnsBody(dnsConfiguration, isConfigTransfer: true);
                    }
                }

                if (isConfigTransfer && blockLists && _dnsServer.BlockListZoneManager.HasManagedSettings &&
                    !_dnsServer.BlockListZoneManager.ManifestOwnershipFromPrimary &&
                    backupZip.GetEntry("blocklist.config") is ZipArchiveEntry managedBlockListEntry)
                {
                    using Stream blockListConfiguration = managedBlockListEntry.Open();
                    _dnsServer.BlockListZoneManager.CheckRestoreManifestOwnership(blockListConfiguration);
                }

                bool restartWebService = false;

                try
                {
                    if (logSettings && !isConfigTransfer)
                    {
                        ZipArchiveEntry entry = backupZip.GetEntry("log.config");
                        if (entry is not null)
                        {
                            //dynamically load and apply logger config
                            await using (Stream stream = entry.Open())
                            {
                                _log.LoadConfig(stream);
                            }
                        }
                    }

                    if (logs && !isConfigTransfer)
                    {
                        _log.BulkManipulateLogFiles(async delegate ()
                        {
                            if (deleteExistingFiles)
                            {
                                //delete existing log files
                                string[] logFiles = Directory.GetFiles(_log.LogFolderAbsolutePath, "*.log", SearchOption.TopDirectoryOnly);

                                foreach (string logFile in logFiles)
                                {
                                    try
                                    {
                                        File.Delete(logFile);
                                    }
                                    catch (Exception ex)
                                    {
                                        _log.Write(ex);
                                    }
                                }
                            }

                            //extract log files from backup
                            foreach (ZipArchiveEntry entry in backupZip.Entries)
                            {
                                if (entry.FullName.StartsWith("logs/", StringComparison.Ordinal))
                                {
                                    try
                                    {
                                        await entry.ExtractToFileAsync(Path.Combine(_log.LogFolderAbsolutePath, entry.Name), true);
                                    }
                                    catch (Exception ex)
                                    {
                                        _log.Write(ex);
                                    }
                                }
                            }
                        });
                    }

                    if (authConfig)
                    {
                        ZipArchiveEntry entry = backupZip.GetEntry("auth.config");
                        if (entry is not null)
                        {
                            //dynamically load and apply auth config
                            await using (Stream stream = entry.Open())
                            {
                                _authManager.LoadConfig(stream, isConfigTransfer, out restartWebService, implantSession);
                            }
                        }
                    }

                    if (clusterConfig && !isConfigTransfer)
                    {
                        ZipArchiveEntry entry = backupZip.GetEntry("cluster.config");
                        if (entry is not null)
                        {
                            //dynamically load and apply cluster config
                            await using (Stream stream = entry.Open())
                            {
                                _clusterManager.LoadConfig(stream);
                            }
                        }
                    }

                    if ((webServiceSettings || dnsSettings) && !isConfigTransfer)
                    {
                        //extract any certs
                        foreach (ZipArchiveEntry certEntry in backupZip.Entries)
                        {
                            if (certEntry.FullName.StartsWith("apps/", StringComparison.Ordinal))
                                continue;

                            if (certEntry.FullName.EndsWith(".pfx", StringComparison.OrdinalIgnoreCase) || certEntry.FullName.EndsWith(".p12", StringComparison.OrdinalIgnoreCase))
                            {
                                try
                                {
                                    string certFile = Path.GetFullPath(Path.Combine(_configFolder, certEntry.FullName));
                                    if (!certFile.StartsWith(_configFolder.TrimEnd(['/', '\\']) + Path.DirectorySeparatorChar, Environment.OSVersion.Platform == PlatformID.Win32NT ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
                                        throw new IOException("Extracting Zip entry would have resulted in a file outside the specified destination directory.");

                                    Directory.CreateDirectory(Path.GetDirectoryName(certFile));

                                    await certEntry.ExtractToFileAsync(certFile, true);
                                }
                                catch (Exception ex)
                                {
                                    _log.Write(ex);
                                }
                            }
                        }
                    }

                    bool updateCertInClusterPrimaryZone = false;

                    if (webServiceSettings && !isConfigTransfer)
                    {
                        ZipArchiveEntry entry = backupZip.GetEntry("webservice.config");
                        if (entry is not null)
                        {
                            //dynamically load and apply web service config
                            await using (Stream stream = entry.Open())
                            {
                                LoadConfig(stream);
                            }

                            //cert may have changed so update cert in cluster primary zone when restoring
                            updateCertInClusterPrimaryZone = true;
                        }
                    }

                    if (dnsSettings)
                    {
                        ZipArchiveEntry entry = backupZip.GetEntry("dns.config");
                        if (entry is not null)
                        {
                            try
                            {
                                //dynamically load and apply DNS settings config
                                await using (Stream stream = entry.Open())
                                {
                                    _dnsServer.LoadConfig(stream, isConfigTransfer);
                                }
                            }
                            catch (InvalidDataException)
                            {
                                if (isConfigTransfer)
                                    throw; //config being synced; throw same exception

                                //most probably an attempt to restore old config
                                await using (Stream stream = entry.Open())
                                {
                                    if (!TryLoadOldConfigFrom(stream))
                                        throw; //was not old config file so must be corrupt config file; throw same exception

                                    _log.Write("Old DNS config file was restored successfully.");

                                    lock (_saveLock)
                                    {
                                        //explicitly save webservice.config
                                        SaveConfigFileInternal();
                                    }
                                }
                            }
                        }
                    }

                    if (zones)
                    {
                        if (isConfigTransfer)
                        {
                            //backup DNSSEC private keys into Secondary zones that are member zone of the secondary cluster catalog zone
                            AuthZoneInfo secondaryClusterCatalogZoneInfo = _dnsServer.AuthZoneManager.GetAuthZoneInfo("cluster-catalog." + _clusterManager.ClusterDomain);
                            if ((secondaryClusterCatalogZoneInfo is not null) && (secondaryClusterCatalogZoneInfo.Type == AuthZoneType.SecondaryCatalog))
                            {
                                HashSet<string> memberZoneNames = new HashSet<string>((secondaryClusterCatalogZoneInfo.ApexZone as SecondaryCatalogZone).GetAllMemberZoneNames());

                                foreach (ZipArchiveEntry entry in backupZip.Entries)
                                {
                                    if (!entry.FullName.StartsWith("zones/", StringComparison.Ordinal) || !entry.FullName.EndsWith(".keys", StringComparison.Ordinal))
                                        continue;

                                    string memberZoneName = Path.GetFileNameWithoutExtension(entry.Name);

                                    AuthZoneInfo memberZoneInfo = _dnsServer.AuthZoneManager.GetAuthZoneInfo(memberZoneName);
                                    if (memberZoneInfo is null)
                                        continue; //no such zone exists; ignore

                                    if (memberZoneInfo.Type != AuthZoneType.Secondary)
                                        continue; //not a Secondary zone; ignore

                                    SecondaryZone memberZone = memberZoneInfo.ApexZone as SecondaryZone;

                                    if (memberZoneNames.Contains(memberZoneName))
                                    {
                                        //read DNSSEC private keys
                                        IReadOnlyCollection<DnssecPrivateKey> dnssecPrivateKeys;

                                        await using (Stream s = entry.Open())
                                        {
                                            dnssecPrivateKeys = AuthZoneInfo.ReadDnssecPrivateKeysFrom(new BinaryReader(s));
                                        }

                                        //backup DNSSEC private keys
                                        memberZone.DnssecPrivateKeys = dnssecPrivateKeys;
                                        _dnsServer.AuthZoneManager.SaveZoneFile(memberZoneInfo.Name);
                                    }
                                    else
                                    {
                                        //not a member zone of the secondary cluster catalog zone
                                        if (memberZone.DnssecPrivateKeys is not null)
                                        {
                                            //found old backup keys; remove them
                                            memberZone.DnssecPrivateKeys = null;
                                            _dnsServer.AuthZoneManager.SaveZoneFile(memberZoneInfo.Name);
                                        }
                                    }
                                }
                            }
                        }
                        else
                        {
                            //restore zones
                            if (deleteExistingFiles)
                            {
                                //delete existing zone files
                                string[] zoneFiles = Directory.GetFiles(Path.Combine(_configFolder, "zones"), "*.zone", SearchOption.TopDirectoryOnly);

                                foreach (string zoneFile in zoneFiles)
                                {
                                    try
                                    {
                                        File.Delete(zoneFile);
                                    }
                                    catch (Exception ex)
                                    {
                                        _log.Write(ex);
                                    }
                                }
                            }

                            //extract zone files from backup
                            foreach (ZipArchiveEntry entry in AuthZoneManager.GetZoneBackupEntries(backupZip))
                            {
                                try
                                {
                                    await entry.ExtractToFileAsync(Path.Combine(_configFolder, "zones", entry.Name), true);
                                }
                                catch (Exception ex)
                                {
                                    _log.Write(ex);
                                }
                            }

                            //reload zones
                            _dnsServer.AuthZoneManager.LoadAllZoneFiles();
                            InspectAndFixZonePermissions();
                        }
                    }

                    if (updateCertInClusterPrimaryZone)
                    {
                        //cert may have changed so update cert in cluster primary zone when restoring
                        if (_clusterManager.ClusterInitialized)
                        {
                            try
                            {
                                _clusterManager.UpdateSelfNodeUrlAndCertificate();
                            }
                            catch (Exception ex)
                            {
                                _log.Write(ex);
                            }
                        }
                    }

                    if (allowedZones)
                    {
                        ZipArchiveEntry entry = backupZip.GetEntry("allowed.config");
                        if (entry is not null)
                        {
                            //dynamically load and apply allowed zones config
                            await using (Stream stream = entry.Open())
                            {
                                _dnsServer.AllowedZoneManager.LoadAllowedZone(stream, isConfigTransfer);
                            }
                        }
                    }

                    if (blockedZones)
                    {
                        ZipArchiveEntry entry = backupZip.GetEntry("blocked.config");
                        if (entry is not null)
                        {
                            //dynamically load and apply blocked zones config
                            await using (Stream stream = entry.Open())
                            {
                                _dnsServer.BlockedZoneManager.LoadBlockedZone(stream, isConfigTransfer);
                            }
                        }
                    }

                    if (blockLists)
                    {
                        if (!isConfigTransfer)
                        {
                            if (deleteExistingFiles)
                            {
                                //delete existing block list files
                                string[] blockListFiles = Directory.GetFiles(Path.Combine(_configFolder, "blocklists"), "*", SearchOption.TopDirectoryOnly);

                                foreach (string blockListFile in blockListFiles)
                                {
                                    try
                                    {
                                        File.Delete(blockListFile);
                                    }
                                    catch (Exception ex)
                                    {
                                        _log.Write(ex);
                                    }
                                }
                            }

                            //extract block list files from backup
                            foreach (ZipArchiveEntry entry in backupZip.Entries)
                            {
                                if (entry.FullName.StartsWith("blocklists/", StringComparison.Ordinal))
                                {
                                    try
                                    {
                                        await entry.ExtractToFileAsync(Path.Combine(_configFolder, "blocklists", entry.Name), true);
                                    }
                                    catch (IOException)
                                    {
                                        //ignore since file may be loading in another thread
                                    }
                                    catch (Exception ex)
                                    {
                                        _log.Write(ex);
                                    }
                                }
                            }
                        }

                        ZipArchiveEntry blockListConfigEntry = backupZip.GetEntry("blocklist.config");
                        if (blockListConfigEntry is not null)
                        {
                            //dynamically load and apply block list config
                            await using (Stream stream = blockListConfigEntry.Open())
                            {
                                _dnsServer.BlockListZoneManager.LoadConfig(stream, isConfigTransfer);
                            }
                        }
                    }

                    if (apps)
                    {
                        if (isConfigTransfer)
                        {
                            //install or update app from zip
                            foreach (ZipArchiveEntry entry in backupZip.Entries)
                            {
                                if (!entry.FullName.StartsWith("apps/", StringComparison.Ordinal))
                                    continue;

                                string[] fullNameParts = entry.FullName.Split('/');
                                if (fullNameParts.Length < 3)
                                    continue;

                                string applicationName = fullNameParts[1];
                                string applicationZipFile = fullNameParts[2];

                                if (!applicationZipFile.Equals(applicationName + ".zip", StringComparison.Ordinal))
                                    continue;

                                if (_dnsServer.DnsApplicationManager.Applications.TryGetValue(applicationName, out _))
                                {
                                    //update existing app
                                    await using (Stream s = entry.Open())
                                    {
                                        await _dnsServer.DnsApplicationManager.UpdateApplicationAsync(applicationName, s);
                                    }
                                }
                                else
                                {
                                    //install new app
                                    await using (Stream s = entry.Open())
                                    {
                                        await _dnsServer.DnsApplicationManager.InstallApplicationAsync(applicationName, s);
                                    }
                                }
                            }

                            //update app config
                            foreach (ZipArchiveEntry entry in backupZip.Entries)
                            {
                                if (!entry.FullName.StartsWith("apps/", StringComparison.Ordinal))
                                    continue;

                                string[] fullNameParts = entry.FullName.Split('/');
                                if (fullNameParts.Length < 3)
                                    continue;

                                string applicationName = fullNameParts[1];
                                string configFile = fullNameParts[2];

                                if (!configFile.Equals("dnsApp.config", StringComparison.Ordinal))
                                    continue;

                                if (_dnsServer.DnsApplicationManager.Applications.TryGetValue(applicationName, out DnsApplication application))
                                {
                                    string config;

                                    await using (Stream s = entry.Open())
                                    {
                                        using (StreamReader sR = new StreamReader(s, true))
                                        {
                                            config = await sR.ReadToEndAsync();
                                        }
                                    }

                                    try
                                    {
                                        await application.SetConfigAsync(config);
                                    }
                                    catch (Exception ex)
                                    {
                                        _log.Write(ex);
                                    }
                                }
                            }

                            //remove apps that are not in the zip file
                            HashSet<string> existingApplications = new HashSet<string>();

                            foreach (ZipArchiveEntry entry in backupZip.Entries)
                            {
                                if (!entry.FullName.StartsWith("apps/", StringComparison.Ordinal))
                                    continue;

                                string[] fullNameParts = entry.FullName.Split('/');
                                if (fullNameParts.Length < 2)
                                    continue;

                                string applicationName = fullNameParts[1];

                                existingApplications.Add(applicationName);
                            }

                            foreach (KeyValuePair<string, DnsApplication> application in _dnsServer.DnsApplicationManager.Applications)
                            {
                                if (!existingApplications.Contains(application.Key))
                                    await _dnsServer.DnsApplicationManager.UninstallApplicationAsync(application.Key);
                            }
                        }
                        else
                        {
                            //unload apps
                            await _dnsServer.DnsApplicationManager.UnloadAllApplicationsAsync();

                            if (deleteExistingFiles)
                            {
                                //delete existing apps
                                string appFolder = Path.Combine(_configFolder, "apps");
                                if (Directory.Exists(appFolder))
                                {
                                    try
                                    {
                                        Directory.Delete(appFolder, true);
                                    }
                                    catch (Exception ex)
                                    {
                                        _log.Write(ex);
                                    }
                                }

                                //create apps folder
                                Directory.CreateDirectory(appFolder);
                            }

                            //extract apps files from backup
                            foreach (ZipArchiveEntry entry in backupZip.Entries)
                            {
                                if (entry.FullName.StartsWith("apps/", StringComparison.Ordinal))
                                {
                                    string filePath = Path.GetFullPath(Path.Combine(_configFolder, entry.FullName));
                                    if (!filePath.StartsWith(_configFolder.TrimEnd(['/', '\\']) + Path.DirectorySeparatorChar, Environment.OSVersion.Platform == PlatformID.Win32NT ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal))
                                        throw new IOException("Extracting Zip entry would have resulted in a file outside the specified destination directory.");

                                    if ((entry.Length == 0) && (entry.Name.Length == 0) && entry.FullName.EndsWith('/'))
                                    {
                                        //directory entry
                                        Directory.CreateDirectory(filePath);
                                    }
                                    else
                                    {
                                        //file entry
                                        Directory.CreateDirectory(Path.GetDirectoryName(filePath));

                                        try
                                        {
                                            await entry.ExtractToFileAsync(filePath, true);
                                        }
                                        catch (Exception ex)
                                        {
                                            _log.Write(ex);
                                        }
                                    }
                                }
                            }

                            //reload apps
                            await _dnsServer.DnsApplicationManager.LoadAllApplicationsAsync();
                        }
                    }

                    if (scopes && !isConfigTransfer)
                    {
                        //stop dhcp server
                        _dhcpServer.Stop();

                        try
                        {
                            if (deleteExistingFiles)
                            {
                                //delete existing scope files
                                string[] scopeFiles = Directory.GetFiles(Path.Combine(_configFolder, "scopes"), "*.scope", SearchOption.TopDirectoryOnly);

                                foreach (string scopeFile in scopeFiles)
                                {
                                    try
                                    {
                                        File.Delete(scopeFile);
                                    }
                                    catch (Exception ex)
                                    {
                                        _log.Write(ex);
                                    }
                                }
                            }

                            //extract scope files from backup
                            foreach (ZipArchiveEntry entry in DhcpServer.GetScopeBackupEntries(backupZip))
                            {
                                try
                                {
                                    await entry.ExtractToFileAsync(Path.Combine(_configFolder, "scopes", entry.Name), true);
                                }
                                catch (Exception ex)
                                {
                                    _log.Write(ex);
                                }
                            }
                        }
                        finally
                        {
                            //start dhcp server
                            _dhcpServer.Start();
                        }
                    }

                    if (stats && !isConfigTransfer)
                    {
                        if (deleteExistingFiles)
                        {
                            //delete existing stats files
                            string[] hourlyStatsFiles = Directory.GetFiles(Path.Combine(_configFolder, "stats"), "*.stat", SearchOption.TopDirectoryOnly);

                            foreach (string hourlyStatsFile in hourlyStatsFiles)
                            {
                                try
                                {
                                    File.Delete(hourlyStatsFile);
                                }
                                catch (Exception ex)
                                {
                                    _log.Write(ex);
                                }
                            }

                            string[] dailyStatsFiles = Directory.GetFiles(Path.Combine(_configFolder, "stats"), "*.dstat", SearchOption.TopDirectoryOnly);

                            foreach (string dailyStatsFile in dailyStatsFiles)
                            {
                                try
                                {
                                    File.Delete(dailyStatsFile);
                                }
                                catch (Exception ex)
                                {
                                    _log.Write(ex);
                                }
                            }
                        }

                        //extract stats files from backup
                        foreach (ZipArchiveEntry entry in backupZip.Entries)
                        {
                            if (entry.FullName.StartsWith("stats/", StringComparison.Ordinal))
                            {
                                try
                                {
                                    await entry.ExtractToFileAsync(Path.Combine(_configFolder, "stats", entry.Name), true);
                                }
                                catch (Exception ex)
                                {
                                    _log.Write(ex);
                                }
                            }
                        }

                        //reload stats
                        _dnsServer.StatsManager.ReloadStats();
                    }
                }
                finally
                {
                    if (isConfigTransfer && restartWebService)
                        RestartService(false, true);
                }
            }
        }

        private static async Task CreateBackupEntryFromSharedFileAsync(ZipArchive backupZip, string sourceFileName, string entryName)
        {
            await using (FileStream fS = new FileStream(sourceFileName, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
            {
                ZipArchiveEntry entry = backupZip.CreateEntry(entryName);

                DateTime lastWrite = File.GetLastWriteTime(sourceFileName);

                // If file to be archived has an invalid last modified time, use the first datetime representable in the Zip timestamp format
                // (midnight on January 1, 1980):
                if (lastWrite.Year < 1980 || lastWrite.Year > 2107)
                    lastWrite = new DateTime(1980, 1, 1, 0, 0, 0);

                entry.LastWriteTime = lastWrite;

                await using (Stream sE = entry.Open())
                {
                    await fS.CopyToAsync(sE);
                }
            }
        }

        #endregion

        #region private

        private void RestartService(bool restartDnsService, bool restartWebService)
        {
            RestartService(restartDnsService, restartWebService, _webServiceLocalAddresses, _webServiceHttpPort, _webServiceTlsPort);
        }

        private void RestartService(bool restartDnsService, bool restartWebService, IReadOnlyList<IPAddress> oldWebServiceLocalAddresses, int oldWebServiceHttpPort, int oldWebServiceTlsPort)
        {
            ThreadPool.QueueUserWorkItem(async delegate (object state)
            {
                if (restartWebService)
                {
                    try
                    {
                        await Task.Delay(2000); //wait for this HTTP response to be delivered before stopping web server

                        _log.Write("Attempting to restart web service.");

                        try
                        {
                            await _settingsApi.WithConfigurationLockAsync(async () =>
                            {
                                await StopWebServiceAsync();
                                await TryStartWebServiceAsync(oldWebServiceLocalAddresses, oldWebServiceHttpPort, oldWebServiceTlsPort);
                            });

                            _log.Write("Web service was restarted successfully.");
                        }
                        catch (Exception ex)
                        {
                            _log.Write("Failed to restart web service.", ex);
                        }

                        //update cluster node URL to reflect latest TLS port
                        if (_clusterManager.ClusterInitialized)
                            _clusterManager.UpdateSelfNodeUrlAndCertificate();
                    }
                    catch (Exception ex)
                    {
                        _log.Write(ex);
                    }
                }

                if (restartDnsService)
                {
                    try
                    {
                        _log.Write("Attempting to restart DNS service.");

                        await _settingsApi.WithConfigurationLockAsync(async () =>
                        {
                            await _dnsServer.StopAsync();
                            await _dnsServer.StartAsync();
                        });

                        _log.Write("DNS service was restarted successfully.");
                    }
                    catch (Exception ex)
                    {
                        _log.Write("Failed to restart DNS service.", ex);
                    }
                }
            });
        }

        #endregion

        #region server version

        private string GetServerVersion()
        {
            return GetCleanVersion(_currentVersion);
        }

        internal static string GetCleanVersion(Version version)
        {
            string strVersion = version.Major + "." + version.Minor;

            if (version.Build > 0)
                strVersion += "." + version.Build;

            if (version.Revision > 0)
                strVersion += "." + version.Revision;

            return strVersion;
        }

        #endregion

        #region web service

        internal static IReadOnlyList<IPAddress> NormalizeWebLocalAddresses(IReadOnlyList<IPAddress> addresses)
        {
            return WebUtilities.GetValidKestrelLocalAddresses(addresses.Count == 0 ? [IPAddress.Any, IPAddress.IPv6Any] : addresses);
        }

        private async Task TryStartWebServiceAsync(IReadOnlyList<IPAddress> oldWebServiceLocalAddresses, int oldWebServiceHttpPort, int oldWebServiceTlsPort)
        {
            try
            {
                _webServiceLocalAddresses = WebUtilities.GetValidKestrelLocalAddresses(_webServiceLocalAddresses);

                await StartWebServiceAsync(false);
                return;
            }
            catch (Exception ex)
            {
                _log.Write("Web Service failed to start.", ex);
            }

            _log.Write("Attempting to revert Web Service end point changes ...");

            try
            {
                _webServiceLocalAddresses = WebUtilities.GetValidKestrelLocalAddresses(oldWebServiceLocalAddresses);
                _webServiceHttpPort = oldWebServiceHttpPort;
                _webServiceTlsPort = oldWebServiceTlsPort;

                await StartWebServiceAsync(false);

                lock (_saveLock)
                {
                    SaveConfigFileInternal(); //save reverted changes
                }

                return;
            }
            catch (Exception ex2)
            {
                _log.Write("Web Service failed to start.", ex2);
            }

            _log.Write("Attempting to start Web Service on ANY (0.0.0.0) fallback address...");

            try
            {
                _webServiceLocalAddresses = [IPAddress.Any];

                await StartWebServiceAsync(true);
                return;
            }
            catch (Exception ex3)
            {
                _log.Write("Web Service failed to start.", ex3);
            }

            _log.Write("Attempting to start Web Service on loopback (127.0.0.1) fallback address...");

            _webServiceLocalAddresses = [IPAddress.Loopback];

            await StartWebServiceAsync(true);
        }

        private string ResolveWebRoot(bool logMissingEnvironment = false)
        {
            if (_webRootOverride is not null)
            {
                if (_webRootOverride.Length == 0)
                    return null;
                if (!Directory.Exists(_webRootOverride))
                    throw new InvalidDataException("/web/rootPath: The configured directory does not exist.");
                return _webRootOverride;
            }

            string path = Environment.GetEnvironmentVariable("DNS_SERVER_WEB_SERVICE_WWW_FOLDER_PATH");
            if (string.IsNullOrEmpty(path))
                return null;
            if (Directory.Exists(path))
                return Path.TrimEndingDirectorySeparator(Path.GetFullPath(path));
            if (logMissingEnvironment)
                _log.Write("Web Service is falling back to the default web root folder since the folder configured by the DNS_SERVER_WEB_SERVICE_WWW_FOLDER_PATH environment variable does not exist: " + path);
            return null;
        }

        private async Task StartWebServiceAsync(bool httpOnlyMode, WebListeners manifestListeners = default, ConfigurationSso.Settings sso = null)
        {
            WebApplicationBuilder builder = WebApplication.CreateBuilder();

            sso ??= _authManager.GetManifestSsoSettings();
            bool ssoEnabled = sso.Enabled && sso.Authority is not null && sso.ClientId is not null && sso.ClientSecret is not null;
            if (ssoEnabled)
            {
                builder.Services.AddAuthentication(delegate (AuthenticationOptions options)
                {
                    options.DefaultScheme = BearerTokenDefaults.AuthenticationScheme;
                    options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
                })
                .AddBearerToken()
                .AddOpenIdConnect(delegate (OpenIdConnectOptions options)
                {
                    options.Authority = sso.Authority.AbsoluteUri;
                    options.ClientId = sso.ClientId;
                    options.ClientSecret = sso.ClientSecret;
                    options.RequireHttpsMetadata = false;
                    options.ResponseType = OpenIdConnectResponseType.Code;
                    options.ResponseMode = OpenIdConnectResponseMode.FormPost;

                    _ssoHttpHandler?.Dispose();
                    _ssoHttpClient?.Dispose();

                    _ssoHttpHandler = new HttpClientNetworkHandler
                    {
                        Proxy = _dnsServer.Proxy,
                        NetworkType = HttpClientNetworkHandler.GetNetworkType(_dnsServer.IPv6Mode),
                        DnsClient = _dnsServer
                    };

                    _ssoHttpClient = new HttpClient(_ssoHttpHandler);

                    options.BackchannelHttpHandler = _ssoHttpHandler;
                    options.Backchannel = _ssoHttpClient;

                    options.Scope.Clear();

                    foreach (string scope in sso.Scopes)
                        options.Scope.Add(scope);

                    //setup user info endpoint json key map for supported claim types
                    options.ClaimActions.MapUniqueJsonKey("sub", "sub");
                    options.ClaimActions.MapUniqueJsonKey("email", "email");
                    options.ClaimActions.MapUniqueJsonKey("preferred_username", "preferred_username");
                    options.ClaimActions.MapUniqueJsonKey("upn", "upn");
                    options.ClaimActions.MapUniqueJsonKey("nickname", "nickname");
                    options.ClaimActions.MapUniqueJsonKey("name", "name");
                    options.ClaimActions.MapUniqueJsonKey("given_name", "given_name");
                    options.ClaimActions.MapJsonKey("groups", "groups");
                    options.ClaimActions.MapJsonKey("roles", "roles");

                    options.CallbackPath = new PathString("/sso/callback");

                    if (sso.MetadataAddress is not null)
                        options.ConfigurationManager = new ConfigurationManager<OpenIdConnectConfiguration>(sso.MetadataAddress.AbsoluteUri, new OpenIdConnectConfigurationRetriever(), new HttpDocumentRetriever(_ssoHttpClient) { RequireHttps = false });

                    options.Events = new OpenIdConnectEvents
                    {
                        OnRedirectToIdentityProvider = async delegate (RedirectContext context)
                        {
                            OpenIdConnectConfiguration configuration = await context.Options.ConfigurationManager.GetConfigurationAsync(context.HttpContext.RequestAborted);

                            context.Options.GetClaimsFromUserInfoEndpoint = !string.IsNullOrEmpty(configuration.UserInfoEndpoint);
                        },
                        OnTicketReceived = async delegate (TicketReceivedContext context)
                        {
                            context.HandleResponse();

                            if ((context.Principal is null) || (context.Principal.Identity is null) || !context.Principal.Identity.IsAuthenticated)
                                context.Response.Redirect("/#error=" + Uri.EscapeDataString("SSO authentication failed. Please try again."));
                            else
                                await _authApi.SsoLoginFinalizeAsync(context.HttpContext, context.Principal);
                        },
                        OnAuthenticationFailed = delegate (AuthenticationFailedContext context)
                        {
                            _log.Write(GetRemoteEndPoint(context.HttpContext), context.Exception);

                            context.HandleResponse();
                            context.Response.Redirect("/#error=" + Uri.EscapeDataString("SSO authentication failed. Please try again."));

                            return Task.CompletedTask;
                        },
                        OnRemoteFailure = delegate (RemoteFailureContext context)
                        {
                            if (context.Failure is not null)
                                _log.Write(GetRemoteEndPoint(context.HttpContext), context.Failure);

                            context.HandleResponse();
                            context.Response.Redirect("/#error=" + Uri.EscapeDataString("SSO remote failure. Please contact your administrator."));

                            return Task.CompletedTask;
                        }
                    };
                });

                builder.Services.AddAuthorization();
            }

            builder.Environment.ContentRootFileProvider = new PhysicalFileProvider(_appFolder)
            {
                UseActivePolling = true,
                UsePollingFileWatcher = true
            };

            string activeWebRoot = ResolveWebRoot(logMissingEnvironment: true);
            string wwwFolderPath = activeWebRoot ?? Path.Combine(_appFolder, "www");

            builder.Environment.WebRootFileProvider = new PhysicalFileProvider(wwwFolderPath)
            {
                UseActivePolling = true,
                UsePollingFileWatcher = true
            };

            builder.Services.AddResponseCompression(delegate (ResponseCompressionOptions options)
            {
                options.EnableForHttps = true;
            });

            builder.WebHost.ConfigureKestrel(delegate (WebHostBuilderContext context, KestrelServerOptions serverOptions)
            {
                //http
                foreach (IPAddress webServiceLocalAddress in _webServiceLocalAddresses)
                    serverOptions.Listen(webServiceLocalAddress, _webServiceHttpPort);

                //http unix socket
                if (!httpOnlyMode && _webServiceEnableHttpUnixSocket && (_webServiceHttpUnixSocket is not null))
                {
                    try
                    {
                        if (!manifestListeners.HttpSocket.HasValues && (_managedWebListeners & ManagedWebHttpSocket) == 0 &&
                            File.Exists(_webServiceHttpUnixSocket))
                            File.Delete(_webServiceHttpUnixSocket);
                    }
                    catch (Exception ex)
                    {
                        _log.Write(ex);
                    }

                    serverOptions.ListenUnixSocket(_webServiceHttpUnixSocket);
                }

                //https unix socket
                if (!httpOnlyMode && _webServiceEnableTlsUnixSocket && (_webServiceTlsUnixSocket is not null) && (_webServiceSslServerAuthenticationOptions is not null))
                {
                    try
                    {
                        if (!manifestListeners.TlsSocket.HasValues && (_managedWebListeners & ManagedWebTlsSocket) == 0 &&
                            File.Exists(_webServiceTlsUnixSocket))
                            File.Delete(_webServiceTlsUnixSocket);
                    }
                    catch (Exception ex)
                    {
                        _log.Write(ex);
                    }

                    serverOptions.ListenUnixSocket(_webServiceTlsUnixSocket, delegate (ListenOptions listenOptions)
                    {
                        if (IsHttp2Supported())
                            listenOptions.Protocols = HttpProtocols.Http1AndHttp2;
                        else
                            listenOptions.Protocols = HttpProtocols.Http1;

                        listenOptions.UseHttps(delegate (SslStream stream, SslClientHelloInfo clientHelloInfo, object state, CancellationToken cancellationToken)
                        {
                            return ValueTask.FromResult(_webServiceSslServerAuthenticationOptions);
                        }, null);
                    });
                }

                //https
                if (!httpOnlyMode && _webServiceEnableTls && (_webServiceSslServerAuthenticationOptions is not null))
                {
                    foreach (IPAddress webServiceLocalAddress in _webServiceLocalAddresses)
                    {
                        serverOptions.Listen(webServiceLocalAddress, _webServiceTlsPort, delegate (ListenOptions listenOptions)
                        {
                            if (_webServiceEnableHttp3)
                                listenOptions.Protocols = HttpProtocols.Http1AndHttp2AndHttp3;
                            else if (IsHttp2Supported())
                                listenOptions.Protocols = HttpProtocols.Http1AndHttp2;
                            else
                                listenOptions.Protocols = HttpProtocols.Http1;

                            listenOptions.UseHttps(delegate (SslStream stream, SslClientHelloInfo clientHelloInfo, object state, CancellationToken cancellationToken)
                            {
                                return ValueTask.FromResult(_webServiceSslServerAuthenticationOptions);
                            }, null);
                        });
                    }
                }

                serverOptions.AddServerHeader = false;
                serverOptions.Limits.MaxRequestBodySize = int.MaxValue;
            });

            builder.Services.Configure(delegate (FormOptions options)
            {
                options.MultipartBodyLengthLimit = int.MaxValue;
            });

            builder.Logging.ClearProviders();

            _webService = builder.Build();

            if (ssoEnabled)
            {
                _webService.Use(delegate (HttpContext context, Func<Task> next)
                {
                    //to allow OIDC to generate correct redirect URI for the callback
                    IPAddress remoteIP = context.Connection.RemoteIpAddress;
                    if ((remoteIP is not null) && NetworkAccessControl.IsAddressAllowed(remoteIP, _webServiceReverseProxyAddresses))
                    {
                        string strScheme = context.Request.Headers["X-Forwarded-Proto"];
                        if (!string.IsNullOrEmpty(strScheme))
                            context.Request.Scheme = strScheme;

                        string strHost = context.Request.Headers["X-Forwarded-Host"];
                        if (!string.IsNullOrEmpty(strHost))
                            context.Request.Host = new HostString(strHost);

                        string strPathBase = context.Request.Headers["X-Forwarded-Prefix"];
                        if (!string.IsNullOrEmpty(strPathBase))
                            context.Request.PathBase = new PathString(strPathBase);
                    }

                    return next();
                });

                _webService.UseAuthentication();
                _webService.UseAuthorization();
            }

            _webService.UseResponseCompression();

            if (!httpOnlyMode && _webServiceHttpToTlsRedirect && _webServiceEnableTls && (_webServiceSslServerAuthenticationOptions is not null))
                _webService.Use(WebServiceHttpsRedirectionMiddleware);

            _webService.UseDefaultFiles();
            _webService.UseStaticFiles(new StaticFileOptions()
            {
                OnPrepareResponse = delegate (StaticFileResponseContext ctx)
                {
                    ctx.Context.Response.Headers["X-Robots-Tag"] = "noindex, nofollow";
                    ctx.Context.Response.Headers.CacheControl = "no-cache";
                    ctx.Context.Response.Headers.XContentTypeOptions = "nosniff";
                    ctx.Context.Response.Headers["Referrer-Policy"] = "same-origin";
                    ctx.Context.Response.Headers.ContentSecurityPolicy =
                        "default-src 'self'; " +
                        "script-src 'self' 'unsafe-inline' 'unsafe-eval'; " +
                        "style-src 'self' 'unsafe-inline'; " +
                        "img-src 'self' data:; " +
                        $"frame-ancestors {_webServiceCspFrameAncestorsHeader};";

                    if (_webServiceCspFrameAncestorsHeader.Equals("'none'", StringComparison.OrdinalIgnoreCase))
                        ctx.Context.Response.Headers.XFrameOptions = "DENY";
                },
                ServeUnknownFileTypes = true
            });

            ConfigureWebServiceRoutes();

            try
            {
                await _webService.StartAsync();
            _activeWebRoot = activeWebRoot;

                foreach (IPAddress webServiceLocalAddress in _webServiceLocalAddresses)
                {
                    _log.Write(new IPEndPoint(webServiceLocalAddress, _webServiceHttpPort), "Http", "Web Service was bound successfully.");

                    if (!httpOnlyMode && _webServiceEnableTls && (_webServiceSslServerAuthenticationOptions is not null))
                        _log.Write(new IPEndPoint(webServiceLocalAddress, _webServiceTlsPort), "Https", "Web Service was bound successfully.");
                }

                if (!httpOnlyMode && _webServiceEnableHttpUnixSocket && (_webServiceHttpUnixSocket is not null))
                    _log.Write(new UnixDomainSocketEndPoint(_webServiceHttpUnixSocket), "HttpUnix", "Web Service was bound successfully.");

                if (!httpOnlyMode && _webServiceEnableTlsUnixSocket && (_webServiceTlsUnixSocket is not null) && (_webServiceSslServerAuthenticationOptions is not null))
                    _log.Write(new UnixDomainSocketEndPoint(_webServiceTlsUnixSocket), "HttpsUnix", "Web Service was bound successfully.");
            }
            catch
            {
                await StopWebServiceAsync();

                foreach (IPAddress webServiceLocalAddress in _webServiceLocalAddresses)
                {
                    _log.Write(new IPEndPoint(webServiceLocalAddress, _webServiceHttpPort), "Http", "Web Service failed to bind.");

                    if (!httpOnlyMode && _webServiceEnableTls && (_webServiceSslServerAuthenticationOptions is not null))
                        _log.Write(new IPEndPoint(webServiceLocalAddress, _webServiceTlsPort), "Https", "Web Service failed to bind.");
                }

                if (!httpOnlyMode && _webServiceEnableHttpUnixSocket && (_webServiceHttpUnixSocket is not null))
                    _log.Write(new UnixDomainSocketEndPoint(_webServiceHttpUnixSocket), "HttpUnix", "Web Service failed to bind.");

                if (!httpOnlyMode && _webServiceEnableTlsUnixSocket && (_webServiceTlsUnixSocket is not null) && (_webServiceSslServerAuthenticationOptions is not null))
                    _log.Write(new UnixDomainSocketEndPoint(_webServiceTlsUnixSocket), "HttpsUnix", "Web Service failed to bind.");

                throw;
            }

            _ssoEnabled = ssoEnabled;
        }

        private async Task StopWebServiceAsync()
        {
            if (_webService is not null)
            {
                await _webService.DisposeAsync();
                _webService = null;
            }

            _ssoHttpHandler?.Dispose();
            _ssoHttpClient?.Dispose();
        }

        private bool IsHttp2Supported()
        {
            if (_webServiceEnableHttp3)
                return true;

            switch (Environment.OSVersion.Platform)
            {
                case PlatformID.Win32NT:
                    return Environment.OSVersion.Version.Major >= 10; //http/2 supported on Windows Server 2016/Windows 10 or later

                case PlatformID.Unix:
                    return true; //http/2 supported on Linux with OpenSSL 1.0.2 or later (for example, Ubuntu 16.04 or later)

                default:
                    return false;
            }
        }

        private IPEndPoint GetRemoteEndPoint(HttpContext context)
        {
            try
            {
                IPAddress remoteIP = context.Connection.RemoteIpAddress; //will be null for unix socket
                if ((remoteIP is not null) && remoteIP.IsIPv4MappedToIPv6)
                    remoteIP = remoteIP.MapToIPv4();

                if (!string.IsNullOrEmpty(_webServiceRealIpHeader) && ((remoteIP is null) || NetworkAccessControl.IsAddressAllowed(remoteIP, _webServiceReverseProxyAddresses)))
                {
                    //get the real IP address of the requesting client from X-Real-IP header set in nginx proxy_pass block
                    string xRealIp = context.Request.Headers[_webServiceRealIpHeader];
                    if (IPAddress.TryParse(xRealIp, out IPAddress address))
                        return new IPEndPoint(address, 0);
                }

                if (remoteIP is not null)
                    return new IPEndPoint(remoteIP, context.Connection.RemotePort);
            }
            catch
            { }

            return IPENDPOINT_ANY_0;
        }

        private void ConfigureWebServiceRoutes()
        {
            _webService.UseExceptionHandler(WebServiceExceptionHandler);

            _webService.Use(WebServiceApiMiddleware);

            _webService.UseRouting();

            //status
            _webService.MapGetAndPost("/api/status", _authApi.StatusAsync);

            //sso
            _webService.MapGetAndPost("/sso/login", _authApi.SsoLoginAsync);
            _webService.MapGetAndPost("/api/sso/status", _authApi.StatusAsync); //depricated

            //user auth
            _webService.MapGetAndPost("/api/user/login", delegate (HttpContext context) { return _authApi.LoginAsync(context, UserSessionType.Standard); });
            _webService.MapGetAndPost("/api/user/createToken", _authApi.CreateToken);
            _webService.MapGetAndPost("/api/user/logout", _authApi.Logout);

            //user
            _webService.MapGetAndPost("/api/user/createSingleUseToken", _authApi.CreateSingleUseToken);
            _webService.MapGetAndPost("/api/user/session/get", _authApi.GetCurrentSessionDetails);
            _webService.MapGetAndPost("/api/user/session/delete", delegate (HttpContext context) { _authApi.DeleteSession(context, false); });
            _webService.MapGetAndPost("/api/user/changePassword", context => _settingsApi.WithConfigurationLockAsync(context, _authApi.ChangePasswordAsync));
            _webService.MapGetAndPost("/api/user/2fa/init", context => _settingsApi.WithConfigurationLockAsync(context, _authApi.Initialize2FA));
            _webService.MapGetAndPost("/api/user/2fa/enable", context => _settingsApi.WithConfigurationLockAsync(context, _authApi.Enable2FA));
            _webService.MapGetAndPost("/api/user/2fa/disable", context => _settingsApi.WithConfigurationLockAsync(context, _authApi.Disable2FA));
            _webService.MapGetAndPost("/api/user/profile/get", _authApi.GetProfile);
            _webService.MapGetAndPost("/api/user/profile/set", context => _settingsApi.WithConfigurationLockAsync(context, _authApi.SetProfile));
            _webService.MapGetAndPost("/api/user/checkForUpdate", _api.CheckForUpdateAsync);

            //dashboard
            _webService.MapGetAndPost("/api/dashboard/metrics/json", _dashboardApi.GetMetricsJson);
            _webService.MapGetAndPost("/api/dashboard/metrics/text", _dashboardApi.GetMetricsText);
            _webService.MapGetAndPost("/api/dashboard/stats/get", _dashboardApi.GetStatsAsync);
            _webService.MapGetAndPost("/api/dashboard/stats/getTop", _dashboardApi.GetTopStatsAsync);
            _webService.MapGetAndPost("/api/dashboard/stats/deleteAll", _logsApi.DeleteAllStats);

            //zones
            _webService.MapGetAndPost("/api/zones/list", _zonesApi.ListZones);
            _webService.MapGetAndPost("/api/zones/catalogs/list", _zonesApi.ListCatalogZones);
            _webService.MapGetAndPost("/api/zones/create", context => _settingsApi.WithConfigurationLockAsync(context, _zonesApi.CreateZoneAsync));
            _webService.MapGetAndPost("/api/zones/import", context => _settingsApi.WithConfigurationLockAsync(context, _zonesApi.ImportZoneAsync));
            _webService.MapGetAndPost("/api/zones/export", _zonesApi.ExportZoneAsync);
            _webService.MapGetAndPost("/api/zones/clone", context => _settingsApi.WithConfigurationLockAsync(context, _zonesApi.CloneZone));
            _webService.MapGetAndPost("/api/zones/convert", context => _settingsApi.WithConfigurationLockAsync(context, _zonesApi.ConvertZone));
            _webService.MapGetAndPost("/api/zones/enable", context => _settingsApi.WithConfigurationLockAsync(context, _zonesApi.EnableZone));
            _webService.MapGetAndPost("/api/zones/disable", context => _settingsApi.WithConfigurationLockAsync(context, _zonesApi.DisableZone));
            _webService.MapGetAndPost("/api/zones/delete", context => _settingsApi.WithConfigurationLockAsync(context, _zonesApi.DeleteZone));
            _webService.MapGetAndPost("/api/zones/resync", _zonesApi.ResyncZone);
            _webService.MapGetAndPost("/api/zones/options/get", _zonesApi.GetZoneOptions);
            _webService.MapGetAndPost("/api/zones/options/set", context => _settingsApi.WithConfigurationLockAsync(context, _zonesApi.SetZoneOptions));
            _webService.MapGetAndPost("/api/zones/permissions/get", delegate (HttpContext context) { _authApi.GetPermissionDetails(context, PermissionSection.Zones); });
            _webService.MapGetAndPost("/api/zones/permissions/set", context => _settingsApi.WithConfigurationLockAsync(context, current => _authApi.SetPermissionsDetails(current, PermissionSection.Zones)));
            _webService.MapGetAndPost("/api/zones/dnssec/sign", _zonesApi.SignPrimaryZone);
            _webService.MapGetAndPost("/api/zones/dnssec/unsign", _zonesApi.UnsignPrimaryZone);
            _webService.MapGetAndPost("/api/zones/dnssec/viewDS", _zonesApi.GetPrimaryZoneDsInfo);
            _webService.MapGetAndPost("/api/zones/dnssec/properties/get", _zonesApi.GetPrimaryZoneDnssecProperties);
            _webService.MapGetAndPost("/api/zones/dnssec/properties/convertToNSEC", _zonesApi.ConvertPrimaryZoneToNSEC);
            _webService.MapGetAndPost("/api/zones/dnssec/properties/convertToNSEC3", _zonesApi.ConvertPrimaryZoneToNSEC3);
            _webService.MapGetAndPost("/api/zones/dnssec/properties/updateNSEC3Params", _zonesApi.UpdatePrimaryZoneNSEC3Parameters);
            _webService.MapGetAndPost("/api/zones/dnssec/properties/updateDnsKeyTtl", _zonesApi.UpdatePrimaryZoneDnssecDnsKeyTtl);
            _webService.MapGetAndPost("/api/zones/dnssec/properties/generatePrivateKey", _zonesApi.AddPrimaryZoneDnssecPrivateKey);
            _webService.MapGetAndPost("/api/zones/dnssec/properties/addPrivateKey", _zonesApi.AddPrimaryZoneDnssecPrivateKey);
            _webService.MapGetAndPost("/api/zones/dnssec/properties/updatePrivateKey", _zonesApi.UpdatePrimaryZoneDnssecPrivateKey);
            _webService.MapGetAndPost("/api/zones/dnssec/properties/deletePrivateKey", _zonesApi.DeletePrimaryZoneDnssecPrivateKey);
            _webService.MapGetAndPost("/api/zones/dnssec/properties/publishAllPrivateKeys", _zonesApi.PublishAllGeneratedPrimaryZoneDnssecPrivateKeys);
            _webService.MapGetAndPost("/api/zones/dnssec/properties/activateKskDnsKey", _zonesApi.ActivatePrimaryZoneKskDnsKey);
            _webService.MapGetAndPost("/api/zones/dnssec/properties/rolloverDnsKey", _zonesApi.RolloverPrimaryZoneDnsKey);
            _webService.MapGetAndPost("/api/zones/dnssec/properties/retireDnsKey", _zonesApi.RetirePrimaryZoneDnsKeyAsync);
            _webService.MapGetAndPost("/api/zones/records/add", context => _settingsApi.WithConfigurationLockAsync(context, _zonesApi.AddRecord));
            _webService.MapGetAndPost("/api/zones/records/get", _zonesApi.GetRecords);
            _webService.MapGetAndPost("/api/zones/records/update", context => _settingsApi.WithConfigurationLockAsync(context, _zonesApi.UpdateRecord));
            _webService.MapGetAndPost("/api/zones/records/delete", context => _settingsApi.WithConfigurationLockAsync(context, _zonesApi.DeleteRecord));

            //cache
            _webService.MapGetAndPost("/api/cache/list", _otherZonesApi.ListCachedZones);
            _webService.MapGetAndPost("/api/cache/delete", _otherZonesApi.DeleteCachedZone);
            _webService.MapGetAndPost("/api/cache/flush", _otherZonesApi.FlushCache);

            //allowed
            _webService.MapGetAndPost("/api/allowed/list", _otherZonesApi.ListAllowedZones);
            _webService.MapGetAndPost("/api/allowed/add", context => _settingsApi.WithConfigurationLockAsync(context, _otherZonesApi.AllowZone));
            _webService.MapGetAndPost("/api/allowed/delete", context => _settingsApi.WithConfigurationLockAsync(context, _otherZonesApi.DeleteAllowedZone));
            _webService.MapGetAndPost("/api/allowed/flush", context => _settingsApi.WithConfigurationLockAsync(context, _otherZonesApi.FlushAllowedZone));
            _webService.MapGetAndPost("/api/allowed/import", context => _settingsApi.WithConfigurationLockAsync(context, _otherZonesApi.ImportAllowedZones));
            _webService.MapGetAndPost("/api/allowed/export", _otherZonesApi.ExportAllowedZonesAsync);

            //blocked
            _webService.MapGetAndPost("/api/blocked/list", _otherZonesApi.ListBlockedZones);
            _webService.MapGetAndPost("/api/blocked/add", context => _settingsApi.WithConfigurationLockAsync(context, _otherZonesApi.BlockZone));
            _webService.MapGetAndPost("/api/blocked/delete", context => _settingsApi.WithConfigurationLockAsync(context, _otherZonesApi.DeleteBlockedZone));
            _webService.MapGetAndPost("/api/blocked/flush", context => _settingsApi.WithConfigurationLockAsync(context, _otherZonesApi.FlushBlockedZone));
            _webService.MapGetAndPost("/api/blocked/import", context => _settingsApi.WithConfigurationLockAsync(context, _otherZonesApi.ImportBlockedZones));
            _webService.MapGetAndPost("/api/blocked/export", _otherZonesApi.ExportBlockedZonesAsync);

            //apps
            _webService.MapGetAndPost("/api/apps/list", _appsApi.ListInstalledAppsAsync);
            _webService.MapGetAndPost("/api/apps/listStoreApps", _appsApi.ListStoreApps);
            _webService.MapGetAndPost("/api/apps/downloadAndInstall", context => _settingsApi.WithConfigurationLockAsync(context, _appsApi.DownloadAndInstallAppAsync));
            _webService.MapGetAndPost("/api/apps/downloadAndUpdate", context => _settingsApi.WithConfigurationLockAsync(context, _appsApi.DownloadAndUpdateAppAsync));
            _webService.MapPost("/api/apps/install", context => _settingsApi.WithConfigurationLockAsync(context, _appsApi.InstallAppAsync));
            _webService.MapPost("/api/apps/update", context => _settingsApi.WithConfigurationLockAsync(context, _appsApi.UpdateAppAsync));
            _webService.MapGetAndPost("/api/apps/uninstall", context => _settingsApi.WithConfigurationLockAsync(context, _appsApi.UninstallAppAsync));
            _webService.MapGetAndPost("/api/apps/config/get", _appsApi.GetAppConfigAsync);
            _webService.MapGetAndPost("/api/apps/config/set", context => _settingsApi.WithConfigurationLockAsync(context, _appsApi.SetAppConfigAsync));

            //dns client
            _webService.MapGetAndPost("/api/dnsClient/resolve", _api.ResolveQueryAsync);
            _webService.MapGetAndPost("/api/dnsClient/healthCheck", _api.HealthCheckAsync);

            //settings
            _webService.MapGetAndPost("/api/settings/get", _settingsApi.GetDnsSettings);
            _webService.MapGet("/api/settings/config/export", context => _settingsApi.WithConfigurationLockAsync(context, _settingsApi.ExportConfigurationAsync));
            _webService.MapPost("/api/settings/config/plan", context => _settingsApi.WithConfigurationLockAsync(context, _settingsApi.PreviewConfigurationAsync));
            _webService.MapPost("/api/settings/config/apply", context => _settingsApi.WithConfigurationLockAsync(context, _settingsApi.ApplyConfigurationAsync));
            _webService.MapGet("/api/settings/config/status", _settingsApi.GetConfigurationApplyStatus);
            _webService.MapGetAndPost("/api/settings/set", context => _settingsApi.WithConfigurationLockAsync(context, _settingsApi.SetDnsSettingsAsync));
            _webService.MapGetAndPost("/api/settings/getTsigKeyNames", _settingsApi.GetTsigKeyNames);
            _webService.MapGetAndPost("/api/settings/forceUpdateBlockLists", _settingsApi.ForceUpdateBlockLists);
            _webService.MapGetAndPost("/api/settings/temporaryDisableBlocking", _settingsApi.TemporaryDisableBlocking);
            _webService.MapGetAndPost("/api/settings/backup", _settingsApi.BackupSettingsAsync);
            _webService.MapPost("/api/settings/restore", context => _settingsApi.WithConfigurationLockAsync(context, _settingsApi.RestoreSettingsAsync));

            //dhcp
            _webService.MapGetAndPost("/api/dhcp/leases/list", _dhcpApi.ListDhcpLeases);
            _webService.MapGetAndPost("/api/dhcp/leases/remove", context => _settingsApi.WithConfigurationLockAsync(context, current => _dhcpApi.WithLeaseLockAsync(current, _dhcpApi.RemoveDhcpLease)));
            _webService.MapGetAndPost("/api/dhcp/leases/convertToReserved", context => _settingsApi.WithConfigurationLockAsync(context, current => _dhcpApi.WithLeaseLockAsync(current, _dhcpApi.ConvertToReservedLease)));
            _webService.MapGetAndPost("/api/dhcp/leases/convertToDynamic", context => _settingsApi.WithConfigurationLockAsync(context, current => _dhcpApi.WithLeaseLockAsync(current, _dhcpApi.ConvertToDynamicLease)));
            _webService.MapGetAndPost("/api/dhcp/scopes/list", _dhcpApi.ListDhcpScopes);
            _webService.MapGetAndPost("/api/dhcp/scopes/get", _dhcpApi.GetDhcpScope);
            _webService.MapGetAndPost("/api/dhcp/scopes/set", context => _settingsApi.WithConfigurationLockAsync(context, _dhcpApi.SetDhcpScopeAsync));
            _webService.MapGetAndPost("/api/dhcp/scopes/addReservedLease", context => _settingsApi.WithConfigurationLockAsync(context, _dhcpApi.AddReservedLease));
            _webService.MapGetAndPost("/api/dhcp/scopes/removeReservedLease", context => _settingsApi.WithConfigurationLockAsync(context, _dhcpApi.RemoveReservedLease));
            _webService.MapGetAndPost("/api/dhcp/scopes/enable", context => _settingsApi.WithConfigurationLockAsync(context, _dhcpApi.EnableDhcpScopeAsync));
            _webService.MapGetAndPost("/api/dhcp/scopes/disable", context => _settingsApi.WithConfigurationLockAsync(context, _dhcpApi.DisableDhcpScope));
            _webService.MapGetAndPost("/api/dhcp/scopes/delete", context => _settingsApi.WithConfigurationLockAsync(context, _dhcpApi.DeleteDhcpScope));

            //administration
            _webService.MapGetAndPost("/api/admin/sessions/list", _authApi.ListSessions);
            _webService.MapGetAndPost("/api/admin/sessions/createToken", _authApi.CreateApiToken);
            _webService.MapGetAndPost("/api/admin/sessions/delete", delegate (HttpContext context) { _authApi.DeleteSession(context, true); });
            _webService.MapGetAndPost("/api/admin/users/list", _authApi.ListUsers);
            _webService.MapGetAndPost("/api/admin/users/create", context => _settingsApi.WithConfigurationLockAsync(context, _authApi.CreateUser));
            _webService.MapGetAndPost("/api/admin/users/get", _authApi.GetUserDetails);
            _webService.MapGetAndPost("/api/admin/users/set", context => _settingsApi.WithConfigurationLockAsync(context, _authApi.SetUserDetails));
            _webService.MapGetAndPost("/api/admin/users/delete", context => _settingsApi.WithConfigurationLockAsync(context, _authApi.DeleteUser));
            _webService.MapGetAndPost("/api/admin/groups/list", _authApi.ListGroups);
            _webService.MapGetAndPost("/api/admin/groups/create", context => _settingsApi.WithConfigurationLockAsync(context, _authApi.CreateGroup));
            _webService.MapGetAndPost("/api/admin/groups/get", _authApi.GetGroupDetails);
            _webService.MapGetAndPost("/api/admin/groups/set", context => _settingsApi.WithConfigurationLockAsync(context, _authApi.SetGroupDetails));
            _webService.MapGetAndPost("/api/admin/groups/delete", context => _settingsApi.WithConfigurationLockAsync(context, _authApi.DeleteGroup));
            _webService.MapGetAndPost("/api/admin/permissions/list", _authApi.ListPermissions);
            _webService.MapGetAndPost("/api/admin/permissions/get", delegate (HttpContext context) { _authApi.GetPermissionDetails(context, PermissionSection.Unknown); });
            _webService.MapGetAndPost("/api/admin/permissions/set", context => _settingsApi.WithConfigurationLockAsync(context, current => _authApi.SetPermissionsDetails(current, PermissionSection.Unknown)));
            _webService.MapGetAndPost("/api/admin/sso/get", _authApi.GetSsoConfig);
            _webService.MapGetAndPost("/api/admin/sso/set", context => _settingsApi.WithConfigurationLockAsync(context, _authApi.SetSsoConfig));
            _webService.MapGetAndPost("/api/admin/sso/users/create", context => _settingsApi.WithConfigurationLockAsync(context, _authApi.CreateSsoUser));
            _webService.MapGetAndPost("/api/admin/sso/users/set", context => _settingsApi.WithConfigurationLockAsync(context, _authApi.SetSsoUser));
            _webService.MapGetAndPost("/api/admin/ldap/get", _authApi.GetLdapConfig);
            _webService.MapGetAndPost("/api/admin/ldap/set", context => _settingsApi.WithConfigurationLockAsync(context, _authApi.SetLdapConfig));
            _webService.MapGetAndPost("/api/admin/ldap/test", _authApi.TestLdapConnectionAsync);
            _webService.MapGetAndPost("/api/admin/cluster/state", _clusterApi.GetClusterState);
            _webService.MapGetAndPost("/api/admin/cluster/init", context => _settingsApi.WithConfigurationLockAsync(context, _clusterApi.InitializeCluster));
            _webService.MapGetAndPost("/api/admin/cluster/primary/delete", context => _settingsApi.WithConfigurationLockAsync(context, _clusterApi.DeleteCluster));
            _webService.MapGetAndPost("/api/admin/cluster/primary/join", context => _settingsApi.WithConfigurationLockAsync(context, _clusterApi.JoinCluster));
            _webService.MapGetAndPost("/api/admin/cluster/primary/removeSecondary", _clusterApi.RemoveSecondaryNodeAsync);
            _webService.MapGetAndPost("/api/admin/cluster/primary/deleteSecondary", context => _settingsApi.WithConfigurationLockAsync(context, _clusterApi.DeleteSecondaryNode));
            _webService.MapGetAndPost("/api/admin/cluster/primary/updateSecondary", context => _settingsApi.WithConfigurationLockAsync(context, _clusterApi.UpdateSecondaryNode));
            _webService.MapGetAndPost("/api/admin/cluster/primary/transferConfig", _clusterApi.TransferConfigAsync);
            _webService.MapGetAndPost("/api/admin/cluster/primary/setOptions", context => _settingsApi.WithConfigurationLockAsync(context, _clusterApi.SetClusterOptions));
            _webService.MapGetAndPost("/api/admin/cluster/initJoin", context => _settingsApi.WithConfigurationLockAsync(context, _clusterApi.InitializeAndJoinClusterAsync));
            _webService.MapGetAndPost("/api/admin/cluster/secondary/leave", context => _settingsApi.WithConfigurationLockAsync(context, _clusterApi.LeaveClusterAsync));
            _webService.MapGetAndPost("/api/admin/cluster/secondary/notify", _clusterApi.ConfigUpdateNotificationAsync);
            _webService.MapGetAndPost("/api/admin/cluster/secondary/resync", _clusterApi.ResyncCluster);
            _webService.MapGetAndPost("/api/admin/cluster/secondary/updatePrimary", _clusterApi.UpdatePrimaryNodeAsync);
            _webService.MapGetAndPost("/api/admin/cluster/secondary/promote", context => _settingsApi.WithConfigurationLockAsync(context, _clusterApi.PromoteToPrimaryNodeAsync));
            _webService.MapGetAndPost("/api/admin/cluster/updateIpAddress", context => _settingsApi.WithConfigurationLockAsync(context, _clusterApi.UpdateSelfNodeIPAddress));

            //logs
            _webService.MapGetAndPost("/api/logs/list", _logsApi.ListLogs);
            _webService.MapGetAndPost("/api/logs/download", _logsApi.DownloadLogAsync);
            _webService.MapGetAndPost("/api/logs/delete", _logsApi.DeleteLog);
            _webService.MapGetAndPost("/api/logs/deleteAll", _logsApi.DeleteAllLogs);
            _webService.MapGetAndPost("/api/logs/query", _logsApi.QueryLogsAsync);
            _webService.MapGetAndPost("/api/logs/export", _logsApi.ExportLogsAsync);

            //fallback
            _webService.MapFallback("/api/{*path}", delegate (HttpContext context)
            {
                //mark api fallback
                context.Items["apiFallback"] = string.Empty;
            });
        }

        private static ClusterNodeType GetClusterNodeTypeForPath(string path)
        {
            switch (path)
            {
                case "/api/user/createToken":
                case "/api/user/changePassword":
                case "/api/user/2fa/init":
                case "/api/user/2fa/enable":
                case "/api/user/2fa/disable":
                case "/api/user/profile/set":

                case "/api/allowed/add":
                case "/api/allowed/delete":
                case "/api/allowed/flush":
                case "/api/allowed/import":

                case "/api/blocked/add":
                case "/api/blocked/delete":
                case "/api/blocked/flush":
                case "/api/blocked/import":

                case "/api/apps/downloadAndInstall":
                case "/api/apps/downloadAndUpdate":
                case "/api/apps/install":
                case "/api/apps/update":
                case "/api/apps/uninstall":
                case "/api/apps/config/set":

                case "/api/admin/sessions/createToken":
                case "/api/admin/users/create":
                case "/api/admin/users/set":
                case "/api/admin/users/delete":
                case "/api/admin/groups/create":
                case "/api/admin/groups/set":
                case "/api/admin/groups/delete":
                case "/api/admin/sso/set":
                case "/api/admin/sso/users/create":
                case "/api/admin/sso/users/set":
                case "/api/admin/ldap/set":
                    return ClusterNodeType.Primary; //this api can be called only on primary node

                case "/sso/login":
                case "/sso/callback":
                case "/api/status":
                case "/api/sso/status":

                case "/api/user/login":
                case "/api/user/logout":
                case "/api/user/session/get":
                case "/api/user/session/delete":
                    return ClusterNodeType.Secondary; //this api must be called on current node

                default:
                    return ClusterNodeType.Unknown; //this api can be called on any specified node
            }
        }

        private Task WebServiceHttpsRedirectionMiddleware(HttpContext context, RequestDelegate next)
        {
            if (context.Request.IsHttps || (context.Connection.RemoteIpAddress is null)) //no redirect for unix socket connection too
                return next(context);

            context.Response.Redirect("https://" + (context.Request.Host.HasValue ? context.Request.Host.Host : _dnsServer.ServerDomain) + (_webServiceTlsPort == 443 ? "" : ":" + _webServiceTlsPort) + context.Request.Path + (context.Request.QueryString.HasValue ? context.Request.QueryString.Value : ""), false, true);
            return Task.CompletedTask;
        }

        private async Task WebServiceApiMiddleware(HttpContext context, RequestDelegate next)
        {
            HttpRequest request = context.Request;

            if (_clusterManager.ClusterInitialized)
            {
                ClusterNodeType pathNodeType = GetClusterNodeTypeForPath(request.Path);
                switch (pathNodeType)
                {
                    case ClusterNodeType.Primary:
                        //this api can be called only on primary node
                        ClusterNode selfNode = _clusterManager.GetSelfNode();
                        if (selfNode.Type == ClusterNodeType.Secondary)
                        {
                            //validate user session before proxying request
                            if (!TryValidateSession(context, out UserSession session))
                                throw new InvalidTokenWebServiceException("Invalid token or session expired.");

                            //proxy to primary node
                            ClusterNode primaryNode = _clusterManager.GetPrimaryNode();
                            await primaryNode.ProxyRequest(context, session.User.Username);
                            return;
                        }

                        break;

                    case ClusterNodeType.Secondary:
                        //this api must be called on current node
                        break;

                    default:
                        //this api can be called on any specified node
                        string nodeName = request.GetQueryOrForm("node", null);
                        if (!string.IsNullOrEmpty(nodeName) && (nodeName != "cluster"))
                        {
                            if (!_clusterManager.TryGetClusterNode(nodeName, out ClusterNode node))
                                throw new DnsWebServiceException("No such node exists in the Cluster by name: " + nodeName);

                            if (node.State != ClusterNodeState.Self)
                            {
                                //validate user session before proxying request
                                if (!TryValidateSession(context, out UserSession session))
                                    throw new InvalidTokenWebServiceException("Invalid token or session expired.");

                                //proxy request to the specified cluster node
                                await node.ProxyRequest(context, session.User.Username);
                                return;
                            }
                        }

                        break;
                }
            }

            bool needsJsonResponseObject;

            switch (request.Path)
            {
                case "/api/status":
                case "/api/sso/status":
                case "/api/user/login":
                case "/api/user/createToken":
                case "/api/user/logout":
                    needsJsonResponseObject = false;
                    break;

                case "/api/user/session/get":
                    {
                        if (!TryValidateSession(context, out UserSession _))
                            throw new InvalidTokenWebServiceException("Invalid token or session expired.");

                        needsJsonResponseObject = false;
                    }
                    break;

                case "/api/dashboard/metrics/text":
                case "/api/zones/export":
                case "/api/allowed/export":
                case "/api/blocked/export":
                case "/api/settings/backup":
                case "/api/logs/download":
                case "/api/logs/export":
                case "/api/admin/cluster/primary/transferConfig":
                    {
                        if (!TryValidateSession(context, out UserSession _))
                            throw new InvalidTokenWebServiceException("Invalid token or session expired.");

                        await next(context);
                    }
                    return;

                case "/api/dnsClient/healthCheck":
                    {
                        if (!TryValidateSession(context, out UserSession _))
                        {
                            IPAddress remoteAddress = GetRemoteEndPoint(context).Address;

                            if (!remoteAddress.Equals(IPAddress.Loopback) && !remoteAddress.Equals(IPAddress.IPv6Loopback))
                                throw new InvalidTokenWebServiceException("Invalid token or session expired.");

                            //allow unauthenticated call from localhost
                        }

                        needsJsonResponseObject = false;
                    }
                    break;

                default:
                    if (request.Path.Value.StartsWith("/api/", StringComparison.OrdinalIgnoreCase))
                    {
                        if (!TryValidateSession(context, out UserSession _))
                            throw new InvalidTokenWebServiceException("Invalid token or session expired.");

                        needsJsonResponseObject = true;
                    }
                    else if (request.Path.Value.StartsWith("/sso/", StringComparison.OrdinalIgnoreCase))
                    {
                        await next(context);
                        return;
                    }
                    else
                    {
                        HttpResponse response = context.Response;
                        response.StatusCode = StatusCodes.Status404NotFound;
                        response.ContentLength = 0;
                        response.Headers.CacheControl = "no-cache, no-store, must-revalidate";
                        response.Headers.Pragma = "no-cache";
                        response.Headers.Expires = "0";
                        return;
                    }

                    break;
            }

            using (MemoryStream mS = new MemoryStream(4096))
            {
                Utf8JsonWriter jsonWriter = new Utf8JsonWriter(mS);
                context.Items["jsonWriter"] = jsonWriter;

                jsonWriter.WriteStartObject();

                if (needsJsonResponseObject)
                {
                    jsonWriter.WritePropertyName("response");
                    jsonWriter.WriteStartObject();

                    await next(context);

                    jsonWriter.WriteEndObject();
                }
                else
                {
                    await next(context);
                }

                jsonWriter.WriteString("server", _dnsServer.ServerDomain);
                jsonWriter.WriteString("status", "ok");

                jsonWriter.WriteEndObject();
                jsonWriter.Flush();

                mS.Position = 0;

                HttpResponse response = context.Response;

                response.Headers.CacheControl = "no-cache, no-store, must-revalidate";
                response.Headers.Pragma = "no-cache";
                response.Headers.Expires = "0";

                object apiFallback = context.Items["apiFallback"]; //check api fallback mark
                if (apiFallback is null)
                {
                    response.StatusCode = StatusCodes.Status200OK;
                    response.ContentType = "application/json; charset=utf-8";
                    response.ContentLength = mS.Length;

                    await mS.CopyToAsync(response.Body);
                }
                else
                {
                    response.StatusCode = StatusCodes.Status404NotFound;
                    response.ContentLength = 0;
                }
            }
        }

        private void WebServiceExceptionHandler(IApplicationBuilder exceptionHandlerApp)
        {
            exceptionHandlerApp.Run(async delegate (HttpContext context)
            {
                IExceptionHandlerPathFeature exceptionHandlerPathFeature = context.Features.Get<IExceptionHandlerPathFeature>();
                if (exceptionHandlerPathFeature.Path.StartsWith("/api/", StringComparison.Ordinal))
                {
                    Exception ex = exceptionHandlerPathFeature.Error;

                    HttpResponse response = context.Response;

                    response.StatusCode = StatusCodes.Status200OK;
                    response.Headers.CacheControl = "no-cache, no-store, must-revalidate";
                    response.Headers.Pragma = "no-cache";
                    response.Headers.Expires = "0";
                    response.ContentType = "application/json; charset=utf-8";

                    await using (Utf8JsonWriter jsonWriter = new Utf8JsonWriter(response.Body))
                    {
                        jsonWriter.WriteStartObject();

                        jsonWriter.WriteString("server", _dnsServer.ServerDomain);

                        if (ex is TwoFactorAuthRequiredWebServiceException)
                        {
                            jsonWriter.WriteString("status", "2fa-required");
                            jsonWriter.WriteString("errorMessage", ex.Message);
                        }
                        else if (ex is InvalidTokenWebServiceException)
                        {
                            jsonWriter.WriteString("status", "invalid-token");
                            jsonWriter.WriteString("errorMessage", ex.Message);
                        }
                        else
                        {
                            _log.Write(GetRemoteEndPoint(context), ex);

                            jsonWriter.WriteString("status", "error");
                            jsonWriter.WriteString("errorMessage", ex.Message);

                            if (ex.InnerException is not null)
                                jsonWriter.WriteString("innerErrorMessage", ex.InnerException.Message);
                        }

                        jsonWriter.WriteEndObject();
                    }
                }
            });
        }

        private static string GetAuthorizationToken(HttpRequest request)
        {
            StringValues authorization = request.Headers.Authorization;
            string token = null;

            foreach (string entry in authorization)
            {
                if (entry.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                {
                    token = entry.Substring(7).Trim();
                    break;
                }
            }

            if (token is null)
                token = request.QueryOrForm("token");

            if (string.IsNullOrEmpty(token))
                return null;

            return token;
        }

        private bool TryValidateSession(HttpContext context, out UserSession session)
        {
            HttpRequest request = context.Request;

            session = _authManager.GetSession(GetAuthorizationToken(request));
            if ((session is null) || session.User.Disabled)
                return false;

            if (session.Type == UserSessionType.SingleUse)
            {
                //delete single use session immediately and continue
                _authManager.DeleteSession(session.Token);
            }
            else
            {
                if (session.HasExpired())
                {
                    _authManager.DeleteSession(session.Token);
                    _authManager.SaveConfigFile();
                    return false;
                }

                IPEndPoint remoteEP = GetRemoteEndPoint(context);

                session.UpdateLastSeen(remoteEP.Address, request.Headers.UserAgent);
                _authManager.LazySaveConfigFile(); //lazy save last seen info
            }

            context.Items["session"] = session;

            return true;
        }

        private User GetSessionUser(HttpContext context, bool standardOnly = false)
        {
            UserSession session = context.GetCurrentSession();

            if ((session.Type == UserSessionType.ClusterApiToken) && _clusterManager.ClusterInitialized)
            {
                //proxy call from cluster node 
                string actingUsername = context.Request.GetQueryOrForm("actingUser", null);
                if (actingUsername is null)
                    return session.User;

                User actingUser = _authManager.GetUser(actingUsername);
                if (actingUser is null)
                    throw new DnsWebServiceException("No such user exists: " + actingUsername);

                return actingUser;
            }
            else
            {
                if (standardOnly && (session.Type != UserSessionType.Standard))
                    throw new DnsWebServiceException("Access was denied.");

                return session.User;
            }
        }

        #endregion

        #region tls

        private void StartTlsCertificateUpdateTimer()
        {
            if (_tlsCertificateUpdateTimer is null)
            {
                _tlsCertificateUpdateTimer = new Timer(delegate (object state)
                {
                    string certificatePath = null;
                    try
                    {
                        lock (_saveLock)
                        {
                            if (_manifestWebRestart || string.IsNullOrEmpty(_webServiceTlsCertificatePath))
                                return;

                            certificatePath = _log.ConvertToAbsolutePath(_webServiceTlsCertificatePath);
                            var file = new FileInfo(certificatePath);
                            if (!file.Exists || file.LastWriteTimeUtc == _webServiceCertificateLastModifiedOn)
                                return;

                            LoadWebServiceTlsCertificate(certificatePath, _webServiceTlsCertificatePassword);
                        }

                        if (_clusterManager?.ClusterInitialized == true)
                            _clusterManager.UpdateSelfNodeUrlAndCertificate();
                    }
                    catch (Exception ex)
                    {
                        _log.Write("DNS Server encountered an error while updating Web Service TLS Certificate: " + certificatePath, ex);
                    }
                }, null, TLS_CERTIFICATE_UPDATE_TIMER_INITIAL_INTERVAL, TLS_CERTIFICATE_UPDATE_TIMER_INTERVAL);
            }
        }

        private void StopTlsCertificateUpdateTimer()
        {
            if (_tlsCertificateUpdateTimer is not null)
            {
                _tlsCertificateUpdateTimer.Dispose();
                _tlsCertificateUpdateTimer = null;
            }
        }

        private void LoadWebServiceTlsCertificate(string tlsCertificatePath, string tlsCertificatePassword)
        {
            Pkcs12Certificate certificate = Pkcs12Certificate.Read(tlsCertificatePath, tlsCertificatePassword, X509KeyStorageFlags.PersistKeySet);
            ConfigureWebTlsOptions(certificate.Context);
            _webServiceCertificateLastModifiedOn = certificate.LastModified;
            _webServiceCertificateFileHash = certificate.FileHash;

            _log.Write("Web Service TLS certificate was loaded: " + tlsCertificatePath);
        }

        private string _webServiceCertificateFileHash;

        private ConfigurationWebCertificate.State CaptureWebCertificate()
        {
            lock (_saveLock)
                return new ConfigurationWebCertificate.State(_webServiceUseSelfSignedTlsCertificate,
                    _webServiceTlsCertificatePath, _webServiceTlsCertificatePassword, _webServiceCertificateFileHash);
        }

        private ConfigurationWebCertificate.Candidate? PrepareWebCertificate(ConfigurationManifest manifest, bool preview = false)
        {
            return ConfigurationWebCertificate.IsDeclared(manifest)
                ? ConfigurationWebCertificate.Prepare(manifest, CaptureWebCertificate(), _log, preview) : null;
        }

        private void CheckManagedWebCertificate(bool selfSigned, string path, string password)
        {
            if ((_managedWebListeners & ManagedWebSelfSigned) != 0 && selfSigned != _webServiceUseSelfSignedTlsCertificate)
                throw new InvalidDataException("/web/useSelfSignedCertificate: Setting is managed by the configuration manifest.");
            if ((_managedWebListeners & ManagedWebCertificatePath) != 0 &&
                (string.IsNullOrWhiteSpace(path) ? null : _log.ConvertToRelativePath(_log.ConvertToAbsolutePath(path))) != _webServiceTlsCertificatePath)
                throw new InvalidDataException("/web/certificate/path: Setting is managed by the configuration manifest.");
            if ((_managedWebListeners & ManagedWebCertificatePassword) != 0 &&
                (password ?? "") != (_webServiceTlsCertificatePassword ?? ""))
                throw new InvalidDataException("/web/certificate/password: Setting is managed by the configuration manifest.");
        }

        private byte[] StageWebCertificate(ConfigurationWebCertificate.Candidate candidate, string serverDomain)
        {
            _webServiceUseSelfSignedTlsCertificate = candidate.Desired.SelfSigned;
            _webServiceTlsCertificatePath = candidate.Desired.Path;
            _webServiceTlsCertificatePassword = candidate.Desired.Password;
            Pkcs12Certificate certificate = candidate.Certificate;
            byte[] generated = null;
            if (certificate is null && candidate.Desired.SelfSigned)
            {
                generated = CreateSelfSignedWebCertificate(serverDomain ?? _dnsServer.ServerDomain);
                certificate = Pkcs12Certificate.Load(generated, null, X509KeyStorageFlags.DefaultKeySet, default);
            }

            if (certificate is null)
                _webServiceSslServerAuthenticationOptions = null;
            else
                ConfigureWebTlsOptions(certificate.Context);
            _webServiceCertificateLastModifiedOn = certificate?.LastModified ?? default;
            _webServiceCertificateFileHash = certificate?.FileHash;
            return generated;
        }

        private void RestoreWebCertificate(ConfigurationWebCertificate.State previous, SslServerAuthenticationOptions options, DateTime lastModified)
        {
            _webServiceUseSelfSignedTlsCertificate = previous.SelfSigned;
            _webServiceTlsCertificatePath = previous.Path;
            _webServiceTlsCertificatePassword = previous.Password;
            _webServiceCertificateFileHash = previous.FileHash;
            _webServiceSslServerAuthenticationOptions = options;
            _webServiceCertificateLastModifiedOn = lastModified;
        }

        private void ConfigureWebTlsOptions(SslStreamCertificateContext certificate)
        {
            List<SslApplicationProtocol> applicationProtocols = new List<SslApplicationProtocol>();

            if (_webServiceEnableHttp3)
                applicationProtocols.Add(new SslApplicationProtocol("h3"));

            if (IsHttp2Supported())
                applicationProtocols.Add(new SslApplicationProtocol("h2"));

            applicationProtocols.Add(new SslApplicationProtocol("http/1.1"));

            _webServiceSslServerAuthenticationOptions = new SslServerAuthenticationOptions
            {
                ApplicationProtocols = applicationProtocols,
                ServerCertificateContext = certificate
            };
        }

        private void RemoveWebServiceTlsCertificate()
        {
            _webServiceSslServerAuthenticationOptions = null;
            _webServiceCertificateFileHash = null;

            _webServiceTlsCertificatePath = null;
            _webServiceTlsCertificatePassword = null;

            StopTlsCertificateUpdateTimer();
        }

        public void SetWebServiceTlsCertificate(string webServiceTlsCertificatePath, string webServiceTlsCertificatePassword)
        {
            if (string.IsNullOrWhiteSpace(webServiceTlsCertificatePath))
                throw new ArgumentException("Web service TLS certificate path cannot be null or empty.", nameof(webServiceTlsCertificatePath));

            if (webServiceTlsCertificatePath.Length > 255)
                throw new ArgumentException("Web service TLS certificate path length cannot exceed 255 characters.", nameof(webServiceTlsCertificatePath));

            if (webServiceTlsCertificatePassword?.Length > 255)
                throw new ArgumentException("Web service TLS certificate password length cannot exceed 255 characters.", nameof(webServiceTlsCertificatePassword));

            webServiceTlsCertificatePath = _log.ConvertToAbsolutePath(webServiceTlsCertificatePath);

            LoadWebServiceTlsCertificate(webServiceTlsCertificatePath, webServiceTlsCertificatePassword);

            _webServiceTlsCertificatePath = _log.ConvertToRelativePath(webServiceTlsCertificatePath);
            _webServiceTlsCertificatePassword = webServiceTlsCertificatePassword;

            StartTlsCertificateUpdateTimer();
        }

        internal static string NormalizeWebHeader(string value, bool realIp)
        {
            if (string.IsNullOrWhiteSpace(value))
                return realIp ? "X-Real-IP" : "'none'";

            if (value.Length > 255 || value.Any(c => realIp
                ? !char.IsAsciiLetterOrDigit(c) && !"!#$%&'*+-.^_`|~".Contains(c)
                : c < ' ' || c > '~'))
                throw new ArgumentException("Invalid web header name or value.");

            return value;
        }

        private void CheckManifestWebListeners(WebListeners listeners)
        {
            if ((_managedWebListeners & ManagedWebAddresses) != 0 && listeners.Addresses is not null &&
                !_webServiceLocalAddresses.HasSameItems(NormalizeWebLocalAddresses(listeners.Addresses)))
                throw new DnsWebServiceException("/web/localAddresses: Setting is managed by the configuration manifest.");
            if ((_managedWebListeners & ManagedWebHttpPort) != 0 && listeners.HttpPort.HasValue && listeners.HttpPort != _webServiceHttpPort)
                throw new DnsWebServiceException("/web/httpPort: Setting is managed by the configuration manifest.");
            if ((_managedWebListeners & ManagedWebTlsPort) != 0 && listeners.TlsPort.HasValue && listeners.TlsPort != _webServiceTlsPort)
                throw new DnsWebServiceException("/web/tlsPort: Setting is managed by the configuration manifest.");
            if ((_managedWebListeners & ManagedWebTlsEnabled) != 0 && listeners.TlsEnabled.HasValue && listeners.TlsEnabled != _webServiceEnableTls)
                throw new DnsWebServiceException("/web/tlsEnabled: Setting is managed by the configuration manifest.");
            if ((_managedWebListeners & ManagedWebHttp3) != 0 && listeners.Http3Enabled.HasValue && listeners.Http3Enabled != _webServiceEnableHttp3)
                throw new DnsWebServiceException("/web/http3Enabled: Setting is managed by the configuration manifest.");
            if ((_managedWebListeners & ManagedWebRedirect) != 0 && listeners.RedirectToTls.HasValue && listeners.RedirectToTls != _webServiceHttpToTlsRedirect)
                throw new DnsWebServiceException("/web/redirectHttpToTls: Setting is managed by the configuration manifest.");
            CheckManifestWebUnixSocket(listeners.HttpSocket, _webServiceEnableHttpUnixSocket, _webServiceHttpUnixSocket,
                ManagedWebHttpSocketEnabled, ManagedWebHttpSocketPath, "/web/httpUnixSocket");
            CheckManifestWebUnixSocket(listeners.TlsSocket, _webServiceEnableTlsUnixSocket, _webServiceTlsUnixSocket,
                ManagedWebTlsSocketEnabled, ManagedWebTlsSocketPath, "/web/tlsUnixSocket");
        }

        private void CheckManifestWebUnixSocket(WebUnixSocket socket, bool currentEnabled, string currentPath, ushort enabledFlag, ushort pathFlag, string path)
        {
            if ((_managedWebListeners & enabledFlag) != 0 && socket.Enabled.HasValue && socket.Enabled != currentEnabled)
                throw new DnsWebServiceException($"{path}/enabled: Setting is managed by the configuration manifest.");
            if ((_managedWebListeners & pathFlag) != 0 && socket.Path is not null && socket.Path != (currentPath ?? ""))
                throw new DnsWebServiceException($"{path}/path: Setting is managed by the configuration manifest.");
            if ((_managedWebListeners & enabledFlag) != 0 && currentEnabled && socket.Path == "")
                throw new DnsWebServiceException($"{path}/path: A path is required by the configuration manifest.");
        }

        private static void ValidateManifestWebUnixSocket(WebUnixSocket socket, bool currentEnabled, string currentPath, string path)
        {
            if (!socket.HasValues || !(socket.Enabled ?? currentEnabled))
                return;
            if (!DnsServer.IsUnixDomainSocketSupported())
                throw new InvalidDataException($"{path}/enabled: Unix domain sockets are unavailable on this host.");
            if (string.IsNullOrEmpty(socket.Path ?? currentPath))
                throw new InvalidDataException($"{path}/path: A path is required when the socket is enabled.");
        }

        private void CheckManifestWebTlsDependencies(bool tlsEnabled, bool hasCertificate)
        {
            if ((_managedWebListeners & ManagedWebTlsEnabled) != 0 && _webServiceEnableTls && !hasCertificate)
                throw new DnsWebServiceException("/web/tlsEnabled: A certificate is required by the configuration manifest.");
            if ((_managedWebListeners & ManagedWebHttp3) != 0 && _webServiceEnableHttp3 && (!tlsEnabled || !hasCertificate))
                throw new DnsWebServiceException("/web/http3Enabled: Web TLS is required by the configuration manifest.");
            if ((_managedWebListeners & ManagedWebRedirect) != 0 && _webServiceHttpToTlsRedirect && (!tlsEnabled || !hasCertificate))
                throw new DnsWebServiceException("/web/redirectHttpToTls: Web TLS is required by the configuration manifest.");
            if ((_managedWebListeners & ManagedWebTlsSocketEnabled) != 0 && _webServiceEnableTlsUnixSocket && !hasCertificate)
                throw new DnsWebServiceException("/web/tlsUnixSocket/enabled: A certificate is required by the configuration manifest.");
        }

        private void ValidateManifestWebListeners(WebListeners listeners, bool? candidateHasCertificate = null)
        {
            bool hasCertificate = candidateHasCertificate ?? (_webServiceSslServerAuthenticationOptions is not null);
            ValidateManifestWebUnixSocket(listeners.HttpSocket, _webServiceEnableHttpUnixSocket, _webServiceHttpUnixSocket, "/web/httpUnixSocket");
            ValidateManifestWebUnixSocket(listeners.TlsSocket, _webServiceEnableTlsUnixSocket, _webServiceTlsUnixSocket, "/web/tlsUnixSocket");
            if (listeners.TlsSocket.HasValues && (listeners.TlsSocket.Enabled ?? _webServiceEnableTlsUnixSocket) &&
                !hasCertificate)
                throw new InvalidDataException("/web/tlsUnixSocket/enabled: Configure a web TLS certificate before enabling the socket.");
            string httpSocketPath = listeners.HttpSocket.Path ?? _webServiceHttpUnixSocket;
            string tlsSocketPath = listeners.TlsSocket.Path ?? _webServiceTlsUnixSocket;
            if ((listeners.HttpSocket.HasValues || listeners.TlsSocket.HasValues) &&
                (listeners.HttpSocket.Enabled ?? _webServiceEnableHttpUnixSocket) && (listeners.TlsSocket.Enabled ?? _webServiceEnableTlsUnixSocket) &&
                httpSocketPath is not null && httpSocketPath == tlsSocketPath)
                throw new InvalidDataException("/web/tlsUnixSocket/path: HTTP and HTTPS sockets require distinct paths.");

            if (candidateHasCertificate == false &&
                ((listeners.TlsEnabled ?? _webServiceEnableTls) || (listeners.TlsSocket.Enabled ?? _webServiceEnableTlsUnixSocket)))
                throw new InvalidDataException("/web/certificate: Disable web TLS and its Unix socket before removing their certificate.");

            if (!listeners.TlsEnabled.HasValue && !listeners.Http3Enabled.HasValue && !listeners.RedirectToTls.HasValue)
                return;

            bool tls = listeners.TlsEnabled ?? _webServiceEnableTls;
            bool http3 = listeners.Http3Enabled ?? _webServiceEnableHttp3;
            bool redirect = listeners.RedirectToTls ?? _webServiceHttpToTlsRedirect;
            if (listeners.Http3Enabled == true && !tls)
                throw new InvalidDataException("/web/http3Enabled: HTTP/3 requires web TLS.");
            if (listeners.RedirectToTls == true && !tls)
                throw new InvalidDataException("/web/redirectHttpToTls: Redirecting HTTP to HTTPS requires web TLS.");
            if (tls && (listeners.TlsEnabled.HasValue || http3 || redirect) && !hasCertificate)
                throw new InvalidDataException("/web/tlsEnabled: Configure a web TLS certificate before enabling TLS.");
            if (tls && http3)
                DnsServer.ValidateQuicSupport("HTTP/3");
        }

        private WebListeners CaptureWebListeners()
        {
            return new WebListeners(_webServiceLocalAddresses, _webServiceHttpPort, _webServiceTlsPort,
                _webServiceEnableTls, _webServiceEnableHttp3, _webServiceHttpToTlsRedirect,
                new WebUnixSocket(_webServiceEnableHttpUnixSocket, _webServiceHttpUnixSocket ?? ""),
                new WebUnixSocket(_webServiceEnableTlsUnixSocket, _webServiceTlsUnixSocket ?? ""));
        }

        private bool WebListenersChange(WebListeners listeners)
        {
            return (listeners.Addresses is not null && !_webServiceLocalAddresses.HasSameItems(listeners.Addresses)) ||
                (listeners.HttpPort.HasValue && listeners.HttpPort != _webServiceHttpPort) ||
                (listeners.TlsPort.HasValue && listeners.TlsPort != _webServiceTlsPort) ||
                (listeners.TlsEnabled.HasValue && listeners.TlsEnabled != _webServiceEnableTls) ||
                (listeners.Http3Enabled.HasValue && listeners.Http3Enabled != _webServiceEnableHttp3) ||
                (listeners.RedirectToTls.HasValue && listeners.RedirectToTls != _webServiceHttpToTlsRedirect) ||
                UnixSocketChanges(listeners.HttpSocket, _webServiceEnableHttpUnixSocket, _webServiceHttpUnixSocket) ||
                UnixSocketChanges(listeners.TlsSocket, _webServiceEnableTlsUnixSocket, _webServiceTlsUnixSocket);
        }

        private static bool UnixSocketChanges(WebUnixSocket socket, bool enabled, string path)
        {
            return (socket.Enabled.HasValue && socket.Enabled != enabled) || (socket.Path is not null && socket.Path != (path ?? ""));
        }

        private static bool StageUnixSocket(WebUnixSocket socket, ref bool enabled, ref string path)
        {
            bool changed = UnixSocketChanges(socket, enabled, path);
            enabled = socket.Enabled ?? enabled;
            if (socket.Path is not null)
                path = socket.Path.Length == 0 ? null : socket.Path;
            return changed;
        }

        private ConfigurationTsig.Candidate PrepareTsigKeys(ConfigurationManifest manifest)
        {
            if (!ConfigurationTsig.TryGetDeclaration(manifest, out JsonElement declaration))
                return default;

            string catalogKey = _clusterManager.ClusterInitialized ? ConfigurationTsig.GetCatalogKey(_clusterManager.ClusterDomain) : null;
            var candidate = ConfigurationTsig.Prepare(manifest, declaration, _dnsServer.TsigKeys, catalogKey);
            _dnsServer.ValidateManifestTsigRemovals(candidate.Keys, manifest);
            return candidate;
        }

        private async Task ApplyManifestWithWebRestartAsync(ConfigurationManifest manifest, WebListeners listeners, ConfigurationProxy.Candidate proxy, ConfigurationDnsCertificate.Candidate dnsCertificate, ConfigurationWebCertificate.Candidate? webCertificate, ConfigurationTsig.Candidate tsig, User creator, ConfigurationLdap.Settings ldap, IReadOnlyDictionary<string, ConfigurationUsers.Change> users, ConfigurationStaticSessions.Candidate staticSessions, ConfigurationSso.Settings sso, ConfigurationApplications.Entry[] apps)
        {
            WebListeners previous = CaptureWebListeners();
            SslServerAuthenticationOptions previousTlsOptions;
            ConfigurationWebCertificate.State previousCertificate;
            DateTime previousCertificateTime;
            lock (_saveLock)
            {
                _manifestWebRestart = true;
                previousTlsOptions = _webServiceSslServerAuthenticationOptions;
                previousCertificate = CaptureWebCertificate();
                previousCertificateTime = _webServiceCertificateLastModifiedOn;
            }

            try
            {
                await StopWebServiceAsync();
                StageWebListeners(listeners);
                byte[] generated = webCertificate is { Changed: true } candidate ? StageWebCertificate(candidate, manifest.GetServerDomain()) : null;
                if (webCertificate is not { Changed: true } && previous.Http3Enabled != _webServiceEnableHttp3 && previousTlsOptions is not null)
                    ConfigureWebTlsOptions(previousTlsOptions.ServerCertificateContext);
                await StartWebServiceAsync(false, listeners, sso);
                bool addressesChanged = !previous.Addresses.HasSameItems(_webServiceLocalAddresses);
                await ApplyManifestAsync(manifest, manifest.GetDnsLocalEndPoints(), proxy, dnsCertificate, tsig, listeners: listeners,
                    listenersChanged: true, webAddressesChanged: addressesChanged, webCertificate: webCertificate, generatedWebCertificate: generated, zoneCreator: creator, ldap: ldap, users: users, staticSessions: staticSessions, sso: sso, apps: apps,
                    previousClusterCertificate: previousTlsOptions?.ServerCertificateContext.TargetCertificate);
            }
            catch
            {
                await StopWebServiceAsync();
                StageWebListeners(previous);
                RestoreWebCertificate(previousCertificate, previousTlsOptions, previousCertificateTime);
                await StartWebServiceAsync(false);
                throw;
            }
            finally
            {
                lock (_saveLock)
                {
                    _manifestWebRestart = false;
                    if (_pendingSave)
                        _saveTimer.Change(SAVE_TIMER_INITIAL_INTERVAL, Timeout.Infinite);
                }
            }
        }

        private bool StageWebListeners(WebListeners listeners)
        {
            bool changed = false;
            if (listeners.Addresses is not null && !_webServiceLocalAddresses.HasSameItems(listeners.Addresses))
            {
                _webServiceLocalAddresses = listeners.Addresses;
                changed = true;
            }
            if (listeners.HttpPort.HasValue && listeners.HttpPort != _webServiceHttpPort)
            {
                _webServiceHttpPort = listeners.HttpPort.Value;
                changed = true;
            }
            if (listeners.TlsPort.HasValue && listeners.TlsPort != _webServiceTlsPort)
            {
                _webServiceTlsPort = listeners.TlsPort.Value;
                changed = true;
            }
            if (listeners.TlsEnabled.HasValue && listeners.TlsEnabled != _webServiceEnableTls)
            {
                _webServiceEnableTls = listeners.TlsEnabled.Value;
                changed = true;
            }
            if (listeners.Http3Enabled.HasValue && listeners.Http3Enabled != _webServiceEnableHttp3)
            {
                _webServiceEnableHttp3 = listeners.Http3Enabled.Value;
                changed = true;
            }
            if (listeners.RedirectToTls.HasValue && listeners.RedirectToTls != _webServiceHttpToTlsRedirect)
            {
                _webServiceHttpToTlsRedirect = listeners.RedirectToTls.Value;
                changed = true;
            }
            changed |= StageUnixSocket(listeners.HttpSocket, ref _webServiceEnableHttpUnixSocket, ref _webServiceHttpUnixSocket);
            changed |= StageUnixSocket(listeners.TlsSocket, ref _webServiceEnableTlsUnixSocket, ref _webServiceTlsUnixSocket);
            return changed;
        }

        private void CheckManifestWebLiveSettings(WebLiveSettings headers)
        {
            CheckManifestWebListeners(headers.Listeners);
            if (_manifestOwnsRealIpHeader && headers.RealIp is not null &&
                !string.Equals(headers.RealIp, _webServiceRealIpHeader, StringComparison.OrdinalIgnoreCase))
                throw new DnsWebServiceException("/web/realIpHeader: Setting is managed by the configuration manifest.");
            if (_manifestOwnsFrameAncestors && headers.FrameAncestors is not null && headers.FrameAncestors != _webServiceCspFrameAncestorsHeader)
                throw new DnsWebServiceException("/web/frameAncestors: Setting is managed by the configuration manifest.");
            if (_manifestOwnsReverseProxyAcl && headers.ReverseProxyAcl is not null &&
                !headers.ReverseProxyAcl.SequenceEqual(_webServiceReverseProxyAddresses ?? []))
                throw new DnsWebServiceException("/web/reverseProxyAcl: Setting is managed by the configuration manifest.");
        }

        private void ApplyManifestWebLiveSettings(WebLiveSettings headers, WebListeners listeners, bool listenersChanged, ConfigurationWebCertificate.Candidate? certificate, bool rootChanged, Action<Action> persist)
        {
            lock (_saveLock)
            {
                string oldRealIp = _webServiceRealIpHeader;
                string oldAncestors = _webServiceCspFrameAncestorsHeader;
                bool oldRealIpOwned = _manifestOwnsRealIpHeader;
                bool oldAncestorsOwned = _manifestOwnsFrameAncestors;
                var oldAcl = _webServiceReverseProxyAddresses;
                bool oldAclOwned = _manifestOwnsReverseProxyAcl;
                ushort oldManagedListeners = _managedWebListeners;
                ushort managedListeners = (ushort)((listeners.Addresses is not null ? ManagedWebAddresses : 0) |
                    (listeners.HttpPort.HasValue ? ManagedWebHttpPort : 0) | (listeners.TlsPort.HasValue ? ManagedWebTlsPort : 0) |
                    (listeners.TlsEnabled.HasValue ? ManagedWebTlsEnabled : 0) | (listeners.Http3Enabled.HasValue ? ManagedWebHttp3 : 0) |
                    (listeners.RedirectToTls.HasValue ? ManagedWebRedirect : 0) |
                    (listeners.HttpSocket.Enabled.HasValue ? ManagedWebHttpSocketEnabled : 0) |
                    (listeners.HttpSocket.Path is not null ? ManagedWebHttpSocketPath : 0) |
                    (listeners.TlsSocket.Enabled.HasValue ? ManagedWebTlsSocketEnabled : 0) |
                    (listeners.TlsSocket.Path is not null ? ManagedWebTlsSocketPath : 0) |
                    (certificate?.OwnsSelfSigned == true ? ManagedWebSelfSigned : 0) |
                    (certificate?.OwnsPath == true ? ManagedWebCertificatePath : 0) |
                    (certificate?.OwnsPassword == true ? ManagedWebCertificatePassword : 0));
                bool aclChanged = headers.ReverseProxyAcl is not null && !headers.ReverseProxyAcl.SequenceEqual(oldAcl ?? []);
                string realIp = string.Equals(headers.RealIp, oldRealIp, StringComparison.OrdinalIgnoreCase) ? oldRealIp : headers.RealIp ?? oldRealIp;
                string ancestors = headers.FrameAncestors ?? oldAncestors;
                if (realIp == oldRealIp && ancestors == oldAncestors && !aclChanged && !listenersChanged && !rootChanged && certificate is not { Changed: true } && managedListeners == oldManagedListeners &&
                    (headers.ReverseProxyAcl is not null) == oldAclOwned &&
                    (headers.RealIp is not null) == oldRealIpOwned && (headers.FrameAncestors is not null) == oldAncestorsOwned)
                {
                    persist(null);
                    return;
                }

                _webServiceRealIpHeader = realIp;
                _webServiceCspFrameAncestorsHeader = ancestors;
                _manifestOwnsRealIpHeader = headers.RealIp is not null;
                _manifestOwnsFrameAncestors = headers.FrameAncestors is not null;
                _manifestOwnsReverseProxyAcl = headers.ReverseProxyAcl is not null;
                _managedWebListeners = managedListeners;
                if (aclChanged)
                    _webServiceReverseProxyAddresses = headers.ReverseProxyAcl.Count == 0 ? null : headers.ReverseProxyAcl;
                try
                {
                    persist(SaveConfigFileInternal);
                    _pendingSave = false;
                }
                catch
                {
                    _webServiceRealIpHeader = oldRealIp;
                    _webServiceCspFrameAncestorsHeader = oldAncestors;
                    _manifestOwnsRealIpHeader = oldRealIpOwned;
                    _manifestOwnsFrameAncestors = oldAncestorsOwned;
                    _webServiceReverseProxyAddresses = oldAcl;
                    _manifestOwnsReverseProxyAcl = oldAclOwned;
                    _managedWebListeners = oldManagedListeners;
                    throw;
                }
            }
        }

        private async Task ApplyManifestAsync(ConfigurationManifest manifest, IReadOnlyList<IPEndPoint> endpoints, ConfigurationProxy.Candidate proxy, ConfigurationDnsCertificate.Candidate dnsCertificate, ConfigurationTsig.Candidate tsig, bool alreadyActive = false, WebListeners listeners = default, bool listenersChanged = false, bool webAddressesChanged = false, bool listenerTuningStaged = false, bool dnsBindingsStaged = false, ConfigurationWebCertificate.Candidate? webCertificate = null, byte[] generatedWebCertificate = null, bool webRootChanged = false, User zoneCreator = null, ConfigurationLdap.Settings ldap = null, IReadOnlyDictionary<string, ConfigurationUsers.Change> users = null, ConfigurationStaticSessions.Candidate staticSessions = null, ConfigurationSso.Settings sso = null, ConfigurationApplications.Entry[] apps = null, X509Certificate2 previousClusterCertificate = null)
        {
            string domain = manifest.GetServerDomain();
            bool clustered = _clusterManager.ClusterInitialized;
            bool secondary = clustered && _clusterManager.GetSelfNode().Type == ClusterNodeType.Secondary;
            var blockLists = _dnsServer.BlockListZoneManager;
            var domainListChange = ConfigurationPlan.CheckClusterDomainListSupport(manifest, _clusterManager);
            int[] dnsPolicyPeers = ConfigurationPlan.CheckClusterDnsPolicySupport(manifest, _clusterManager);
            var previousBlockLists = (blockLists.BlockListUrls, blockLists.BlockListUpdateIntervalHours,
                blockLists.ManifestOwnsSources, blockLists.ManifestOwnsUpdateInterval);
            bool regenerateCertificate = generatedWebCertificate is null && _webServiceUseSelfSignedTlsCertificate &&
                ((webAddressesChanged && !_clusterManager.ClusterInitialized) || (domain is not null && !string.Equals(domain, _dnsServer.ServerDomain, StringComparison.OrdinalIgnoreCase)));
            Action writeCertificate = regenerateCertificate ? () => CheckAndLoadSelfSignedCertificate(true, true, domain ?? _dnsServer.ServerDomain) : null;
            if (generatedWebCertificate is not null)
            {
                writeCertificate = () =>
                {
                    using var file = new FileStream(Path.Combine(_configFolder, "self-signed-cert.pfx"), FileMode.Create, FileAccess.Write);
                    file.Write(generatedWebCertificate);
                    file.Flush(flushToDisk: true);
                };
            }

            SslServerAuthenticationOptions previousTlsOptions = _webServiceSslServerAuthenticationOptions;
            DateTime previousCertificateLastModified = _webServiceCertificateLastModifiedOn;
            string previousCertificateFileHash = _webServiceCertificateFileHash;
            try
            {
                var zones = _dnsServer.AuthZoneManager.PrepareManifestZoneAndAuthChanges(manifest, _authManager, zoneCreator, tsig.Keys ?? _dnsServer.TsigKeys,
                    ldap ?? ConfigurationLdap.Prepare(manifest, _authManager), users, staticSessions,
                    sso is not null && ConfigurationSso.Same(_authManager.GetManifestSsoSettings(), sso) ? null : sso);
                var clusterOptions = ConfigurationClusterOptions.Prepare(manifest, _clusterManager,
                    webCertificate is { Changed: true }, previousClusterCertificate, WebServiceTlsCertificate);
                Action writeCluster = null;
                int[] blockListPeers = ConfigurationPlan.CheckClusterBlockListSupport(manifest, _clusterManager);
                Action checkBlockListPeers = blockListPeers.Length == 0 ? null : () =>
                {
                    if (!_clusterManager.CheckDeclarativeBlockListPeers().SequenceEqual(blockListPeers))
                        throw new InvalidDataException("/blocklists: Cluster membership changed during apply. Create a new preview.");
                };
                Action checkDomainListPeers = domainListChange is { } domainLists ? () =>
                {
                    if (!_clusterManager.CheckDeclarativeDomainListPeers(domainLists.Path).SequenceEqual(domainLists.Peers))
                        throw new InvalidDataException($"{domainLists.Path}: Cluster membership changed during apply. Create a new preview.");
                } : null;
                Action checkDnsPolicyPeers = dnsPolicyPeers is null ? null : () =>
                {
                    if (!_clusterManager.CheckDeclarativeDnsPolicyPeers().SequenceEqual(dnsPolicyPeers))
                        throw new InvalidDataException("/dns: Cluster membership changed during apply. Create a new preview.");
                };
                var clusterFiles = new List<string>(2);
                if (clusterOptions is { ValuesChanged: true } or { AddressesChanged: true } or { EndpointChanged: true })
                    clusterFiles.Add("cluster.config");
                if (clusterOptions is { OwnershipChanged: true })
                    clusterFiles.Add(ConfigurationClusterOptions.OwnershipFile);
                if (clusterOptions is { } clusterChange)
                    clusterFiles.AddRange(clusterChange.ZoneRecords.Select(record => Path.Combine("zones", record.Zone + ".zone")).Distinct());
                DnsApplicationManager manager = _dnsServer.DnsApplicationManager;
                apps ??= ConfigurationApplications.Prepare(manifest, manager);
                await ConfigurationApplications.ApplyAsync(manager, apps, ConfigurationApplications.GetOwnedPaths(manifest), (writeApps, appFiles) =>
                    _dhcpServer.ApplyManifestScopesAsync(manifest, (writeScopes, scopeFiles) =>
                    ConfigurationPlan.ApplyAsync(manifest, _log, _dnsServer, endpoints, domain, _webServiceTlsPort, writeCertificate,
                        (headers, persist) => ApplyManifestWebLiveSettings(headers, listeners, listenersChanged, webCertificate, webRootChanged, persist),
                        alreadyActive, listenerTuningStaged, dnsBindingsStaged, proxy, dnsCertificate, tsig, checkBlockListPeers + checkDomainListPeers + checkDnsPolicyPeers + writeApps + writeScopes + zones.Write + (clusterFiles.Count == 0 ? null : () => writeCluster?.Invoke()), [.. appFiles, .. scopeFiles, .. zones.Files, .. clusterFiles],
                        persist => _clusterManager.ApplyManifestOptions(clusterOptions, write =>
                        {
                            writeCluster = write;
                            zones.Commit(persist);
                        }), isClusterSecondary: secondary)));
            }
            catch
            {
                if (regenerateCertificate)
                {
                    _webServiceSslServerAuthenticationOptions = previousTlsOptions;
                    _webServiceCertificateLastModifiedOn = previousCertificateLastModified;
                    _webServiceCertificateFileHash = previousCertificateFileHash;
                }

                throw;
            }

            if (clustered && !secondary && (dnsPolicyPeers is not null || domainListChange.HasValue || previousBlockLists != (blockLists.BlockListUrls,
                blockLists.BlockListUpdateIntervalHours, blockLists.ManifestOwnsSources, blockLists.ManifestOwnsUpdateInterval)))
                _clusterManager.TriggerNotifyAllSecondaryNodesIfPrimarySelfNode();

            if (webCertificate is { Changed: true })
            {
                if (_webServiceTlsCertificatePath is null)
                    StopTlsCertificateUpdateTimer();
                else
                    StartTlsCertificateUpdateTimer();
            }

            if (_ssoHttpHandler is not null)
            {
                _ssoHttpHandler.Proxy = _dnsServer.Proxy;
                _ssoHttpHandler.NetworkType = HttpClientNetworkHandler.GetNetworkType(_dnsServer.IPv6Mode);
            }
        }

        private byte[] CreateSelfSignedWebCertificate(string serverDomain)
        {
            using RSA rsa = RSA.Create(2048);
            CertificateRequest req = new CertificateRequest("cn=" + serverDomain, rsa, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

            SubjectAlternativeNameBuilder san = new SubjectAlternativeNameBuilder();
            bool sanAdded = false;

            foreach (IPAddress localAddress in _webServiceLocalAddresses)
            {
                if (localAddress.Equals(IPAddress.IPv6Any) || localAddress.Equals(IPAddress.Any))
                    continue;

                san.AddIpAddress(localAddress);
                sanAdded = true;
            }

            if (sanAdded)
                req.CertificateExtensions.Add(san.Build());

            using X509Certificate2 cert = req.CreateSelfSigned(DateTimeOffset.UtcNow, DateTimeOffset.UtcNow.AddYears(5));

            return cert.Export(X509ContentType.Pkcs12, null as string);
        }

        private void CheckAndLoadSelfSignedCertificate(bool forceGenerateNew, bool throwException, string serverDomain = null)
        {
            string selfSignedCertificateFilePath = Path.Combine(_configFolder, "self-signed-cert.pfx");

            if (_webServiceUseSelfSignedTlsCertificate)
            {
                string oldSelfSignedCertificateFilePath = Path.Combine(_configFolder, "cert.pfx");

                if (serverDomain is null && !oldSelfSignedCertificateFilePath.Equals(_log.ConvertToAbsolutePath(_webServiceTlsCertificatePath), Environment.OSVersion.Platform == PlatformID.Win32NT ? StringComparison.OrdinalIgnoreCase : StringComparison.Ordinal) && File.Exists(oldSelfSignedCertificateFilePath) && !File.Exists(selfSignedCertificateFilePath))
                    File.Move(oldSelfSignedCertificateFilePath, selfSignedCertificateFilePath);

                if (forceGenerateNew || !File.Exists(selfSignedCertificateFilePath))
                {
                    using var certificateFile = new FileStream(selfSignedCertificateFilePath, FileMode.Create, FileAccess.Write);
                    certificateFile.Write(CreateSelfSignedWebCertificate(serverDomain ?? _dnsServer.ServerDomain));
                    certificateFile.Flush(flushToDisk: true);
                }

                if ((_webServiceSslServerAuthenticationOptions is null) || string.IsNullOrEmpty(_webServiceTlsCertificatePath))
                {
                    try
                    {
                        LoadWebServiceTlsCertificate(selfSignedCertificateFilePath, null);

                        if (!forceGenerateNew)
                        {
                            if (_webServiceSslServerAuthenticationOptions.ServerCertificateContext.TargetCertificate.NotAfter < DateTime.UtcNow.AddYears(1))
                            {
                                _log.Write("Web Service TLS self signed certificate is nearing expiration and will be regenerated.");
                                CheckAndLoadSelfSignedCertificate(true, throwException); //force generate new cert

                                if (_clusterManager.ClusterInitialized)
                                    _clusterManager.UpdateSelfNodeUrlAndCertificate();
                            }
                        }
                    }
                    catch (Exception ex)
                    {
                        _log.Write("DNS Server encountered an error while loading self signed Web Service TLS certificate: " + selfSignedCertificateFilePath, ex);

                        if (throwException)
                            throw;
                    }
                }
            }
            else
            {
                File.Delete(selfSignedCertificateFilePath);
            }
        }

        #endregion

        #region secondary catalog zones

        private void AuthZoneManager_SecondaryCatalogZoneAdded(object sender, SecondaryCatalogEventArgs e)
        {
            AuthZoneInfo secondaryCatalogZoneInfo = new AuthZoneInfo(sender as ApexZone);
            AuthZoneInfo memberZoneInfo = e.ZoneInfo;

            //clone user/group permissions from source zone
            Permission sourceZonePermissions = _authManager.GetPermission(PermissionSection.Zones, secondaryCatalogZoneInfo.Name);

            foreach (KeyValuePair<User, PermissionFlag> userPermission in sourceZonePermissions.UserPermissions)
                _authManager.SetPermission(PermissionSection.Zones, memberZoneInfo.Name, userPermission.Key, userPermission.Value);

            foreach (KeyValuePair<Group, PermissionFlag> groupPermissions in sourceZonePermissions.GroupPermissions)
                _authManager.SetPermission(PermissionSection.Zones, memberZoneInfo.Name, groupPermissions.Key, groupPermissions.Value);

            //set default permissions
            _authManager.SetPermission(PermissionSection.Zones, memberZoneInfo.Name, _authManager.GetGroup(Group.ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
            _authManager.SetPermission(PermissionSection.Zones, memberZoneInfo.Name, _authManager.GetGroup(Group.DNS_ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
            _authManager.SaveConfigFile();

            //sync dnssec private keys for secondary members zone when it is a cluster secondary catalog zone
            if (_clusterManager.ClusterInitialized && (memberZoneInfo.Type == AuthZoneType.Secondary) && secondaryCatalogZoneInfo.Name.Equals("cluster-catalog." + _clusterManager.ClusterDomain, StringComparison.OrdinalIgnoreCase))
                _clusterManager.TriggerRefreshForConfig([memberZoneInfo.Name]);

            //delete cache for this zone to allow rebuilding cache data as needed by stub or forwarder zone
            _dnsServer.CacheZoneManager.DeleteZone(memberZoneInfo.Name);
        }

        private void AuthZoneManager_SecondaryCatalogZoneRemoved(object sender, SecondaryCatalogEventArgs e)
        {
            _authManager.RemoveAllPermissions(PermissionSection.Zones, e.ZoneInfo.Name);
            _authManager.SaveConfigFile();

            //delete cache for this zone to allow rebuilding cache data without using the current zone
            _dnsServer.CacheZoneManager.DeleteZone(e.ZoneInfo.Name);
        }

        #endregion

        #region public

        public async Task StartAsync(bool throwIfBindFails = false)
        {
            if (_disposed)
                ObjectDisposedException.ThrowIf(_disposed, this);

            if (_isRunning)
                throw new DnsWebServiceException("The DNS web service is already running.");

            try
            {
                ConfigurationManifest startupManifest = ConfigurationManifest.LoadForStartup(_configFolder);
                if (!ConfigurationStaticSessions.TryGetDeclaration(startupManifest, out _))
                    _authManager.LoadManifestStaticSessions();
                bool useLegacyServerDomain = startupManifest?.GetServerDomain() is null;
                string domainWarning = startupManifest?.GetServerDomainEnvironmentWarning();
                if (domainWarning is not null)
                    _log.Write(domainWarning);

                //init dns server
                _dnsServer = new DnsServer(_configFolder, Path.Combine(_appFolder, "dohwww"), _log);

                //init dhcp server
                _dhcpServer = new DhcpServer(Path.Combine(_configFolder, "scopes"), _log);
                _dhcpServer.DnsServer = _dnsServer;
                _dhcpServer.AuthManager = _authManager;

                //load web service config file
                LoadConfigFile(useLegacyServerDomain);

                //load dns config file
                _dnsServer.LoadConfigFile(useLegacyServerDomain);

                //load all dns applications
                await _dnsServer.DnsApplicationManager.LoadAllApplicationsAsync();

                //load all zones files
                _dnsServer.AuthZoneManager.SecondaryCatalogZoneAdded += AuthZoneManager_SecondaryCatalogZoneAdded;
                _dnsServer.AuthZoneManager.SecondaryCatalogZoneRemoved += AuthZoneManager_SecondaryCatalogZoneRemoved;
                _dnsServer.AuthZoneManager.LoadAllZoneFiles();
                InspectAndFixZonePermissions();

                //disable zones from old config format
                if (_configDisabledZones != null)
                {
                    foreach (string domain in _configDisabledZones)
                    {
                        AuthZoneInfo zoneInfo = _dnsServer.AuthZoneManager.GetAuthZoneInfo(domain);
                        if (zoneInfo is not null)
                        {
                            zoneInfo.Disabled = true;
                            _dnsServer.AuthZoneManager.SaveZoneFile(zoneInfo.Name);
                        }
                    }
                }

                //load allowed zone and blocked zone files
                _dnsServer.AllowedZoneManager.LoadAllowedZoneFile();
                _dnsServer.BlockedZoneManager.LoadBlockedZoneFile();
                _dnsServer.BlockListZoneManager.LoadConfigFile();

                //init cluster manager and load config file
                _clusterManager = new ClusterManager(this);
                User bootstrapAdmin = _authManager.GetUser("admin");
                var bootstrap = ConfigurationClusterOptions.PrepareBootstrap(startupManifest, _clusterManager, bootstrapAdmin);
                if (bootstrap is not null && !IsWebServiceTlsEnabled)
                    throw new InvalidDataException("/cluster/bootstrap: Configure web TLS before bootstrapping the node.");
                if (startupManifest is not null && bootstrap is null)
                {
                    ConfigurationPlan.CheckClusterApplySupport(startupManifest, _clusterManager);
                    ConfigurationClusterOptions.Prepare(startupManifest, _clusterManager);
                }
                ConfigurationSso.Settings sso = ConfigurationSso.Prepare(startupManifest, _authManager);
                ConfigurationProxy.Candidate proxy = startupManifest is null ? default : ConfigurationPlan.PrepareProxy(startupManifest, _dnsServer);

                //cert may have changed so update cluster certs when loading
                if (_clusterManager.ClusterInitialized)
                {
                    try
                    {
                        _clusterManager.UpdateSelfNodeUrlAndCertificate();
                    }
                    catch (Exception ex)
                    {
                        _log.Write(ex);
                    }
                }

                ConfigurationTsig.Candidate tsig = PrepareTsigKeys(startupManifest);
                DnsServer.DnsBindings dnsBindings = ConfigurationPlan.GetDnsBindings(startupManifest);
                DnsServer.DnsBindings previousDnsBindings = _dnsServer.CaptureDnsBindings();
                ConfigurationDnsCertificate.Candidate dnsCertificate = ConfigurationDnsCertificate.Prepare(startupManifest, _dnsServer);
                ConfigurationPlan.ValidateDnsCertificateAndBindings(dnsCertificate, dnsBindings, previousDnsBindings, _dnsServer.HasDnsListenerCertificate);
                bool dnsCertificateStaged = _dnsServer.DnsCertificateChanged(dnsCertificate);
                bool dnsBindingsStaged = DnsServer.DnsBindingsDiffer(dnsBindings, previousDnsBindings);
                string declaredWebRoot = ConfigurationPlan.ReadWebRoot(startupManifest, _log);
                string previousWebRoot = _webRootOverride;
                bool previousWebRootOwnership = _manifestOwnsWebRoot;
                bool webRootChanged = startupManifest is not null &&
                    (declaredWebRoot is not null && declaredWebRoot != previousWebRoot || (declaredWebRoot is not null) != previousWebRootOwnership);
                ConfigurationWebCertificate.Candidate? webCertificate = PrepareWebCertificate(startupManifest);
                ConfigurationWebCertificate.State previousWebCertificate = CaptureWebCertificate();
                DateTime previousWebCertificateTime = _webServiceCertificateLastModifiedOn;
                WebListeners listeners = ConfigurationPlan.GetWebListeners(startupManifest);
                DnsServer.DnsTuning tuning = ConfigurationPlan.GetDnsTuning(startupManifest);
                DnsServer.DnsTuning previousListenerTuning = _dnsServer.CaptureListenerTuning();
                bool listenerTuningStaged = _dnsServer.DnsTuningRequiresRestart(tuning);
                WebListeners previousWebListeners = CaptureWebListeners();
                SslServerAuthenticationOptions previousTlsOptions = _webServiceSslServerAuthenticationOptions;
                if (webRootChanged || webCertificate is { Changed: true })
                {
                    lock (_saveLock)
                        _manifestWebRestart = true;
                }
                try
                {
                    await _settingsApi.WithConfigurationLockAsync(async () =>
                    {
                        // Start the web service and bind the DNS candidate before committing the manifest.
                        if (startupManifest is not null)
                        {
                            _webRootOverride = declaredWebRoot ?? previousWebRoot;
                            _manifestOwnsWebRoot = declaredWebRoot is not null;
                        }
                        ValidateManifestWebListeners(listeners, webCertificate?.HasCertificate);
                        bool listenersChanged = StageWebListeners(listeners);
                        byte[] generated = webCertificate is { Changed: true } candidate ? StageWebCertificate(candidate, startupManifest.GetServerDomain()) : null;
                        if (webCertificate is not { Changed: true } && previousWebListeners.Http3Enabled != _webServiceEnableHttp3 && previousTlsOptions is not null)
                            ConfigureWebTlsOptions(previousTlsOptions.ServerCertificateContext);
                        if (throwIfBindFails || sso is not null || listeners.HasValues || _managedWebListeners != 0 || webRootChanged || _webRootOverride is not null || webCertificate is { Changed: true })
                            await StartWebServiceAsync(false, listeners, sso);
                        else
                            await TryStartWebServiceAsync([IPAddress.Any, IPAddress.IPv6Any], 5380, 53443);

                        _isRunning = true;
                        IReadOnlyList<IPEndPoint> endpoints = startupManifest?.GetDnsLocalEndPoints();
                        if (listenerTuningStaged)
                            _dnsServer.SetListenerTuning(tuning);
                        if (dnsBindingsStaged)
                            _dnsServer.StageManifestDnsBindings(dnsBindings);
                        if (dnsCertificateStaged)
                            _dnsServer.StageManifestDnsCertificate(dnsCertificate);
                        await _dnsServer.StartAsync(throwIfBindFails || endpoints is not null || dnsBindings != default || dnsCertificateStaged, endpoints ?? _dnsServer.LocalEndPoints);
                        bool declaresDhcp = startupManifest is not null && startupManifest.Settings.TryGetProperty("dhcp", out var dhcp) &&
                            dhcp.TryGetProperty("scopes", out _);
                        await _dhcpServer.StartAsync(waitForScopes: declaresDhcp);
                        if (bootstrap is ConfigurationClusterOptions.PrimaryBootstrap primary)
                            _clusterManager.InitializePrimaryFromManifest(primary, bootstrapAdmin);
                        else if (bootstrap is ConfigurationClusterOptions.SecondaryBootstrap secondary)
                            await _clusterManager.InitializeAndJoinClusterAsync(secondary.Addresses, secondary.PrimaryUrl, secondary.Username,
                                secondary.Password, secondary.Totp, secondary.PrimaryAddress is null ? null : [secondary.PrimaryAddress],
                                secondary.IgnoreCertificateErrors, expectedDomain: secondary.Domain);
                        else if (startupManifest is not null)
                        {
                            bool webAddressesChanged = !previousWebListeners.Addresses.HasSameItems(_webServiceLocalAddresses);
                            await _dhcpServer.EnterManifestGateAsync();
                            try
                            {
                                await ApplyManifestAsync(startupManifest, endpoints, proxy, dnsCertificate, tsig, alreadyActive: true, listeners, listenersChanged, webAddressesChanged, listenerTuningStaged, dnsBindingsStaged, webCertificate, generated, webRootChanged, sso: sso,
                                    previousClusterCertificate: previousTlsOptions?.ServerCertificateContext.TargetCertificate);
                            }
                            finally
                            {
                                _dhcpServer.ExitManifestGate();
                            }
                        }
                    });
                }
                catch
                {
                    await StopAsync();
                    if (listenerTuningStaged)
                        _dnsServer.SetListenerTuning(previousListenerTuning);
                    if (dnsBindingsStaged)
                        _dnsServer.FinishManifestDnsBindings(committed: false);
                    if (dnsCertificateStaged)
                        _dnsServer.FinishManifestDnsCertificate(committed: false);
                    if (listeners.HasValues)
                        StageWebListeners(previousWebListeners);
                    _webRootOverride = previousWebRoot;
                    _manifestOwnsWebRoot = previousWebRootOwnership;
                    RestoreWebCertificate(previousWebCertificate, previousTlsOptions, previousWebCertificateTime);
                    throw;
                }

                finally
                {
                    if (webRootChanged || webCertificate is { Changed: true })
                    {
                        lock (_saveLock)
                        {
                            _manifestWebRestart = false;
                            if (_pendingSave)
                                _saveTimer.Change(SAVE_TIMER_INITIAL_INTERVAL, Timeout.Infinite);
                        }
                    }
                }

                _log.Write("DNS Server (v" + _currentVersion.ToString() + ") was started successfully.");
            }
            catch (Exception ex)
            {
                _log.Write("Failed to start DNS Server (v" + _currentVersion.ToString() + ").", ex);
                throw;
            }
        }

        public async Task StopAsync()
        {
            if (!_isRunning || _disposed)
                return;

            try
            {
                //stop cluster manager
                _clusterManager?.Dispose();

                //stop web service
                await StopWebServiceAsync();

                //stop dhcp
                _dhcpServer?.Dispose();

                //stop dns & save cache to disk
                if (_dnsServer is not null)
                    await _dnsServer.DisposeAsync();

                _log.Write("DNS Server (v" + _currentVersion.ToString() + ") was stopped successfully.");
                _isRunning = false;
            }
            catch (Exception ex)
            {
                _log.Write("Failed to stop DNS Server (v" + _currentVersion.ToString() + ").", ex);
                throw;
            }
        }

        #endregion

        #region properties

        public DnsServer DnsServer
        { get { return _dnsServer; } }

        public DateTime UpTimeStamp
        { get { return _uptimestamp; } }

        public string ConfigFolder
        { get { return _configFolder; } }

        public string Version
        { get { return GetCleanVersion(_currentVersion); } }

        public int WebServiceHttpPort
        { get { return _webServiceHttpPort; } }

        public int WebServiceTlsPort
        { get { return _webServiceTlsPort; } }

        public bool IsWebServiceTlsEnabled
        {
            get
            {
                return _webServiceEnableTls && (_webServiceUseSelfSignedTlsCertificate || !string.IsNullOrEmpty(_webServiceTlsCertificatePath)) && (_webServiceSslServerAuthenticationOptions is not null);
            }
        }

        internal X509Certificate2 WebServiceTlsCertificate
        {
            get
            {
                if (_webServiceSslServerAuthenticationOptions is null)
                    return null;

                return _webServiceSslServerAuthenticationOptions.ServerCertificateContext.TargetCertificate;
            }
        }

        internal AuthManager AuthManager
        { get { return _authManager; } }

        internal LogManager LogManager
        { get { return _log; } }

        #endregion
    }
}
