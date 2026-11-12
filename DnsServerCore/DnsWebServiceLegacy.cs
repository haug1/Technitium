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

using DnsServerCore.Dns;
using DnsServerCore.Dns.ZoneManagers;
using DnsServerCore.Dns.Zones;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Mail;
using System.Net.Quic;
using System.Net.Sockets;
using System.Text;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ClientConnection;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using TechnitiumLibrary.Net.Proxy;

namespace DnsServerCore
{
    public partial class DnsWebService
    {
        #region legacy config

        private bool TryLoadOldConfigFile()
        {
            string configFile = Path.Combine(_configFolder, "dns.config");

            try
            {
                using (FileStream fS = new FileStream(configFile, FileMode.Open, FileAccess.Read))
                {
                    if (TryLoadOldConfigFrom(fS))
                    {
                        _log.Write("Old DNS config file was loaded: " + configFile);
                        return true;
                    }
                }
            }
            catch (FileNotFoundException)
            {
                //do nothing
            }
            catch (Exception ex)
            {
                _log.Write("DNS Server encountered an error while trying to load old DNS config file: " + configFile, ex);
            }

            return false;
        }

        private bool TryLoadOldConfigFrom(Stream s)
        {
            if (Encoding.ASCII.GetString(s.ReadExactly(2)) == "DS")
            {
                BinaryReader bR = new BinaryReader(s);

                int version = bR.ReadByte();

                ReadOldConfigFrom(bR, version);

                s.Dispose();
                _dnsServer.SaveConfigFile(true);

                return true;
            }

            return false;
        }

        private void ReadOldConfigFrom(BinaryReader bR, int version)
        {
            if ((version >= 28) && (version <= 42))
            {
                ReadConfigFromV42(bR, version);
            }
            else if ((version >= 2) && (version <= 27))
            {
                ReadConfigFromV27(bR, version);

                //new default settings
                DnsClientConnection.IPv4SourceAddresses = null;
                DnsClientConnection.IPv6SourceAddresses = null;
                _dnsServer.EnableUdpSocketPool = Environment.OSVersion.Platform == PlatformID.Win32NT;
                UdpClientConnection.SocketPoolExcludedPorts = [(ushort)_webServiceTlsPort];
                _dnsServer.MaxConcurrentResolutionsPerCore = 100;
                _dnsServer.DnsApplicationManager.EnableAutomaticUpdate = true;
                _webServiceEnableHttp3 = _webServiceEnableTls && QuicConnection.IsSupported && Socket.OSSupportsIPv6;
                _dnsServer.EnableDnsOverHttp3 = _dnsServer.EnableDnsOverHttps && QuicConnection.IsSupported && Socket.OSSupportsIPv6;
                if (!_manifestOwnsRealIpHeader)
                    _webServiceRealIpHeader = "X-Real-IP";
                _dnsServer.DnsOverHttpRealIpHeader = "X-Real-IP";
                _dnsServer.DefaultResponsiblePerson = null;
                _dnsServer.AuthZoneManager.UseSoaSerialDateScheme = false;
                _dnsServer.AuthZoneManager.MinSoaRefresh = 300;
                _dnsServer.AuthZoneManager.MinSoaRetry = 300;
                _dnsServer.ZoneTransferAllowedNetworks = null;
                _dnsServer.NotifyAllowedNetworks = null;
                _dnsServer.EDnsClientSubnet = false;
                _dnsServer.EDnsClientSubnetIPv4PrefixLength = 24;
                _dnsServer.EDnsClientSubnetIPv6PrefixLength = 56;
                _dnsServer.EDnsClientSubnetIpv4Override = null;
                _dnsServer.EDnsClientSubnetIpv6Override = null;
                _dnsServer.QpmLimitBypassList = null;

                if (_dnsServer.EnableDnsOverUdpProxy || _dnsServer.EnableDnsOverTcpProxy || _dnsServer.EnableDnsOverHttp)
                {
                    _dnsServer.DnsReverseProxyNetworkACL =
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

                _dnsServer.BlockingBypassList = null;
                _dnsServer.BlockingAnswerTtl = 30;
                _dnsServer.ResolverConcurrency = 2;
                _dnsServer.CacheZoneManager.ServeStaleAnswerTtl = CacheZoneManager.SERVE_STALE_ANSWER_TTL;
                _dnsServer.CacheZoneManager.ServeStaleResetTtl = CacheZoneManager.SERVE_STALE_RESET_TTL;
                _dnsServer.ServeStaleMaxWaitTime = DnsServer.SERVE_STALE_MAX_WAIT_TIME;
                _dnsServer.ConcurrentForwarding = true;
                _dnsServer.ResolverLogManager = _log;
                _dnsServer.StatsManager.EnableInMemoryStats = false;
            }
            else
            {
                throw new InvalidDataException("DNS Server config version not supported.");
            }
        }

        private readonly record struct LegacyWebConfiguration(int HttpPort, int TlsPort, IReadOnlyList<IPAddress> Addresses,
            bool EnableTls, bool EnableHttp3, bool RedirectToTls, bool UseSelfSignedCertificate,
            string CertificatePath, string CertificatePassword, string RealIpHeader);

        private static LegacyWebConfiguration ReadLegacyWebConfiguration(BinaryReader reader, int version)
        {
            int httpPort = reader.ReadInt32();
            int tlsPort = reader.ReadInt32();
            int addressCount = reader.ReadByte();
            IPAddress[] addresses = addressCount == 0 ? [IPAddress.Any, IPAddress.IPv6Any] : new IPAddress[addressCount];
            for (int i = 0; i < addressCount; i++)
                addresses[i] = IPAddressExtensions.ReadFrom(reader);

            bool enableTls = reader.ReadBoolean();
            bool enableHttp3 = version >= 33 ? reader.ReadBoolean() : enableTls && QuicConnection.IsSupported && Socket.OSSupportsIPv6;
            bool redirectToTls = reader.ReadBoolean();
            bool useSelfSignedCertificate = reader.ReadBoolean();
            string certificatePath = reader.BaseStream.ReadShortString();
            string certificatePassword = reader.BaseStream.ReadShortString();
            string realIpHeader = version >= 38 ? reader.BaseStream.ReadShortString() : "X-Real-IP";

            return new LegacyWebConfiguration(httpPort, tlsPort, addresses, enableTls, enableHttp3, redirectToTls,
                useSelfSignedCertificate, certificatePath.Length == 0 ? null : certificatePath, certificatePassword, realIpHeader);
        }

        private static IReadOnlyList<IPEndPoint> ReadLegacyLocalEndPoints(BinaryReader reader)
        {
            int count = reader.ReadByte();
            var endpoints = new List<IPEndPoint>(count);
            for (int i = 0; i < count; i++)
            {
                var endpoint = (IPEndPoint)EndPointExtensions.ReadFrom(reader);
                if (endpoint.Port != 853)
                    endpoints.Add(endpoint);
            }

            return DnsServer.NormalizeLocalEndPoints(endpoints);
        }

        private static (NetworkAddress[] Ipv4, NetworkAddress[] Ipv6, uint RecordTtl) ReadLegacyDnsDefaults(BinaryReader reader, int version)
        {
            NetworkAddress[] ipv4 = version >= 34 ? AuthZoneInfo.ReadNetworkAddressesFrom(reader) : null;
            NetworkAddress[] ipv6 = version >= 34 ? AuthZoneInfo.ReadNetworkAddressesFrom(reader) : null;
            return (ipv4, ipv6, reader.ReadUInt32());
        }

        private static DnsServer.AuthoritativeDefaults ReadLegacySoaTiming(BinaryReader reader, int version)
        {
            return new DnsServer.AuthoritativeDefaults(null, null, null, version >= 33 && reader.ReadBoolean(),
                version >= 40 ? reader.ReadUInt32() : 300u, version >= 40 ? reader.ReadUInt32() : 300u);
        }

        private bool CheckRestoreManifestDnsSettings(Stream stream, bool isConfigTransfer = false)
        {
            var reader = new BinaryReader(stream);
            string format = Encoding.ASCII.GetString(stream.ReadExactly(2));
            if (format == "DC")
            {
                _dnsServer.CheckRestoreManifestDnsSettings(reader, isConfigTransfer);
                return _dnsServer.HasManagedProxy || _dnsServer.HasManagedRecursionPolicy || _dnsServer.HasManagedBlockingPolicy || _dnsServer.HasManagedForwardingPolicy || _dnsServer.HasManagedRateLimits || _dnsServer.HasManagedDnsTuning || !isConfigTransfer && (_dnsServer.HasManagedDnsListenerPolicy || _dnsServer.ManifestOwnsInMemoryStatistics || _dnsServer.ManifestOwnsStatisticsRetention ||
                    _dnsServer.ManifestOwnsResolverLogging || _dnsServer.ManifestOwnsQueryLogging || _dnsServer.HasManagedCachePolicy);
            }

            if (format == "DS")
            {
                if (_dnsServer.HasManagedDnsListenerPolicy)
                    throw new InvalidDataException("/dns/listeners: Cannot verify DNS listener policy in this combined backup format.");

                if (_dnsServer.HasManagedProxy)
                    throw new InvalidDataException("/dns/proxy: Cannot verify outbound proxy settings in this combined backup format.");

                if (!isConfigTransfer && _dnsServer.HasManagedCachePolicy)
                    throw new InvalidDataException("/dns/cache: Cannot verify cache policy in this combined backup format.");

                if (_dnsServer.HasManagedDnsTuning)
                    throw new InvalidDataException("/dns/tuning: Cannot verify DNS tuning in this combined backup format.");

                if (_dnsServer.HasManagedRateLimits)
                    throw new InvalidDataException("/dns/rateLimits: Cannot verify query-rate limits in this combined backup format.");

                if (_dnsServer.HasManagedForwardingPolicy)
                    throw new InvalidDataException("/dns/forwarding: Cannot verify forwarding policy in this combined backup format.");

                if (_dnsServer.HasManagedBlockingPolicy)
                    throw new InvalidDataException("/dns/blocking: Cannot verify blocking policy in this combined backup format.");

                if (_dnsServer.HasManagedRecursionPolicy)
                    throw new InvalidDataException("/dns/recursion: Cannot verify recursion policy in this combined backup format.");

                if (!isConfigTransfer && (_dnsServer.ManifestOwnsInMemoryStatistics || _dnsServer.ManifestOwnsStatisticsRetention))
                    throw new InvalidDataException("/statistics: Release statistics ownership before restoring this combined DNS backup format.");

                if (!isConfigTransfer && _dnsServer.ManifestOwnsResolverLogging)
                    throw new InvalidDataException("/logging/ignoreResolverLogs: Release resolver logging ownership before restoring this combined DNS backup format.");
                if (!isConfigTransfer && _dnsServer.ManifestOwnsQueryLogging)
                    throw new InvalidDataException("/logging/logQueries: Release query logging ownership before restoring this combined DNS backup format.");

                if (_dnsServer.BlockListZoneManager.ManifestOwnsSources)
                    throw new InvalidDataException("/blocklists/sources: Cannot verify the source list in this combined backup format.");
                if (_dnsServer.BlockListZoneManager.ManifestOwnsUpdateInterval)
                    throw new InvalidDataException("/blocklists/updateIntervalHours: Cannot verify the update interval in this combined backup format.");

                int version = reader.ReadByte();
                if (version is >= 28 and <= 42)
                {
                    LegacyWebConfiguration web = ReadLegacyWebConfiguration(reader, version);
                    CheckManifestWebLiveSettings(new WebLiveSettings(web.RealIpHeader, null, Listeners: new WebListeners(web.Addresses, web.HttpPort, web.TlsPort, web.EnableTls, web.EnableHttp3, web.RedirectToTls)));
                    CheckManifestWebTlsDependencies(web.EnableTls, web.UseSelfSignedCertificate || web.CertificatePath is not null);
                    string domain = stream.ReadShortString();
                    if (!isConfigTransfer && _dnsServer.ManifestOwnsServerDomain)
                        _dnsServer.CheckManifestServerDomain(DnsServer.NormalizeServerDomain(domain));
                    _dnsServer.CheckManifestLocalEndPoints(ReadLegacyLocalEndPoints(reader));
                    bool checkOutbound = !isConfigTransfer && _dnsServer.HasManagedOutboundSockets;
                    bool readResolver = _dnsServer.HasManagedResolverProtocol || _dnsServer.HasManagedClientSubnet;
                    bool readOutbound = readResolver || checkOutbound;
                    bool readAppAutoUpdate = readOutbound || _dnsServer.ManifestOwnsAppAutoUpdate;
                    if (_dnsServer.ManifestOwnsDefaultRecordTtl || _dnsServer.HasManagedSoaTiming || _dnsServer.ManifestOwnsResponsiblePerson || _dnsServer.HasManagedAuthoritativeNetworks || _dnsServer.HasManagedSourceNetworks || readAppAutoUpdate)
                    {
                        var (ipv4, ipv6, recordTtl) = ReadLegacyDnsDefaults(reader, version);
                        if (_dnsServer.HasManagedSourceNetworks && !isConfigTransfer)
                            _dnsServer.CheckManifestSourceNetworks(new DnsServer.SourceNetworks(ipv4 ?? [], ipv6 ?? []));
                        var defaults = new DnsServer.AuthoritativeDefaults(recordTtl, null, null);
                        if (_dnsServer.HasManagedSoaTiming || _dnsServer.ManifestOwnsResponsiblePerson || _dnsServer.HasManagedAuthoritativeNetworks || readAppAutoUpdate)
                        {
                            string responsiblePerson = version >= 36 ? reader.BaseStream.ReadShortString() : "";
                            if (_dnsServer.HasManagedSoaTiming || _dnsServer.HasManagedAuthoritativeNetworks || readAppAutoUpdate)
                                defaults = ReadLegacySoaTiming(reader, version) with { Record = recordTtl };
                            if (_dnsServer.ManifestOwnsResponsiblePerson)
                                defaults = defaults with { ResponsiblePerson = DnsServer.NormalizeDefaultResponsiblePerson(responsiblePerson) };
                        }
                        if (_dnsServer.HasManagedAuthoritativeNetworks || readAppAutoUpdate)
                        {
                            defaults = defaults with
                            {
                                ZoneTransferNetworks = version >= 33 ? AuthZoneInfo.ReadNetworkAddressesFrom(reader) ?? [] : [],
                                NotifyNetworks = version >= 34 ? AuthZoneInfo.ReadNetworkAddressesFrom(reader) ?? [] : []
                            };
                        }
                        _dnsServer.CheckManifestAuthoritativeDefaults(defaults);
                        if (readAppAutoUpdate)
                            _dnsServer.CheckManifestAppAutoUpdate(reader.ReadBoolean());
                        if (readOutbound)
                        {
                            IPv6Mode ipv6Mode = DnsServer.ReadLegacyIpv6Mode(reader);
                            bool pool = version >= 42 ? reader.ReadBoolean() : DnsServer.DefaultUdpSocketPoolEnabled;
                            bool readExcludedPorts = readResolver || (checkOutbound && _dnsServer.ManifestOwnsSocketPoolExcludedPorts);
                            ushort[] ports = readExcludedPorts
                                ? version >= 42 ? DnsServer.ReadSocketPoolExcludedPorts(reader) : [(ushort)web.TlsPort]
                                : null;
                            if (checkOutbound)
                                _dnsServer.CheckManifestOutboundSockets(new DnsServer.OutboundSocketSettings(ipv6Mode, pool, ports));
                            if (readResolver)
                            {
                                _dnsServer.CheckManifestResolverSettings(new DnsServer.ResolverSettings(null, reader.ReadUInt16(), reader.ReadBoolean()));
                                if (_dnsServer.HasManagedClientSubnet)
                                    _dnsServer.CheckManifestClientSubnet(_dnsServer.NormalizeClientSubnetSettings(
                                        DnsServer.ReadClientSubnetSettings(reader, version >= 29, version >= 35)));
                            }
                        }
                    }
                    return false;
                }

                if (version is >= 2 and <= 27)
                {
                    CheckManifestWebLiveSettings(new WebLiveSettings("X-Real-IP", null));
                    if (_managedWebListeners != 0)
                        throw new InvalidDataException("/web: Cannot verify the web listeners in this combined backup format.");
                    if (!isConfigTransfer && _dnsServer.ManifestOwnsServerDomain)
                        _dnsServer.CheckManifestServerDomain(DnsServer.NormalizeServerDomain(stream.ReadShortString()));

                    if (version < 6)
                        _dnsServer.CheckManifestLocalEndPoints(DnsServer.NormalizeLocalEndPoints(null));
                    else if (_dnsServer.ManifestOwnsLocalEndPoints)
                        throw new InvalidDataException("/dns/localEndpoints: Cannot verify the DNS listeners in this backup format.");

                    if (version >= 23 && _dnsServer.ManifestOwnsDefaultRecordTtl)
                        throw new InvalidDataException("/dns/authoritative/defaultRecordTtl: Cannot verify the default record TTL in this backup format.");

                    if (_dnsServer.HasManagedSourceNetworks && !isConfigTransfer)
                        _dnsServer.CheckManifestSourceNetworks(new DnsServer.SourceNetworks([], []));
                    if (version >= 25 && _dnsServer.ManifestOwnsUdpPayloadSize)
                        throw new InvalidDataException("/dns/udpPayloadSize: Cannot verify the UDP payload size in this backup format.");
                    if (version >= 26 && _dnsServer.ManifestOwnsDnssecValidation)
                        throw new InvalidDataException("/dns/dnssecValidation: Cannot verify DNSSEC validation in this backup format.");

                    if (!isConfigTransfer)
                    {
                        if (_dnsServer.ManifestOwnsIpv6Mode)
                            throw new InvalidDataException("/dns/ipv6Mode: Cannot verify IPv6 mode in this combined backup format.");
                        if (_dnsServer.ManifestOwnsSocketPoolExcludedPorts)
                            throw new InvalidDataException("/dns/udpSocketPool/excludedPorts: Cannot verify the excluded ports in this combined backup format.");
                        _dnsServer.CheckManifestOutboundSockets(new DnsServer.OutboundSocketSettings(null, DnsServer.DefaultUdpSocketPoolEnabled));
                    }
                    _dnsServer.CheckManifestClientSubnet(new DnsServer.ClientSubnetSettings(false, 24, 56, true, null, true, null));
                    _dnsServer.CheckManifestAppAutoUpdate(true);
                    _dnsServer.CheckManifestResolverSettings(new DnsServer.ResolverSettings(null,
                        version < 25 ? DnsDatagram.EDNS_DEFAULT_UDP_PAYLOAD_SIZE : null, version < 26 ? true : null));
                    _dnsServer.CheckManifestAuthoritativeDefaults(new DnsServer.AuthoritativeDefaults(
                        version < 23 ? 3600u : null, null, null, false, 300, 300, "", [], []));
                    return false;
                }
            }

            throw new InvalidDataException("/dns/localEndpoints: Cannot verify the DNS listeners in this backup format.");
        }

        private void ReadConfigFromV42(BinaryReader bR, int version)
        {
            LegacyWebConfiguration web = ReadLegacyWebConfiguration(bR, version);
            if ((_managedWebListeners & ManagedWebHttpPort) == 0)
                _webServiceHttpPort = web.HttpPort;
            if ((_managedWebListeners & ManagedWebTlsPort) == 0)
                _webServiceTlsPort = web.TlsPort;
            if ((_managedWebListeners & ManagedWebAddresses) == 0)
                _webServiceLocalAddresses = web.Addresses;
            if ((_managedWebListeners & ManagedWebTlsEnabled) == 0)
                _webServiceEnableTls = web.EnableTls;
            if ((_managedWebListeners & ManagedWebHttp3) == 0)
                _webServiceEnableHttp3 = web.EnableHttp3;
            if ((_managedWebListeners & ManagedWebRedirect) == 0)
                _webServiceHttpToTlsRedirect = web.RedirectToTls;
            _webServiceUseSelfSignedTlsCertificate = web.UseSelfSignedCertificate;
            _webServiceTlsCertificatePath = web.CertificatePath;
            _webServiceTlsCertificatePassword = web.CertificatePassword;

            if (_webServiceTlsCertificatePath is null)
            {
                StopTlsCertificateUpdateTimer();
            }
            else
            {
                string webServiceTlsCertificatePath = _log.ConvertToAbsolutePath(_webServiceTlsCertificatePath);

                try
                {
                    LoadWebServiceTlsCertificate(webServiceTlsCertificatePath, _webServiceTlsCertificatePassword);
                }
                catch (Exception ex)
                {
                    _log.Write("DNS Server encountered an error while loading Web Service TLS certificate: " + webServiceTlsCertificatePath, ex);
                }

                StartTlsCertificateUpdateTimer();
            }

            CheckAndLoadSelfSignedCertificate(false, false);
            if (!_manifestOwnsRealIpHeader)
                _webServiceRealIpHeader = web.RealIpHeader;

            //dns
            {
                //general
                string domain = bR.BaseStream.ReadShortString();
                if (!_dnsServer.ManifestOwnsServerDomain)
                    _dnsServer.ServerDomain = domain;
                IReadOnlyList<IPEndPoint> endpoints = ReadLegacyLocalEndPoints(bR);
                if (!_dnsServer.ManifestOwnsLocalEndPoints)
                    _dnsServer.LocalEndPoints = endpoints;

                var (ipv4, ipv6, recordTtl) = ReadLegacyDnsDefaults(bR, version);
                DnsServer.SetSourceNetworks(new DnsServer.SourceNetworks(ipv4 ?? [], ipv6 ?? []));
                _dnsServer.SetAuthoritativeDefaults(new DnsServer.AuthoritativeDefaults(recordTtl, null, null));

                if (version >= 36)
                {
                    string rp = bR.BaseStream.ReadShortString();
                    if (rp.Length == 0)
                        _dnsServer.DefaultResponsiblePerson = null;
                    else
                        _dnsServer.DefaultResponsiblePerson = new MailAddress(rp);
                }
                else
                {
                    _dnsServer.DefaultResponsiblePerson = null;
                }

                _dnsServer.SetAuthoritativeDefaults(ReadLegacySoaTiming(bR, version));

                if (version >= 33)
                    _dnsServer.ZoneTransferAllowedNetworks = AuthZoneInfo.ReadNetworkAddressesFrom(bR);
                else
                    _dnsServer.ZoneTransferAllowedNetworks = null;

                if (version >= 34)
                    _dnsServer.NotifyAllowedNetworks = AuthZoneInfo.ReadNetworkAddressesFrom(bR);
                else
                    _dnsServer.NotifyAllowedNetworks = null;

                _dnsServer.DnsApplicationManager.EnableAutomaticUpdate = bR.ReadBoolean();

                _dnsServer.IPv6Mode = bR.ReadBoolean() ? IPv6Mode.Preferred : IPv6Mode.Disabled;

                if (version >= 42)
                {
                    _dnsServer.EnableUdpSocketPool = bR.ReadBoolean();

                    UdpClientConnection.SocketPoolExcludedPorts = DnsServer.ReadSocketPoolExcludedPorts(bR);
                }
                else
                {
                    _dnsServer.EnableUdpSocketPool = Environment.OSVersion.Platform == PlatformID.Win32NT;
                    UdpClientConnection.SocketPoolExcludedPorts = [(ushort)_webServiceTlsPort];
                }

                _dnsServer.UdpPayloadSize = bR.ReadUInt16();
                _dnsServer.DnssecValidation = bR.ReadBoolean();

                if (version >= 29)
                {
                    _dnsServer.EDnsClientSubnet = bR.ReadBoolean();
                    _dnsServer.EDnsClientSubnetIPv4PrefixLength = bR.ReadByte();
                    _dnsServer.EDnsClientSubnetIPv6PrefixLength = bR.ReadByte();
                }
                else
                {
                    _dnsServer.EDnsClientSubnet = false;
                    _dnsServer.EDnsClientSubnetIPv4PrefixLength = 24;
                    _dnsServer.EDnsClientSubnetIPv6PrefixLength = 56;
                }

                if (version >= 35)
                {
                    if (bR.ReadBoolean())
                        _dnsServer.EDnsClientSubnetIpv4Override = NetworkAddress.ReadFrom(bR);
                    else
                        _dnsServer.EDnsClientSubnetIpv4Override = null;

                    if (bR.ReadBoolean())
                        _dnsServer.EDnsClientSubnetIpv6Override = NetworkAddress.ReadFrom(bR);
                    else
                        _dnsServer.EDnsClientSubnetIpv6Override = null;
                }
                else
                {
                    _dnsServer.EDnsClientSubnetIpv4Override = null;
                    _dnsServer.EDnsClientSubnetIpv6Override = null;
                }

                if (version >= 42)
                {
                    {
                        int count = bR.ReadByte();
                        Dictionary<int, (int, int)> qpmPrefixLimitsIPv4 = new Dictionary<int, (int, int)>(count);

                        for (int i = 0; i < count; i++)
                            qpmPrefixLimitsIPv4.Add(bR.ReadInt32(), (bR.ReadInt32(), bR.ReadInt32()));

                        _dnsServer.QpmPrefixLimitsIPv4 = qpmPrefixLimitsIPv4;
                    }

                    {
                        int count = bR.ReadByte();
                        Dictionary<int, (int, int)> qpmPrefixLimitsIPv6 = new Dictionary<int, (int, int)>(count);

                        for (int i = 0; i < count; i++)
                            qpmPrefixLimitsIPv6.Add(bR.ReadInt32(), (bR.ReadInt32(), bR.ReadInt32()));

                        _dnsServer.QpmPrefixLimitsIPv6 = qpmPrefixLimitsIPv6;
                    }

                    _dnsServer.QpmLimitSampleMinutes = bR.ReadInt32();
                    _dnsServer.QpmLimitUdpTruncationPercentage = bR.ReadInt32();
                }
                else
                {
                    int qpmLimitRequests = bR.ReadInt32();
                    _ = bR.ReadInt32(); //obsolete qpmLimitErrors
                    int qpmLimitSampleMinutes = bR.ReadInt32();
                    int qpmLimitIPv4PrefixLength = bR.ReadInt32();
                    int qpmLimitIPv6PrefixLength = bR.ReadInt32();

                    _dnsServer.QpmPrefixLimitsIPv4 = new Dictionary<int, (int, int)>()
                    {
                        { qpmLimitIPv4PrefixLength, (qpmLimitRequests, qpmLimitRequests) }
                    };

                    _dnsServer.QpmPrefixLimitsIPv6 = new Dictionary<int, (int, int)>()
                    {
                        { qpmLimitIPv6PrefixLength, (qpmLimitRequests, qpmLimitRequests) }
                    };

                    _dnsServer.QpmLimitSampleMinutes = qpmLimitSampleMinutes;
                    _dnsServer.QpmLimitUdpTruncationPercentage = 0;
                }

                if (version >= 34)
                    _dnsServer.QpmLimitBypassList = AuthZoneInfo.ReadNetworkAddressesFrom(bR);
                else
                    _dnsServer.QpmLimitBypassList = null;

                _dnsServer.ClientTimeout = bR.ReadInt32();
                if (version < 34)
                {
                    if (_dnsServer.ClientTimeout == 4000)
                        _dnsServer.ClientTimeout = 2000;
                }

                _dnsServer.TcpSendTimeout = bR.ReadInt32();
                _dnsServer.TcpReceiveTimeout = bR.ReadInt32();

                if (version >= 30)
                {
                    _dnsServer.QuicIdleTimeout = bR.ReadInt32();
                    _dnsServer.QuicMaxInboundStreams = bR.ReadInt32();
                    _dnsServer.ListenBacklog = bR.ReadInt32();
                }
                else
                {
                    _dnsServer.QuicIdleTimeout = 60000;
                    _dnsServer.QuicMaxInboundStreams = 100;
                    _dnsServer.ListenBacklog = 100;
                }

                if (version >= 40)
                    _dnsServer.MaxConcurrentResolutionsPerCore = bR.ReadUInt16();
                else
                    _dnsServer.MaxConcurrentResolutionsPerCore = 100;

                //optional protocols
                if (version >= 32)
                {
                    _dnsServer.EnableDnsOverUdpProxy = bR.ReadBoolean();
                    _dnsServer.EnableDnsOverTcpProxy = bR.ReadBoolean();
                }
                else
                {
                    _dnsServer.EnableDnsOverUdpProxy = false;
                    _dnsServer.EnableDnsOverTcpProxy = false;
                }

                _dnsServer.EnableDnsOverHttp = bR.ReadBoolean();
                _dnsServer.EnableDnsOverTls = bR.ReadBoolean();
                _dnsServer.EnableDnsOverHttps = bR.ReadBoolean();

                if (version >= 37)
                    _dnsServer.EnableDnsOverHttp3 = bR.ReadBoolean();
                else
                    _dnsServer.EnableDnsOverHttp3 = _dnsServer.EnableDnsOverHttps && QuicConnection.IsSupported && Socket.OSSupportsIPv6;

                if (version >= 32)
                {
                    _dnsServer.EnableDnsOverQuic = bR.ReadBoolean();

                    _dnsServer.DnsOverUdpProxyPort = bR.ReadInt32();
                    _dnsServer.DnsOverTcpProxyPort = bR.ReadInt32();
                    _dnsServer.DnsOverHttpPort = bR.ReadInt32();
                    _dnsServer.DnsOverTlsPort = bR.ReadInt32();
                    _dnsServer.DnsOverHttpsPort = bR.ReadInt32();
                    _dnsServer.DnsOverQuicPort = bR.ReadInt32();
                }
                else if (version >= 31)
                {
                    _dnsServer.EnableDnsOverQuic = bR.ReadBoolean();

                    _dnsServer.DnsOverHttpPort = bR.ReadInt32();
                    _dnsServer.DnsOverTlsPort = bR.ReadInt32();
                    _dnsServer.DnsOverHttpsPort = bR.ReadInt32();
                    _dnsServer.DnsOverQuicPort = bR.ReadInt32();
                }
                else if (version >= 30)
                {
                    _ = bR.ReadBoolean(); //removed EnableDnsOverHttpPort80 value
                    _dnsServer.EnableDnsOverQuic = bR.ReadBoolean();

                    _dnsServer.DnsOverHttpPort = bR.ReadInt32();
                    _dnsServer.DnsOverTlsPort = bR.ReadInt32();
                    _dnsServer.DnsOverHttpsPort = bR.ReadInt32();
                    _dnsServer.DnsOverQuicPort = bR.ReadInt32();
                }
                else
                {
                    _dnsServer.EnableDnsOverQuic = false;

                    _dnsServer.DnsOverUdpProxyPort = 538;
                    _dnsServer.DnsOverTcpProxyPort = 538;

                    if (_dnsServer.EnableDnsOverHttps)
                    {
                        _dnsServer.EnableDnsOverHttp = true;
                        _dnsServer.DnsOverHttpPort = 80;
                    }
                    else if (_dnsServer.EnableDnsOverHttp)
                    {
                        _dnsServer.DnsOverHttpPort = 8053;
                    }
                    else
                    {
                        _dnsServer.DnsOverHttpPort = 80;
                    }

                    _dnsServer.DnsOverTlsPort = 853;
                    _dnsServer.DnsOverHttpsPort = 443;
                    _dnsServer.DnsOverQuicPort = 853;
                }

                if (version >= 39)
                {
                    _dnsServer.DnsReverseProxyNetworkACL = AuthZoneInfo.ReadNetworkACLFrom(bR);
                }
                else
                {
                    if (_dnsServer.EnableDnsOverUdpProxy || _dnsServer.EnableDnsOverTcpProxy || _dnsServer.EnableDnsOverHttp)
                    {
                        _dnsServer.DnsReverseProxyNetworkACL =
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
                }

                string dnsTlsCertificatePath = bR.BaseStream.ReadShortString();
                string dnsTlsCertificatePassword = bR.BaseStream.ReadShortString();

                if (dnsTlsCertificatePath.Length == 0)
                    dnsTlsCertificatePath = null;

                if (dnsTlsCertificatePath is null)
                    _dnsServer.RemoveDnsTlsCertificate();
                else
                    _dnsServer.SetDnsTlsCertificate(dnsTlsCertificatePath, dnsTlsCertificatePassword);

                if (version >= 38)
                    _dnsServer.DnsOverHttpRealIpHeader = bR.BaseStream.ReadShortString();
                else
                    _dnsServer.DnsOverHttpRealIpHeader = "X-Real-IP";

                //tsig
                {
                    int count = bR.ReadByte();
                    Dictionary<string, TsigKey> tsigKeys = new Dictionary<string, TsigKey>(count);

                    for (int i = 0; i < count; i++)
                    {
                        string keyName = bR.BaseStream.ReadShortString();
                        string sharedSecret = bR.BaseStream.ReadShortString();
                        TsigAlgorithm algorithm = (TsigAlgorithm)bR.ReadByte();

                        tsigKeys.Add(keyName, new TsigKey(keyName, sharedSecret, algorithm));
                    }

                    _dnsServer.TsigKeys = tsigKeys;
                }

                //recursion
                _dnsServer.Recursion = (DnsServerRecursion)bR.ReadByte();

                if (version >= 37)
                {
                    _dnsServer.RecursionNetworkACL = AuthZoneInfo.ReadNetworkACLFrom(bR);
                }
                else
                {
                    NetworkAddress[] recursionDeniedNetworks = AuthZoneInfo.ReadNetworkAddressesFrom(bR);
                    NetworkAddress[] recursionAllowedNetworks = AuthZoneInfo.ReadNetworkAddressesFrom(bR);
                    _dnsServer.RecursionNetworkACL = AuthZoneInfo.ConvertDenyAllowToACL(recursionDeniedNetworks, recursionAllowedNetworks);
                }

                _dnsServer.RandomizeName = bR.ReadBoolean();
                _dnsServer.QnameMinimization = bR.ReadBoolean();

                if (version <= 40)
                    _ = bR.ReadBoolean(); //removed NsRevalidation option

                _dnsServer.ResolverRetries = bR.ReadInt32();
                _dnsServer.ResolverTimeout = bR.ReadInt32();

                if (version >= 37)
                    _dnsServer.ResolverConcurrency = bR.ReadInt32();
                else
                    _dnsServer.ResolverConcurrency = 2;

                _dnsServer.ResolverMaxStackCount = bR.ReadInt32();

                //cache
                if (version >= 30)
                    _dnsServer.SaveCacheToDisk = bR.ReadBoolean();
                else
                    _dnsServer.SaveCacheToDisk = true;

                _dnsServer.ServeStale = bR.ReadBoolean();
                _dnsServer.CacheZoneManager.ServeStaleTtl = bR.ReadUInt32();

                if (version >= 36)
                {
                    _dnsServer.CacheZoneManager.ServeStaleAnswerTtl = bR.ReadUInt32();
                    _dnsServer.CacheZoneManager.ServeStaleResetTtl = bR.ReadUInt32();
                    _dnsServer.ServeStaleMaxWaitTime = bR.ReadInt32();
                }
                else
                {
                    _dnsServer.CacheZoneManager.ServeStaleAnswerTtl = CacheZoneManager.SERVE_STALE_ANSWER_TTL;
                    _dnsServer.CacheZoneManager.ServeStaleResetTtl = CacheZoneManager.SERVE_STALE_RESET_TTL;
                    _dnsServer.ServeStaleMaxWaitTime = DnsServer.SERVE_STALE_MAX_WAIT_TIME;
                }

                _dnsServer.CacheZoneManager.MaximumEntries = bR.ReadInt64();
                _dnsServer.CacheZoneManager.MinimumRecordTtl = bR.ReadUInt32();
                _dnsServer.CacheZoneManager.MaximumRecordTtl = bR.ReadUInt32();
                _dnsServer.CacheZoneManager.NegativeRecordTtl = bR.ReadUInt32();
                _dnsServer.CacheZoneManager.FailureRecordTtl = bR.ReadUInt32();

                _dnsServer.CachePrefetchEligibility = bR.ReadInt32();
                _dnsServer.CachePrefetchTrigger = bR.ReadInt32();
                _ = bR.ReadInt32(); //_dnsServer.CachePrefetchSampleIntervalMinutes 
                _ = bR.ReadInt32(); //_dnsServer.CachePrefetchSampleEligibilityHitsPerHour

                //blocking
                _dnsServer.EnableBlocking = bR.ReadBoolean();
                _dnsServer.AllowTxtBlockingReport = bR.ReadBoolean();

                if (version >= 33)
                    _dnsServer.BlockingBypassList = AuthZoneInfo.ReadNetworkAddressesFrom(bR);
                else
                    _dnsServer.BlockingBypassList = null;

                _dnsServer.BlockingType = (DnsServerBlockingType)bR.ReadByte();

                if (version >= 38)
                    _dnsServer.BlockingAnswerTtl = bR.ReadUInt32();
                else
                    _dnsServer.BlockingAnswerTtl = 30;

                {
                    //read custom blocking addresses
                    int count = bR.ReadByte();
                    if (count > 0)
                    {
                        List<DnsARecordData> dnsARecords = new List<DnsARecordData>();
                        List<DnsAAAARecordData> dnsAAAARecords = new List<DnsAAAARecordData>();

                        for (int i = 0; i < count; i++)
                        {
                            IPAddress customAddress = IPAddressExtensions.ReadFrom(bR);

                            switch (customAddress.AddressFamily)
                            {
                                case AddressFamily.InterNetwork:
                                    dnsARecords.Add(new DnsARecordData(customAddress));
                                    break;

                                case AddressFamily.InterNetworkV6:
                                    dnsAAAARecords.Add(new DnsAAAARecordData(customAddress));
                                    break;
                            }
                        }

                        _dnsServer.CustomBlockingARecords = dnsARecords;
                        _dnsServer.CustomBlockingAAAARecords = dnsAAAARecords;
                    }
                    else
                    {
                        _dnsServer.CustomBlockingARecords = null;
                        _dnsServer.CustomBlockingAAAARecords = null;
                    }
                }

                {
                    //read block list urls
                    int count = bR.ReadByte();
                    string[] blockListUrls = new string[count];

                    for (int i = 0; i < count; i++)
                        blockListUrls[i] = bR.BaseStream.ReadShortString();

                    _dnsServer.BlockListZoneManager.BlockListUrls = blockListUrls;

                    _dnsServer.BlockListZoneManager.BlockListUpdateIntervalHours = bR.ReadInt32();
                    _dnsServer.BlockListZoneManager.BlockListLastUpdatedOn = bR.BaseStream.ReadDateTime();
                }

                //proxy & forwarders
                NetProxyType proxyType = (NetProxyType)bR.ReadByte();
                if (proxyType != NetProxyType.None)
                {
                    string address = bR.BaseStream.ReadShortString();
                    int port = bR.ReadInt32();
                    NetworkCredential credential = null;

                    if (bR.ReadBoolean()) //credential set
                        credential = new NetworkCredential(bR.BaseStream.ReadShortString(), bR.BaseStream.ReadShortString());

                    _dnsServer.Proxy = NetProxy.CreateProxy(proxyType, address, port, credential);

                    int count = bR.ReadByte();
                    List<NetProxyBypassItem> bypassList = new List<NetProxyBypassItem>(count);

                    for (int i = 0; i < count; i++)
                        bypassList.Add(new NetProxyBypassItem(bR.BaseStream.ReadShortString()));

                    _dnsServer.Proxy.BypassList = bypassList;
                }
                else
                {
                    _dnsServer.Proxy = null;
                }

                {
                    int count = bR.ReadByte();
                    if (count > 0)
                    {
                        NameServerAddress[] forwarders = new NameServerAddress[count];

                        for (int i = 0; i < count; i++)
                        {
                            forwarders[i] = new NameServerAddress(bR);

                            if (forwarders[i].Protocol == DnsTransportProtocol.HttpsJson)
                                forwarders[i] = forwarders[i].Clone(DnsTransportProtocol.Https);
                        }

                        _dnsServer.Forwarders = forwarders;
                    }
                    else
                    {
                        _dnsServer.Forwarders = null;
                    }
                }

                if (version >= 37)
                    _dnsServer.ConcurrentForwarding = bR.ReadBoolean();
                else
                    _dnsServer.ConcurrentForwarding = true;

                _dnsServer.ForwarderRetries = bR.ReadInt32();
                _dnsServer.ForwarderTimeout = bR.ReadInt32();
                _dnsServer.ForwarderConcurrency = bR.ReadInt32();

                //logging
                if (version >= 33)
                {
                    if (bR.ReadBoolean()) //ignore resolver logs
                        _dnsServer.ResolverLogManager = null;
                    else
                        _dnsServer.ResolverLogManager = _log;
                }
                else
                {
                    _dnsServer.ResolverLogManager = _log;
                }

                if (bR.ReadBoolean()) //log all queries
                    _dnsServer.QueryLogManager = _log;
                else
                    _dnsServer.QueryLogManager = null;

                if (version >= 34)
                    _dnsServer.StatsManager.EnableInMemoryStats = bR.ReadBoolean();
                else
                    _dnsServer.StatsManager.EnableInMemoryStats = false;

                {
                    int maxStatFileDays = bR.ReadInt32();
                    if (maxStatFileDays < 0)
                        maxStatFileDays = 0;

                    _dnsServer.StatsManager.MaxStatFileDays = maxStatFileDays;
                }
            }
        }

        private void ReadConfigFromV27(BinaryReader bR, int version)
        {
            string serverDomain = bR.BaseStream.ReadShortString();
            if (!_dnsServer.ManifestOwnsServerDomain)
                _dnsServer.ServerDomain = serverDomain;
            _webServiceHttpPort = bR.ReadInt32();

            if (version >= 13)
            {
                {
                    int count = bR.ReadByte();
                    if (count > 0)
                    {
                        IPAddress[] localAddresses = new IPAddress[count];

                        for (int i = 0; i < count; i++)
                            localAddresses[i] = IPAddressExtensions.ReadFrom(bR);

                        _webServiceLocalAddresses = localAddresses;
                    }
                    else
                    {
                        _webServiceLocalAddresses = new IPAddress[] { IPAddress.Any, IPAddress.IPv6Any };
                    }
                }

                _webServiceTlsPort = bR.ReadInt32();
                _webServiceEnableTls = bR.ReadBoolean();
                _webServiceHttpToTlsRedirect = bR.ReadBoolean();
                _webServiceTlsCertificatePath = bR.BaseStream.ReadShortString();
                _webServiceTlsCertificatePassword = bR.BaseStream.ReadShortString();

                if (_webServiceTlsCertificatePath.Length == 0)
                    _webServiceTlsCertificatePath = null;

                if (_webServiceTlsCertificatePath is null)
                {
                    StopTlsCertificateUpdateTimer();
                }
                else
                {
                    string webServiceTlsCertificatePath = _log.ConvertToAbsolutePath(_webServiceTlsCertificatePath);

                    try
                    {
                        LoadWebServiceTlsCertificate(webServiceTlsCertificatePath, _webServiceTlsCertificatePassword);
                    }
                    catch (Exception ex)
                    {
                        _log.Write("DNS Server encountered an error while loading Web Service TLS certificate: " + webServiceTlsCertificatePath, ex);
                    }

                    StartTlsCertificateUpdateTimer();
                }
            }
            else
            {
                _webServiceLocalAddresses = new IPAddress[] { IPAddress.Any, IPAddress.IPv6Any };

                _webServiceTlsPort = 53443;
                _webServiceEnableTls = false;
                _webServiceHttpToTlsRedirect = false;
                _webServiceTlsCertificatePath = string.Empty;
                _webServiceTlsCertificatePassword = string.Empty;
            }

            _dnsServer.IPv6Mode = bR.ReadBoolean() ? IPv6Mode.Preferred : IPv6Mode.Disabled;

            if (bR.ReadBoolean()) //logQueries
                _dnsServer.QueryLogManager = _log;

            if (version >= 14)
            {
                int maxStatFileDays = bR.ReadInt32();
                if (maxStatFileDays < 0)
                    maxStatFileDays = 0;

                _dnsServer.StatsManager.MaxStatFileDays = maxStatFileDays;
            }
            else
            {
                _dnsServer.StatsManager.MaxStatFileDays = 0;
            }

            if (version >= 17)
            {
                _dnsServer.Recursion = (DnsServerRecursion)bR.ReadByte();

                NetworkAddress[] recursionDeniedNetworks;
                {
                    int count = bR.ReadByte();
                    if (count > 0)
                    {
                        NetworkAddress[] networks = new NetworkAddress[count];

                        for (int i = 0; i < count; i++)
                            networks[i] = NetworkAddress.ReadFrom(bR);

                        recursionDeniedNetworks = networks;
                    }
                    else
                    {
                        recursionDeniedNetworks = null;
                    }
                }

                NetworkAddress[] recursionAllowedNetworks;
                {
                    int count = bR.ReadByte();
                    if (count > 0)
                    {
                        NetworkAddress[] networks = new NetworkAddress[count];

                        for (int i = 0; i < count; i++)
                            networks[i] = NetworkAddress.ReadFrom(bR);

                        recursionAllowedNetworks = networks;
                    }
                    else
                    {
                        recursionAllowedNetworks = null;
                    }
                }

                _dnsServer.RecursionNetworkACL = AuthZoneInfo.ConvertDenyAllowToACL(recursionDeniedNetworks, recursionAllowedNetworks);
            }
            else
            {
                bool allowRecursion = bR.ReadBoolean();
                bool allowRecursionOnlyForPrivateNetworks;

                if (version >= 4)
                    allowRecursionOnlyForPrivateNetworks = bR.ReadBoolean();
                else
                    allowRecursionOnlyForPrivateNetworks = true; //default true for security reasons

                if (allowRecursion)
                {
                    if (allowRecursionOnlyForPrivateNetworks)
                        _dnsServer.Recursion = DnsServerRecursion.AllowOnlyForPrivateNetworks;
                    else
                        _dnsServer.Recursion = DnsServerRecursion.Allow;
                }
                else
                {
                    _dnsServer.Recursion = DnsServerRecursion.Deny;
                }
            }

            if (version >= 12)
                _dnsServer.RandomizeName = bR.ReadBoolean();
            else
                _dnsServer.RandomizeName = false; //default false to allow resolving from bad name servers

            if (version >= 15)
                _dnsServer.QnameMinimization = bR.ReadBoolean();
            else
                _dnsServer.QnameMinimization = true; //default true to enable privacy feature

            if (version >= 20)
            {
                int qpmLimitRequests = bR.ReadInt32();
                _ = bR.ReadInt32(); //obsolete qpmLimitErrors
                int qpmLimitSampleMinutes = bR.ReadInt32();
                int qpmLimitIPv4PrefixLength = bR.ReadInt32();
                int qpmLimitIPv6PrefixLength = bR.ReadInt32();

                _dnsServer.QpmPrefixLimitsIPv4 = new Dictionary<int, (int, int)>()
                {
                    { qpmLimitIPv4PrefixLength, (qpmLimitRequests, qpmLimitRequests) }
                };

                _dnsServer.QpmPrefixLimitsIPv6 = new Dictionary<int, (int, int)>()
                {
                    { qpmLimitIPv6PrefixLength, (qpmLimitRequests, qpmLimitRequests) }
                };

                _dnsServer.QpmLimitSampleMinutes = qpmLimitSampleMinutes;
                _dnsServer.QpmLimitUdpTruncationPercentage = 0;
            }
            else if (version >= 17)
            {
                int qpmLimitRequests = bR.ReadInt32();
                int qpmLimitSampleMinutes = bR.ReadInt32();
                _ = bR.ReadInt32(); //read obsolete value _dnsServer.QpmLimitSamplingIntervalInMinutes

                _dnsServer.QpmPrefixLimitsIPv4 = new Dictionary<int, (int, int)>()
                {
                    { 24, (qpmLimitRequests, qpmLimitRequests) }
                };

                _dnsServer.QpmPrefixLimitsIPv6 = new Dictionary<int, (int, int)>()
                {
                    { 56, (qpmLimitRequests, qpmLimitRequests) }
                };

                _dnsServer.QpmLimitSampleMinutes = qpmLimitSampleMinutes;
                _dnsServer.QpmLimitUdpTruncationPercentage = 0;
            }
            else
            {
                _dnsServer.QpmPrefixLimitsIPv4 = new Dictionary<int, (int, int)>()
                {
                    { 32, (600, 600) },
                    { 24, (6000, 6000) }
                };

                _dnsServer.QpmPrefixLimitsIPv6 = new Dictionary<int, (int, int)>()
                {
                    { 128, (600, 600) },
                    { 64, (1200, 1200) },
                    { 56, (6000, 6000) }
                };

                _dnsServer.QpmLimitSampleMinutes = 5;
                _dnsServer.QpmLimitUdpTruncationPercentage = 50;
            }

            if (version >= 13)
            {
                _dnsServer.ServeStale = bR.ReadBoolean();
                _dnsServer.CacheZoneManager.ServeStaleTtl = bR.ReadUInt32();
            }
            else
            {
                _dnsServer.ServeStale = true;
                _dnsServer.CacheZoneManager.ServeStaleTtl = CacheZoneManager.SERVE_STALE_TTL;
            }

            if (version >= 9)
            {
                _dnsServer.CachePrefetchEligibility = bR.ReadInt32();
                _dnsServer.CachePrefetchTrigger = bR.ReadInt32();
                _ = bR.ReadInt32(); //_dnsServer.CachePrefetchSampleIntervalMinutes
                _ = bR.ReadInt32(); //_dnsServer.CachePrefetchSampleEligibilityHitsPerHour
            }
            else
            {
                _dnsServer.CachePrefetchEligibility = 2;
                _dnsServer.CachePrefetchTrigger = 9;
            }

            NetProxyType proxyType = (NetProxyType)bR.ReadByte();
            if (proxyType != NetProxyType.None)
            {
                string address = bR.BaseStream.ReadShortString();
                int port = bR.ReadInt32();
                NetworkCredential credential = null;

                if (bR.ReadBoolean()) //credential set
                    credential = new NetworkCredential(bR.BaseStream.ReadShortString(), bR.BaseStream.ReadShortString());

                _dnsServer.Proxy = NetProxy.CreateProxy(proxyType, address, port, credential);

                if (version >= 10)
                {
                    int count = bR.ReadByte();
                    List<NetProxyBypassItem> bypassList = new List<NetProxyBypassItem>(count);

                    for (int i = 0; i < count; i++)
                        bypassList.Add(new NetProxyBypassItem(bR.BaseStream.ReadShortString()));

                    _dnsServer.Proxy.BypassList = bypassList;
                }
                else
                {
                    _dnsServer.Proxy.BypassList = null;
                }
            }
            else
            {
                _dnsServer.Proxy = null;
            }

            {
                int count = bR.ReadByte();
                if (count > 0)
                {
                    NameServerAddress[] forwarders = new NameServerAddress[count];

                    for (int i = 0; i < count; i++)
                    {
                        forwarders[i] = new NameServerAddress(bR);
                        if (forwarders[i].Protocol == DnsTransportProtocol.HttpsJson)
                            forwarders[i] = forwarders[i].Clone(DnsTransportProtocol.Https);
                    }

                    _dnsServer.Forwarders = forwarders;
                }
                else
                {
                    _dnsServer.Forwarders = null;
                }
            }

            if (version <= 10)
            {
                DnsTransportProtocol forwarderProtocol = (DnsTransportProtocol)bR.ReadByte();
                if (forwarderProtocol == DnsTransportProtocol.HttpsJson)
                    forwarderProtocol = DnsTransportProtocol.Https;

                if (_dnsServer.Forwarders != null)
                {
                    List<NameServerAddress> forwarders = new List<NameServerAddress>();

                    foreach (NameServerAddress forwarder in _dnsServer.Forwarders)
                    {
                        if (forwarder.Protocol == forwarderProtocol)
                            forwarders.Add(forwarder);
                        else
                            forwarders.Add(forwarder.Clone(forwarderProtocol));
                    }

                    _dnsServer.Forwarders = forwarders;
                }
            }

            {
                int count = bR.ReadByte();
                if (count > 0)
                {
                    if (version > 2)
                    {
                        for (int i = 0; i < count; i++)
                        {
                            string username = bR.BaseStream.ReadShortString();
                            string passwordHash = bR.BaseStream.ReadShortString();

                            if (username.Equals("admin", StringComparison.OrdinalIgnoreCase))
                            {
                                _authManager.LoadOldConfig(passwordHash, true);
                                break;
                            }
                        }
                    }
                    else
                    {
                        for (int i = 0; i < count; i++)
                        {
                            string username = bR.BaseStream.ReadShortString();
                            string password = bR.BaseStream.ReadShortString();

                            if (username.Equals("admin", StringComparison.OrdinalIgnoreCase))
                            {
                                _authManager.LoadOldConfig(password, false);
                                break;
                            }
                        }
                    }
                }
            }

            if (version <= 6)
            {
                int count = bR.ReadInt32();
                _configDisabledZones = new List<string>(count);

                for (int i = 0; i < count; i++)
                {
                    string domain = bR.BaseStream.ReadShortString();
                    _configDisabledZones.Add(domain);
                }
            }

            if (version >= 18)
                _dnsServer.EnableBlocking = bR.ReadBoolean();
            else
                _dnsServer.EnableBlocking = true;

            if (version >= 18)
                _dnsServer.BlockingType = (DnsServerBlockingType)bR.ReadByte();
            else if (version >= 16)
                _dnsServer.BlockingType = bR.ReadBoolean() ? DnsServerBlockingType.NxDomain : DnsServerBlockingType.AnyAddress;
            else
                _dnsServer.BlockingType = DnsServerBlockingType.AnyAddress;

            if (version >= 18)
            {
                //read custom blocking addresses
                int count = bR.ReadByte();
                if (count > 0)
                {
                    List<DnsARecordData> dnsARecords = new List<DnsARecordData>();
                    List<DnsAAAARecordData> dnsAAAARecords = new List<DnsAAAARecordData>();

                    for (int i = 0; i < count; i++)
                    {
                        IPAddress customAddress = IPAddressExtensions.ReadFrom(bR);

                        switch (customAddress.AddressFamily)
                        {
                            case AddressFamily.InterNetwork:
                                dnsARecords.Add(new DnsARecordData(customAddress));
                                break;

                            case AddressFamily.InterNetworkV6:
                                dnsAAAARecords.Add(new DnsAAAARecordData(customAddress));
                                break;
                        }
                    }

                    _dnsServer.CustomBlockingARecords = dnsARecords;
                    _dnsServer.CustomBlockingAAAARecords = dnsAAAARecords;
                }
                else
                {
                    _dnsServer.CustomBlockingARecords = null;
                    _dnsServer.CustomBlockingAAAARecords = null;
                }
            }
            else
            {
                _dnsServer.CustomBlockingARecords = null;
                _dnsServer.CustomBlockingAAAARecords = null;
            }

            if (version > 4)
            {
                //read block list urls
                int count = bR.ReadByte();
                string[] blockListUrls = new string[count];

                for (int i = 0; i < count; i++)
                    blockListUrls[i] = bR.BaseStream.ReadShortString();

                _dnsServer.BlockListZoneManager.BlockListUrls = blockListUrls;

                _dnsServer.BlockListZoneManager.BlockListLastUpdatedOn = bR.BaseStream.ReadDateTime();

                if (version >= 13)
                    _dnsServer.BlockListZoneManager.BlockListUpdateIntervalHours = bR.ReadInt32();
            }
            else
            {
                _dnsServer.BlockListZoneManager.BlockListUrls = null;
                _dnsServer.BlockListZoneManager.BlockListLastUpdatedOn = DateTime.MinValue;
                _dnsServer.BlockListZoneManager.BlockListUpdateIntervalHours = 24;
            }

            IReadOnlyList<IPEndPoint> endpoints = version >= 6 ? ReadLegacyLocalEndPoints(bR) : DnsServer.NormalizeLocalEndPoints(null);
            if (!_dnsServer.ManifestOwnsLocalEndPoints)
                _dnsServer.LocalEndPoints = endpoints;

            if (version >= 8)
            {
                _dnsServer.EnableDnsOverHttp = bR.ReadBoolean();
                _dnsServer.EnableDnsOverTls = bR.ReadBoolean();
                _dnsServer.EnableDnsOverHttps = bR.ReadBoolean();
                string dnsTlsCertificatePath = bR.BaseStream.ReadShortString();
                string dnsTlsCertificatePassword = bR.BaseStream.ReadShortString();

                if (dnsTlsCertificatePath.Length == 0)
                    dnsTlsCertificatePath = null;

                if (dnsTlsCertificatePath is null)
                    _dnsServer.RemoveDnsTlsCertificate();
                else
                    _dnsServer.SetDnsTlsCertificate(dnsTlsCertificatePath, dnsTlsCertificatePassword);
            }
            else
            {
                _dnsServer.EnableDnsOverHttp = false;
                _dnsServer.EnableDnsOverTls = false;
                _dnsServer.EnableDnsOverHttps = false;

                _dnsServer.RemoveDnsTlsCertificate();
            }

            if (version >= 19)
            {
                _dnsServer.CacheZoneManager.MinimumRecordTtl = bR.ReadUInt32();
                _dnsServer.CacheZoneManager.MaximumRecordTtl = bR.ReadUInt32();
                _dnsServer.CacheZoneManager.NegativeRecordTtl = bR.ReadUInt32();
                _dnsServer.CacheZoneManager.FailureRecordTtl = bR.ReadUInt32();
            }
            else
            {
                _dnsServer.CacheZoneManager.MinimumRecordTtl = CacheZoneManager.MINIMUM_RECORD_TTL;
                _dnsServer.CacheZoneManager.MaximumRecordTtl = CacheZoneManager.MAXIMUM_RECORD_TTL;
                _dnsServer.CacheZoneManager.NegativeRecordTtl = CacheZoneManager.NEGATIVE_RECORD_TTL;
                _dnsServer.CacheZoneManager.FailureRecordTtl = CacheZoneManager.FAILURE_RECORD_TTL;
            }

            if (version >= 21)
            {
                int count = bR.ReadByte();
                Dictionary<string, TsigKey> tsigKeys = new Dictionary<string, TsigKey>(count);

                for (int i = 0; i < count; i++)
                {
                    string keyName = bR.BaseStream.ReadShortString();
                    string sharedSecret = bR.BaseStream.ReadShortString();
                    TsigAlgorithm algorithm = (TsigAlgorithm)bR.ReadByte();

                    tsigKeys.Add(keyName, new TsigKey(keyName, sharedSecret, algorithm));
                }

                _dnsServer.TsigKeys = tsigKeys;
            }
            else if (version >= 20)
            {
                int count = bR.ReadByte();
                Dictionary<string, TsigKey> tsigKeys = new Dictionary<string, TsigKey>(count);

                for (int i = 0; i < count; i++)
                {
                    string keyName = bR.BaseStream.ReadShortString();
                    string sharedSecret = bR.BaseStream.ReadShortString();

                    tsigKeys.Add(keyName, new TsigKey(keyName, sharedSecret, TsigAlgorithm.HMAC_SHA256));
                }

                _dnsServer.TsigKeys = tsigKeys;
            }
            else
            {
                _dnsServer.TsigKeys = null;
            }

            if (version >= 22)
                _ = bR.ReadBoolean(); //removed NsRevalidation option

            if (version >= 23)
            {
                _dnsServer.AllowTxtBlockingReport = bR.ReadBoolean();
                _dnsServer.AuthZoneManager.DefaultRecordTtl = bR.ReadUInt32();
            }
            else
            {
                _dnsServer.AllowTxtBlockingReport = true;
                _dnsServer.AuthZoneManager.DefaultRecordTtl = 3600;
            }

            if (version >= 24)
            {
                _webServiceUseSelfSignedTlsCertificate = bR.ReadBoolean();

                CheckAndLoadSelfSignedCertificate(false, false);
            }
            else
            {
                _webServiceUseSelfSignedTlsCertificate = false;
            }

            if (version >= 25)
                _dnsServer.UdpPayloadSize = bR.ReadUInt16();
            else
                _dnsServer.UdpPayloadSize = DnsDatagram.EDNS_DEFAULT_UDP_PAYLOAD_SIZE;

            if (version >= 26)
            {
                _dnsServer.DnssecValidation = bR.ReadBoolean();

                _dnsServer.ResolverRetries = bR.ReadInt32();
                _dnsServer.ResolverTimeout = bR.ReadInt32();
                _dnsServer.ResolverMaxStackCount = bR.ReadInt32();

                _dnsServer.ForwarderRetries = bR.ReadInt32();
                _dnsServer.ForwarderTimeout = bR.ReadInt32();
                _dnsServer.ForwarderConcurrency = bR.ReadInt32();

                _dnsServer.ClientTimeout = bR.ReadInt32();
                if (_dnsServer.ClientTimeout == 4000)
                    _dnsServer.ClientTimeout = 2000;

                _dnsServer.TcpSendTimeout = bR.ReadInt32();
                _dnsServer.TcpReceiveTimeout = bR.ReadInt32();
            }
            else
            {
                _dnsServer.DnssecValidation = true;
                CreateForwarderZoneToDisableDnssecForNTP();

                _dnsServer.ResolverRetries = 2;
                _dnsServer.ResolverTimeout = 1500;
                _dnsServer.ResolverMaxStackCount = 16;

                _dnsServer.ForwarderRetries = 3;
                _dnsServer.ForwarderTimeout = 2000;
                _dnsServer.ForwarderConcurrency = 2;

                _dnsServer.ClientTimeout = 2000;
                _dnsServer.TcpSendTimeout = 10000;
                _dnsServer.TcpReceiveTimeout = 10000;
            }

            if (version >= 27)
                _dnsServer.CacheZoneManager.MaximumEntries = bR.ReadInt32();
            else
                _dnsServer.CacheZoneManager.MaximumEntries = 10000;
        }

        #endregion
    }
}
