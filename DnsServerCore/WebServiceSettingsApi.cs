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
using DnsServerCore.Cluster;
using DnsServerCore.Configuration;
using DnsServerCore.Dns;
using DnsServerCore.Dns.ZoneManagers;
using DnsServerCore.Dns.Zones;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Globalization;
using System.IO;
using System.Linq;
using System.IO.Compression;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ClientConnection;
using TechnitiumLibrary.Net.Dns.ResourceRecords;
using TechnitiumLibrary.Net.Http.Client;
using TechnitiumLibrary.Net.Proxy;

namespace DnsServerCore
{
    public partial class DnsWebService
    {
        sealed class WebServiceSettingsApi
        {
            #region variables

            readonly DnsWebService _dnsWebService;
            readonly byte[] _configurationRevisionKey = RandomNumberGenerator.GetBytes(32);
            private sealed class WebApplyOperation
            {
                internal readonly Guid Id = Guid.NewGuid();
                internal volatile string State = "pending";
                internal string Error;
            }

            private volatile WebApplyOperation _lastWebApply;
            private readonly Lock _webApplyGate = new();
            readonly SemaphoreSlim _configurationLock = new(1, 1);

            #endregion

            #region constructor

            public WebServiceSettingsApi(DnsWebService dnsWebService)
            {
                _dnsWebService = dnsWebService;
            }

            #endregion

            #region private

            private void WriteDnsSettings(Utf8JsonWriter jsonWriter, bool includeSecrets = true)
            {
                //info
                jsonWriter.WriteString("version", _dnsWebService.GetServerVersion());
                jsonWriter.WriteString("uptimestamp", _dnsWebService._uptimestamp);

                jsonWriter.WriteBoolean("clusterInitialized", _dnsWebService._clusterManager.ClusterInitialized);

                if (_dnsWebService._clusterManager.ClusterInitialized)
                {
                    jsonWriter.WriteString("clusterDomain", _dnsWebService._clusterManager.ClusterDomain);

                    _dnsWebService._clusterApi.WriteClusterNodes(jsonWriter);
                }

                //general
                jsonWriter.WriteString("dnsServerDomain", _dnsWebService._dnsServer.ServerDomain);

                jsonWriter.WriteStringArray("dnsServerLocalEndPoints", _dnsWebService._dnsServer.LocalEndPoints);

                jsonWriter.WriteStringArray("dnsServerIPv4SourceAddresses", DnsClientConnection.IPv4SourceAddresses);
                jsonWriter.WriteStringArray("dnsServerIPv6SourceAddresses", DnsClientConnection.IPv6SourceAddresses);

                jsonWriter.WriteNumber("defaultRecordTtl", _dnsWebService._dnsServer.AuthZoneManager.DefaultRecordTtl);
                jsonWriter.WriteNumber("defaultNsRecordTtl", _dnsWebService._dnsServer.AuthZoneManager.DefaultNsRecordTtl);
                jsonWriter.WriteNumber("defaultSoaRecordTtl", _dnsWebService._dnsServer.AuthZoneManager.DefaultSoaRecordTtl);
                jsonWriter.WriteString("defaultResponsiblePerson", _dnsWebService._dnsServer.DefaultResponsiblePerson?.Address);
                jsonWriter.WriteBoolean("useSoaSerialDateScheme", _dnsWebService._dnsServer.AuthZoneManager.UseSoaSerialDateScheme);
                jsonWriter.WriteNumber("minSoaRefresh", _dnsWebService._dnsServer.AuthZoneManager.MinSoaRefresh);
                jsonWriter.WriteNumber("minSoaRetry", _dnsWebService._dnsServer.AuthZoneManager.MinSoaRetry);
                jsonWriter.WriteStringArray("zoneTransferAllowedNetworks", _dnsWebService._dnsServer.ZoneTransferAllowedNetworks);
                jsonWriter.WriteStringArray("notifyAllowedNetworks", _dnsWebService._dnsServer.NotifyAllowedNetworks);

                jsonWriter.WriteBoolean("dnsServerEnableCheckForUpdate", _dnsWebService._dnsServer.EnableCheckForUpdate);
                jsonWriter.WriteBoolean("dnsAppsEnableAutomaticUpdate", _dnsWebService._dnsServer.DnsApplicationManager.EnableAutomaticUpdate);

                jsonWriter.WriteString("ipv6Mode", _dnsWebService._dnsServer.IPv6Mode.ToString());
                jsonWriter.WriteBoolean("preferIPv6", _dnsWebService._dnsServer.IPv6Mode == IPv6Mode.Preferred);
                jsonWriter.WriteBoolean("enableUdpSocketPool", _dnsWebService._dnsServer.EnableUdpSocketPool);

                jsonWriter.WriteStartArray("socketPoolExcludedPorts");

                ushort[] socketPoolExcludedPorts = UdpClientConnection.SocketPoolExcludedPorts;
                if (socketPoolExcludedPorts is not null)
                {
                    foreach (ushort excludedPort in socketPoolExcludedPorts)
                        jsonWriter.WriteNumberValue(excludedPort);
                }

                jsonWriter.WriteEndArray();

                jsonWriter.WriteNumber("udpPayloadSize", _dnsWebService._dnsServer.UdpPayloadSize);

                jsonWriter.WriteBoolean("dnssecValidation", _dnsWebService._dnsServer.DnssecValidation);

                jsonWriter.WriteBoolean("eDnsClientSubnet", _dnsWebService._dnsServer.EDnsClientSubnet);
                jsonWriter.WriteNumber("eDnsClientSubnetIPv4PrefixLength", _dnsWebService._dnsServer.EDnsClientSubnetIPv4PrefixLength);
                jsonWriter.WriteNumber("eDnsClientSubnetIPv6PrefixLength", _dnsWebService._dnsServer.EDnsClientSubnetIPv6PrefixLength);
                jsonWriter.WriteString("eDnsClientSubnetIpv4Override", _dnsWebService._dnsServer.EDnsClientSubnetIpv4Override?.ToString());
                jsonWriter.WriteString("eDnsClientSubnetIpv6Override", _dnsWebService._dnsServer.EDnsClientSubnetIpv6Override?.ToString());

                jsonWriter.WriteStartArray("qpmPrefixLimitsIPv4");

                foreach (KeyValuePair<int, (int, int)> qpmPrefixLimit in _dnsWebService._dnsServer.QpmPrefixLimitsIPv4)
                {
                    jsonWriter.WriteStartObject();

                    jsonWriter.WriteNumber("prefix", qpmPrefixLimit.Key);
                    jsonWriter.WriteNumber("udpLimit", qpmPrefixLimit.Value.Item1);
                    jsonWriter.WriteNumber("tcpLimit", qpmPrefixLimit.Value.Item2);

                    jsonWriter.WriteEndObject();
                }

                jsonWriter.WriteEndArray();

                jsonWriter.WriteStartArray("qpmPrefixLimitsIPv6");

                foreach (KeyValuePair<int, (int, int)> qpmPrefixLimit in _dnsWebService._dnsServer.QpmPrefixLimitsIPv6)
                {
                    jsonWriter.WriteStartObject();

                    jsonWriter.WriteNumber("prefix", qpmPrefixLimit.Key);
                    jsonWriter.WriteNumber("udpLimit", qpmPrefixLimit.Value.Item1);
                    jsonWriter.WriteNumber("tcpLimit", qpmPrefixLimit.Value.Item2);

                    jsonWriter.WriteEndObject();
                }

                jsonWriter.WriteEndArray();

                jsonWriter.WriteNumber("qpmLimitSampleMinutes", _dnsWebService._dnsServer.QpmLimitSampleMinutes);
                jsonWriter.WriteNumber("qpmLimitUdpTruncationPercentage", _dnsWebService._dnsServer.QpmLimitUdpTruncationPercentage);

                jsonWriter.WritePropertyName("qpmLimitBypassList");
                jsonWriter.WriteStartArray();

                if (_dnsWebService._dnsServer.QpmLimitBypassList is not null)
                {
                    foreach (NetworkAddress network in _dnsWebService._dnsServer.QpmLimitBypassList)
                        jsonWriter.WriteStringValue(network.ToString());
                }

                jsonWriter.WriteEndArray();

                jsonWriter.WriteNumber("clientTimeout", _dnsWebService._dnsServer.ClientTimeout);
                jsonWriter.WriteNumber("tcpSendTimeout", _dnsWebService._dnsServer.TcpSendTimeout);
                jsonWriter.WriteNumber("tcpReceiveTimeout", _dnsWebService._dnsServer.TcpReceiveTimeout);
                jsonWriter.WriteNumber("quicIdleTimeout", _dnsWebService._dnsServer.QuicIdleTimeout);
                jsonWriter.WriteNumber("quicMaxInboundStreams", _dnsWebService._dnsServer.QuicMaxInboundStreams);
                jsonWriter.WriteNumber("listenBacklog", _dnsWebService._dnsServer.ListenBacklog);
                jsonWriter.WriteNumber("udpSendBufferSizeKB", _dnsWebService._dnsServer.UdpSendBufferSizeKB);
                jsonWriter.WriteNumber("udpReceiveBufferSizeKB", _dnsWebService._dnsServer.UdpReceiveBufferSizeKB);
                jsonWriter.WriteNumber("maxConcurrentResolutionsPerCore", _dnsWebService._dnsServer.MaxConcurrentResolutionsPerCore);

                //web service
                jsonWriter.WritePropertyName("webServiceLocalAddresses");
                jsonWriter.WriteStartArray();

                foreach (IPAddress localAddress in _dnsWebService._webServiceLocalAddresses)
                {
                    if (localAddress.AddressFamily == AddressFamily.InterNetworkV6)
                        jsonWriter.WriteStringValue("[" + localAddress.ToString() + "]");
                    else
                        jsonWriter.WriteStringValue(localAddress.ToString());
                }

                jsonWriter.WriteEndArray();

                jsonWriter.WriteNumber("webServiceHttpPort", _dnsWebService._webServiceHttpPort);

                jsonWriter.WriteBoolean("webServiceEnableHttpUnixSocket", _dnsWebService._webServiceEnableHttpUnixSocket);
                jsonWriter.WriteString("webServiceHttpUnixSocket", _dnsWebService._webServiceHttpUnixSocket);

                jsonWriter.WriteBoolean("webServiceEnableTlsUnixSocket", _dnsWebService._webServiceEnableTlsUnixSocket);
                jsonWriter.WriteString("webServiceTlsUnixSocket", _dnsWebService._webServiceTlsUnixSocket);

                jsonWriter.WriteBoolean("webServiceEnableTls", _dnsWebService._webServiceEnableTls);
                jsonWriter.WriteBoolean("webServiceEnableHttp3", _dnsWebService._webServiceEnableHttp3);
                jsonWriter.WriteBoolean("webServiceHttpToTlsRedirect", _dnsWebService._webServiceHttpToTlsRedirect);
                jsonWriter.WriteString("webServiceRootPath", _dnsWebService._activeWebRoot);
                jsonWriter.WriteBoolean("webServiceUseSelfSignedTlsCertificate", _dnsWebService._webServiceUseSelfSignedTlsCertificate);

                jsonWriter.WriteNumber("webServiceTlsPort", _dnsWebService._webServiceTlsPort);

                jsonWriter.WritePropertyName("webServiceReverseProxyAddresses");
                {
                    jsonWriter.WriteStartArray();

                    if (_dnsWebService._webServiceReverseProxyAddresses is not null)
                    {
                        foreach (NetworkAccessControl nac in _dnsWebService._webServiceReverseProxyAddresses)
                            jsonWriter.WriteStringValue(nac.ToString());
                    }

                    jsonWriter.WriteEndArray();
                }

                jsonWriter.WriteString("webServiceRealIpHeader", _dnsWebService._webServiceRealIpHeader);
                jsonWriter.WriteString("webServiceCspFrameAncestorsHeader", _dnsWebService._webServiceCspFrameAncestorsHeader);
                jsonWriter.WriteString("webServiceTlsCertificatePath", _dnsWebService._webServiceTlsCertificatePath);
                jsonWriter.WriteString("webServiceTlsCertificatePassword", string.IsNullOrEmpty(_dnsWebService._webServiceTlsCertificatePath) ? null : "************");

                //optional protocols
                jsonWriter.WriteBoolean("enableEDnsClientSubnetSourceAddress", _dnsWebService._dnsServer.EnableEDnsClientSubnetSourceAddress);
                jsonWriter.WriteBoolean("enableDnsOverUdpProxy", _dnsWebService._dnsServer.EnableDnsOverUdpProxy);
                jsonWriter.WriteBoolean("enableDnsOverTcpProxy", _dnsWebService._dnsServer.EnableDnsOverTcpProxy);
                jsonWriter.WriteBoolean("enableDnsOverHttp", _dnsWebService._dnsServer.EnableDnsOverHttp);
                jsonWriter.WriteBoolean("enableDnsOverHttpUnixSocket", _dnsWebService._dnsServer.EnableDnsOverHttpUnixSocket);
                jsonWriter.WriteBoolean("enableDnsOverHttpsUnixSocket", _dnsWebService._dnsServer.EnableDnsOverHttpsUnixSocket);
                jsonWriter.WriteBoolean("enableDnsOverTls", _dnsWebService._dnsServer.EnableDnsOverTls);
                jsonWriter.WriteBoolean("enableDnsOverHttps", _dnsWebService._dnsServer.EnableDnsOverHttps);
                jsonWriter.WriteBoolean("enableDnsOverHttp3", _dnsWebService._dnsServer.EnableDnsOverHttp3);
                jsonWriter.WriteBoolean("enableDnsOverQuic", _dnsWebService._dnsServer.EnableDnsOverQuic);

                jsonWriter.WriteBoolean("enableDnsOverHttpHelpRedirect", _dnsWebService._dnsServer.EnableDnsOverHttpHelpRedirect);

                jsonWriter.WriteNumber("dnsOverUdpProxyPort", _dnsWebService._dnsServer.DnsOverUdpProxyPort);
                jsonWriter.WriteNumber("dnsOverTcpProxyPort", _dnsWebService._dnsServer.DnsOverTcpProxyPort);
                jsonWriter.WriteNumber("dnsOverHttpPort", _dnsWebService._dnsServer.DnsOverHttpPort);
                jsonWriter.WriteString("dnsOverHttpUnixSocket", _dnsWebService._dnsServer.DnsOverHttpUnixSocket);
                jsonWriter.WriteString("dnsOverHttpsUnixSocket", _dnsWebService._dnsServer.DnsOverHttpsUnixSocket);
                jsonWriter.WriteNumber("dnsOverTlsPort", _dnsWebService._dnsServer.DnsOverTlsPort);
                jsonWriter.WriteNumber("dnsOverHttpsPort", _dnsWebService._dnsServer.DnsOverHttpsPort);
                jsonWriter.WriteNumber("dnsOverQuicPort", _dnsWebService._dnsServer.DnsOverQuicPort);

                jsonWriter.WritePropertyName("dnsReverseProxyNetworkACL");
                {
                    jsonWriter.WriteStartArray();

                    if (_dnsWebService._dnsServer.DnsReverseProxyNetworkACL is not null)
                    {
                        foreach (NetworkAccessControl nac in _dnsWebService._dnsServer.DnsReverseProxyNetworkACL)
                            jsonWriter.WriteStringValue(nac.ToString());
                    }

                    jsonWriter.WriteEndArray();
                }

                jsonWriter.WriteString("dnsOverHttpRealIpHeader", _dnsWebService._dnsServer.DnsOverHttpRealIpHeader);
                jsonWriter.WriteString("dnsTlsCertificatePath", _dnsWebService._dnsServer.DnsTlsCertificatePath);
                jsonWriter.WriteString("dnsTlsCertificatePassword", string.IsNullOrEmpty(_dnsWebService._dnsServer.DnsTlsCertificatePath) ? null : "************");

                //tsig
                jsonWriter.WritePropertyName("tsigKeys");
                {
                    jsonWriter.WriteStartArray();

                    if (_dnsWebService._dnsServer.TsigKeys is not null)
                    {
                        foreach (KeyValuePair<string, TsigKey> tsigKey in _dnsWebService._dnsServer.TsigKeys.ToImmutableSortedDictionary())
                        {
                            jsonWriter.WriteStartObject();

                            jsonWriter.WriteString("keyName", tsigKey.Key);
                            if (includeSecrets)
                                jsonWriter.WriteString("sharedSecret", tsigKey.Value.SharedSecret);
                            jsonWriter.WriteString("algorithmName", tsigKey.Value.AlgorithmName);

                            jsonWriter.WriteEndObject();
                        }
                    }

                    jsonWriter.WriteEndArray();
                }

                //recursion
                jsonWriter.WriteString("recursion", _dnsWebService._dnsServer.Recursion.ToString());

                jsonWriter.WritePropertyName("recursionNetworkACL");
                {
                    jsonWriter.WriteStartArray();

                    if (_dnsWebService._dnsServer.RecursionNetworkACL is not null)
                    {
                        foreach (NetworkAccessControl nac in _dnsWebService._dnsServer.RecursionNetworkACL)
                            jsonWriter.WriteStringValue(nac.ToString());
                    }

                    jsonWriter.WriteEndArray();
                }

                jsonWriter.WriteBoolean("randomizeName", _dnsWebService._dnsServer.RandomizeName);
                jsonWriter.WriteBoolean("qnameMinimization", _dnsWebService._dnsServer.QnameMinimization);
                jsonWriter.WriteBoolean("locallyServedDnsZones", _dnsWebService._dnsServer.LocallyServedDnsZones);

                jsonWriter.WriteNumber("resolverRetries", _dnsWebService._dnsServer.ResolverRetries);
                jsonWriter.WriteNumber("resolverTimeout", _dnsWebService._dnsServer.ResolverTimeout);
                jsonWriter.WriteNumber("resolverConcurrency", _dnsWebService._dnsServer.ResolverConcurrency);
                jsonWriter.WriteNumber("resolverMaxStackCount", _dnsWebService._dnsServer.ResolverMaxStackCount);

                //cache
                jsonWriter.WriteBoolean("saveCache", _dnsWebService._dnsServer.SaveCacheToDisk);
                jsonWriter.WriteBoolean("serveStale", _dnsWebService._dnsServer.ServeStale);
                jsonWriter.WriteNumber("serveStaleTtl", _dnsWebService._dnsServer.CacheZoneManager.ServeStaleTtl);
                jsonWriter.WriteNumber("serveStaleAnswerTtl", _dnsWebService._dnsServer.CacheZoneManager.ServeStaleAnswerTtl);
                jsonWriter.WriteNumber("serveStaleResetTtl", _dnsWebService._dnsServer.CacheZoneManager.ServeStaleResetTtl);
                jsonWriter.WriteNumber("serveStaleMaxWaitTime", _dnsWebService._dnsServer.ServeStaleMaxWaitTime);

                jsonWriter.WriteNumber("cacheMaximumEntries", _dnsWebService._dnsServer.CacheZoneManager.MaximumEntries);
                jsonWriter.WriteNumber("cacheMinimumRecordTtl", _dnsWebService._dnsServer.CacheZoneManager.MinimumRecordTtl);
                jsonWriter.WriteNumber("cacheMaximumRecordTtl", _dnsWebService._dnsServer.CacheZoneManager.MaximumRecordTtl);
                jsonWriter.WriteNumber("cacheNegativeRecordTtl", _dnsWebService._dnsServer.CacheZoneManager.NegativeRecordTtl);
                jsonWriter.WriteNumber("cacheFailureRecordTtl", _dnsWebService._dnsServer.CacheZoneManager.FailureRecordTtl);

                jsonWriter.WriteBoolean("enableCachePrefetch", _dnsWebService._dnsServer.EnableCachePrefetch);
                jsonWriter.WriteNumber("cachePrefetchEligibility", _dnsWebService._dnsServer.CachePrefetchEligibility);
                jsonWriter.WriteNumber("cachePrefetchTrigger", _dnsWebService._dnsServer.CachePrefetchTrigger);

                //blocking
                jsonWriter.WriteBoolean("enableBlocking", _dnsWebService._dnsServer.EnableBlocking);
                jsonWriter.WriteBoolean("configuredEnableBlocking", _dnsWebService._dnsServer.ConfiguredEnableBlocking);
                jsonWriter.WriteBoolean("allowTxtBlockingReport", _dnsWebService._dnsServer.AllowTxtBlockingReport);

                jsonWriter.WritePropertyName("blockingBypassList");
                jsonWriter.WriteStartArray();

                if (_dnsWebService._dnsServer.BlockingBypassList is not null)
                {
                    foreach (NetworkAddress network in _dnsWebService._dnsServer.BlockingBypassList)
                        jsonWriter.WriteStringValue(network.ToString());
                }

                jsonWriter.WriteEndArray();

                if (!_dnsWebService._dnsServer.EnableBlocking && (DateTime.UtcNow < _dnsWebService._dnsServer.BlockListZoneManager.TemporaryDisableBlockingTill))
                    jsonWriter.WriteString("temporaryDisableBlockingTill", _dnsWebService._dnsServer.BlockListZoneManager.TemporaryDisableBlockingTill);

                jsonWriter.WriteString("blockingType", _dnsWebService._dnsServer.BlockingType.ToString());
                jsonWriter.WriteNumber("blockingAnswerTtl", _dnsWebService._dnsServer.BlockingAnswerTtl);

                jsonWriter.WritePropertyName("customBlockingAddresses");
                jsonWriter.WriteStartArray();

                foreach (DnsARecordData record in _dnsWebService._dnsServer.CustomBlockingARecords)
                    jsonWriter.WriteStringValue(record.Address.ToString());

                foreach (DnsAAAARecordData record in _dnsWebService._dnsServer.CustomBlockingAAAARecords)
                    jsonWriter.WriteStringValue(record.Address.ToString());

                jsonWriter.WriteEndArray();

                jsonWriter.WritePropertyName("blockListUrls");

                if (_dnsWebService._dnsServer.BlockListZoneManager.BlockListUrls.Count == 0)
                {
                    jsonWriter.WriteNullValue();
                }
                else
                {
                    jsonWriter.WriteStartArray();

                    foreach (string blockListUrl in _dnsWebService._dnsServer.BlockListZoneManager.BlockListUrls)
                        jsonWriter.WriteStringValue(blockListUrl);

                    jsonWriter.WriteEndArray();
                }

                jsonWriter.WriteNumber("blockListUpdateIntervalHours", _dnsWebService._dnsServer.BlockListZoneManager.BlockListUpdateIntervalHours);

                if (_dnsWebService._dnsServer.BlockListZoneManager.BlockListUpdateEnabled)
                {
                    DateTime blockListNextUpdatedOn = _dnsWebService._dnsServer.BlockListZoneManager.BlockListLastUpdatedOn.AddHours(_dnsWebService._dnsServer.BlockListZoneManager.BlockListUpdateIntervalHours);

                    jsonWriter.WriteString("blockListNextUpdatedOn", blockListNextUpdatedOn);
                }

                //proxy & forwarders
                jsonWriter.WritePropertyName("proxy");
                if (_dnsWebService._dnsServer.Proxy == null)
                {
                    jsonWriter.WriteNullValue();
                }
                else
                {
                    jsonWriter.WriteStartObject();

                    NetProxy proxy = _dnsWebService._dnsServer.Proxy;

                    jsonWriter.WriteString("type", proxy.Type.ToString());
                    jsonWriter.WriteString("address", proxy.Address);
                    jsonWriter.WriteNumber("port", proxy.Port);

                    NetworkCredential credential = proxy.Credential;
                    if (credential != null)
                    {
                        jsonWriter.WriteString("username", credential.UserName);
                        if (includeSecrets)
                            jsonWriter.WriteString("password", credential.Password);
                    }

                    jsonWriter.WritePropertyName("bypass");
                    jsonWriter.WriteStartArray();

                    foreach (NetProxyBypassItem item in proxy.BypassList)
                        jsonWriter.WriteStringValue(item.Value);

                    jsonWriter.WriteEndArray();

                    jsonWriter.WriteEndObject();
                }

                jsonWriter.WritePropertyName("forwarders");

                DnsTransportProtocol forwarderProtocol = DnsTransportProtocol.Udp;

                if (_dnsWebService._dnsServer.Forwarders == null)
                {
                    jsonWriter.WriteNullValue();
                }
                else
                {
                    forwarderProtocol = _dnsWebService._dnsServer.Forwarders[0].Protocol;

                    jsonWriter.WriteStartArray();

                    foreach (NameServerAddress forwarder in _dnsWebService._dnsServer.Forwarders)
                        jsonWriter.WriteStringValue(forwarder.OriginalAddress);

                    jsonWriter.WriteEndArray();
                }

                jsonWriter.WriteStartArray("configuredForwarders");
                foreach (NameServerAddress forwarder in _dnsWebService._dnsServer.Forwarders ?? [])
                {
                    jsonWriter.WriteStartObject();
                    jsonWriter.WriteString("address", forwarder.OriginalAddress);
                    jsonWriter.WriteString("transport", forwarder.Protocol.ToString());
                    jsonWriter.WriteEndObject();
                }
                jsonWriter.WriteEndArray();

                jsonWriter.WriteString("forwarderProtocol", forwarderProtocol.ToString());
                jsonWriter.WriteBoolean("concurrentForwarding", _dnsWebService._dnsServer.ConcurrentForwarding);

                jsonWriter.WriteNumber("forwarderRetries", _dnsWebService._dnsServer.ForwarderRetries);
                jsonWriter.WriteNumber("forwarderTimeout", _dnsWebService._dnsServer.ForwarderTimeout);
                jsonWriter.WriteNumber("forwarderConcurrency", _dnsWebService._dnsServer.ForwarderConcurrency);

                //logging
                jsonWriter.WriteBoolean("enableLogging", _dnsWebService._log.LoggingType != LoggingType.None);
                jsonWriter.WriteString("loggingType", _dnsWebService._log.LoggingType.ToString());
                jsonWriter.WriteBoolean("ignoreResolverLogs", _dnsWebService._dnsServer.ResolverLogManager == null);
                jsonWriter.WriteBoolean("logQueries", _dnsWebService._dnsServer.QueryLogManager != null);
                jsonWriter.WriteBoolean("noStackTrace", _dnsWebService._log.NoStackTrace);
                jsonWriter.WriteBoolean("useLocalTime", _dnsWebService._log.UseLocalTime);
                jsonWriter.WriteString("logFolder", _dnsWebService._log.LogFolder);
                jsonWriter.WriteNumber("maxLogFileDays", _dnsWebService._log.MaxLogFileDays);
                jsonWriter.WriteStartArray("managedSettings");
                if (_dnsWebService._manifestOwnsRealIpHeader)
                    jsonWriter.WriteStringValue("/web/realIpHeader");
                if (_dnsWebService._manifestOwnsFrameAncestors)
                    jsonWriter.WriteStringValue("/web/frameAncestors");
                if (_dnsWebService._dnsServer.AllowedZoneManager.ManifestOwnsList)
                    jsonWriter.WriteStringValue("/allowZones");
                if (_dnsWebService._dnsServer.BlockedZoneManager.ManifestOwnsList)
                    jsonWriter.WriteStringValue("/blockZones");
                if (_dnsWebService._manifestOwnsWebRoot)
                    jsonWriter.WriteStringValue("/web/rootPath");
                if ((_dnsWebService._managedWebListeners & ManagedWebSelfSigned) != 0)
                    jsonWriter.WriteStringValue("/web/useSelfSignedCertificate");
                if ((_dnsWebService._managedWebListeners & ManagedWebCertificatePath) != 0)
                    jsonWriter.WriteStringValue("/web/certificate/path");
                if ((_dnsWebService._managedWebListeners & ManagedWebCertificatePassword) != 0)
                    jsonWriter.WriteStringValue("/web/certificate/password");
                if (_dnsWebService._manifestOwnsReverseProxyAcl)
                    jsonWriter.WriteStringValue("/web/reverseProxyAcl");
                if ((_dnsWebService._managedWebListeners & ManagedWebAddresses) != 0)
                    jsonWriter.WriteStringValue("/web/localAddresses");
                if ((_dnsWebService._managedWebListeners & ManagedWebHttpPort) != 0)
                    jsonWriter.WriteStringValue("/web/httpPort");
                if ((_dnsWebService._managedWebListeners & ManagedWebTlsPort) != 0)
                    jsonWriter.WriteStringValue("/web/tlsPort");
                if ((_dnsWebService._managedWebListeners & ManagedWebTlsSocketPath) != 0)
                    jsonWriter.WriteStringValue("/web/tlsUnixSocket/path");
                if ((_dnsWebService._managedWebListeners & ManagedWebTlsSocketEnabled) != 0)
                    jsonWriter.WriteStringValue("/web/tlsUnixSocket/enabled");
                if ((_dnsWebService._managedWebListeners & ManagedWebHttpSocketPath) != 0)
                    jsonWriter.WriteStringValue("/web/httpUnixSocket/path");
                if ((_dnsWebService._managedWebListeners & ManagedWebHttpSocketEnabled) != 0)
                    jsonWriter.WriteStringValue("/web/httpUnixSocket/enabled");
                if ((_dnsWebService._managedWebListeners & ManagedWebRedirect) != 0)
                    jsonWriter.WriteStringValue("/web/redirectHttpToTls");
                if ((_dnsWebService._managedWebListeners & ManagedWebHttp3) != 0)
                    jsonWriter.WriteStringValue("/web/http3Enabled");
                if ((_dnsWebService._managedWebListeners & ManagedWebTlsEnabled) != 0)
                    jsonWriter.WriteStringValue("/web/tlsEnabled");
                foreach (string path in _dnsWebService._dnsServer.GetManagedDnsPaths())
                    jsonWriter.WriteStringValue(path);
                if (_dnsWebService._dnsServer.BlockListZoneManager.ManifestOwnsUpdateInterval)
                    jsonWriter.WriteStringValue("/blocklists/updateIntervalHours");
                if (_dnsWebService._dnsServer.BlockListZoneManager.ManifestOwnsSources)
                    jsonWriter.WriteStringValue("/blocklists/sources");
                foreach (string path in _dnsWebService._log.GetManagedManifestPaths())
                    jsonWriter.WriteStringValue(path);
                jsonWriter.WriteEndArray();

                jsonWriter.WriteBoolean("enableInMemoryStats", _dnsWebService._dnsServer.StatsManager.EnableInMemoryStats);
                jsonWriter.WriteNumber("maxStatFileDays", _dnsWebService._dnsServer.StatsManager.MaxStatFileDays);
            }

            #endregion

            #region public

            public void GetDnsSettings(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Settings, sessionUser, PermissionFlag.View))
                    throw new DnsWebServiceException("Access was denied.");

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();
                WriteDnsSettings(jsonWriter);
            }

            public Task ExportConfigurationAsync(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);
                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Settings, sessionUser, PermissionFlag.View))
                    throw new DnsWebServiceException("Access was denied.");

                bool includePreviewOnly = context.Request.TryGetQueryOrForm("includePreviewOnly", bool.Parse, out bool include) && include;
                using JsonDocument snapshot = CaptureConfigurationSnapshot(sessionUser: sessionUser, exportDomainLists: true);
                var manifest = ConfigurationPlan.Export(snapshot.RootElement, includePreviewOnly);
                var missingInputs = new SortedSet<string>(StringComparer.Ordinal);
                DnsServer dns = _dnsWebService._dnsServer;

                if (_dnsWebService._authManager.IsPermitted(PermissionSection.DhcpServer, sessionUser, PermissionFlag.View))
                {
                    var scopes = ConfigurationDhcp.ExportScopes(_dnsWebService._dhcpServer.Scopes, missingInputs);
                    if (scopes.Count > 0)
                        manifest.Add("dhcp", new System.Text.Json.Nodes.JsonObject { ["scopes"] = scopes });
                }

                if (dns.BlockListZoneManager.BlockListUrls.Count > 0)
                    missingInputs.Add("/blocklists/sources");
                if (dns.Forwarders?.Count > 0 && manifest["dns"]?["forwarding"]?["servers"] is null)
                    missingInputs.Add("/dns/forwarding/servers");
                if (!string.IsNullOrEmpty(dns.Proxy?.Credential?.Password))
                    missingInputs.Add("/dns/proxy/password");
                if (!string.IsNullOrEmpty(dns.DnsTlsCertificatePassword))
                    missingInputs.Add("/dns/listeners/certificate/password");
                if (_dnsWebService._activeWebRoot is not null && !includePreviewOnly)
                    missingInputs.Add("/web/rootPath");
                if (!string.IsNullOrEmpty(_dnsWebService._webServiceTlsCertificatePassword))
                    missingInputs.Add("/web/certificate/password");
                if (dns.TsigKeys is not null)
                {
                    string catalogKey = _dnsWebService._clusterManager.ClusterInitialized
                        ? ConfigurationTsig.GetCatalogKey(_dnsWebService._clusterManager.ClusterDomain) : null;
                    foreach (string name in dns.TsigKeys.Keys)
                    {
                        if (!string.Equals(name, catalogKey, StringComparison.OrdinalIgnoreCase))
                            missingInputs.Add(ConfigurationPlan.AppendPath(ConfigurationTsig.Path, name) + "/secret");
                    }
                }

                context.Response.Headers.CacheControl = "no-store";
                Utf8JsonWriter writer = context.GetCurrentJsonWriter();
                writer.WritePropertyName("manifest");
                manifest.WriteTo(writer);
                writer.WriteStartArray("missingInputs");
                foreach (string path in missingInputs)
                    writer.WriteStringValue(path);
                writer.WriteEndArray();
                return Task.CompletedTask;
            }

            public async Task PreviewConfigurationAsync(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);
                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Settings, sessionUser, PermissionFlag.View))
                    throw new DnsWebServiceException("Access was denied.");

                if (!context.Request.HasJsonContentType())
                    throw new DnsWebServiceException("Send the configuration manifest as JSON.");

                try
                {
                    ConfigurationManifest manifest = await ConfigurationManifest.ReadAsync(context.Request.Body, context.RequestAborted);
                    bool declaresWebRoot = manifest.Settings.TryGetProperty("web", out JsonElement web) && web.TryGetProperty("rootPath", out _);
                    bool declaresWebCertificate = ConfigurationWebCertificate.IsDeclared(manifest);
                    if ((declaresWebRoot || declaresWebCertificate) &&
                        !_dnsWebService._authManager.IsPermitted(PermissionSection.Settings, sessionUser, PermissionFlag.Modify))
                        throw new DnsWebServiceException("Access was denied.");

                    var webCertificate = declaresWebCertificate ? _dnsWebService.PrepareWebCertificate(manifest, preview: true) : null;
                    _dnsWebService.ValidateManifestWebListeners(ConfigurationPlan.GetWebListeners(manifest), webCertificate?.HasCertificate);
                    CheckDnsCertificatePreviewPermission(manifest, sessionUser);
                    ConfigurationDnsCertificate.Candidate dnsCertificate = ConfigurationDnsCertificate.Prepare(manifest, _dnsWebService._dnsServer, preview: true);
                    using ConfigurationDhcp.ScopeSnapshot dhcpSnapshot = CaptureDhcpScopeSnapshot(manifest, sessionUser);
                    using JsonDocument current = CaptureConfigurationSnapshot(manifest, sessionUser, dnsCertificate: dnsCertificate,
                        webCertificate: webCertificate, dhcpSnapshot: dhcpSnapshot);
                    var changes = ConfigurationPlan.Create(manifest, current.RootElement, _dnsWebService._log);
                    if (dhcpSnapshot is not null)
                        ConfigurationDhcp.ValidatePersistableScopes(manifest, dhcpSnapshot.Scopes, _dnsWebService._log, _dnsWebService._dhcpServer);
                    string revision = ConfigurationPlan.GetRevision(manifest, current.RootElement, _configurationRevisionKey);

                    Utf8JsonWriter response = context.GetCurrentJsonWriter();
                    response.WriteString("revision", revision);
                    string domainWarning = manifest.GetServerDomainEnvironmentWarning();
                    if (domainWarning is not null)
                    {
                        response.WriteStartArray("warnings");
                        response.WriteStringValue(domainWarning);
                        response.WriteEndArray();
                    }
                    response.WriteStartArray("changes");
                    foreach (ConfigurationChange change in changes)
                    {
                        response.WriteStartObject();
                        response.WriteString("path", change.Path);
                        response.WriteString("kind", change.Kind.ToString());
                        response.WriteBoolean("restartWebService", change.RestartWebService);
                        response.WriteBoolean("restartDnsService", change.RestartDnsService);
                        response.WriteEndObject();
                    }
                    response.WriteEndArray();
                }
                catch (InvalidDataException ex)
                {
                    throw new DnsWebServiceException(ex.Message);
                }
            }

            public async Task ApplyConfigurationAsync(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);
                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Settings, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                if (!context.Request.HasJsonContentType())
                    throw new DnsWebServiceException("Send the configuration manifest as JSON.");

                string expected = context.Request.Headers.IfMatch.ToString();
                if (expected.Length != 66)
                    throw new DnsWebServiceException("Supply the preview revision in the If-Match header.");

                bool dhcpGate = false;
                try
                {
                    ConfigurationManifest manifest = await ConfigurationManifest.ReadAsync(context.Request.Body, context.RequestAborted);
                    ConfigurationPlan.CheckApplySupport(manifest);
                    ConfigurationPlan.CheckClusterApplySupport(manifest, _dnsWebService._clusterManager.ClusterInitialized);
                    if (HasDhcpScopeDeclaration(manifest))
                    {
                        await _dnsWebService._dhcpServer.EnterManifestGateAsync(context.RequestAborted);
                        dhcpGate = true;
                    }
                    var (proxy, dnsCertificate, webCertificate, tsig) = CheckApplyRevision(manifest, expected, sessionUser);
                    WebListeners listeners = ConfigurationPlan.GetWebListeners(manifest);
                    _dnsWebService.ValidateManifestWebListeners(listeners, webCertificate?.HasCertificate);

                    if (_dnsWebService.WebListenersChange(listeners) || webCertificate is { Changed: true })
                    {
                        var operation = new WebApplyOperation();
                        lock (_webApplyGate)
                            _lastWebApply = operation;
                        context.GetCurrentJsonWriter().WriteString("operationId", operation.Id.ToString("N"));
                        context.Response.OnCompleted(() =>
                        {
                            _ = Task.Run(() => CompleteWebApplyAsync(manifest, listeners, expected, operation, sessionUser));
                            return Task.CompletedTask;
                        });
                    }
                    else
                    {
                        await _dnsWebService.ApplyManifestAsync(manifest, manifest.GetDnsLocalEndPoints(), proxy, dnsCertificate, tsig, listeners: listeners, webCertificate: webCertificate);
                    }
                }
                catch (InvalidDataException ex)
                {
                    throw new DnsWebServiceException(ex.Message);
                }
                catch (SocketException)
                {
                    throw new DnsWebServiceException("/dns/localEndpoints: Could not bind the DNS listeners.");
                }
                catch (Exception ex) when (ex is IOException or UnauthorizedAccessException)
                {
                    throw new DnsWebServiceException("Could not activate or persist the configuration settings.");
                }
                finally
                {
                    if (dhcpGate)
                        _dnsWebService._dhcpServer.ExitManifestGate();
                }
            }

            private (ConfigurationProxy.Candidate Proxy, ConfigurationDnsCertificate.Candidate Certificate, ConfigurationWebCertificate.Candidate? WebCertificate, ConfigurationTsig.Candidate Tsig) CheckApplyRevision(ConfigurationManifest manifest, string expected, User sessionUser)
            {
                if ((_dnsWebService._dnsServer.AllowedZoneManager.ManifestOwnsList &&
                     !manifest.Settings.TryGetProperty("allowZones", out _) &&
                     !_dnsWebService._authManager.IsPermitted(PermissionSection.Allowed, sessionUser, PermissionFlag.Modify)) ||
                    (_dnsWebService._dnsServer.BlockedZoneManager.ManifestOwnsList &&
                     !manifest.Settings.TryGetProperty("blockZones", out _) &&
                     !_dnsWebService._authManager.IsPermitted(PermissionSection.Blocked, sessionUser, PermissionFlag.Modify)))
                    throw new DnsWebServiceException("Access was denied.");

                ConfigurationProxy.Candidate proxy = ConfigurationPlan.PrepareProxy(manifest, _dnsWebService._dnsServer);
                ConfigurationDnsCertificate.Candidate dnsCertificate = ConfigurationDnsCertificate.Prepare(manifest, _dnsWebService._dnsServer);
                var webCertificate = _dnsWebService.PrepareWebCertificate(manifest);
                var tsig = _dnsWebService.PrepareTsigKeys(manifest);
                using ConfigurationDhcp.ScopeSnapshot dhcpSnapshot = CaptureDhcpScopeSnapshot(manifest, sessionUser);
                if ((dhcpSnapshot is not null || _dnsWebService._dhcpServer.ManagedPaths.Count > 0) &&
                    !_dnsWebService._authManager.IsPermitted(PermissionSection.DhcpServer, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                using JsonDocument current = CaptureConfigurationSnapshot(manifest, sessionUser, proxy, dnsCertificate, webCertificate, tsig, dhcpSnapshot: dhcpSnapshot);
                if (dhcpSnapshot is not null)
                {
                    var changes = new List<ConfigurationChange>();
                    ConfigurationDhcp.Compare(manifest.Settings.GetProperty("dhcp"), current.RootElement.GetProperty("manifestDhcpScopes"), changes);
                    if (changes.Any(change => change.Kind == ConfigurationChangeKind.Remove &&
                        !change.Path.Contains("/reservations/", StringComparison.Ordinal)) &&
                        !_dnsWebService._authManager.IsPermitted(PermissionSection.DhcpServer, sessionUser, PermissionFlag.Delete))
                        throw new DnsWebServiceException("Access was denied.");
                }
                string revision = ConfigurationPlan.GetRevision(manifest, current.RootElement, _configurationRevisionKey);
                if (!CryptographicOperations.FixedTimeEquals(Encoding.UTF8.GetBytes(expected), Encoding.UTF8.GetBytes("\"" + revision + "\"")))
                    throw new DnsWebServiceException("The configuration preview is stale. Create a new preview before applying.");
                ConfigurationPlan.ValidateDnsCertificateAndBindings(dnsCertificate, ConfigurationPlan.GetDnsBindings(manifest),
                    _dnsWebService._dnsServer.CaptureDnsBindings(), _dnsWebService._dnsServer.HasDnsListenerCertificate);
                return (proxy, dnsCertificate, webCertificate, tsig);
            }

            private async Task CompleteWebApplyAsync(ConfigurationManifest manifest, WebListeners listeners, string expected, WebApplyOperation operation, User sessionUser)
            {
                try
                {
                    await WithConfigurationLockAsync(async () =>
                    {
                        ConfigurationPlan.CheckClusterApplySupport(manifest, _dnsWebService._clusterManager.ClusterInitialized);
                        bool dhcpGate = HasDhcpScopeDeclaration(manifest);
                        if (dhcpGate)
                            await _dnsWebService._dhcpServer.EnterManifestGateAsync();
                        try
                        {
                            var (proxy, dnsCertificate, webCertificate, tsig) = CheckApplyRevision(manifest, expected, sessionUser);
                            _dnsWebService.ValidateManifestWebListeners(listeners, webCertificate?.HasCertificate);
                            await _dnsWebService.ApplyManifestWithWebRestartAsync(manifest, listeners, proxy, dnsCertificate, webCertificate, tsig);
                        }
                        finally
                        {
                            if (dhcpGate)
                                _dnsWebService._dhcpServer.ExitManifestGate();
                        }
                    });
                    operation.State = "applied";
                }
                catch (Exception ex)
                {
                    operation.Error = ex is InvalidDataException or DnsWebServiceException
                        ? ex.Message : "Could not bind the web listeners or persist the configuration settings.";
                    _dnsWebService._log.Write("Manifest web listener apply failed.", ex);
                    operation.State = "failed";
                }
            }

            public void GetConfigurationApplyStatus(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);
                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Settings, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                WebApplyOperation operation = _lastWebApply;
                if (operation is null || !Guid.TryParseExact(context.Request.QueryOrForm("operationId"), "N", out Guid id) || operation.Id != id)
                    throw new DnsWebServiceException("Configuration apply operation was not found.");

                string state = operation.State;
                Utf8JsonWriter writer = context.GetCurrentJsonWriter();
                writer.WriteString("state", state);
                if (state == "failed")
                    writer.WriteString("message", operation.Error);
            }

            public Task WithConfigurationLockAsync(HttpContext context, Action<HttpContext> action)
            {
                return WithConfigurationLockAsync(context, current =>
                {
                    action(current);
                    return Task.CompletedTask;
                });
            }

            public async Task WithConfigurationLockAsync(HttpContext context, Func<HttpContext, Task> action)
            {
                Task waitForConfiguration;
                lock (_webApplyGate)
                {
                    // Requests that arrive during a restart must not wait for the old web service to stop.
                    RejectPendingWebApply();
                    waitForConfiguration = _configurationLock.WaitAsync(context.RequestAborted);
                }

                await waitForConfiguration;
                try
                {
                    RejectPendingWebApply();
                    await action(context);
                }
                finally
                {
                    _configurationLock.Release();
                }
            }

            private void RejectPendingWebApply()
            {
                if (_lastWebApply?.State == "pending")
                    throw new DnsWebServiceException("A manifest web listener apply is in progress.");
            }

            internal async Task WithConfigurationLockAsync(Func<Task> action, CancellationToken cancellationToken = default)
            {
                await _configurationLock.WaitAsync(cancellationToken);
                try
                {
                    await action();
                }
                finally
                {
                    _configurationLock.Release();
                }
            }

            private void CheckDnsCertificatePreviewPermission(ConfigurationManifest manifest, User sessionUser)
            {
                if (ConfigurationDnsCertificate.TryGetDeclaration(manifest, out JsonElement certificate) &&
                    certificate.ValueKind == JsonValueKind.Object &&
                    (certificate.TryGetProperty("path", out _) || certificate.TryGetProperty("password", out _)) &&
                    !_dnsWebService._authManager.IsPermitted(PermissionSection.Settings, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");
            }

            private static bool HasDhcpScopeDeclaration(ConfigurationManifest manifest) =>
                manifest.Settings.TryGetProperty("dhcp", out JsonElement dhcp) && dhcp.TryGetProperty("scopes", out _);

            private ConfigurationDhcp.ScopeSnapshot CaptureDhcpScopeSnapshot(ConfigurationManifest manifest, User sessionUser)
            {
                if (manifest is null || !manifest.Settings.TryGetProperty("dhcp", out JsonElement dhcp) ||
                    !dhcp.TryGetProperty("scopes", out JsonElement scopes))
                    return null;

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.DhcpServer, sessionUser, PermissionFlag.View))
                    throw new DnsWebServiceException("Access was denied.");
                return new ConfigurationDhcp.ScopeSnapshot(scopes, _dnsWebService._dhcpServer.Scopes);
            }

            private JsonDocument CaptureConfigurationSnapshot(ConfigurationManifest manifest = null, User sessionUser = null, ConfigurationProxy.Candidate? preparedProxy = null, ConfigurationDnsCertificate.Candidate dnsCertificate = default, ConfigurationWebCertificate.Candidate? webCertificate = null, ConfigurationTsig.Candidate? preparedTsig = null, bool exportDomainLists = false, ConfigurationDhcp.ScopeSnapshot dhcpSnapshot = null)
            {
                using var snapshot = new MemoryStream();
                using (var writer = new Utf8JsonWriter(snapshot))
                {
                    writer.WriteStartObject();
                    WriteDnsSettings(writer, includeSecrets: false);
                    writer.WriteStartArray("manifestDhcpOwnership");
                    foreach (string path in _dnsWebService._dhcpServer.ManagedPaths)
                        writer.WriteStringValue(path);
                    writer.WriteEndArray();
                    writer.WriteBoolean("dnsListenerCertificateLoaded", _dnsWebService._dnsServer.HasDnsListenerCertificate);
                    ConfigurationDnsCertificate.WriteSnapshot(writer, _dnsWebService._dnsServer.CaptureDnsCertificate(), dnsCertificate, _configurationRevisionKey);
                    if (webCertificate.HasValue)
                        ConfigurationWebCertificate.WriteSnapshot(writer, webCertificate.Value, _configurationRevisionKey);
                    if (ConfigurationProxy.TryGetDeclaration(manifest, out JsonElement proxy))
                    {
                        string password = null;
                        if (proxy.TryGetProperty("password", out JsonElement reference))
                        {
                            if (reference.ValueKind != JsonValueKind.Null &&
                                !_dnsWebService._authManager.IsPermitted(PermissionSection.Settings, sessionUser, PermissionFlag.Modify))
                                throw new DnsWebServiceException("Access was denied.");
                            password = preparedProxy.HasValue ? preparedProxy.Value.Proxy?.Credential?.Password
                                : ConfigurationProxy.ResolvePassword(manifest, reference);
                        }
                        ConfigurationProxy.WritePasswordSnapshot(writer, password, _dnsWebService._dnsServer.Proxy, _configurationRevisionKey);
                    }
                    if (ConfigurationTsig.TryGetDeclaration(manifest, out _))
                    {
                        if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Settings, sessionUser, PermissionFlag.Modify))
                            throw new DnsWebServiceException("Access was denied.");
                        var candidate = preparedTsig ?? _dnsWebService.PrepareTsigKeys(manifest);
                        ConfigurationTsig.WriteSnapshot(writer, _dnsWebService._dnsServer.TsigKeys, candidate.Keys, _configurationRevisionKey);
                    }
                    WriteDomainListSnapshot(writer, manifest, sessionUser, "allowZones", PermissionSection.Allowed,
                        _dnsWebService._dnsServer.AllowedZoneManager.GetManifestNames, exportDomainLists);
                    WriteDomainListSnapshot(writer, manifest, sessionUser, "blockZones", PermissionSection.Blocked,
                        _dnsWebService._dnsServer.BlockedZoneManager.GetManifestNames, exportDomainLists);
                    if (manifest is not null && manifest.Settings.TryGetProperty("zones", out JsonElement zones))
                        WriteManifestZoneSnapshot(writer, zones, sessionUser);
                    if (dhcpSnapshot is not null)
                        ConfigurationDhcp.WriteSnapshot(writer, manifest.Settings.GetProperty("dhcp").GetProperty("scopes"), dhcpSnapshot.Scopes);
                    writer.WriteEndObject();
                }

                snapshot.Position = 0;
                return JsonDocument.Parse(snapshot);
            }

            private void WriteDomainListSnapshot(Utf8JsonWriter writer, ConfigurationManifest manifest, User user, string field,
                PermissionSection section, Func<string[]> readCurrent, bool export)
            {
                JsonElement declaration = default;
                bool declared = manifest is not null && manifest.Settings.TryGetProperty(field, out declaration);
                if (!declared && !export)
                    return;
                if (!_dnsWebService._authManager.IsPermitted(section, user, PermissionFlag.View))
                {
                    if (declared)
                        throw new DnsWebServiceException("Access was denied.");
                    return;
                }
                string[] current = readCurrent();
                if (declared)
                {
                    string[] desired = ConfigurationDomainLists.Read(declaration, "/" + field);
                    if (!_dnsWebService._authManager.IsPermitted(section, user, PermissionFlag.Modify) ||
                        (current.Except(desired, StringComparer.Ordinal).Any() &&
                         !_dnsWebService._authManager.IsPermitted(section, user, PermissionFlag.Delete)))
                        throw new DnsWebServiceException("Access was denied.");
                }

                writer.WriteStartArray(field);
                foreach (string name in current)
                    writer.WriteStringValue(name);
                writer.WriteEndArray();
            }

            private void WriteManifestZoneSnapshot(Utf8JsonWriter writer, JsonElement zones, User sessionUser)
            {
                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, sessionUser, PermissionFlag.View))
                    throw new DnsWebServiceException("Access was denied.");

                writer.WriteStartObject("manifestZones");
                foreach (JsonProperty declaration in zones.EnumerateObject())
                {
                    string name = ConfigurationManifest.CanonicalDnsName(declaration.Name, "/zones", allowRoot: true);
                    AuthZoneInfo zone = _dnsWebService._dnsServer.AuthZoneManager.GetAuthZoneInfo(name);
                    if (zone is not null && !_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, zone.Name, sessionUser, PermissionFlag.View))
                        throw new DnsWebServiceException("Access was denied.");

                    writer.WriteStartObject(name);
                    bool clusterProtected = _dnsWebService._clusterManager.ClusterInitialized &&
                        (_dnsWebService._clusterManager.IsClusterPrimaryZone(name) || _dnsWebService._clusterManager.IsClusterCatalogZone(name));
                    if (zone is not null)
                    {
                        writer.WriteString("type", zone.Type.ToString());
                        writer.WriteBoolean("enabled", !zone.Disabled);
                        writer.WriteBoolean("clusterProtected", clusterProtected);
                        if (declaration.Value.ValueKind == JsonValueKind.Object)
                            ConfigurationZonePolicies.WriteSnapshot(writer, declaration.Value, zone);
                    }

                    if (declaration.Value.ValueKind == JsonValueKind.Object &&
                        declaration.Value.TryGetProperty("records", out JsonElement records))
                    {
                        string path = ConfigurationPlan.AppendPath("/zones", declaration.Name) + "/records";
                        if (clusterProtected || (zone is not null && zone.Type != AuthZoneType.Primary))
                            throw new InvalidDataException($"{path}: Record preview requires a primary zone outside the cluster infrastructure.");

                        var currentRecords = new List<DnsResourceRecord>();
                        if (zone is not null)
                        {
                            writer.WriteString("recordRevision", zone.LastModified);
                            _dnsWebService._dnsServer.AuthZoneManager.ListAllZoneRecords(name, currentRecords);
                        }
                        writer.WriteStartArray("recordChanges");
                        foreach (ConfigurationChangeKind? change in ConfigurationPlan.CompareZoneRecords(
                            name, declaration.Name, _dnsWebService._dnsServer.ServerDomain, records, currentRecords))
                        {
                            if (change.HasValue)
                                writer.WriteNumberValue((int)change.Value);
                            else
                                writer.WriteNullValue();
                        }
                        writer.WriteEndArray();
                    }
                    writer.WriteEndObject();
                }
                writer.WriteEndObject();
            }

            private static (LoggingType? Destination, bool? NoStackTrace, int? RetentionDays, bool? UseLocalTime) ReadLoggingFields(HttpRequest request)
            {
                LoggingType? destination = null;
                if (request.TryGetQueryOrFormEnum("loggingType", out LoggingType loggingType))
                    destination = loggingType;
                else if (request.TryGetQueryOrForm("enableLogging", bool.Parse, out bool enableLogging))
                    destination = enableLogging ? LoggingType.File : LoggingType.None;

                return (destination,
                    request.TryGetQueryOrForm("noStackTrace", bool.Parse, out bool noStackTrace) ? noStackTrace : null,
                    request.TryGetQueryOrForm("maxLogFileDays", int.Parse, out int retentionDays) ? retentionDays : null,
                    request.TryGetQueryOrForm("useLocalTime", bool.Parse, out bool useLocalTime) ? useLocalTime : null);
            }

            private static Dictionary<int, (int Udp, int Tcp)> ReadRateLimitTable(HttpRequest request, string parameter, string path)
            {
                if (!request.TryQueryOrFormArray(parameter,
                    value => new KeyValuePair<int, (int, int)>(value.GetProperty("prefix").GetInt32(),
                        (value.GetProperty("udpLimit").GetInt32(), value.GetProperty("tcpLimit").GetInt32())),
                    row => new KeyValuePair<int, (int, int)>(int.Parse(row[0]), (int.Parse(row[1]), int.Parse(row[2]))),
                    3, out KeyValuePair<int, (int, int)>[] rows, '|'))
                    return null;

                var table = new Dictionary<int, (int, int)>(rows.Length);
                foreach ((int prefix, (int udp, int tcp)) in rows)
                {
                    if (!table.TryAdd(prefix, (udp, tcp)))
                        throw new DnsWebServiceException($"/dns/rateLimits/{path}: Duplicate prefix length.");
                }
                return table;
            }

            private static string FormatRateLimitTable(IReadOnlyDictionary<int, (int Udp, int Tcp)> table)
            {
                return string.Join('|', table.Select(entry => $"{entry.Key}|{entry.Value.Udp}|{entry.Value.Tcp}"));
            }

            public async Task SetDnsSettingsAsync(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Settings, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                bool serverDomainChanged = false;
                bool webServiceLocalAddressesChanged = false;
                bool webServiceTlsCertificateChanged = false;
                bool restartDnsService = false;
                bool restartWebService = false;
                IReadOnlyList<IPAddress> oldWebServiceLocalAddresses = _dnsWebService._webServiceLocalAddresses;
                int oldWebServiceHttpPort = _dnsWebService._webServiceHttpPort;
                int oldWebServiceTlsPort = _dnsWebService._webServiceTlsPort;
                bool _webServiceEnablingTls = false;

                Dictionary<string, string> clusterParameters = new Dictionary<string, string>(128);

                HttpRequest request = context.Request;
                using JsonDocument jsonDocument = request.HasJsonContentType()
                    ? await JsonDocument.ParseAsync(request.Body)
                    : null;
                if (jsonDocument is not null)
                    context.Items["jsonContent"] = jsonDocument;

                request.TryQueryOrFormArray("webServiceReverseProxyAddresses", NetworkAccessControl.Parse, out NetworkAccessControl[] reverseProxyAcl);
                if (reverseProxyAcl?.Length > byte.MaxValue)
                    throw new ArgumentOutOfRangeException("WebServiceReverseProxyAddresses", "Web Service Reverse Proxy Addresses list cannot have more than 255 entries.");

                var webListeners = new WebListeners(
                    request.TryQueryOrFormArray("webServiceLocalAddresses", IPAddress.Parse, out IPAddress[] webServiceLocalAddresses)
                        ? NormalizeWebLocalAddresses(webServiceLocalAddresses) : null,
                    request.TryGetQueryOrForm("webServiceHttpPort", int.Parse, out int webServiceHttpPort) ? webServiceHttpPort : null,
                    request.TryGetQueryOrForm("webServiceTlsPort", int.Parse, out int webServiceTlsPort) ? webServiceTlsPort : null,
                    request.TryGetQueryOrForm("webServiceEnableTls", bool.Parse, out bool webServiceEnableTls) ? webServiceEnableTls : null,
                    request.TryGetQueryOrForm("webServiceEnableHttp3", bool.Parse, out bool webServiceEnableHttp3) ? webServiceEnableHttp3 : null,
                    request.TryGetQueryOrForm("webServiceHttpToTlsRedirect", bool.Parse, out bool webServiceHttpToTlsRedirect) ? webServiceHttpToTlsRedirect : null,
                    ReadWebUnixSocket("webServiceEnableHttpUnixSocket", "webServiceHttpUnixSocket"),
                    ReadWebUnixSocket("webServiceEnableTlsUnixSocket", "webServiceTlsUnixSocket"));

                WebUnixSocket ReadWebUnixSocket(string enabledName, string pathName)
                {
                    return new WebUnixSocket(
                        request.TryGetQueryOrForm(enabledName, bool.Parse, out bool enabled) ? enabled : null,
                        request.TryGetQueryOrForm(pathName, out string path) ? string.IsNullOrWhiteSpace(path) ? "" : path : null);
                }

                var webHeaders = new WebLiveSettings(
                    request.TryGetQueryOrForm("webServiceRealIpHeader", out string realIpHeader) ? NormalizeWebHeader(realIpHeader, realIp: true) : null,
                    request.TryGetQueryOrForm("webServiceCspFrameAncestorsHeader", out string frameAncestors) ? NormalizeWebHeader(frameAncestors, realIp: false) : null, reverseProxyAcl, webListeners);
                _dnsWebService.CheckManifestWebLiveSettings(webHeaders);
                bool proposedSelfSigned = request.GetQueryOrForm("webServiceUseSelfSignedTlsCertificate", bool.Parse, _dnsWebService._webServiceUseSelfSignedTlsCertificate);
                string proposedCertificatePath = request.QueryOrForm("webServiceTlsCertificatePath");
                string proposedCertificatePassword = proposedCertificatePath is null ? _dnsWebService._webServiceTlsCertificatePassword :
                    proposedCertificatePath.Length == 0 ? null : request.QueryOrForm("webServiceTlsCertificatePassword");
                if (proposedCertificatePath != "" && proposedCertificatePassword is null or "************")
                    proposedCertificatePassword = _dnsWebService._webServiceTlsCertificatePassword;
                _dnsWebService.CheckManagedWebCertificate(proposedSelfSigned,
                    proposedCertificatePath ?? _dnsWebService._webServiceTlsCertificatePath, proposedCertificatePassword);

                if ((_dnsWebService._managedWebListeners & (ManagedWebTlsEnabled | ManagedWebHttp3 | ManagedWebRedirect | ManagedWebTlsSocketEnabled)) != 0)
                {
                    bool selfSigned = request.GetQueryOrForm("webServiceUseSelfSignedTlsCertificate", bool.Parse, _dnsWebService._webServiceUseSelfSignedTlsCertificate);
                    string certificatePath = request.QueryOrForm("webServiceTlsCertificatePath") ?? _dnsWebService._webServiceTlsCertificatePath;
                    _dnsWebService.CheckManifestWebTlsDependencies(webListeners.TlsEnabled ?? _dnsWebService._webServiceEnableTls,
                        selfSigned || !string.IsNullOrWhiteSpace(certificatePath));
                }

                (LoggingType? destination, bool? noStackTrace, int? retentionDays, bool? useLocalTime) = ReadLoggingFields(request);
                request.TryGetQueryOrForm("logFolder", out string logFolder);
                _dnsWebService._log.CheckManifestOwnership(destination, noStackTrace, retentionDays, useLocalTime, logFolder);
                string requestedDomain = null;
                if (request.TryGetQueryOrForm("dnsServerDomain", out string dnsServerDomain))
                {
                    requestedDomain = DnsServer.NormalizeServerDomain(dnsServerDomain);
                    _dnsWebService._dnsServer.CheckManifestServerDomain(requestedDomain);
                }
                IReadOnlyList<IPEndPoint> requestedDnsEndpoints = null;
                if (request.TryQueryOrFormArray("dnsServerLocalEndPoints", InterfaceEndPoint.Parse, out IPEndPoint[] dnsServerLocalEndPoints))
                {
                    requestedDnsEndpoints = DnsServer.NormalizeLocalEndPoints(dnsServerLocalEndPoints, useDefaultPort: true);
                    _dnsWebService._dnsServer.CheckManifestLocalEndPoints(requestedDnsEndpoints);
                }

                request.TryQueryOrFormArray("dnsServerIPv4SourceAddresses", NetworkAddress.Parse, out NetworkAddress[] ipv4SourceAddresses);
                request.TryQueryOrFormArray("dnsServerIPv6SourceAddresses", NetworkAddress.Parse, out NetworkAddress[] ipv6SourceAddresses);
                var sourceNetworks = new DnsServer.SourceNetworks(ipv4SourceAddresses, ipv6SourceAddresses);
                _dnsWebService._dnsServer.CheckManifestSourceNetworks(sourceNetworks);

                string defaultResponsiblePerson = request.QueryOrForm("defaultResponsiblePerson");
                request.TryQueryOrFormArray("zoneTransferAllowedNetworks", NetworkAddress.Parse, out NetworkAddress[] zoneTransferAllowedNetworks);
                request.TryQueryOrFormArray("notifyAllowedNetworks", NetworkAddress.Parse, out NetworkAddress[] notifyAllowedNetworks);
                if (zoneTransferAllowedNetworks?.Length > byte.MaxValue || notifyAllowedNetworks?.Length > byte.MaxValue)
                    throw new ArgumentException("Authoritative network allowlists cannot have more than 255 entries.");

                var authoritativeDefaults = new DnsServer.AuthoritativeDefaults(
                    request.TryGetQueryOrForm("defaultRecordTtl", ZoneFile.ParseTtl, out uint defaultRecordTtl) ? defaultRecordTtl : null,
                    request.TryGetQueryOrForm("defaultNsRecordTtl", ZoneFile.ParseTtl, out uint defaultNsRecordTtl) ? defaultNsRecordTtl : null,
                    request.TryGetQueryOrForm("defaultSoaRecordTtl", ZoneFile.ParseTtl, out uint defaultSoaRecordTtl) ? defaultSoaRecordTtl : null,
                    request.TryGetQueryOrForm("useSoaSerialDateScheme", bool.Parse, out bool useSoaSerialDateScheme) ? useSoaSerialDateScheme : null,
                    request.TryGetQueryOrForm("minSoaRefresh", ZoneFile.ParseTtl, out uint minSoaRefresh) ? minSoaRefresh : null,
                    request.TryGetQueryOrForm("minSoaRetry", ZoneFile.ParseTtl, out uint minSoaRetry) ? minSoaRetry : null,
                    defaultResponsiblePerson is null ? null : DnsServer.NormalizeDefaultResponsiblePerson(defaultResponsiblePerson),
                    zoneTransferAllowedNetworks, notifyAllowedNetworks);
                _dnsWebService._dnsServer.CheckManifestAuthoritativeDefaults(authoritativeDefaults);
                bool hasBlockListSources = request.TryQueryOrFormArray("blockListUrls", out string[] blockListUrls);
                if (hasBlockListSources)
                {
                    IReadOnlyList<string> sources = BlockListZoneManager.NormalizeBlockListUrls(blockListUrls);
                    _dnsWebService._dnsServer.BlockListZoneManager.CheckManifestSources(sources);
                }
                bool hasBlockListInterval = request.TryGetQueryOrForm("blockListUpdateIntervalHours", int.Parse, out int blockListUpdateIntervalHours);
                if (hasBlockListInterval)
                    _dnsWebService._dnsServer.BlockListZoneManager.CheckManifestUpdateInterval(blockListUpdateIntervalHours);
                bool hasUpdateChecks = request.TryGetQueryOrForm("dnsServerEnableCheckForUpdate", bool.Parse, out bool dnsServerEnableCheckForUpdate);
                bool hasUdpPayload = request.TryGetQueryOrForm("udpPayloadSize", ushort.Parse, out ushort udpPayloadSize);
                bool hasDnssecValidation = request.TryGetQueryOrForm("dnssecValidation", bool.Parse, out bool dnssecValidation);
                _dnsWebService._dnsServer.CheckManifestResolverSettings(new DnsServer.ResolverSettings(
                    hasUpdateChecks ? dnsServerEnableCheckForUpdate : null, hasUdpPayload ? udpPayloadSize : null,
                    hasDnssecValidation ? dnssecValidation : null));

                IPv6Mode? requestedIpv6Mode = null;
                if (request.TryGetQueryOrFormEnum("ipv6Mode", out IPv6Mode ipv6Mode))
                    requestedIpv6Mode = ipv6Mode;
                else if (request.TryGetQueryOrForm("preferIPv6", bool.Parse, out bool preferIPv6))
                    requestedIpv6Mode = preferIPv6 ? IPv6Mode.Preferred : IPv6Mode.Disabled;
                bool hasUdpPool = request.TryGetQueryOrForm("enableUdpSocketPool", bool.Parse, out bool enableUdpSocketPool);
                bool hasExcludedPorts = request.TryQueryOrFormArray("socketPoolExcludedPorts", ushort.Parse, out ushort[] socketPoolExcludedPorts);
                _dnsWebService._dnsServer.CheckManifestOutboundSockets(new DnsServer.OutboundSocketSettings(
                    requestedIpv6Mode, hasUdpPool ? enableUdpSocketPool : null, hasExcludedPorts ? socketPoolExcludedPorts : null));

                bool hasAppAutoUpdate = request.TryGetQueryOrForm("dnsAppsEnableAutomaticUpdate", bool.Parse, out bool dnsAppsEnableAutomaticUpdate);
                if (hasAppAutoUpdate)
                    _dnsWebService._dnsServer.CheckManifestAppAutoUpdate(dnsAppsEnableAutomaticUpdate);

                string ipv4Override = request.QueryOrForm("eDnsClientSubnetIpv4Override");
                string ipv6Override = request.QueryOrForm("eDnsClientSubnetIpv6Override");
                var requestedSubnet = new DnsServer.ClientSubnetSettings(
                    request.TryGetQueryOrForm("eDnsClientSubnet", bool.Parse, out bool ecsEnabled) ? ecsEnabled : null,
                    request.TryGetQueryOrForm("eDnsClientSubnetIPv4PrefixLength", byte.Parse, out byte ecsIpv4) ? ecsIpv4 : null,
                    request.TryGetQueryOrForm("eDnsClientSubnetIPv6PrefixLength", byte.Parse, out byte ecsIpv6) ? ecsIpv6 : null,
                    ipv4Override is not null, ConfigurationManifest.ReadNetwork(string.IsNullOrEmpty(ipv4Override) ? null : ipv4Override,
                        "/dns/clientSubnet/ipv4Override", AddressFamily.InterNetwork),
                    ipv6Override is not null, ConfigurationManifest.ReadNetwork(string.IsNullOrEmpty(ipv6Override) ? null : ipv6Override,
                        "/dns/clientSubnet/ipv6Override", AddressFamily.InterNetworkV6));
                DnsServer.ClientSubnetSettings subnet = _dnsWebService._dnsServer.CheckManifestClientSubnet(
                    _dnsWebService._dnsServer.NormalizeClientSubnetSettings(requestedSubnet));

                bool hasRecursionMode = request.TryGetQueryOrFormEnum("recursion", out DnsServerRecursion recursion);
                bool hasRecursionAcl = request.TryQueryOrFormArray("recursionNetworkACL", NetworkAccessControl.Parse, out NetworkAccessControl[] recursionNetworkACL);
                _dnsWebService._dnsServer.CheckManifestRecursionPolicy(new DnsServer.RecursionPolicy(
                    hasRecursionMode ? recursion : null, hasRecursionAcl ? recursionNetworkACL : null));

                DnsServer.RecursionPolicy resolverOptions = _dnsWebService._dnsServer.CheckManifestResolverOptions(new DnsServer.RecursionPolicy(
                    null, null,
                    request.TryGetQueryOrForm("randomizeName", bool.Parse, out bool randomizeName) ? randomizeName : null,
                    request.TryGetQueryOrForm("qnameMinimization", bool.Parse, out bool qnameMinimization) ? qnameMinimization : null,
                    request.TryGetQueryOrForm("locallyServedDnsZones", bool.Parse, out bool locallyServedDnsZones) ? locallyServedDnsZones : null,
                    request.TryGetQueryOrForm("resolverRetries", int.Parse, out int resolverRetries) ? resolverRetries : null,
                    request.TryGetQueryOrForm("resolverTimeout", int.Parse, out int resolverTimeout) ? resolverTimeout : null,
                    request.TryGetQueryOrForm("resolverConcurrency", int.Parse, out int resolverConcurrency) ? resolverConcurrency : null,
                    request.TryGetQueryOrForm("resolverMaxStackCount", int.Parse, out int resolverMaxStackCount) ? resolverMaxStackCount : null));

                var requestedCache = new DnsServer.CachePolicy(
                    request.TryGetQueryOrForm("saveCache", bool.Parse, out bool saveCache) ? saveCache : null,
                    request.TryGetQueryOrForm("serveStale", bool.Parse, out bool serveStale) ? serveStale : null,
                    request.TryGetQueryOrForm("serveStaleTtl", ZoneFile.ParseTtl, out uint serveStaleTtl) ? serveStaleTtl : null,
                    request.TryGetQueryOrForm("serveStaleAnswerTtl", ZoneFile.ParseTtl, out uint serveStaleAnswerTtl) ? serveStaleAnswerTtl : null,
                    request.TryGetQueryOrForm("serveStaleResetTtl", ZoneFile.ParseTtl, out uint serveStaleResetTtl) ? serveStaleResetTtl : null,
                    request.TryGetQueryOrForm("serveStaleMaxWaitTime", int.Parse, out int serveStaleMaxWaitTime) ? serveStaleMaxWaitTime : null,
                    request.TryGetQueryOrForm("cacheMaximumEntries", long.Parse, out long cacheMaximumEntries) ? cacheMaximumEntries : null,
                    request.TryGetQueryOrForm("cacheMinimumRecordTtl", ZoneFile.ParseTtl, out uint cacheMinimumRecordTtl) ? cacheMinimumRecordTtl : null,
                    request.TryGetQueryOrForm("cacheMaximumRecordTtl", ZoneFile.ParseTtl, out uint cacheMaximumRecordTtl) ? cacheMaximumRecordTtl : null,
                    request.TryGetQueryOrForm("cacheNegativeRecordTtl", ZoneFile.ParseTtl, out uint cacheNegativeRecordTtl) ? cacheNegativeRecordTtl : null,
                    request.TryGetQueryOrForm("cacheFailureRecordTtl", ZoneFile.ParseTtl, out uint cacheFailureRecordTtl) ? cacheFailureRecordTtl : null,
                    request.TryGetQueryOrForm("enableCachePrefetch", bool.Parse, out bool enableCachePrefetch) ? enableCachePrefetch : null,
                    request.TryGetQueryOrForm("cachePrefetchEligibility", int.Parse, out int cachePrefetchEligibility) ? cachePrefetchEligibility : null,
                    request.TryGetQueryOrForm("cachePrefetchTrigger", int.Parse, out int cachePrefetchTrigger) ? cachePrefetchTrigger : null);
                DnsServer.CachePolicy cachePolicy = _dnsWebService._dnsServer.CheckManifestCachePolicy(
                    _dnsWebService._dnsServer.NormalizeCachePrefetch(requestedCache));

                IPAddress[] blockingAddresses = null;
                if (request.TryQueryOrFormArray("customBlockingAddresses", out string[] customBlockingAddresses))
                {
                    var addresses = new List<IPAddress>();
                    foreach (string address in customBlockingAddresses)
                    {
                        if (IPAddress.TryParse(address, out IPAddress parsed))
                            addresses.Add(parsed);
                    }
                    blockingAddresses = DnsServer.NormalizeBlockingAddresses(addresses);
                }

                DnsServer.BlockingPolicy blockingPolicy = _dnsWebService._dnsServer.CheckManifestBlockingPolicy(new DnsServer.BlockingPolicy(
                    request.TryGetQueryOrForm("enableBlocking", bool.Parse, out bool enableBlocking) ? enableBlocking : null,
                    request.TryGetQueryOrForm("allowTxtBlockingReport", bool.Parse, out bool allowTxtBlockingReport) ? allowTxtBlockingReport : null,
                    request.TryQueryOrFormArray("blockingBypassList", NetworkAddress.Parse, out NetworkAddress[] blockingBypassList) ? blockingBypassList : null,
                    request.TryGetQueryOrFormEnum("blockingType", out DnsServerBlockingType blockingType) ? blockingType : null,
                    request.TryGetQueryOrForm("blockingAnswerTtl", ZoneFile.ParseTtl, out uint blockingAnswerTtl) ? blockingAnswerTtl : null,
                    blockingAddresses));

                if (!request.TryQueryOrFormArray("dnsReverseProxyNetworkACL", NetworkAccessControl.Parse, out NetworkAccessControl[] dnsProxyAcl))
                    request.TryQueryOrFormArray("reverseProxyNetworkACL", NetworkAccessControl.Parse, out dnsProxyAcl);
                if (dnsProxyAcl?.Length > byte.MaxValue)
                    throw new ArgumentOutOfRangeException("dnsReverseProxyNetworkACL", "The DNS reverse proxy ACL cannot have more than 255 entries.");

                var dnsListenerPolicy = _dnsWebService._dnsServer.CheckManifestDnsListenerPolicy(new DnsServer.DnsListenerPolicy(
                    request.TryGetQueryOrForm("enableEDnsClientSubnetSourceAddress", bool.Parse, out bool subnetAsSource) ? subnetAsSource : null,
                    request.TryGetQueryOrForm("enableDnsOverHttpHelpRedirect", bool.Parse, out bool helpRedirect) ? helpRedirect : null,
                    request.TryGetQueryOrForm("dnsOverHttpRealIpHeader", out string dnsRealIpHeader) ? DnsServer.NormalizeDnsRealIpHeader(dnsRealIpHeader) : null,
                    dnsProxyAcl));

                var dnsBindings = new DnsServer.DnsBindings(
                    request.TryGetQueryOrForm("enableDnsOverUdpProxy", bool.Parse, out bool udpProxyEnabled) ? udpProxyEnabled : null,
                    request.TryGetQueryOrForm("dnsOverUdpProxyPort", int.Parse, out int udpProxyPort) ? udpProxyPort : null,
                    request.TryGetQueryOrForm("enableDnsOverTcpProxy", bool.Parse, out bool tcpProxyEnabled) ? tcpProxyEnabled : null,
                    request.TryGetQueryOrForm("dnsOverTcpProxyPort", int.Parse, out int tcpProxyPort) ? tcpProxyPort : null,
                    request.TryGetQueryOrForm("enableDnsOverHttp", bool.Parse, out bool httpEnabled) ? httpEnabled : null,
                    request.TryGetQueryOrForm("dnsOverHttpPort", int.Parse, out int httpPort) ? httpPort : null,
                    request.TryGetQueryOrForm("enableDnsOverTls", bool.Parse, out bool tlsEnabled) ? tlsEnabled : null,
                    request.TryGetQueryOrForm("dnsOverTlsPort", int.Parse, out int tlsPort) ? tlsPort : null,
                    request.TryGetQueryOrForm("enableDnsOverHttps", bool.Parse, out bool httpsEnabled) ? httpsEnabled : null,
                    request.TryGetQueryOrForm("dnsOverHttpsPort", int.Parse, out int httpsPort) ? httpsPort : null,
                    request.TryGetQueryOrForm("enableDnsOverQuic", bool.Parse, out bool quicEnabled) ? quicEnabled : null,
                    request.TryGetQueryOrForm("dnsOverQuicPort", int.Parse, out int quicPort) ? quicPort : null,
                    request.TryGetQueryOrForm("enableDnsOverHttp3", bool.Parse, out bool http3Enabled) ? http3Enabled : null,
                    request.TryGetQueryOrForm("enableDnsOverHttpUnixSocket", bool.Parse, out bool httpSocketEnabled) ? httpSocketEnabled : null,
                    request.TryQueryOrForm("dnsOverHttpUnixSocket", out string httpSocketPath) ? string.IsNullOrWhiteSpace(httpSocketPath) ? "" : httpSocketPath : null,
                    request.TryGetQueryOrForm("enableDnsOverHttpsUnixSocket", bool.Parse, out bool httpsSocketEnabled) ? httpsSocketEnabled : null,
                    request.TryQueryOrForm("dnsOverHttpsUnixSocket", out string httpsSocketPath) ? string.IsNullOrWhiteSpace(httpsSocketPath) ? "" : httpsSocketPath : null);
                _dnsWebService._dnsServer.CheckManagedDnsBindings(dnsBindings);
                string dnsTlsCertificatePath = request.QueryOrForm("dnsTlsCertificatePath");
                string dnsTlsCertificatePassword = request.QueryOrForm("dnsTlsCertificatePassword");
                if (dnsTlsCertificatePassword is null or "************")
                    dnsTlsCertificatePassword = _dnsWebService._dnsServer.DnsTlsCertificatePassword;
                if (dnsTlsCertificatePath is not null)
                    _dnsWebService._dnsServer.CheckManagedDnsCertificate(dnsTlsCertificatePath, dnsTlsCertificatePath.Length == 0 ? null : dnsTlsCertificatePassword);
                _dnsWebService._dnsServer.CheckManagedDnsBindingDependencies(dnsBindings, removingCertificate: dnsTlsCertificatePath == "");

                Dictionary<string, TsigKey> requestedTsigKeys = null;
                if (request.TryQueryOrFormArray("tsigKeys",
                    item => ReadTsigKey(item.GetProperty("keyName").GetString(), item.GetProperty("sharedSecret").GetString(),
                        item.GetProperty("algorithmName").GetString()),
                    row => ReadTsigKey(row[0], row[1], row[2]), 3, out TsigKey[] tsigKeys, '|'))
                {
                    if (tsigKeys.Length > byte.MaxValue)
                        throw new InvalidDataException("/dns/tsigKeys: At most 255 TSIG keys are supported.");
                    requestedTsigKeys = tsigKeys.ToDictionary(key => key.KeyName, StringComparer.OrdinalIgnoreCase);
                    if (_dnsWebService._clusterManager.ClusterInitialized &&
                        !requestedTsigKeys.ContainsKey(ConfigurationTsig.GetCatalogKey(_dnsWebService._clusterManager.ClusterDomain)))
                        throw new DnsWebServiceException("Cannot remove the TSIG key for the Cluster Catalog zone.");
                    _dnsWebService._dnsServer.CheckManagedTsigKeys(requestedTsigKeys);
                }

                static TsigKey ReadTsigKey(string name, string secret, string algorithm)
                {
                    name = name.TrimEnd('.').ToLowerInvariant();
                    if (DnsClient.IsDomainNameUnicode(name))
                        name = DnsClient.ConvertDomainNameToAscii(name);
                    DnsClient.IsDomainNameValid(name, true);
                    return secret.Length == 0 ? new TsigKey(name, algorithm) : new TsigKey(name, secret, algorithm);
                }

                bool hasProxyType = request.TryGetQueryOrFormEnum("proxyType", out NetProxyType proxyType);
                NetProxy requestedProxy = null;
                bool hasProxyBypass = false;
                if (hasProxyType)
                {
                    if (proxyType != NetProxyType.None)
                    {
                        NetworkCredential credential = null;
                        if (request.TryGetQueryOrForm("proxyUsername", out string username))
                        {
                            if (Encoding.UTF8.GetByteCount(username) > byte.MaxValue)
                                throw new ArgumentException("Proxy username cannot exceed 255 UTF-8 bytes.", "proxyUsername");
                            string password = request.QueryOrForm("proxyPassword");
                            if (password is not null && Encoding.UTF8.GetByteCount(password) > byte.MaxValue)
                                throw new ArgumentException("Proxy password cannot exceed 255 UTF-8 bytes.", "proxyPassword");
                            credential = new NetworkCredential(username, password);
                        }
                        requestedProxy = NetProxy.CreateProxy(proxyType, request.QueryOrForm("proxyAddress"),
                            int.Parse(request.QueryOrForm("proxyPort")), credential);
                        hasProxyBypass = request.TryQueryOrFormArray("proxyBypass", value => new NetProxyBypassItem(value), out NetProxyBypassItem[] bypass);
                        if (hasProxyBypass)
                            requestedProxy.BypassList = bypass;
                    }
                    _dnsWebService._dnsServer.CheckManifestProxy(requestedProxy);
                }

                NetProxyType effectiveProxyType = hasProxyType ? proxyType : _dnsWebService._dnsServer.Proxy?.Type ?? NetProxyType.None;
                bool hasForwarders = request.TryQueryOrFormArray("forwarders", NameServerAddress.Parse, out NameServerAddress[] forwarders);
                DnsTransportProtocol forwarderProtocol = DnsTransportProtocol.Udp;
                if (hasForwarders && forwarders.Length > 0)
                {
                    forwarderProtocol = request.GetQueryOrFormEnum("forwarderProtocol", DnsTransportProtocol.Udp);
                    if (forwarderProtocol == DnsTransportProtocol.HttpsJson)
                        forwarderProtocol = DnsTransportProtocol.Https;
                    for (int i = 0; i < forwarders.Length; i++)
                        forwarders[i] = forwarders[i].Clone(forwarderProtocol);
                }

                DnsServer.ValidateForwardingServers(hasForwarders ? forwarders : hasProxyType ? _dnsWebService._dnsServer.Forwarders : null, effectiveProxyType);
                DnsServer.ForwardingPolicy forwardingPolicy = _dnsWebService._dnsServer.CheckManifestForwarding(new DnsServer.ForwardingPolicy(
                    hasForwarders ? forwarders : null,
                    request.TryGetQueryOrForm("concurrentForwarding", bool.Parse, out bool concurrentForwarding) ? concurrentForwarding : null,
                    request.TryGetQueryOrForm("forwarderRetries", int.Parse, out int forwarderRetries) ? forwarderRetries : null,
                    request.TryGetQueryOrForm("forwarderTimeout", int.Parse, out int forwarderTimeout) ? forwarderTimeout : null,
                    request.TryGetQueryOrForm("forwarderConcurrency", int.Parse, out int forwarderConcurrency) ? forwarderConcurrency : null));

                DnsServer.RateLimitPolicy rateLimits = _dnsWebService._dnsServer.CheckManifestRateLimits(new DnsServer.RateLimitPolicy(
                    ReadRateLimitTable(request, "qpmPrefixLimitsIPv4", "ipv4"), ReadRateLimitTable(request, "qpmPrefixLimitsIPv6", "ipv6"),
                    request.TryGetQueryOrForm("qpmLimitSampleMinutes", int.Parse, out int sampleMinutes) ? sampleMinutes : null,
                    request.TryGetQueryOrForm("qpmLimitUdpTruncationPercentage", int.Parse, out int truncation) ? truncation : null,
                    request.TryQueryOrFormArray("qpmLimitBypassList", NetworkAddress.Parse, out NetworkAddress[] rateLimitBypass) ? rateLimitBypass : null));

                DnsServer.DnsTuning dnsTuning = _dnsWebService._dnsServer.CheckManifestDnsTuning(new DnsServer.DnsTuning(
                    request.TryGetQueryOrForm("clientTimeout", int.Parse, out int clientTimeout) ? clientTimeout : null,
                    request.TryGetQueryOrForm("tcpSendTimeout", int.Parse, out int tcpSendTimeout) ? tcpSendTimeout : null,
                    request.TryGetQueryOrForm("tcpReceiveTimeout", int.Parse, out int tcpReceiveTimeout) ? tcpReceiveTimeout : null,
                    request.TryGetQueryOrForm("quicIdleTimeout", int.Parse, out int quicIdleTimeout) ? quicIdleTimeout : null,
                    request.TryGetQueryOrForm("quicMaxInboundStreams", int.Parse, out int quicMaxInboundStreams) ? quicMaxInboundStreams : null,
                    request.TryGetQueryOrForm("listenBacklog", int.Parse, out int listenBacklog) ? listenBacklog : null,
                    request.TryGetQueryOrForm("udpSendBufferSizeKB", int.Parse, out int udpSendBufferSizeKB) ? udpSendBufferSizeKB : null,
                    request.TryGetQueryOrForm("udpReceiveBufferSizeKB", int.Parse, out int udpReceiveBufferSizeKB) ? udpReceiveBufferSizeKB : null,
                    request.TryGetQueryOrForm("maxConcurrentResolutionsPerCore", ushort.Parse, out ushort maxConcurrentResolutionsPerCore) ? maxConcurrentResolutionsPerCore : null));

                bool hasIgnoreResolverLogs = request.TryGetQueryOrForm("ignoreResolverLogs", bool.Parse, out bool ignoreResolverLogs);
                bool hasLogQueries = request.TryGetQueryOrForm("logQueries", bool.Parse, out bool logQueries);
                _dnsWebService._dnsServer.CheckManifestDnsLogging(new DnsServer.DnsLoggingSettings(
                    hasIgnoreResolverLogs ? ignoreResolverLogs : null, hasLogQueries ? logQueries : null));

                bool hasInMemoryStats = request.TryGetQueryOrForm("enableInMemoryStats", bool.Parse, out bool enableInMemoryStats);
                bool hasStatRetention = request.TryGetQueryOrForm("maxStatFileDays", int.Parse, out int maxStatFileDays);
                _dnsWebService._dnsServer.CheckManifestStatistics(new DnsServer.StatisticsSettings(
                    hasInMemoryStats ? enableInMemoryStats : null, hasStatRetention ? maxStatFileDays : null));

                try
                {
                    try
                    {
                        #region general

                        if (requestedDomain is not null && !_dnsWebService._dnsServer.ManifestOwnsServerDomain &&
                            !_dnsWebService._dnsServer.ServerDomain.Equals(requestedDomain, StringComparison.OrdinalIgnoreCase))
                        {
                            if (_dnsWebService._clusterManager.ClusterInitialized)
                                DnsServer.CheckClusterServerDomain(requestedDomain, _dnsWebService._clusterManager.ClusterDomain);

                            _dnsWebService._dnsServer.ServerDomain = requestedDomain;
                            serverDomainChanged = true;
                        }

                        if ((requestedDnsEndpoints is not null) && !_dnsWebService._dnsServer.ManifestOwnsLocalEndPoints)
                        {
                            if (!_dnsWebService._dnsServer.LocalEndPoints.HasSameItems(requestedDnsEndpoints))
                                restartDnsService = true;

                            _dnsWebService._dnsServer.LocalEndPoints = requestedDnsEndpoints;
                        }

                        DnsServer.SetSourceNetworks(sourceNetworks);

                        _dnsWebService._dnsServer.SetAuthoritativeDefaults(authoritativeDefaults);
                        if (authoritativeDefaults.Record.HasValue)
                            clusterParameters.Add("defaultRecordTtl", defaultRecordTtl.ToString());
                        if (authoritativeDefaults.Ns.HasValue)
                            clusterParameters.Add("defaultNsRecordTtl", defaultNsRecordTtl.ToString());
                        if (authoritativeDefaults.Soa.HasValue)
                            clusterParameters.Add("defaultSoaRecordTtl", defaultSoaRecordTtl.ToString());

                        if (defaultResponsiblePerson is not null)
                            clusterParameters.Add("defaultResponsiblePerson", defaultResponsiblePerson);

                        if (authoritativeDefaults.SerialDateScheme.HasValue)
                            clusterParameters.Add("useSoaSerialDateScheme", useSoaSerialDateScheme.ToString());
                        if (authoritativeDefaults.MinRefresh.HasValue)
                            clusterParameters.Add("minSoaRefresh", minSoaRefresh.ToString());
                        if (authoritativeDefaults.MinRetry.HasValue)
                            clusterParameters.Add("minSoaRetry", minSoaRetry.ToString());

                        if (zoneTransferAllowedNetworks is not null)
                            clusterParameters.Add("zoneTransferAllowedNetworks", zoneTransferAllowedNetworks.Join());
                        if (notifyAllowedNetworks is not null)
                            clusterParameters.Add("notifyAllowedNetworks", notifyAllowedNetworks.Join());

                        if (hasUpdateChecks)
                        {
                            _dnsWebService._dnsServer.EnableCheckForUpdate = dnsServerEnableCheckForUpdate;

                            clusterParameters.Add("dnsServerEnableCheckForUpdate", dnsServerEnableCheckForUpdate.ToString());
                        }

                        if (hasAppAutoUpdate && !_dnsWebService._dnsServer.ManifestOwnsAppAutoUpdate)
                        {
                            _dnsWebService._dnsServer.DnsApplicationManager.EnableAutomaticUpdate = dnsAppsEnableAutomaticUpdate;

                            clusterParameters.Add("dnsAppsEnableAutomaticUpdate", dnsAppsEnableAutomaticUpdate.ToString());
                        }

                        if (requestedIpv6Mode.HasValue && !_dnsWebService._dnsServer.ManifestOwnsIpv6Mode)
                            _dnsWebService._dnsServer.IPv6Mode = requestedIpv6Mode.Value;

                        if (hasUdpPool && !_dnsWebService._dnsServer.ManifestOwnsUdpSocketPool)
                            _dnsWebService._dnsServer.EnableUdpSocketPool = enableUdpSocketPool;

                        if (hasExcludedPorts && !_dnsWebService._dnsServer.ManifestOwnsSocketPoolExcludedPorts)
                            UdpClientConnection.SocketPoolExcludedPorts = socketPoolExcludedPorts;

                        if (hasUdpPayload)
                        {
                            _dnsWebService._dnsServer.UdpPayloadSize = udpPayloadSize;

                            clusterParameters.Add("udpPayloadSize", udpPayloadSize.ToString());
                        }

                        if (hasDnssecValidation)
                        {
                            _dnsWebService._dnsServer.DnssecValidation = dnssecValidation;

                            clusterParameters.Add("dnssecValidation", dnssecValidation.ToString());
                        }

                        _dnsWebService._dnsServer.SetClientSubnetSettings(subnet);
                        if (subnet.Enabled.HasValue)
                            clusterParameters.Add("eDnsClientSubnet", subnet.Enabled.Value.ToString());
                        if (subnet.Ipv4Prefix.HasValue)
                            clusterParameters.Add("eDnsClientSubnetIPv4PrefixLength", subnet.Ipv4Prefix.Value.ToString());
                        if (subnet.Ipv6Prefix.HasValue)
                            clusterParameters.Add("eDnsClientSubnetIPv6PrefixLength", subnet.Ipv6Prefix.Value.ToString());
                        if (subnet.HasIpv4Override)
                            clusterParameters.Add("eDnsClientSubnetIpv4Override", ipv4Override);
                        if (subnet.HasIpv6Override)
                            clusterParameters.Add("eDnsClientSubnetIpv6Override", ipv6Override);

                        _dnsWebService._dnsServer.SetRateLimitPolicy(rateLimits);
                        if (rateLimits.Ipv4 is not null)
                            clusterParameters.Add("qpmPrefixLimitsIPv4", FormatRateLimitTable(rateLimits.Ipv4));
                        if (rateLimits.Ipv6 is not null)
                            clusterParameters.Add("qpmPrefixLimitsIPv6", FormatRateLimitTable(rateLimits.Ipv6));
                        if (rateLimits.SampleMinutes.HasValue)
                            clusterParameters.Add("qpmLimitSampleMinutes", rateLimits.SampleMinutes.Value.ToString());
                        if (rateLimits.UdpTruncationPercentage.HasValue)
                            clusterParameters.Add("qpmLimitUdpTruncationPercentage", rateLimits.UdpTruncationPercentage.Value.ToString());
                        if (rateLimits.BypassNetworks is not null)
                            clusterParameters.Add("qpmLimitBypassList", rateLimits.BypassNetworks.Join());

                        restartDnsService |= _dnsWebService._dnsServer.DnsTuningRequiresRestart(dnsTuning);
                        _dnsWebService._dnsServer.SetDnsTuning(dnsTuning);
                        if (dnsTuning.ClientTimeout.HasValue)
                            clusterParameters.Add("clientTimeout", dnsTuning.ClientTimeout.Value.ToString());
                        if (dnsTuning.TcpSendTimeout.HasValue)
                            clusterParameters.Add("tcpSendTimeout", dnsTuning.TcpSendTimeout.Value.ToString());
                        if (dnsTuning.TcpReceiveTimeout.HasValue)
                            clusterParameters.Add("tcpReceiveTimeout", dnsTuning.TcpReceiveTimeout.Value.ToString());
                        if (dnsTuning.QuicIdleTimeout.HasValue)
                            clusterParameters.Add("quicIdleTimeout", dnsTuning.QuicIdleTimeout.Value.ToString());
                        if (dnsTuning.QuicMaxInboundStreams.HasValue)
                            clusterParameters.Add("quicMaxInboundStreams", dnsTuning.QuicMaxInboundStreams.Value.ToString());
                        if (dnsTuning.ListenBacklog.HasValue)
                            clusterParameters.Add("listenBacklog", dnsTuning.ListenBacklog.Value.ToString());
                        if (dnsTuning.UdpSendBufferSizeKB.HasValue)
                            clusterParameters.Add("udpSendBufferSizeKB", dnsTuning.UdpSendBufferSizeKB.Value.ToString());
                        if (dnsTuning.UdpReceiveBufferSizeKB.HasValue)
                            clusterParameters.Add("udpReceiveBufferSizeKB", dnsTuning.UdpReceiveBufferSizeKB.Value.ToString());
                        if (dnsTuning.MaxConcurrentResolutionsPerCore.HasValue)
                            clusterParameters.Add("maxConcurrentResolutionsPerCore", dnsTuning.MaxConcurrentResolutionsPerCore.Value.ToString());

                        #endregion

                        #region web service

                        var editableListeners = new WebListeners(
                            (_dnsWebService._managedWebListeners & ManagedWebAddresses) == 0 ? webListeners.Addresses : null,
                            (_dnsWebService._managedWebListeners & ManagedWebHttpPort) == 0 ? webListeners.HttpPort : null,
                            (_dnsWebService._managedWebListeners & ManagedWebTlsPort) == 0 ? webListeners.TlsPort : null);
                        webServiceLocalAddressesChanged = editableListeners.Addresses is not null &&
                            !_dnsWebService._webServiceLocalAddresses.HasSameItems(editableListeners.Addresses);
                        restartWebService |= _dnsWebService.StageWebListeners(editableListeners);

                        if (webListeners.HttpSocket.Enabled is bool webServiceEnableHttpUnixSocket &&
                            (_dnsWebService._managedWebListeners & ManagedWebHttpSocketEnabled) == 0)
                        {
                            if (_dnsWebService._webServiceEnableHttpUnixSocket != webServiceEnableHttpUnixSocket)
                            {
                                if (webServiceEnableHttpUnixSocket)
                                {
                                    if (!DnsServer.IsUnixDomainSocketSupported())
                                        throw new ArgumentException("Unix Domain Sockets (UDS) are supported only on Linux, Windows 10 (build 17063 and later), and Windows Server 2019 (update 1809 and later).", "webServiceEnableHttpUnixSocket");
                                }

                                _dnsWebService._webServiceEnableHttpUnixSocket = webServiceEnableHttpUnixSocket;
                                restartWebService = true;
                            }
                        }

                        if (request.TryQueryOrForm("webServiceHttpUnixSocket", out string webServiceHttpUnixSocket))
                        {
                            if (string.IsNullOrWhiteSpace(webServiceHttpUnixSocket))
                                webServiceHttpUnixSocket = null;

                            if (_dnsWebService._webServiceHttpUnixSocket != webServiceHttpUnixSocket)
                            {
                                _dnsWebService._webServiceHttpUnixSocket = webServiceHttpUnixSocket;
                                restartWebService = true;
                            }
                        }

                        if (webListeners.TlsSocket.Enabled is bool webServiceEnableTlsUnixSocket &&
                            (_dnsWebService._managedWebListeners & ManagedWebTlsSocketEnabled) == 0)
                        {
                            if (_dnsWebService._webServiceEnableTlsUnixSocket != webServiceEnableTlsUnixSocket)
                            {
                                if (webServiceEnableTlsUnixSocket)
                                {
                                    if (!DnsServer.IsUnixDomainSocketSupported())
                                        throw new ArgumentException("Unix Domain Sockets (UDS) are supported only on Linux, Windows 10 (build 17063 and later), and Windows Server 2019 (update 1809 and later).", "webServiceEnableTlsUnixSocket");
                                }

                                _dnsWebService._webServiceEnableTlsUnixSocket = webServiceEnableTlsUnixSocket;
                                restartWebService = true;
                            }
                        }

                        if (request.TryQueryOrForm("webServiceTlsUnixSocket", out string webServiceTlsUnixSocket))
                        {
                            if (string.IsNullOrWhiteSpace(webServiceTlsUnixSocket))
                                webServiceTlsUnixSocket = null;

                            if (_dnsWebService._webServiceTlsUnixSocket != webServiceTlsUnixSocket)
                            {
                                _dnsWebService._webServiceTlsUnixSocket = webServiceTlsUnixSocket;
                                restartWebService = true;
                            }
                        }

                        if (webListeners.TlsEnabled.HasValue && (_dnsWebService._managedWebListeners & ManagedWebTlsEnabled) == 0)
                        {
                            if (_dnsWebService._webServiceEnableTls != webServiceEnableTls)
                            {
                                _dnsWebService._webServiceEnableTls = webServiceEnableTls;
                                _webServiceEnablingTls = webServiceEnableTls;
                                restartWebService = true;
                            }
                        }

                        if (webListeners.Http3Enabled.HasValue && (_dnsWebService._managedWebListeners & ManagedWebHttp3) == 0)
                        {
                            if (_dnsWebService._webServiceEnableHttp3 != webServiceEnableHttp3)
                            {
                                if (webServiceEnableHttp3)
                                    DnsServer.ValidateQuicSupport("HTTP/3");

                                _dnsWebService._webServiceEnableHttp3 = webServiceEnableHttp3;
                                restartWebService = true;
                            }
                        }

                        if (webListeners.RedirectToTls.HasValue && (_dnsWebService._managedWebListeners & ManagedWebRedirect) == 0)
                        {
                            if (_dnsWebService._webServiceHttpToTlsRedirect != webServiceHttpToTlsRedirect)
                            {
                                _dnsWebService._webServiceHttpToTlsRedirect = webServiceHttpToTlsRedirect;
                                restartWebService = true;
                            }
                        }

                        if (request.TryGetQueryOrForm("webServiceUseSelfSignedTlsCertificate", bool.Parse, out bool webServiceUseSelfSignedTlsCertificate))
                            _dnsWebService._webServiceUseSelfSignedTlsCertificate = webServiceUseSelfSignedTlsCertificate;



                        if (reverseProxyAcl is not null && !_dnsWebService._manifestOwnsReverseProxyAcl)
                            _dnsWebService._webServiceReverseProxyAddresses = reverseProxyAcl.Length == 0 ? null : reverseProxyAcl;

                        if (webHeaders.RealIp is not null && !_dnsWebService._manifestOwnsRealIpHeader)
                            _dnsWebService._webServiceRealIpHeader = webHeaders.RealIp;
                        if (webHeaders.FrameAncestors is not null && !_dnsWebService._manifestOwnsFrameAncestors)
                            _dnsWebService._webServiceCspFrameAncestorsHeader = webHeaders.FrameAncestors;

                        string webServiceTlsCertificatePath = request.QueryOrForm("webServiceTlsCertificatePath");
                        if (webServiceTlsCertificatePath is not null)
                        {
                            if (webServiceTlsCertificatePath.Length == 0)
                            {
                                if (!string.IsNullOrEmpty(_dnsWebService._webServiceTlsCertificatePath))
                                {
                                    _dnsWebService.RemoveWebServiceTlsCertificate();
                                    webServiceTlsCertificateChanged = true;
                                }
                            }
                            else
                            {
                                string webServiceTlsCertificatePassword = request.QueryOrForm("webServiceTlsCertificatePassword");

                                if ((webServiceTlsCertificatePassword is null) || (webServiceTlsCertificatePassword == "************"))
                                    webServiceTlsCertificatePassword = _dnsWebService._webServiceTlsCertificatePassword;

                                if ((webServiceTlsCertificatePath != _dnsWebService._webServiceTlsCertificatePath) || (webServiceTlsCertificatePassword != _dnsWebService._webServiceTlsCertificatePassword))
                                {
                                    _dnsWebService.SetWebServiceTlsCertificate(webServiceTlsCertificatePath, webServiceTlsCertificatePassword);
                                    webServiceTlsCertificateChanged = true;
                                }
                            }
                        }

                        #endregion

                        #region optional protocols

                        _dnsWebService._dnsServer.SetDnsListenerPolicy(dnsListenerPolicy);

                        if (dnsBindings.UdpProxyEnabled is bool requestedUdpProxyEnabled &&
                            _dnsWebService._dnsServer.EnableDnsOverUdpProxy != requestedUdpProxyEnabled)
                        {
                            _dnsWebService._dnsServer.EnableDnsOverUdpProxy = requestedUdpProxyEnabled;
                            restartDnsService = true;
                        }

                        if (dnsBindings.UdpProxyPort is int requestedUdpProxyPort &&
                            _dnsWebService._dnsServer.DnsOverUdpProxyPort != requestedUdpProxyPort)
                        {
                            _dnsWebService._dnsServer.DnsOverUdpProxyPort = requestedUdpProxyPort;
                            restartDnsService = true;
                        }

                        if (dnsBindings.TcpProxyEnabled is bool requestedTcpProxyEnabled &&
                            _dnsWebService._dnsServer.EnableDnsOverTcpProxy != requestedTcpProxyEnabled)
                        {
                            _dnsWebService._dnsServer.EnableDnsOverTcpProxy = requestedTcpProxyEnabled;
                            restartDnsService = true;
                        }

                        if (dnsBindings.TcpProxyPort is int requestedTcpProxyPort &&
                            _dnsWebService._dnsServer.DnsOverTcpProxyPort != requestedTcpProxyPort)
                        {
                            _dnsWebService._dnsServer.DnsOverTcpProxyPort = requestedTcpProxyPort;
                            restartDnsService = true;
                        }

                        if (dnsBindings.HttpEnabled is bool requestedHttpEnabled &&
                            _dnsWebService._dnsServer.EnableDnsOverHttp != requestedHttpEnabled)
                        {
                            _dnsWebService._dnsServer.EnableDnsOverHttp = requestedHttpEnabled;
                            restartDnsService = true;
                        }

                        if (dnsBindings.HttpPort is int requestedHttpPort &&
                            _dnsWebService._dnsServer.DnsOverHttpPort != requestedHttpPort)
                        {
                            _dnsWebService._dnsServer.DnsOverHttpPort = requestedHttpPort;
                            restartDnsService = true;
                        }

                        if (dnsBindings.TlsEnabled is bool requestedTlsEnabled &&
                            _dnsWebService._dnsServer.EnableDnsOverTls != requestedTlsEnabled)
                        {
                            _dnsWebService._dnsServer.EnableDnsOverTls = requestedTlsEnabled;
                            restartDnsService = true;
                        }

                        if (dnsBindings.TlsPort is int requestedTlsPort &&
                            _dnsWebService._dnsServer.DnsOverTlsPort != requestedTlsPort)
                        {
                            _dnsWebService._dnsServer.DnsOverTlsPort = requestedTlsPort;
                            restartDnsService = true;
                        }

                        if (dnsBindings.HttpsEnabled is bool requestedHttpsEnabled &&
                            _dnsWebService._dnsServer.EnableDnsOverHttps != requestedHttpsEnabled)
                        {
                            _dnsWebService._dnsServer.EnableDnsOverHttps = requestedHttpsEnabled;
                            restartDnsService = true;
                        }

                        if (dnsBindings.HttpsPort is int requestedHttpsPort &&
                            _dnsWebService._dnsServer.DnsOverHttpsPort != requestedHttpsPort)
                        {
                            _dnsWebService._dnsServer.DnsOverHttpsPort = requestedHttpsPort;
                            restartDnsService = true;
                        }

                        if (dnsBindings.QuicEnabled is bool requestedQuicEnabled &&
                            _dnsWebService._dnsServer.EnableDnsOverQuic != requestedQuicEnabled)
                        {
                            _dnsWebService._dnsServer.EnableDnsOverQuic = requestedQuicEnabled;
                            restartDnsService = true;
                        }

                        if (dnsBindings.QuicPort is int requestedQuicPort &&
                            _dnsWebService._dnsServer.DnsOverQuicPort != requestedQuicPort)
                        {
                            _dnsWebService._dnsServer.DnsOverQuicPort = requestedQuicPort;
                            restartDnsService = true;
                        }

                        if (dnsBindings.Http3Enabled is bool requestedHttp3Enabled &&
                            _dnsWebService._dnsServer.EnableDnsOverHttp3 != requestedHttp3Enabled)
                        {
                            _dnsWebService._dnsServer.EnableDnsOverHttp3 = requestedHttp3Enabled;
                            restartDnsService = true;
                        }

                        if (dnsBindings.HttpSocketEnabled is bool requestedHttpSocketEnabled &&
                            _dnsWebService._dnsServer.EnableDnsOverHttpUnixSocket != requestedHttpSocketEnabled)
                        {
                            _dnsWebService._dnsServer.EnableDnsOverHttpUnixSocket = requestedHttpSocketEnabled;
                            restartDnsService = true;
                        }

                        if (dnsBindings.HttpSocketPath is string requestedHttpSocketPath &&
                            _dnsWebService._dnsServer.DnsOverHttpUnixSocket != (requestedHttpSocketPath.Length == 0 ? null : requestedHttpSocketPath))
                        {
                            _dnsWebService._dnsServer.DnsOverHttpUnixSocket = requestedHttpSocketPath;
                            restartDnsService = true;
                        }

                        if (dnsBindings.HttpsSocketEnabled is bool requestedHttpsSocketEnabled &&
                            _dnsWebService._dnsServer.EnableDnsOverHttpsUnixSocket != requestedHttpsSocketEnabled)
                        {
                            _dnsWebService._dnsServer.EnableDnsOverHttpsUnixSocket = requestedHttpsSocketEnabled;
                            restartDnsService = true;
                        }

                        if (dnsBindings.HttpsSocketPath is string requestedHttpsSocketPath &&
                            _dnsWebService._dnsServer.DnsOverHttpsUnixSocket != (requestedHttpsSocketPath.Length == 0 ? null : requestedHttpsSocketPath))
                        {
                            _dnsWebService._dnsServer.DnsOverHttpsUnixSocket = requestedHttpsSocketPath;
                            restartDnsService = true;
                        }

                        if (dnsTlsCertificatePath is not null)
                        {
                            if (dnsTlsCertificatePath.Length == 0)
                            {
                                if (!string.IsNullOrEmpty(_dnsWebService._dnsServer.DnsTlsCertificatePath) && (_dnsWebService._dnsServer.EnableDnsOverTls || _dnsWebService._dnsServer.EnableDnsOverHttps || _dnsWebService._dnsServer.EnableDnsOverQuic))
                                    restartDnsService = true;

                                _dnsWebService._dnsServer.RemoveDnsTlsCertificate();
                            }
                            else
                            {
                                if ((dnsTlsCertificatePath != _dnsWebService._dnsServer.DnsTlsCertificatePath) || (dnsTlsCertificatePassword != _dnsWebService._dnsServer.DnsTlsCertificatePassword))
                                {
                                    _dnsWebService._dnsServer.SetDnsTlsCertificate(dnsTlsCertificatePath, dnsTlsCertificatePassword, true);

                                    if (string.IsNullOrEmpty(_dnsWebService._dnsServer.DnsTlsCertificatePath) && (_dnsWebService._dnsServer.EnableDnsOverTls || _dnsWebService._dnsServer.EnableDnsOverHttps || _dnsWebService._dnsServer.EnableDnsOverQuic))
                                        restartDnsService = true;
                                }
                            }
                        }

                        #endregion

                        #region tsig

                        if (requestedTsigKeys is not null)
                        {
                            _dnsWebService._dnsServer.TsigKeys = requestedTsigKeys;
                            clusterParameters.Add("tsigKeys", string.Join("|", requestedTsigKeys.Values.Select(
                                key => $"{key.KeyName}|{key.SharedSecret}|{key.AlgorithmName}")));
                        }

                        #endregion

                        #region recursion

                        if (hasRecursionMode && !_dnsWebService._dnsServer.ManifestOwnsRecursionMode)
                        {
                            _dnsWebService._dnsServer.Recursion = recursion;

                            clusterParameters.Add("recursion", recursion.ToString());
                        }

                        if (hasRecursionAcl && !_dnsWebService._dnsServer.ManifestOwnsRecursionAcl)
                        {
                            _dnsWebService._dnsServer.RecursionNetworkACL = recursionNetworkACL;

                            clusterParameters.Add("recursionNetworkACL", recursionNetworkACL.Join());
                        }

                        if (resolverOptions.RandomizeName.HasValue)
                        {
                            _dnsWebService._dnsServer.RandomizeName = randomizeName;
                            clusterParameters.Add("randomizeName", randomizeName.ToString());
                        }

                        if (resolverOptions.QnameMinimization.HasValue)
                        {
                            _dnsWebService._dnsServer.QnameMinimization = qnameMinimization;
                            clusterParameters.Add("qnameMinimization", qnameMinimization.ToString());
                        }

                        if (resolverOptions.LocallyServedDnsZones.HasValue)
                        {
                            _dnsWebService._dnsServer.LocallyServedDnsZones = locallyServedDnsZones;
                            clusterParameters.Add("locallyServedDnsZones", locallyServedDnsZones.ToString());
                        }

                        if (resolverOptions.ResolverRetries.HasValue)
                        {
                            _dnsWebService._dnsServer.ResolverRetries = resolverRetries;
                            clusterParameters.Add("resolverRetries", resolverRetries.ToString());
                        }

                        if (resolverOptions.ResolverTimeout.HasValue)
                        {
                            _dnsWebService._dnsServer.ResolverTimeout = resolverTimeout;
                            clusterParameters.Add("resolverTimeout", resolverTimeout.ToString());
                        }

                        if (resolverOptions.ResolverConcurrency.HasValue)
                        {
                            _dnsWebService._dnsServer.ResolverConcurrency = resolverConcurrency;
                            clusterParameters.Add("resolverConcurrency", resolverConcurrency.ToString());
                        }

                        if (resolverOptions.ResolverMaxStackCount.HasValue)
                        {
                            _dnsWebService._dnsServer.ResolverMaxStackCount = resolverMaxStackCount;
                            clusterParameters.Add("resolverMaxStackCount", resolverMaxStackCount.ToString());
                        }

                        #endregion

                        #region cache

                        _dnsWebService._dnsServer.SetCachePolicy(cachePolicy);

                        #endregion

                        #region blocking

                        _dnsWebService._dnsServer.SetBlockingPolicy(blockingPolicy, cancelPause: true);
                        if (blockingPolicy.Enabled.HasValue)
                            clusterParameters.Add("enableBlocking", blockingPolicy.Enabled.Value.ToString());
                        if (blockingPolicy.AllowTxtReport.HasValue)
                            clusterParameters.Add("allowTxtBlockingReport", blockingPolicy.AllowTxtReport.Value.ToString());
                        if (blockingPolicy.BypassNetworks is not null)
                            clusterParameters.Add("blockingBypassList", blockingPolicy.BypassNetworks.Join());
                        if (blockingPolicy.ResponseType.HasValue)
                            clusterParameters.Add("blockingType", blockingPolicy.ResponseType.Value.ToString());
                        if (blockingPolicy.AnswerTtl.HasValue)
                            clusterParameters.Add("blockingAnswerTtl", blockingPolicy.AnswerTtl.Value.ToString());
                        if (blockingPolicy.CustomAddresses is not null)
                            clusterParameters.Add("customBlockingAddresses", blockingPolicy.CustomAddresses.Join());

                        if (hasBlockListSources && !_dnsWebService._dnsServer.BlockListZoneManager.ManifestOwnsSources)
                        {
                            _dnsWebService._dnsServer.BlockListZoneManager.BlockListUrls = blockListUrls;
                            _dnsWebService._dnsServer.BlockListZoneManager.SaveConfigFile();

                            clusterParameters.Add("blockListUrls", blockListUrls.Join());
                        }

                        if (hasBlockListInterval)
                        {
                            _dnsWebService._dnsServer.BlockListZoneManager.BlockListUpdateIntervalHours = blockListUpdateIntervalHours;
                            _dnsWebService._dnsServer.BlockListZoneManager.SaveConfigFile();

                            clusterParameters.Add("blockListUpdateIntervalHours", blockListUpdateIntervalHours.ToString());
                        }

                        #endregion

                        #region proxy & forwarders

                        //proxy & forwarders
                        if (hasProxyType)
                        {
                            if (ConfigurationProxy.Differences(_dnsWebService._dnsServer.Proxy, requestedProxy) != 0)
                                _dnsWebService._dnsServer.Proxy = requestedProxy;
                            if (requestedProxy is not null)
                            {
                                if (requestedProxy.Credential is not null)
                                {
                                    clusterParameters.Add("proxyUsername", requestedProxy.Credential.UserName);
                                    clusterParameters.Add("proxyPassword", requestedProxy.Credential.Password);
                                }
                                clusterParameters.Add("proxyAddress", requestedProxy.Address);
                                clusterParameters.Add("proxyPort", requestedProxy.Port.ToString());
                                if (hasProxyBypass)
                                    clusterParameters.Add("proxyBypass", requestedProxy.BypassList.Join());
                            }

                            clusterParameters.Add("proxyType", proxyType.ToString());
                        }

                        _dnsWebService._dnsServer.SetForwardingPolicy(forwardingPolicy);
                        if (forwardingPolicy.Servers is not null)
                        {
                            if (forwardingPolicy.Servers.Count > 0)
                                clusterParameters.Add("forwarderProtocol", forwarderProtocol.ToString());
                            clusterParameters.Add("forwarders", forwardingPolicy.Servers.Join());
                        }
                        if (forwardingPolicy.Concurrent.HasValue)
                            clusterParameters.Add("concurrentForwarding", forwardingPolicy.Concurrent.Value.ToString());
                        if (forwardingPolicy.Retries.HasValue)
                            clusterParameters.Add("forwarderRetries", forwardingPolicy.Retries.Value.ToString());
                        if (forwardingPolicy.Timeout.HasValue)
                            clusterParameters.Add("forwarderTimeout", forwardingPolicy.Timeout.Value.ToString());
                        if (forwardingPolicy.Concurrency.HasValue)
                            clusterParameters.Add("forwarderConcurrency", forwardingPolicy.Concurrency.Value.ToString());

                        #endregion

                        #region logging

                        if (destination.HasValue)
                            _dnsWebService._log.LoggingType = destination.Value;

                        if (hasIgnoreResolverLogs && !_dnsWebService._dnsServer.ManifestOwnsResolverLogging)
                            _dnsWebService._dnsServer.ResolverLogManager = ignoreResolverLogs ? null : _dnsWebService._log;

                        if (hasLogQueries && !_dnsWebService._dnsServer.ManifestOwnsQueryLogging)
                            _dnsWebService._dnsServer.QueryLogManager = logQueries ? _dnsWebService._log : null;

                        if (noStackTrace.HasValue)
                            _dnsWebService._log.NoStackTrace = noStackTrace.Value;

                        if (useLocalTime.HasValue)
                            _dnsWebService._log.UseLocalTime = useLocalTime.Value;

                        if (logFolder is not null)
                            _dnsWebService._log.LogFolder = logFolder;

                        if (retentionDays.HasValue)
                            _dnsWebService._log.MaxLogFileDays = retentionDays.Value;

                        if (hasInMemoryStats && !_dnsWebService._dnsServer.ManifestOwnsInMemoryStatistics)
                            _dnsWebService._dnsServer.StatsManager.EnableInMemoryStats = enableInMemoryStats;

                        if (hasStatRetention && !_dnsWebService._dnsServer.ManifestOwnsStatisticsRetention)
                            _dnsWebService._dnsServer.StatsManager.MaxStatFileDays = maxStatFileDays;

                        #endregion
                    }
                    finally
                    {
                        //enforce cluster mandatory TLS requirement
                        if (_dnsWebService._clusterManager.ClusterInitialized)
                        {
                            if (!_dnsWebService._webServiceEnableTls || string.IsNullOrEmpty(_dnsWebService._webServiceTlsCertificatePath))
                            {
                                //force enable TLS with self-signed certificate if cluster is initialized
                                _dnsWebService._webServiceEnableTls = true;
                                _dnsWebService._webServiceUseSelfSignedTlsCertificate = true;
                            }
                        }

                        //TLS actions
                        _dnsWebService.CheckAndLoadSelfSignedCertificate(serverDomainChanged || webServiceLocalAddressesChanged, true);

                        if (_dnsWebService._webServiceEnableTls && string.IsNullOrEmpty(_dnsWebService._webServiceTlsCertificatePath) && !_dnsWebService._webServiceUseSelfSignedTlsCertificate)
                        {
                            //disable TLS
                            _dnsWebService._webServiceEnableTls = false;
                            restartWebService = true;
                        }

                        //update sso http handler
                        if (_dnsWebService._ssoHttpHandler is not null)
                        {
                            _dnsWebService._ssoHttpHandler.Proxy = _dnsWebService._dnsServer.Proxy;
                            _dnsWebService._ssoHttpHandler.NetworkType = HttpClientNetworkHandler.GetNetworkType(_dnsWebService._dnsServer.IPv6Mode);
                        }

                        //cluster update actions
                        if (_dnsWebService._clusterManager.ClusterInitialized)
                        {
                            if (webServiceTlsCertificateChanged || serverDomainChanged || webServiceLocalAddressesChanged)
                                _dnsWebService._clusterManager.UpdateSelfNodeUrlAndCertificate();
                        }

                        //save config
                        _dnsWebService.SaveConfigFile();
                        _dnsWebService._dnsServer.SaveConfigFile();
                        _dnsWebService._dnsServer.BlockListZoneManager.SaveConfigFile();
                        _dnsWebService._log.SaveConfigFile();
                    }

                    _dnsWebService._log.Write(_dnsWebService.GetRemoteEndPoint(context), "[" + sessionUser.Username + "] DNS Settings were updated successfully.");

                    //trigger cluster update
                    if (_dnsWebService._clusterManager.ClusterInitialized)
                    {
                        if (_dnsWebService._clusterManager.GetSelfNode().Type == ClusterNodeType.Primary)
                            _dnsWebService._clusterManager.TriggerNotifyAllSecondaryNodes();
                        else if (clusterParameters.Count > 0)
                            await _dnsWebService._clusterManager.GetPrimaryNode().SetClusterSettingsAsync(sessionUser, clusterParameters);
                    }

                    Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();
                    WriteDnsSettings(jsonWriter);
                }
                finally
                {
                    if (restartDnsService || restartWebService)
                        _dnsWebService.RestartService(restartDnsService, restartWebService, oldWebServiceLocalAddresses, oldWebServiceHttpPort, oldWebServiceTlsPort);
                }
            }

            public void GetTsigKeyNames(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (
                    !_dnsWebService._authManager.IsPermitted(PermissionSection.Settings, sessionUser, PermissionFlag.View) &&
                    !_dnsWebService._authManager.IsPermitted(PermissionSection.Zones, sessionUser, PermissionFlag.Modify)
                   )
                {
                    throw new DnsWebServiceException("Access was denied.");
                }

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();

                jsonWriter.WritePropertyName("tsigKeyNames");
                {
                    jsonWriter.WriteStartArray();

                    if (_dnsWebService._dnsServer.TsigKeys is not null)
                    {
                        foreach (KeyValuePair<string, TsigKey> tsigKey in _dnsWebService._dnsServer.TsigKeys)
                            jsonWriter.WriteStringValue(tsigKey.Key);
                    }

                    jsonWriter.WriteEndArray();
                }
            }

            public async Task BackupSettingsAsync(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Settings, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                bool authConfig = request.GetQueryOrForm("authConfig", bool.Parse, false);
                bool clusterConfig = request.GetQueryOrForm("clusterConfig", bool.Parse, false);
                bool webServiceSettings = request.GetQueryOrForm("webServiceSettings", bool.Parse, false);
                bool dnsSettings = request.GetQueryOrForm("dnsSettings", bool.Parse, false);
                bool logSettings = request.GetQueryOrForm("logSettings", bool.Parse, false);
                bool zones = request.GetQueryOrForm("zones", bool.Parse, false);
                bool allowedZones = request.GetQueryOrForm("allowedZones", bool.Parse, false);
                bool blockedZones = request.GetQueryOrForm("blockedZones", bool.Parse, false);
                bool blockLists = request.GetQueryOrForm("blockLists", bool.Parse, false);
                bool apps = request.GetQueryOrForm("apps", bool.Parse, false);
                bool scopes = request.GetQueryOrForm("scopes", bool.Parse, false);
                bool stats = request.GetQueryOrForm("stats", bool.Parse, false);
                bool logs = request.GetQueryOrForm("logs", bool.Parse, false);

                string tmpFile = Path.GetTempFileName();
                try
                {
                    await using (FileStream backupZipStream = new FileStream(tmpFile, FileMode.Create, FileAccess.ReadWrite))
                    {
                        //create backup zip
                        await _dnsWebService.BackupConfigAsync(backupZipStream, authConfig, clusterConfig, webServiceSettings, dnsSettings, logSettings, zones, allowedZones, blockedZones, blockLists, apps, scopes, stats, logs);

                        //send zip file
                        backupZipStream.Position = 0;

                        HttpResponse response = context.Response;

                        response.ContentType = "application/zip";
                        response.ContentLength = backupZipStream.Length;
                        response.Headers.ContentDisposition = "attachment;filename=" + _dnsWebService._dnsServer.ServerDomain + DateTime.UtcNow.ToString("_yyyy-MM-dd_HH-mm-ss", CultureInfo.InvariantCulture) + "_backup.zip";

                        await using (Stream output = response.Body)
                        {
                            await backupZipStream.CopyToAsync(output);
                        }
                    }
                }
                finally
                {
                    try
                    {
                        File.Delete(tmpFile);
                    }
                    catch (Exception ex)
                    {
                        _dnsWebService._log.Write(ex);
                    }
                }

                _dnsWebService._log.Write(_dnsWebService.GetRemoteEndPoint(context), "[" + sessionUser.Username + "] Settings backup zip file was exported.");
            }

            public async Task RestoreSettingsAsync(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Settings, sessionUser, PermissionFlag.Delete))
                    throw new DnsWebServiceException("Access was denied.");

                HttpRequest request = context.Request;

                bool authConfig = request.GetQueryOrForm("authConfig", bool.Parse, false);
                bool clusterConfig = request.GetQueryOrForm("clusterConfig", bool.Parse, false);
                bool webServiceSettings = request.GetQueryOrForm("webServiceSettings", bool.Parse, false);
                bool dnsSettings = request.GetQueryOrForm("dnsSettings", bool.Parse, false);
                bool logSettings = request.GetQueryOrForm("logSettings", bool.Parse, false);
                bool zones = request.GetQueryOrForm("zones", bool.Parse, false);
                bool allowedZones = request.GetQueryOrForm("allowedZones", bool.Parse, false);
                bool blockedZones = request.GetQueryOrForm("blockedZones", bool.Parse, false);
                bool blockLists = request.GetQueryOrForm("blockLists", bool.Parse, false);
                bool apps = request.GetQueryOrForm("apps", bool.Parse, false);
                bool scopes = request.GetQueryOrForm("scopes", bool.Parse, false);
                bool stats = request.GetQueryOrForm("stats", bool.Parse, false);
                bool logs = request.GetQueryOrForm("logs", bool.Parse, false);
                bool deleteExistingFiles = request.GetQueryOrForm("deleteExistingFiles", bool.Parse, false);

                if (!request.HasFormContentType || (request.Form.Files.Count == 0))
                    throw new DnsWebServiceException("DNS backup zip file is missing.");

                IReadOnlyList<IPAddress> oldWebServiceLocalAddresses = _dnsWebService._webServiceLocalAddresses;
                int oldWebServiceHttpPort = _dnsWebService._webServiceHttpPort;
                int oldWebServiceTlsPort = _dnsWebService._webServiceTlsPort;

                bool restoreStarted = false;
                try
                {
                    //write to temp file
                    string tmpFile = Path.GetTempFileName();
                    try
                    {
                        await using (FileStream fS = new FileStream(tmpFile, FileMode.Create, FileAccess.ReadWrite))
                        {
                            await request.Form.Files[0].CopyToAsync(fS);

                            fS.Position = 0;

                            bool checkLog = logSettings && _dnsWebService._log.HasManagedLoggingSettings;
                            bool ownsBlockListSettings = _dnsWebService._dnsServer.BlockListZoneManager.HasManagedSettings;
                            bool checkDns = dnsSettings && (_dnsWebService._dnsServer.HasManagedDnsSettings || ownsBlockListSettings || _dnsWebService._manifestOwnsRealIpHeader || _dnsWebService._managedWebListeners != 0);
                            bool checkBlockList = blockLists && ownsBlockListSettings;
                            bool checkWeb = webServiceSettings && (_dnsWebService._manifestOwnsRealIpHeader || _dnsWebService._manifestOwnsFrameAncestors || _dnsWebService._manifestOwnsReverseProxyAcl || _dnsWebService._managedWebListeners != 0);
                            bool checkDomainLists = allowedZones && _dnsWebService._dnsServer.AllowedZoneManager.ManifestOwnsList ||
                                blockedZones && _dnsWebService._dnsServer.BlockedZoneManager.ManifestOwnsList;
                            bool checkScopes = scopes && _dnsWebService._dhcpServer.ManagedPaths.Count > 0;
                            if (checkLog || checkDns || checkBlockList || checkWeb || checkDomainLists || checkScopes)
                            {
                                using (var archive = new ZipArchive(fS, ZipArchiveMode.Read, leaveOpen: true))
                                {
                                    if (checkScopes)
                                        _dnsWebService._dhcpServer.CheckManifestScopeRestore(archive, deleteExistingFiles);
                                    if (checkDomainLists)
                                        _dnsWebService.CheckManagedDomainLists(archive, allowedZones, blockedZones);
                                    if (checkLog && archive.GetEntry("log.config") is ZipArchiveEntry logEntry)
                                    {
                                        using Stream logConfiguration = logEntry.Open();
                                        _dnsWebService._log.CheckRestoreManifestOwnership(logConfiguration);
                                    }
                                    if (checkDns && archive.GetEntry("dns.config") is ZipArchiveEntry dnsEntry)
                                    {
                                        bool checkDnsBody;
                                        using (Stream dnsConfiguration = dnsEntry.Open())
                                            checkDnsBody = _dnsWebService.CheckRestoreManifestDnsSettings(dnsConfiguration);
                                        if (checkDnsBody)
                                        {
                                            using Stream dnsConfiguration = dnsEntry.Open();
                                            _dnsWebService._dnsServer.CheckRestoreManifestDnsBody(dnsConfiguration);
                                        }
                                    }
                                    if (checkWeb && archive.GetEntry("webservice.config") is ZipArchiveEntry webEntry)
                                    {
                                        using Stream webConfiguration = webEntry.Open();
                                        _dnsWebService.CheckManifestWebLiveSettings(_dnsWebService.ReadConfigFrom(webConfiguration, apply: false));
                                    }
                                    if (checkBlockList && archive.GetEntry("blocklist.config") is ZipArchiveEntry blockListEntry)
                                    {
                                        using Stream blockListConfiguration = blockListEntry.Open();
                                        _dnsWebService._dnsServer.BlockListZoneManager.CheckRestoreManifestOwnership(blockListConfiguration);
                                    }
                                }

                                fS.Position = 0;
                            }

                            restoreStarted = true;
                            await _dnsWebService.RestoreConfigAsync(fS, authConfig, clusterConfig, webServiceSettings, dnsSettings, logSettings, zones, allowedZones, blockedZones, blockLists, apps, scopes, stats, logs, deleteExistingFiles, context.GetCurrentSession());

                            _dnsWebService._log.Write(_dnsWebService.GetRemoteEndPoint(context), "[" + sessionUser.Username + "] Settings backup zip file was restored.");
                        }
                    }
                    finally
                    {
                        try
                        {
                            File.Delete(tmpFile);
                        }
                        catch (Exception ex)
                        {
                            _dnsWebService._log.Write(ex);
                        }
                    }

                    //trigger cluster update
                    if (_dnsWebService._clusterManager.ClusterInitialized)
                        _dnsWebService._clusterManager.TriggerNotifyAllSecondaryNodesIfPrimarySelfNode();

                    Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();
                    WriteDnsSettings(jsonWriter);

                }
                finally
                {
                    if (restoreStarted && (dnsSettings || webServiceSettings))
                        _dnsWebService.RestartService(dnsSettings, webServiceSettings, oldWebServiceLocalAddresses, oldWebServiceHttpPort, oldWebServiceTlsPort);
                }
            }

            public void ForceUpdateBlockLists(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Settings, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                _dnsWebService._dnsServer.BlockListZoneManager.ForceUpdateBlockLists();

                _dnsWebService._log.Write(_dnsWebService.GetRemoteEndPoint(context), "[" + sessionUser.Username + "] Block list update was triggered.");

                if (_dnsWebService._clusterManager.ClusterInitialized)
                {
                    UserSession session = context.GetCurrentSession();

                    if (session.Type == UserSessionType.ClusterApiToken)
                        return; //call from cluster node itself

                    //relay action on all other cluster nodes async
                    ThreadPool.QueueUserWorkItem(async delegate (object state)
                    {
                        try
                        {
                            IReadOnlyDictionary<int, ClusterNode> clusterNodes = _dnsWebService._clusterManager.ClusterNodes;
                            List<Task> tasks = new List<Task>(clusterNodes.Count);

                            foreach (KeyValuePair<int, ClusterNode> clusterNode in clusterNodes)
                            {
                                if (clusterNode.Value.State == ClusterNodeState.Self)
                                    continue;

                                tasks.Add(clusterNode.Value.ForceUpdateBlockListsAsync(sessionUser));
                            }

                            foreach (Task task in tasks)
                            {
                                try
                                {
                                    await task;
                                }
                                catch (Exception ex)
                                {
                                    _dnsWebService._log.Write(ex);
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            _dnsWebService._log.Write(ex);
                        }
                    });
                }
            }

            public void TemporaryDisableBlocking(HttpContext context)
            {
                User sessionUser = _dnsWebService.GetSessionUser(context);

                if (!_dnsWebService._authManager.IsPermitted(PermissionSection.Settings, sessionUser, PermissionFlag.Modify))
                    throw new DnsWebServiceException("Access was denied.");

                int minutes = context.Request.GetQueryOrForm("minutes", int.Parse);

                _dnsWebService._dnsServer.BlockListZoneManager.TemporaryDisableBlocking(minutes, _dnsWebService.GetRemoteEndPoint(context), sessionUser.Username);

                Utf8JsonWriter jsonWriter = context.GetCurrentJsonWriter();
                jsonWriter.WriteString("temporaryDisableBlockingTill", _dnsWebService._dnsServer.BlockListZoneManager.TemporaryDisableBlockingTill);

                if (_dnsWebService._clusterManager.ClusterInitialized)
                {
                    UserSession session = context.GetCurrentSession();

                    if (session.Type == UserSessionType.ClusterApiToken)
                        return; //call from cluster node itself

                    //relay action on all other cluster nodes async
                    ThreadPool.QueueUserWorkItem(async delegate (object state)
                    {
                        try
                        {
                            IReadOnlyDictionary<int, ClusterNode> clusterNodes = _dnsWebService._clusterManager.ClusterNodes;
                            List<Task> tasks = new List<Task>(clusterNodes.Count);

                            foreach (KeyValuePair<int, ClusterNode> clusterNode in clusterNodes)
                            {
                                if (clusterNode.Value.State == ClusterNodeState.Self)
                                    continue;

                                tasks.Add(clusterNode.Value.TemporaryDisableBlockingAsync(sessionUser, minutes));
                            }

                            foreach (Task task in tasks)
                            {
                                try
                                {
                                    await task;
                                }
                                catch (Exception ex)
                                {
                                    _dnsWebService._log.Write(ex);
                                }
                            }
                        }
                        catch (Exception ex)
                        {
                            _dnsWebService._log.Write(ex);
                        }
                    });
                }
            }

            #endregion
        }
    }
}
