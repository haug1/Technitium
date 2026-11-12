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
using DnsServerCore.Dns;
using DnsServerCore.Dns.Dnssec;
using DnsServerCore.Dns.ResourceRecords;
using DnsServerCore.Dns.Zones;
using DnsServerCore.Dns.ZoneManagers;
using DnsServerCore.HttpApi;
using DnsServerCore.HttpApi.Models;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Net.Dns;
using TechnitiumLibrary.Net.Dns.ResourceRecords;

namespace DnsServerCore.Cluster
{
    sealed class ClusterManager : IDisposable
    {
        #region variables

        const ushort HEARTBEAT_REFRESH_INTERVAL_SECONDS = 30;
        const ushort HEARTBEAT_RETRY_INTERVAL_SECONDS = 10;
        const ushort CONFIG_REFRESH_INTERVAL_SECONDS = 900;
        const ushort CONFIG_RETRY_INTERVAL_SECONDS = 60;

        readonly DnsWebService _dnsWebService;

        string _clusterDomain;
        ushort _heartbeatRefreshIntervalSeconds;
        ushort _heartbeatRetryIntervalSeconds;
        ushort _configRefreshIntervalSeconds;
        ushort _configRetryIntervalSeconds;
        DateTime _configLastSynced;
        volatile string[] _managedOptionNames = [];

        IReadOnlyDictionary<int, ClusterNode> _clusterNodes;

        readonly SemaphoreSlim _configRefreshLock = new SemaphoreSlim(1, 1);
        readonly Timer _configRefreshTimer;
        bool _configRefreshTimerTriggered;
        IReadOnlyCollection<string> _configRefreshIncludeZones;
        const int CONFIG_REFRESH_TIMER_INTERVAL = 5000;

        readonly Timer _notifyAllSecondaryNodesTimer;
        volatile bool _notifyAllSecondaryNodesTimerTriggered;
        const int NOTIFY_ALL_SECONDARY_NODES_TIMER_INTERVAL = 5000;

        readonly Timer _clusterUpdateForSecondaryNodeChangesTimer;
        readonly Lock _secondaryUpdateLock = new Lock();
        bool _secondaryUpdateScheduled;
        bool _secondaryUpdatePending;
        volatile bool _secondaryUpdateStopped;
        const int CLUSTER_UPDATE_FOR_SECONDARY_NODE_CHANGES_TIMER_INTERVAL = 5000;

        readonly Lock _saveLock = new Lock();
        bool _pendingSave;
        readonly Timer _saveTimer;
        const int SAVE_TIMER_INITIAL_INTERVAL = 5000;

        volatile int _recordUpdateForMemberZonesId;

        #endregion

        #region constructor

        public ClusterManager(DnsWebService dnsWebService)
        {
            _dnsWebService = dnsWebService;

            _configRefreshTimer = new Timer(ConfigRefreshTimerCallbackAsync);
            _notifyAllSecondaryNodesTimer = new Timer(NotifyAllSecondaryNodesTimerCallbackAsync);
            _clusterUpdateForSecondaryNodeChangesTimer = new Timer(ClusterUpdateForSecondaryNodeChangesTimerCallbackAsync);

            _saveTimer = new Timer(delegate (object state)
            {
                lock (_saveLock)
                {
                    if (_pendingSave)
                    {
                        try
                        {
                            SaveConfigFileInternal();
                            _pendingSave = false;
                        }
                        catch (Exception ex)
                        {
                            _dnsWebService.LogManager.Write(ex);
                        }
                    }
                }
            });

            LoadConfigFile();

            string ownershipFile = Path.Combine(_dnsWebService.ConfigFolder, ConfigurationClusterOptions.OwnershipFile);
            if (File.Exists(ownershipFile))
                _managedOptionNames = JsonSerializer.Deserialize<string[]>(File.ReadAllBytes(ownershipFile)) ?? [];

            if (ClusterInitialized)
            {
                //find and fix Cluster API token
                bool foundClusterApiToken = false;

                foreach (UserSession session in _dnsWebService.AuthManager.Sessions)
                {
                    if (session.Type == UserSessionType.ClusterApiToken)
                    {
                        foundClusterApiToken = true;
                        break;
                    }
                }

                if (!foundClusterApiToken)
                {
                    Group administrators = _dnsWebService.AuthManager.GetGroup(Group.ADMINISTRATORS);

                    foreach (UserSession session in _dnsWebService.AuthManager.Sessions)
                    {
                        if ((session.Type == UserSessionType.ApiToken) && _clusterDomain.Equals(session.TokenName, StringComparison.OrdinalIgnoreCase) && session.User.IsMemberOfGroup(administrators))
                        {
                            session.UpgradeToClusterApiToken();
                            break;
                        }
                    }
                }
            }
        }

        #endregion

        #region IDisposable

        bool _disposed;

        public void Dispose()
        {
            if (_disposed)
                return;

            _configRefreshTimer?.Dispose();
            _notifyAllSecondaryNodesTimer?.Dispose();
            lock (_secondaryUpdateLock)
            {
                _secondaryUpdateStopped = true;
                _clusterUpdateForSecondaryNodeChangesTimer.Dispose();
            }

            DisposeAllNodes();

            lock (_saveLock)
            {
                _saveTimer?.Dispose();

                if (_pendingSave)
                {
                    try
                    {
                        SaveConfigFileInternal();
                    }
                    catch (Exception ex)
                    {
                        _dnsWebService.LogManager.Write(ex);
                    }
                    finally
                    {
                        _pendingSave = false;
                    }
                }
            }

            _configRefreshLock?.Dispose();

            _disposed = true;
        }

        #endregion

        #region config

        private void LoadConfigFile()
        {
            string configFile = Path.Combine(_dnsWebService.ConfigFolder, "cluster.config");

            try
            {
                DisposeAllNodes(); //dispose existing nodes, if any

                using (FileStream fS = new FileStream(configFile, FileMode.Open, FileAccess.Read))
                {
                    ReadConfigFrom(fS);
                }

                InitializeHeartbeatTimerFor(_clusterNodes);
                UpdateConfigRefreshTimer();

                _dnsWebService.LogManager.Write("DNS Server Cluster config file was loaded: " + configFile);
            }
            catch (FileNotFoundException)
            {
                //do nothing
            }
            catch (Exception ex)
            {
                _dnsWebService.LogManager.Write("DNS Server encountered an error while loading the Cluster config file: " + configFile, ex);
            }
        }

        public void LoadConfig(Stream s)
        {
            lock (_saveLock)
            {
                DisposeAllNodes(); //dispose existing nodes, if any

                ReadConfigFrom(s);

                InitializeHeartbeatTimerFor(_clusterNodes);
                UpdateConfigRefreshTimer();

                //save config file
                SaveConfigFileInternal();
                _pendingSave = false;
            }
        }

        private void UpdateConfigRefreshTimer(int refreshInterval = CONFIG_REFRESH_TIMER_INTERVAL)
        {
            //ensure that the new refresh interval is applied using lock
            _configRefreshLock.Wait();
            try
            {
                if (ClusterInitialized && (GetSelfNode().Type == ClusterNodeType.Secondary))
                    _configRefreshTimer.Change(refreshInterval, Timeout.Infinite); //start config refresh timer only for secondary nodes
                else
                    _configRefreshTimer.Change(Timeout.Infinite, Timeout.Infinite);
            }
            finally
            {
                _configRefreshLock.Release();
            }
        }

        private void StopConfigRefreshTimer()
        {
            //ensure that the timer is stopped using lock
            _configRefreshLock.Wait();
            try
            {
                _configRefreshTimer.Change(Timeout.Infinite, Timeout.Infinite);
            }
            finally
            {
                _configRefreshLock.Release();
            }
        }

        private void SaveConfigFileInternal(ConfigurationClusterOptions.Settings? options = null, IReadOnlyList<IPAddress> selfAddresses = null, Uri selfUrl = null)
        {
            if (!ClusterInitialized)
                throw new InvalidOperationException();

            string tmpConfigFile = Path.Combine(_dnsWebService.ConfigFolder, "cluster.tmp");
            string configFile = Path.Combine(_dnsWebService.ConfigFolder, "cluster.config");

            using (FileStream fS = new FileStream(tmpConfigFile, FileMode.Create, FileAccess.Write))
            {
                WriteConfigTo(fS, options, selfAddresses, selfUrl);
                if (options.HasValue || selfAddresses is not null || selfUrl is not null)
                    fS.Flush(flushToDisk: true);
            }

            File.Move(tmpConfigFile, configFile, true);

            _dnsWebService.LogManager.Write("DNS Server Cluster config file was saved: " + configFile);
        }

        private void SaveConfigFile(bool immediately = false)
        {
            if (!ClusterInitialized)
                throw new InvalidOperationException();

            lock (_saveLock)
            {
                if (immediately)
                {
                    SaveConfigFileInternal();
                    _pendingSave = false;
                    return;
                }

                if (_pendingSave)
                    return;

                _pendingSave = true;
                _saveTimer.Change(SAVE_TIMER_INITIAL_INTERVAL, Timeout.Infinite);
            }
        }

        private void UnloadAndDeleteConfigFile()
        {
            StopConfigRefreshTimer();

            DisposeAllNodes(); //dispose existing nodes, if any

            lock (_saveLock)
            {
                //unload
                _clusterDomain = null;
                _configLastSynced = default;
                _clusterNodes = null;

                //delete config file
                string configFile = Path.Combine(_dnsWebService.ConfigFolder, "cluster.config");

                try
                {
                    if (File.Exists(configFile))
                    {
                        File.Delete(configFile);

                        _dnsWebService.LogManager.Write("DNS Server Cluster config file was deleted: " + configFile);
                    }
                }
                catch (Exception ex)
                {
                    _dnsWebService.LogManager.Write("DNS Server encountered an error while deleting the Cluster config file: " + configFile, ex);
                }

                if (_managedOptionNames.Length != 0)
                {
                    WriteManifestOwnership([]);
                    _managedOptionNames = [];
                }

                _pendingSave = false;
            }
        }

        private void ReadConfigFrom(Stream s)
        {
            if (Encoding.ASCII.GetString(s.ReadExactly(2)) != "CL") //format
                throw new InvalidDataException("DNS Server Cluster config file format is invalid.");

            BinaryReader bR = new BinaryReader(s);

            int version = bR.ReadByte();
            switch (version)
            {
                case 1:
                    _clusterDomain = bR.ReadString();
                    _heartbeatRefreshIntervalSeconds = bR.ReadUInt16();
                    _heartbeatRetryIntervalSeconds = bR.ReadUInt16();
                    _configRefreshIntervalSeconds = bR.ReadUInt16();
                    _configRetryIntervalSeconds = bR.ReadUInt16();
                    _configLastSynced = s.ReadDateTime();

                    Dictionary<int, ClusterNode> clusterNodes = null;
                    int count = bR.ReadByte();

                    if (count > 0)
                    {
                        clusterNodes = new Dictionary<int, ClusterNode>(count);

                        for (int i = 0; i < count; i++)
                        {
                            ClusterNode node = new ClusterNode(this, bR);
                            clusterNodes.TryAdd(node.Id, node);
                        }
                    }

                    _clusterNodes = clusterNodes;
                    break;

                default:
                    throw new InvalidDataException("DNS Server Cluster config version not supported.");
            }
        }

        private void WriteConfigTo(Stream s, ConfigurationClusterOptions.Settings? options = null, IReadOnlyList<IPAddress> selfAddresses = null, Uri selfUrl = null)
        {
            BinaryWriter bW = new BinaryWriter(s);

            bW.Write(Encoding.ASCII.GetBytes("CL")); //format
            bW.Write((byte)1); //version

            bW.Write(_clusterDomain);
            var settings = options ?? GetManifestOptions();
            bW.Write(settings.HeartbeatRefresh);
            bW.Write(settings.HeartbeatRetry);
            bW.Write(settings.ConfigRefresh);
            bW.Write(settings.ConfigRetry);
            s.WriteDateTime(_configLastSynced);

            IReadOnlyDictionary<int, ClusterNode> clusterNodes = _clusterNodes;
            if (clusterNodes is null)
            {
                bW.Write((byte)0);
            }
            else
            {
                bW.Write(Convert.ToByte(clusterNodes.Count));

                foreach (ClusterNode node in clusterNodes.Values)
                {
                    bool self = node.State == ClusterNodeState.Self;
                    node.WriteTo(bW, self ? selfAddresses : null, self ? selfUrl : null);
                }
            }
        }

        #endregion

        #region private

        private void DisposeAllNodes()
        {
            IReadOnlyDictionary<int, ClusterNode> clusterNodes = _clusterNodes;
            if (clusterNodes is not null)
            {
                foreach (KeyValuePair<int, ClusterNode> clusterNode in clusterNodes)
                    clusterNode.Value.Dispose();
            }
        }

        private static void InitializeHeartbeatTimerFor(IReadOnlyDictionary<int, ClusterNode> clusterNodes)
        {
            //start heartbeat timers for all nodes except self node
            foreach (KeyValuePair<int, ClusterNode> node in clusterNodes)
            {
                if (node.Value.State == ClusterNodeState.Self)
                    continue;

                node.Value.InitializeHeartbeatTimer();
            }
        }

        private void UpdateHeartbeatTimerForAllClusterNodes()
        {
            IReadOnlyDictionary<int, ClusterNode> clusterNodes = _clusterNodes;
            if (clusterNodes is not null)
            {
                foreach (KeyValuePair<int, ClusterNode> clusterNode in clusterNodes)
                {
                    if (clusterNode.Value.State == ClusterNodeState.Self)
                        continue;

                    clusterNode.Value.UpdateHeartbeatTimer();
                }
            }
        }

        private void DeleteAllClusterConfig()
        {
            //delete cluster catalog zone
            string clusterCatalogDomain = "cluster-catalog." + _clusterDomain;

            AuthZoneInfo clusterCatalogZoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(clusterCatalogDomain);
            if (clusterCatalogZoneInfo is not null)
            {
                if (_dnsWebService.DnsServer.AuthZoneManager.DeleteZone(clusterCatalogZoneInfo, true))
                    _dnsWebService.AuthManager.RemoveAllPermissions(PermissionSection.Zones, clusterCatalogDomain);
            }

            //remove TSIG key for cluster catalog zone
            {
                IReadOnlyDictionary<string, TsigKey> existingKeys = _dnsWebService.DnsServer.TsigKeys;
                if (existingKeys is not null)
                {
                    Dictionary<string, TsigKey> updatedKeys = new Dictionary<string, TsigKey>(existingKeys);
                    updatedKeys.Remove(clusterCatalogDomain);

                    _dnsWebService.DnsServer.TsigKeys = updatedKeys;
                }
            }

            //delete cluster API token
            {
                foreach (UserSession session in _dnsWebService.AuthManager.Sessions)
                {
                    if (session.Type == UserSessionType.ClusterApiToken)
                    {
                        _dnsWebService.AuthManager.DeleteSession(session.Token);
                        break;
                    }
                }
            }

            //finalize
            if (_dnsWebService.DnsServer.ServerDomain.EndsWith("." + _clusterDomain, StringComparison.OrdinalIgnoreCase))
                _dnsWebService.DnsServer.ServerDomain = _dnsWebService.DnsServer.ServerDomain.Substring(0, _dnsWebService.DnsServer.ServerDomain.Length - (_clusterDomain.Length + 1));

            //save all changes
            _dnsWebService.DnsServer.SaveConfigFile();
            _dnsWebService.AuthManager.SaveConfigFile();

            UnloadAndDeleteConfigFile();
        }

        #endregion

        #region primary node

        internal string PreparePrimaryInitialization(string domain, IReadOnlyList<IPAddress> addresses, User user)
        {
            if (ClusterInitialized)
                throw new DnsServerException("Failed to initialize Cluster: the Cluster is already initialized.");

            if (user.Type != UserType.Local)
                throw new DnsServerException("Failed to initialize Cluster: only a local administrator user can initialize cluster. Please login with a local administrator user account and try again.");

            if (addresses.Count is 0 or > byte.MaxValue)
                throw new DnsServerException("Failed to initialize Cluster: specify between 1 and 255 Primary node IP addresses.");

            string clusterDomain = ConfigurationManifest.CanonicalDnsName(domain, "/cluster/domain", allowRoot: false);
            _dnsWebService.DnsServer.CheckManifestServerDomain(GetBootstrapNodeName(clusterDomain));
            string catalogDomain = ConfigurationManifest.CanonicalDnsName("cluster-catalog." + clusterDomain, "/cluster/domain", allowRoot: false);
            var zones = _dnsWebService.DnsServer.AuthZoneManager;
            CheckZone(clusterDomain, AuthZoneType.Primary);
            CheckZone(catalogDomain, AuthZoneType.Catalog);
            return clusterDomain;

            void CheckZone(string name, AuthZoneType expectedType)
            {
                AuthZoneManager.ValidateZoneName(name);
                zones.CheckManifestZoneMembership(name);
                AuthZoneInfo existing = zones.GetAuthZoneInfo(name);
                if (existing is not null && existing.Type != expectedType)
                    throw new DnsServerException($"Failed to initialize Cluster: zone '{name}' already exists and must be a {expectedType} zone.");
            }
        }

        private string GetBootstrapNodeName(string clusterDomain)
        {
            string serverDomain = _dnsWebService.DnsServer.ServerDomain;
            if (serverDomain.EndsWith("." + clusterDomain, StringComparison.OrdinalIgnoreCase))
                return serverDomain;

            int labelEnd = serverDomain.IndexOf('.');
            return labelEnd < 0 ? serverDomain + "." + clusterDomain : string.Concat(serverDomain.AsSpan(0, labelEnd), ".", clusterDomain);
        }

        internal void InitializeCluster(string clusterDomain, IReadOnlyList<IPAddress> primaryNodeIpAddresses, User user, IPAddress remoteAddress, string userAgent, ConfigurationClusterOptions.Settings? options = null)
        {
            if (!_dnsWebService.IsWebServiceTlsEnabled)
                throw new InvalidOperationException();

            //create self node
            string serverDomain = GetBootstrapNodeName(clusterDomain);
            Uri primaryNodeUrl = new Uri($"https://{serverDomain}:{_dnsWebService.WebServiceTlsPort}/");

            ClusterNode selfPrimaryNode = new ClusterNode(this, RandomNumberGenerator.GetInt32(int.MaxValue), primaryNodeUrl, primaryNodeIpAddresses, ClusterNodeType.Primary, ClusterNodeState.Self);

            //create cluster primary zone
            AuthZoneInfo clusterZoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(clusterDomain);
            if (clusterZoneInfo is null)
            {
                clusterZoneInfo = _dnsWebService.DnsServer.AuthZoneManager.CreatePrimaryZone(clusterDomain);
                if (clusterZoneInfo is null)
                    throw new DnsServerException($"Failed to initialize Cluster: failed to create the Cluster zone '{clusterDomain}'. Please try again.");
            }
            else if (clusterZoneInfo.Type != AuthZoneType.Primary)
            {
                throw new DnsServerException($"Failed to initialize Cluster: the zone '{clusterZoneInfo.Name}' already exists and is not a Primary zone. Please delete the existing zone or use a different Cluster domain name.");
            }

            //create cluster catalog zone
            string clusterCatalogDomain = "cluster-catalog." + clusterDomain;

            AuthZoneInfo clusterCatalogZoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(clusterCatalogDomain);
            if (clusterCatalogZoneInfo is null)
            {
                clusterCatalogZoneInfo = _dnsWebService.DnsServer.AuthZoneManager.CreateCatalogZone(clusterCatalogDomain);
                if (clusterCatalogZoneInfo is null)
                    throw new DnsServerException($"Failed to initialize Cluster: failed to create the Cluster Catalog zone '{clusterCatalogDomain}'. Please try again.");
            }
            else if (clusterCatalogZoneInfo.Type != AuthZoneType.Catalog)
            {
                throw new DnsServerException($"Failed to initialize Cluster: the zone '{clusterCatalogZoneInfo.Name}' already exists and is not a Catalog zone. Please delete the existing zone or use a different Cluster domain name.");
            }

            //set cluster primary zone permissions
            _dnsWebService.AuthManager.SetPermission(PermissionSection.Zones, clusterZoneInfo.Name, _dnsWebService.AuthManager.GetGroup(Group.ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
            _dnsWebService.AuthManager.SetPermission(PermissionSection.Zones, clusterZoneInfo.Name, _dnsWebService.AuthManager.GetGroup(Group.DNS_ADMINISTRATORS), PermissionFlag.View);

            //set cluster catalog zone permissions
            _dnsWebService.AuthManager.SetPermission(PermissionSection.Zones, clusterCatalogZoneInfo.Name, _dnsWebService.AuthManager.GetGroup(Group.ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
            _dnsWebService.AuthManager.SetPermission(PermissionSection.Zones, clusterCatalogZoneInfo.Name, _dnsWebService.AuthManager.GetGroup(Group.DNS_ADMINISTRATORS), PermissionFlag.View);

            //ensure cluster zone is a member of cluster catalog zone
            if (clusterZoneInfo.CatalogZoneName is null)
                _dnsWebService.DnsServer.AuthZoneManager.AddCatalogMemberZone(clusterCatalogZoneInfo.Name, clusterZoneInfo);
            else if (!clusterZoneInfo.CatalogZoneName.Equals(clusterCatalogZoneInfo.Name, StringComparison.OrdinalIgnoreCase))
                _dnsWebService.DnsServer.AuthZoneManager.ChangeCatalogMemberZoneOwnership(clusterZoneInfo, clusterCatalogZoneInfo.Name);

            //sign cluster zone
            if (clusterZoneInfo.ApexZone.DnssecStatus == AuthZoneDnssecStatus.Unsigned)
            {
                DnssecPrivateKey kskPrivateKey = DnssecPrivateKey.Create(DnssecAlgorithm.ECDSAP256SHA256, DnssecPrivateKeyType.KeySigningKey);
                DnssecPrivateKey zskPrivateKey = DnssecPrivateKey.Create(DnssecAlgorithm.ECDSAP256SHA256, DnssecPrivateKeyType.ZoneSigningKey);
                zskPrivateKey.RolloverDays = 90;

                _dnsWebService.DnsServer.AuthZoneManager.SignPrimaryZone(clusterZoneInfo.Name, kskPrivateKey, zskPrivateKey, 3600, false);
            }

            //create TSIG key for cluster catalog zone if it does not exist
            {
                IReadOnlyDictionary<string, TsigKey> existingKeys = _dnsWebService.DnsServer.TsigKeys;
                if (existingKeys is null)
                {
                    Dictionary<string, TsigKey> updatedKeys = new Dictionary<string, TsigKey>();
                    updatedKeys[clusterCatalogDomain] = new TsigKey(clusterCatalogDomain, TsigAlgorithm.HMAC_SHA256);

                    _dnsWebService.DnsServer.TsigKeys = updatedKeys;
                }
                else if (!existingKeys.ContainsKey(clusterCatalogDomain))
                {
                    Dictionary<string, TsigKey> updatedKeys = new Dictionary<string, TsigKey>(existingKeys);
                    updatedKeys[clusterCatalogDomain] = new TsigKey(clusterCatalogDomain, TsigAlgorithm.HMAC_SHA256);

                    _dnsWebService.DnsServer.TsigKeys = updatedKeys;
                }
            }

            //create cluster API token if it does not exist
            {
                List<UserSession> userSessions = _dnsWebService.AuthManager.GetSessions(user);
                bool apiTokenExists = false;

                foreach (UserSession existingSession in userSessions)
                {
                    if (existingSession.Type == UserSessionType.ClusterApiToken)
                    {
                        apiTokenExists = true;
                        break;
                    }
                }

                if (!apiTokenExists)
                    _dnsWebService.AuthManager.CreateSession(UserSessionType.ClusterApiToken, clusterZoneInfo.Name, user.Username, remoteAddress, userAgent);
            }

            //dispose existing nodes, if any
            DisposeAllNodes();

            //initialize cluster
            _clusterNodes = new Dictionary<int, ClusterNode>(1)
            {
                [selfPrimaryNode.Id] = selfPrimaryNode
            };

            _clusterDomain = clusterZoneInfo.Name;
            SetManifestOptions(options ?? DefaultManifestOptions);

            //update cluster primary zone and save zone file
            FindExistingRecordTtlValues(out uint nsTtl, out uint aTtl); //find existing record TTL values
            RemoveAllClusterPrimaryZoneNSRecords(); //remove all existing NS records
            AddClusterPrimaryZoneRecordsFor(selfPrimaryNode, nsTtl, aTtl, _dnsWebService.WebServiceTlsCertificate);

            //update cluster catalog zone ACLs, TSIG key name and save zone file
            UpdateClusterCatalogZoneOptions(clusterCatalogZoneInfo);

            //finalize
            _dnsWebService.DnsServer.ServerDomain = selfPrimaryNode.Name;

            //save all changes
            _dnsWebService.DnsServer.SaveConfigFile(true);
            _dnsWebService.AuthManager.SaveConfigFile(true);
            SaveConfigFile(immediately: options.HasValue);
        }

        internal static ConfigurationClusterOptions.Settings DefaultManifestOptions => new(
            HEARTBEAT_REFRESH_INTERVAL_SECONDS, HEARTBEAT_RETRY_INTERVAL_SECONDS, CONFIG_REFRESH_INTERVAL_SECONDS, CONFIG_RETRY_INTERVAL_SECONDS);

        internal void InitializePrimaryFromManifest(ConfigurationClusterOptions.PrimaryBootstrap bootstrap, User admin)
        {
            string catalog = "cluster-catalog." + bootstrap.Domain;
            var zones = _dnsWebService.DnsServer.AuthZoneManager;
            ConfigurationJournal.Persist(_dnsWebService.ConfigFolder, () =>
            {
                try
                {
                    InitializeCluster(bootstrap.Domain, bootstrap.Addresses, admin, IPAddress.Loopback, null, bootstrap.Options);
                    zones.FlushZoneSaves(bootstrap.Domain, catalog);
                    WriteManifestOwnership(bootstrap.Ownership);
                }
                finally
                {
                    zones.ClearClusterBootstrapSaves(bootstrap.Domain, catalog);
                }
            }, "dns.config", "auth.config", "cluster.config", ConfigurationClusterOptions.OwnershipFile,
                Path.Combine("zones", bootstrap.Domain + ".zone"), Path.Combine("zones", catalog + ".zone"));
            _managedOptionNames = bootstrap.Ownership;
        }

        internal ClusterRecordChange[] PrepareLivePrimaryBootstrap(ConfigurationClusterOptions.PrimaryBootstrap bootstrap)
        {
            var zones = _dnsWebService.DnsServer.AuthZoneManager;
            if (zones.GetAuthZoneInfo(bootstrap.Domain) is not null ||
                zones.GetAuthZoneInfo("cluster-catalog." + bootstrap.Domain) is not null)
                throw new InvalidDataException("/cluster/bootstrap: Use startup bootstrap to adopt existing cluster zones.");

            var reverseRecords = new List<ClusterRecordChange>();
            foreach (IPAddress address in bootstrap.Addresses)
            {
                string owner = Zone.GetReverseZone(address, address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128);
                AuthZoneInfo reverse = zones.FindAuthZoneInfo(owner);
                if (reverse?.Type is not (AuthZoneType.Primary or AuthZoneType.Forwarder))
                    continue;

                zones.CheckManifestZoneRecords(reverse.Name);
                reverseRecords.Add(new ClusterRecordChange(reverse.Name, owner, DnsResourceRecordType.PTR,
                    zones.GetRecords(reverse.Name, owner, DnsResourceRecordType.PTR).ToArray(), [], reverse.LastModified));
            }

            return reverseRecords.ToArray();
        }

        internal void InitializeLivePrimaryFromManifest(ConfigurationClusterOptions.PrimaryBootstrap bootstrap, User actor,
            ClusterRecordChange[] reverseRecords)
        {
            var dns = _dnsWebService.DnsServer;
            var zones = dns.AuthZoneManager;
            var auth = _dnsWebService.AuthManager;
            string domain = dns.ServerDomain;
            var keys = dns.TsigKeys;
            var tokens = auth.Sessions.Where(session => session.Type == UserSessionType.ClusterApiToken).Select(session => session.Token).ToHashSet();
            string catalog = "cluster-catalog." + bootstrap.Domain;
            string[] reverseZones = reverseRecords.Select(record => record.Zone).Distinct().ToArray();
            var previousOptions = GetManifestOptions();
            var previousGrants = new[] { bootstrap.Domain, catalog }.Select(name =>
                (Name: name, Groups: auth.GetPermission(PermissionSection.Zones, name)?.GroupPermissions.ToArray())).ToArray();
            bool started = false;
            try
            {
                ConfigurationJournal.Persist(_dnsWebService.ConfigFolder, () =>
                {
                    try
                    {
                        started = true;
                        InitializeCluster(bootstrap.Domain, bootstrap.Addresses, actor, IPAddress.Loopback, null, bootstrap.Options);
                        zones.FlushZoneSaves([bootstrap.Domain, catalog, .. reverseZones]);
                        WriteManifestOwnership(bootstrap.Ownership);
                    }
                    finally
                    {
                        zones.ClearClusterBootstrapSaves([bootstrap.Domain, catalog, .. reverseZones]);
                    }
                }, ["dns.config", "auth.config", "cluster.config", ConfigurationClusterOptions.OwnershipFile,
                    Path.Combine("zones", bootstrap.Domain + ".zone"), Path.Combine("zones", catalog + ".zone"),
                    .. reverseZones.Select(name => Path.Combine("zones", name + ".zone"))]);
            }
            catch
            {
                if (started)
                {
                    lock (_saveLock)
                    {
                        DisposeAllNodes();
                        _clusterNodes = null;
                        _clusterDomain = null;
                        _pendingSave = false;
                        SetManifestOptions(previousOptions);
                    }
                    zones.DeleteZone(bootstrap.Domain);
                    zones.DeleteZone(catalog);
                    foreach (ClusterRecordChange record in reverseRecords)
                    {
                        if (record.Previous.Count == 0)
                            zones.DeleteRecords(record.Zone, record.Owner, record.Type);
                        else
                            zones.SetRecords(record.Zone, record.Previous);
                        zones.SaveZoneFile(record.Zone);
                    }
                    foreach (var (name, groups) in previousGrants)
                    {
                        foreach (string groupName in new[] { Group.ADMINISTRATORS, Group.DNS_ADMINISTRATORS })
                        {
                            Group group = auth.GetGroup(groupName);
                            auth.RemovePermission(PermissionSection.Zones, name, group);
                            if (groups is not null && groups.FirstOrDefault(entry => entry.Key == group) is { Value: not PermissionFlag.None } grant)
                                auth.SetPermission(PermissionSection.Zones, name, group, grant.Value);
                        }
                    }
                    foreach (UserSession session in auth.Sessions)
                    {
                        if (session.Type == UserSessionType.ClusterApiToken && !tokens.Contains(session.Token))
                            auth.DeleteSession(session.Token);
                    }
                    dns.TsigKeys = keys;
                    dns.ServerDomain = domain;
                }
                throw;
            }
            _managedOptionNames = bootstrap.Ownership;
        }

        public void DeleteCluster(bool forceDelete)
        {
            if (!ClusterInitialized)
                throw new DnsServerException("Failed to delete Cluster: the Cluster is not initialized.");

            if (GetSelfNode().Type != ClusterNodeType.Primary)
                throw new DnsServerException("Failed to delete Cluster: only a Primary node can delete the Cluster.");

            CheckManifestTopologyChange();

            if (!forceDelete && (_clusterNodes.Count > 1))
                throw new DnsServerException("Failed to delete Cluster: please remove all Secondary nodes before deleting the Cluster.");

            DeleteAllClusterConfig();
        }

        internal void CompletePrimaryHandoff(int successorId, string revision)
        {
            if (!ClusterInitialized || GetSelfNode().Type != ClusterNodeType.Primary ||
                !_clusterNodes.TryGetValue(successorId, out ClusterNode successor) || successor.Type != ClusterNodeType.Secondary)
                throw new DnsServerException("Cluster handoff requires a registered Secondary successor.");

            string currentRevision = GetPrimaryHandoffRevision(GetSelfNode().Id, successorId);
            if (!string.Equals(revision, currentRevision, StringComparison.Ordinal))
                throw new DnsServerException("/cluster: The interval policy changed during handoff. Retry promotion.");

            DeleteAllClusterConfig();
        }

        private string GetPrimaryHandoffRevision(int primaryId, int successorId)
        {
            byte[] payload = JsonSerializer.SerializeToUtf8Bytes(new
            {
                domain = _clusterDomain,
                primaryId,
                successorId,
                options = GetManifestOptions(),
                ownership = _managedOptionNames.Where(ConfigurationClusterOptions.IsInterval).Order(StringComparer.Ordinal)
            });
            return Convert.ToHexString(SHA256.HashData(payload));
        }

        public ClusterNode JoinCluster(int secondaryNodeId, Uri secondaryNodeUrl, IReadOnlyList<IPAddress> secondaryNodeIpAddresses, X509Certificate2 secondaryNodeCertificate, bool supportsDeclarativeOptions)
        {
            if (!ClusterInitialized)
                throw new DnsServerException("Failed to add Secondary node: the Cluster is not initialized.");

            if (GetSelfNode().Type != ClusterNodeType.Primary)
                throw new DnsServerException("Failed to add Secondary node: only a Primary node can add a Secondary node to the Cluster.");

            string secondaryNodeDomain = secondaryNodeUrl.Host.ToLowerInvariant();

            if (!secondaryNodeDomain.EndsWith("." + _clusterDomain, StringComparison.OrdinalIgnoreCase))
                throw new DnsServerException("Failed to add Secondary node: the Secondary node domain name must be a subdomain of the Cluster domain name.");

            IReadOnlyDictionary<int, ClusterNode> existingClusterNodes = _clusterNodes;

            //validate for duplicate names
            foreach (KeyValuePair<int, ClusterNode> existingClusterNode in existingClusterNodes)
            {
                if (existingClusterNode.Value.Name.Equals(secondaryNodeUrl.Host, StringComparison.OrdinalIgnoreCase))
                    throw new DnsServerException("Failed to add Secondary node: A node with the same DNS Server Domain Name already exists in the Cluster. Please try again after changing the Secondary node's DNS Server Domain Name.");
            }

            //add secondary node to cluster nodes
            ClusterNode secondaryNode = new ClusterNode(this, secondaryNodeId, secondaryNodeUrl, secondaryNodeIpAddresses, ClusterNodeType.Secondary, ClusterNodeState.Unknown)
            {
                SupportsDeclarativeClusterOptions = supportsDeclarativeOptions
            };
            Dictionary<int, ClusterNode> updatedClusterNodes = new Dictionary<int, ClusterNode>(existingClusterNodes.Count + 1);

            foreach (KeyValuePair<int, ClusterNode> existingClusterNode in existingClusterNodes)
                updatedClusterNodes[existingClusterNode.Value.Id] = existingClusterNode.Value;

            if (!updatedClusterNodes.TryAdd(secondaryNode.Id, secondaryNode))
                throw new DnsServerException("Failed to add Secondary node: node ID already exists in the Cluster. Please try again.");

            if (updatedClusterNodes.Count > 255)
                throw new DnsServerException("Failed to add Secondary node: a maximum of 255 nodes are supported by the Cluster.");

            IReadOnlyDictionary<int, ClusterNode> originalValue = Interlocked.CompareExchange(ref _clusterNodes, updatedClusterNodes, existingClusterNodes);
            if (!ReferenceEquals(originalValue, existingClusterNodes))
                throw new DnsServerException("Failed to add Secondary node: please try again.");

            secondaryNode.InitializeHeartbeatTimer();

            //update cluster zone and save zone file
            FindExistingRecordTtlValues(out uint nsTtl, out uint aTtl); //find existing record TTL values
            AddClusterPrimaryZoneRecordsFor(secondaryNode, nsTtl, aTtl, secondaryNodeCertificate);

            //update cluster catalog zone ACLs and save zone file
            UpdateClusterCatalogZoneOptions();

            //save all changes
            SaveConfigFile();

            //notify all secondary nodes
            TriggerNotifyAllSecondaryNodes();

            //trigger NS and SOA update for member zones
            TriggerRecordUpdateForClusterCatalogMemberZones();

            return secondaryNode;
        }

        public async Task<ClusterNode> AskSecondaryNodeToLeaveClusterAsync(int secondaryNodeId)
        {
            if (!ClusterInitialized)
                throw new DnsServerException("Failed to ask Secondary node to leave: the Cluster is not initialized.");

            if (GetSelfNode().Type != ClusterNodeType.Primary)
                throw new DnsServerException("Failed to ask Secondary node to leave: only a Primary node can ask a Secondary node to leave the Cluster.");

            //find existing secondary node
            if (!_clusterNodes.TryGetValue(secondaryNodeId, out ClusterNode secondaryNode))
                throw new DnsServerException("Failed to ask Secondary node to leave: the specified node does not exist in the Cluster.");

            if (secondaryNode.Type == ClusterNodeType.Primary)
                throw new DnsServerException("Failed to ask Secondary node to leave: the specified node is the Cluster Primary node and cannot be removed.");

            //ask secondary node to leave the cluster
            await secondaryNode.AskSecondaryNodeToLeaveClusterAsync();

            return secondaryNode;
        }

        public ClusterNode DeleteSecondaryNode(int secondaryNodeId)
        {
            if (!ClusterInitialized)
                throw new DnsServerException("Failed to delete Secondary node: the Cluster is not initialized.");

            if (GetSelfNode().Type != ClusterNodeType.Primary)
                throw new DnsServerException("Failed to delete Secondary node: only a Primary node can delete a Secondary node from the Cluster.");

            //find existing secondary node
            IReadOnlyDictionary<int, ClusterNode> existingClusterNodes = _clusterNodes;

            if (!existingClusterNodes.TryGetValue(secondaryNodeId, out ClusterNode secondaryNode))
                throw new DnsServerException("Failed to delete Secondary node: the specified node does not exist in the Cluster.");

            if (secondaryNode.Type == ClusterNodeType.Primary)
                throw new DnsServerException("Failed to delete Secondary node: the specified node is the Cluster Primary node and cannot be deleted.");

            //delete secondary node from cluster nodes
            Dictionary<int, ClusterNode> updatedClusterNodes = new Dictionary<int, ClusterNode>(existingClusterNodes.Count - 1);

            foreach (KeyValuePair<int, ClusterNode> existingClusterNode in existingClusterNodes)
            {
                if (existingClusterNode.Key == secondaryNodeId)
                    continue;

                updatedClusterNodes[existingClusterNode.Key] = existingClusterNode.Value;
            }

            IReadOnlyDictionary<int, ClusterNode> originalValue = Interlocked.CompareExchange(ref _clusterNodes, updatedClusterNodes, existingClusterNodes);
            if (!ReferenceEquals(originalValue, existingClusterNodes))
                throw new InvalidOperationException("Failed to delete Secondary node: please try again.");

            secondaryNode.Dispose();

            //update cluster zone and save zone file
            RemoveClusterPrimaryZoneRecordsFor(secondaryNode);

            //update cluster catalog zone ACLs and save zone file
            UpdateClusterCatalogZoneOptions();

            //save all changes
            SaveConfigFile();

            //notify all secondary nodes
            TriggerNotifyAllSecondaryNodes();

            //trigger NS and SOA update for member zones
            TriggerRecordUpdateForClusterCatalogMemberZones();

            return secondaryNode;
        }

        public ClusterNode UpdateSecondaryNode(int secondaryNodeId, Uri secondaryNodeUrl, IReadOnlyList<IPAddress> secondaryNodeIpAddresses, X509Certificate2 secondaryNodeCertificate)
        {
            if (!ClusterInitialized)
                throw new DnsServerException("Failed to update Secondary node: the Cluster is not initialized.");

            if (GetSelfNode().Type != ClusterNodeType.Primary)
                throw new DnsServerException("Failed to update Secondary node: only a Primary node can update a Secondary node's details in the Cluster.");

            IReadOnlyDictionary<int, ClusterNode> clusterNodes = _clusterNodes;

            if (!clusterNodes.TryGetValue(secondaryNodeId, out ClusterNode secondaryNode))
                throw new DnsServerException("Failed to update Secondary node: the specified node does not exist in the Cluster.");

            if (secondaryNode.Type != ClusterNodeType.Secondary)
                throw new DnsServerException("Failed to update Secondary node: the specified node to update must be a Secondary node.");

            //validate for duplicate names
            foreach (KeyValuePair<int, ClusterNode> clusterNode in clusterNodes)
            {
                if (clusterNode.Key == secondaryNodeId)
                    continue; //skip self

                if (clusterNode.Value.Name.Equals(secondaryNodeUrl.Host, StringComparison.OrdinalIgnoreCase))
                    throw new DnsServerException("Failed to update Secondary node: A node with the same DNS Server Domain Name already exists in the Cluster. Please try again after changing the Secondary node's DNS Server Domain Name.");
            }

            bool secondaryNodeDomainChanged = !secondaryNode.Name.Equals(secondaryNodeUrl.Host, StringComparison.OrdinalIgnoreCase);

            //find existing record TTL values
            FindExistingRecordTtlValues(out uint nsTtl, out uint aTtl);

            //update cluster zone to remove existing records for secondary node
            RemoveClusterPrimaryZoneRecordsFor(secondaryNode);

            //update secondary node URL and IP address
            secondaryNode.UpdateNode(secondaryNodeUrl, secondaryNodeIpAddresses);

            //update cluster zone to add updated records for secondary node and save zone file
            AddClusterPrimaryZoneRecordsFor(secondaryNode, nsTtl, aTtl, secondaryNodeCertificate);

            //update cluster catalog zone ACLs and save zone file
            UpdateClusterCatalogZoneOptions();

            //save all changes
            SaveConfigFile();

            //notify all secondary nodes
            TriggerNotifyAllSecondaryNodes();

            //trigger NS and SOA update for member zones only if secondary node domain name has changed
            if (secondaryNodeDomainChanged)
                TriggerRecordUpdateForClusterCatalogMemberZones();

            return secondaryNode;
        }

        public Task TransferConfigAsync(Stream zipStream, DateTime ifModifiedSince, ICollection<string> includeZones)
        {
            if (!ClusterInitialized)
                throw new DnsServerException("Failed to transfer configuration: the Cluster is not initialized.");

            if (GetSelfNode().Type != ClusterNodeType.Primary)
                throw new DnsServerException("Failed to transfer configuration: only the Primary node can transfer the configuration.");

            return _dnsWebService.BackupConfigAsync(zipStream: zipStream,
                                                    authConfig: true,
                                                    clusterConfig: false,
                                                    webServiceSettings: false,
                                                    dnsSettings: true,
                                                    logSettings: false,
                                                    zones: true,
                                                    allowedZones: true,
                                                    blockedZones: true,
                                                    blockLists: true,
                                                    apps: true,
                                                    scopes: false,
                                                    stats: false,
                                                    logs: false,
                                                    isConfigTransfer: true,
                                                    ifModifiedSince: ifModifiedSince,
                                                    includeZones: includeZones);
        }

        public void UpdateClusterOptions(ushort heartbeatRefreshIntervalSeconds, ushort heartbeatRetryIntervalSeconds, ushort configRefreshIntervalSeconds, ushort configRetryIntervalSeconds)
        {
            if (!ClusterInitialized)
                throw new DnsServerException("Failed to update Cluster options: the Cluster is not initialized.");

            if (GetSelfNode().Type != ClusterNodeType.Primary)
                throw new DnsServerException("Failed to update Cluster options: only the Primary node can update the Cluster options.");

            var desired = new ConfigurationClusterOptions.Settings(heartbeatRefreshIntervalSeconds,
                heartbeatRetryIntervalSeconds, configRefreshIntervalSeconds, configRetryIntervalSeconds);
            lock (_saveLock)
            {
                var current = GetManifestOptions();
                ValidateClusterOptions(desired);
                if (current == desired)
                    return;

                if (_managedOptionNames.Length != 0)
                {
                    JsonElement currentOptions = ConfigurationClusterOptions.Export(current);
                    JsonElement desiredOptions = ConfigurationClusterOptions.Export(desired);
                    foreach (string name in _managedOptionNames.Where(ConfigurationClusterOptions.IsInterval))
                    {
                        if (!JsonElement.DeepEquals(currentOptions.GetProperty(name), desiredOptions.GetProperty(name)))
                            throw new DnsServerException($"/cluster/{name}: This setting is managed by the configuration manifest.");
                    }
                }

                SetManifestOptions(desired);
                SaveConfigFile();
            }

            UpdateHeartbeatTimerForAllClusterNodes();
            TriggerNotifyAllSecondaryNodes();
        }

        internal IReadOnlyList<string> ManagedOptionNames => _managedOptionNames;

        internal void CheckManifestTopologyChange()
        {
            if (_managedOptionNames.Length != 0)
                throw new DnsServerException("/cluster: Release manifest ownership of cluster options before replacing the cluster configuration.");
        }

        private void SetManifestOptions(ConfigurationClusterOptions.Settings options) =>
            (_heartbeatRefreshIntervalSeconds, _heartbeatRetryIntervalSeconds, _configRefreshIntervalSeconds, _configRetryIntervalSeconds) = options;

        internal ConfigurationClusterOptions.Settings GetManifestOptions()
        {
            lock (_saveLock)
                return new(_heartbeatRefreshIntervalSeconds, _heartbeatRetryIntervalSeconds, _configRefreshIntervalSeconds, _configRetryIntervalSeconds);
        }

        internal static void ValidateClusterOptions(ConfigurationClusterOptions.Settings settings)
        {
            var (heartbeatRefreshIntervalSeconds, heartbeatRetryIntervalSeconds, configRefreshIntervalSeconds, configRetryIntervalSeconds) = settings;
            if ((heartbeatRefreshIntervalSeconds < 10) || (heartbeatRefreshIntervalSeconds > 300))
                throw new ArgumentOutOfRangeException(nameof(heartbeatRefreshIntervalSeconds));

            if ((heartbeatRetryIntervalSeconds < 10) || (heartbeatRetryIntervalSeconds > 300))
                throw new ArgumentOutOfRangeException(nameof(heartbeatRetryIntervalSeconds));

            if ((configRefreshIntervalSeconds < 30) || (configRefreshIntervalSeconds > 3600))
                throw new ArgumentOutOfRangeException(nameof(configRefreshIntervalSeconds));

            if ((configRetryIntervalSeconds < 30) || (configRetryIntervalSeconds > 3600))
                throw new ArgumentOutOfRangeException(nameof(configRetryIntervalSeconds));

            if (configRefreshIntervalSeconds <= heartbeatRefreshIntervalSeconds)
                throw new ArgumentException("Failed to update Cluster options: The config refresh interval must be greater than the heartbeat refresh interval.");

        }

        internal sealed record ClusterRecordChange(string Zone, string Owner, DnsResourceRecordType Type,
            IReadOnlyList<DnsResourceRecord> Previous, IReadOnlyList<DnsResourceRecord> Desired, DateTime Revision);

        internal ClusterRecordChange[] PreparePrimaryNodeRecords(ClusterNode self, IReadOnlyList<IPAddress> desired, Uri endpoint)
        {
            bool addressesChanged = !ConfigurationClusterOptions.SameAddresses(self.IPAddresses, desired);
            bool portChanged = self.Url.Port != endpoint.Port;
            if (!addressesChanged && !portChanged)
                return [];

            var zones = _dnsWebService.DnsServer.AuthZoneManager;
            AuthZoneInfo zone = zones.GetAuthZoneInfo(_clusterDomain);
            if (zone?.Type != AuthZoneType.Primary || zones.GetRecords(zone.Name, self.Name, DnsResourceRecordType.CNAME).Count != 0)
                throw new InvalidDataException("/cluster: The Primary zone must contain an addressable node name.");

            FindExistingRecordTtlValues(out _, out uint ttl);
            var changes = new List<ClusterRecordChange>();
            if (addressesChanged)
            {
                AddForwardRecords(AddressFamily.InterNetwork, DnsResourceRecordType.A);
                AddForwardRecords(AddressFamily.InterNetworkV6, DnsResourceRecordType.AAAA);
            }

            if (portChanged)
            {
                X509Certificate2 certificate = _dnsWebService.WebServiceTlsCertificate;
                if (certificate is null)
                    throw new InvalidDataException("/web/tlsPort: Cluster HTTPS requires a certificate.");

                var association = new DnsTLSARecordData(DnsTLSACertificateUsage.DANE_EE, DnsTLSASelector.SPKI,
                    DnsTLSAMatchingType.SHA2_256, certificate);
                SetEndpointRecord(self.Url.Port, false);
                SetEndpointRecord(endpoint.Port, true);

                void SetEndpointRecord(int port, bool wanted)
                {
                    string owner = $"_{port}._tcp.{self.Name}";
                    IReadOnlyList<DnsResourceRecord> current = zones.GetRecords(zone.Name, owner, DnsResourceRecordType.TLSA);
                    if (wanted == current.Any(record => record.RDATA.Equals(association)))
                        return;

                    IReadOnlyList<DnsResourceRecord> next = wanted
                        ? [.. current, CreateRecord(owner, DnsResourceRecordType.TLSA, current.FirstOrDefault()?.TTL ?? ttl, association)]
                        : current.Where(record => !record.RDATA.Equals(association)).ToArray();
                    changes.Add(new ClusterRecordChange(zone.Name, owner, DnsResourceRecordType.TLSA, current.ToArray(), next, zone.LastModified));
                }
            }

            foreach (IPAddress address in self.IPAddresses.Except(desired).Concat(desired.Except(self.IPAddresses)))
            {
                string owner = Zone.GetReverseZone(address, address.AddressFamily == AddressFamily.InterNetwork ? 32 : 128);
                AuthZoneInfo reverse = zones.FindAuthZoneInfo(owner);
                if (reverse?.Type is not (AuthZoneType.Primary or AuthZoneType.Forwarder))
                    continue;

                IReadOnlyList<DnsResourceRecord> current = zones.GetRecords(reverse.Name, owner, DnsResourceRecordType.PTR);
                var ptr = new DnsPTRRecordData(self.Name);
                bool wanted = desired.Contains(address);
                if (wanted == current.Any(record => record.RDATA.Equals(ptr)))
                    continue;

                zones.CheckManifestZoneRecords(reverse.Name);
                IReadOnlyList<DnsResourceRecord> next = wanted
                    ? [.. current, CreateRecord(owner, DnsResourceRecordType.PTR, current.FirstOrDefault()?.TTL ?? ttl, ptr)]
                    : current.Where(record => !record.RDATA.Equals(ptr)).ToArray();
                changes.Add(new ClusterRecordChange(reverse.Name, owner, DnsResourceRecordType.PTR, current.ToArray(), next, reverse.LastModified));
            }

            return changes.ToArray();

            void AddForwardRecords(AddressFamily family, DnsResourceRecordType type)
            {
                IReadOnlyList<DnsResourceRecord> current = zones.GetRecords(zone.Name, self.Name, type);
                DnsResourceRecord[] next = desired.Where(address => address.AddressFamily == family)
                    .Select(address => CreateRecord(self.Name, type, ttl,
                        family == AddressFamily.InterNetwork ? new DnsARecordData(address) : new DnsAAAARecordData(address))).ToArray();
                if (!current.Select(record => record.RDATA).ToHashSet().SetEquals(next.Select(record => record.RDATA)))
                    changes.Add(new ClusterRecordChange(zone.Name, self.Name, type, current.ToArray(), next, zone.LastModified));
            }

            static DnsResourceRecord CreateRecord(string owner, DnsResourceRecordType type, uint ttl, DnsResourceRecordData data)
            {
                var record = new DnsResourceRecord(owner, type, DnsClass.IN, ttl, data);
                GenericRecordInfo info = record.GetAuthGenericRecordInfo();
                info.LastModified = DateTime.UtcNow;
                info.Comments = "Cluster managed record. Do not update or delete.";
                return record;
            }
        }

        internal int[] CheckDeclarativeIntervalPeers()
        {
            var peers = _clusterNodes.Values.Where(node => node.State != ClusterNodeState.Self).OrderBy(node => node.Id);
            var ids = new List<int>();
            foreach (ClusterNode peer in peers)
            {
                if (!peer.SupportsDeclarativeClusterOptions)
                    throw new InvalidDataException($"/cluster: Node '{peer.Name}' has not advertised support for declarative interval changes.");
                ids.Add(peer.Id);
            }
            return ids.ToArray();
        }

        internal void ApplyManifestOptions(ConfigurationClusterOptions.Candidate? candidate, Action<Action> persist)
        {
            if (candidate is not { } change || (!change.ValuesChanged && !change.AddressesChanged && !change.EndpointChanged && !change.OwnershipChanged))
            {
                persist(null);
                return;
            }

            lock (_saveLock)
            {
                if (!ClusterInitialized || GetSelfNode().Type != change.NodeType || GetSelfNode().Id != change.NodeId ||
                    GetSelfNode().Url != change.CurrentUrl || !ConfigurationClusterOptions.SameAddresses(GetSelfNode().IPAddresses, change.CurrentAddresses) || GetManifestOptions() != change.Current || !_managedOptionNames.SequenceEqual(change.CurrentOwnership))
                    throw new InvalidDataException("/cluster: Cluster options changed during apply. Create a new preview.");

                var zones = _dnsWebService.DnsServer.AuthZoneManager;
                string[] recordZones = change.ZoneRecords.Select(record => record.Zone).Distinct().ToArray();
                int appliedRecords = 0;
                try
                {
                    persist(() =>
                    {
                        if (change.ValuesChanged && !CheckDeclarativeIntervalPeers().SequenceEqual(change.IntervalPeers))
                            throw new InvalidDataException("/cluster: Cluster membership changed during apply. Create a new preview.");

                        foreach (ClusterRecordChange record in change.ZoneRecords)
                        {
                            if (zones.GetAuthZoneInfo(record.Zone)?.LastModified != record.Revision)
                                throw new InvalidDataException("/cluster: An affected zone changed during apply. Create a new preview.");
                        }
                        foreach (ClusterRecordChange record in change.ZoneRecords)
                        {
                            appliedRecords++;
                            ReplaceRecords(record, record.Desired);
                        }
                        if (recordZones.Length != 0)
                            zones.FlushZoneSaves(recordZones);
                        if (change.ValuesChanged || change.AddressesChanged || change.EndpointChanged)
                            SaveConfigFileInternal(change.ValuesChanged ? change.Desired : null,
                                change.AddressesChanged ? change.DesiredAddresses : null, change.EndpointChanged ? change.DesiredUrl : null);
                        if (change.OwnershipChanged)
                            WriteManifestOwnership(change.DesiredOwnership);
                    });
                }
                catch
                {
                    for (int index = appliedRecords - 1; index >= 0; index--)
                    {
                        ClusterRecordChange record = change.ZoneRecords[index];
                        ReplaceRecords(record, record.Previous);
                        zones.SaveZoneFile(record.Zone);
                    }
                    throw;
                }

                void ReplaceRecords(ClusterRecordChange record, IReadOnlyList<DnsResourceRecord> values)
                {
                    if (values.Count == 0)
                        zones.DeleteRecords(record.Zone, record.Owner, record.Type);
                    else
                        zones.SetRecords(record.Zone, values);
                }

                if (change.ValuesChanged)
                    SetManifestOptions(change.Desired);
                if (change.AddressesChanged)
                    GetSelfNode().UpdateSelfNodeIPAddresses(change.DesiredAddresses);
                if (change.EndpointChanged)
                    GetSelfNode().UpdateSelfNodeUrl(change.DesiredUrl);
                _managedOptionNames = change.DesiredOwnership;
            }

            if (change.ValuesChanged)
                UpdateHeartbeatTimerForAllClusterNodes();
            if (change.NodeType == ClusterNodeType.Primary && (change.ValuesChanged || change.AddressesChanged || change.EndpointChanged || change.OwnershipChanged))
                TriggerNotifyAllSecondaryNodes();
            else if (change.AddressesChanged || change.EndpointChanged)
                TriggerClusterUpdateForSecondaryNodeChanges();
        }

        private void WriteManifestOwnership(string[] names)
        {
            string file = Path.Combine(_dnsWebService.ConfigFolder, ConfigurationClusterOptions.OwnershipFile);
            if (names.Length == 0)
            {
                File.Delete(file);
                return;
            }

            string temporary = file + ".tmp";
            using (var stream = new FileStream(temporary, FileMode.Create, FileAccess.Write))
            {
                JsonSerializer.Serialize(stream, names);
                stream.Flush(flushToDisk: true);
            }
            File.Move(temporary, file, true);
        }

        private void FindExistingRecordTtlValues(out uint nsTtl, out uint aTtl)
        {
            //try get existing NS record TTL
            IReadOnlyList<DnsResourceRecord> existingNSRecords = _dnsWebService.DnsServer.AuthZoneManager.GetRecords(_clusterDomain, _clusterDomain, DnsResourceRecordType.NS);
            if (existingNSRecords.Count > 0)
            {
                DnsResourceRecord existingNSRecord = existingNSRecords[0];

                nsTtl = existingNSRecord.TTL;

                string nsDomain = (existingNSRecord.RDATA as DnsNSRecordData).NameServer;

                if (nsDomain.EndsWith("." + _clusterDomain, StringComparison.OrdinalIgnoreCase))
                {
                    IReadOnlyList<DnsResourceRecord> existingRecords = _dnsWebService.DnsServer.AuthZoneManager.GetRecords(_clusterDomain, nsDomain, DnsResourceRecordType.A);
                    if (existingRecords.Count == 0)
                        existingRecords = _dnsWebService.DnsServer.AuthZoneManager.GetRecords(_clusterDomain, nsDomain, DnsResourceRecordType.AAAA);

                    if (existingRecords.Count > 0)
                        aTtl = existingRecords[0].TTL;
                    else
                        aTtl = _dnsWebService.DnsServer.AuthZoneManager.DefaultRecordTtl;
                }
                else
                {
                    aTtl = _dnsWebService.DnsServer.AuthZoneManager.DefaultRecordTtl;
                }
            }
            else
            {
                nsTtl = _dnsWebService.DnsServer.AuthZoneManager.DefaultNsRecordTtl;
                aTtl = _dnsWebService.DnsServer.AuthZoneManager.DefaultRecordTtl;
            }
        }

        private void RemoveAllClusterPrimaryZoneNSRecords()
        {
            //remove all existing NS records
            _dnsWebService.DnsServer.AuthZoneManager.DeleteRecords(_clusterDomain, _clusterDomain, DnsResourceRecordType.NS);
        }

        private void RemoveClusterPrimaryZoneRecordsFor(ClusterNode node)
        {
            //remove NS record
            _dnsWebService.DnsServer.AuthZoneManager.DeleteRecord(_clusterDomain, _clusterDomain, DnsResourceRecordType.NS, new DnsNSRecordData(node.Name));

            //remove A/AAAA records
            _dnsWebService.DnsServer.AuthZoneManager.DeleteRecords(_clusterDomain, node.Name, DnsResourceRecordType.A);
            _dnsWebService.DnsServer.AuthZoneManager.DeleteRecords(_clusterDomain, node.Name, DnsResourceRecordType.AAAA);

            //remove CNAME records if manually added by user
            _dnsWebService.DnsServer.AuthZoneManager.DeleteRecords(_clusterDomain, node.Name, DnsResourceRecordType.CNAME);

            //remove PTR record
            foreach (IPAddress ipAddress in node.IPAddresses)
            {
                string ptrDomain = Zone.GetReverseZone(ipAddress, ipAddress.AddressFamily == AddressFamily.InterNetwork ? 32 : 128);

                AuthZoneInfo reverseZoneInfo = _dnsWebService.DnsServer.AuthZoneManager.FindAuthZoneInfo(ptrDomain);
                if (reverseZoneInfo is not null)
                {
                    if ((reverseZoneInfo.Type == AuthZoneType.Primary) || (reverseZoneInfo.Type == AuthZoneType.Forwarder))
                    {
                        _dnsWebService.DnsServer.AuthZoneManager.DeleteRecord(reverseZoneInfo.Name, ptrDomain, DnsResourceRecordType.PTR, new DnsPTRRecordData(node.Name));
                        _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(reverseZoneInfo.Name);
                    }
                }
            }

            //remove TLSA DANE-EE record
            _dnsWebService.DnsServer.AuthZoneManager.DeleteRecords(_clusterDomain, $"_{node.Url.Port}._tcp.{node.Name}", DnsResourceRecordType.TLSA);

            //save zone file
            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(_clusterDomain);
        }

        private void AddClusterPrimaryZoneRecordsFor(ClusterNode node, uint nsTtl, uint aTtl, X509Certificate2 certificate)
        {
            const string recordComments = "Cluster managed record. Do not update or delete.";

            if (node.Type == ClusterNodeType.Primary)
            {
                //update SOA record
                IReadOnlyList<DnsResourceRecord> existingSoaRecords = _dnsWebService.DnsServer.AuthZoneManager.GetRecords(_clusterDomain, _clusterDomain, DnsResourceRecordType.SOA);
                DnsResourceRecord existingSoaRecord = existingSoaRecords[0];
                DnsSOARecordData existingSoa = existingSoaRecord.RDATA as DnsSOARecordData;

                DnsSOARecordData newSoa = new DnsSOARecordData(node.Name, existingSoa.ResponsiblePerson, existingSoa.Serial, existingSoa.Refresh, existingSoa.Retry, existingSoa.Expire, existingSoa.Minimum);
                DnsResourceRecord newSoaRecord = new DnsResourceRecord(_clusterDomain, DnsResourceRecordType.SOA, DnsClass.IN, existingSoaRecord.TTL, newSoa);

                _dnsWebService.DnsServer.AuthZoneManager.SetRecord(_clusterDomain, newSoaRecord);
            }

            //add NS record
            DnsResourceRecord nsRecord = new DnsResourceRecord(_clusterDomain, DnsResourceRecordType.NS, DnsClass.IN, nsTtl, new DnsNSRecordData(node.Name));

            GenericRecordInfo nsRecordInfo = nsRecord.GetAuthGenericRecordInfo();
            nsRecordInfo.LastModified = DateTime.UtcNow;
            nsRecordInfo.Comments = recordComments;

            _dnsWebService.DnsServer.AuthZoneManager.AddRecord(_clusterDomain, nsRecord);

            //set A/AAAA record
            List<DnsResourceRecord> ipv4AddressRecords = new List<DnsResourceRecord>(node.IPAddresses.Count);
            List<DnsResourceRecord> ipv6AddressRecords = new List<DnsResourceRecord>(node.IPAddresses.Count);

            foreach (IPAddress ipAddress in node.IPAddresses)
            {
                DnsResourceRecord record;

                switch (ipAddress.AddressFamily)
                {
                    case AddressFamily.InterNetwork:
                        record = new DnsResourceRecord(node.Name, DnsResourceRecordType.A, DnsClass.IN, aTtl, new DnsARecordData(ipAddress));
                        ipv4AddressRecords.Add(record);
                        break;

                    case AddressFamily.InterNetworkV6:
                        record = new DnsResourceRecord(node.Name, DnsResourceRecordType.AAAA, DnsClass.IN, aTtl, new DnsAAAARecordData(ipAddress));
                        ipv6AddressRecords.Add(record);
                        break;

                    default:
                        throw new InvalidOperationException();
                }

                GenericRecordInfo recordInfo = record.GetAuthGenericRecordInfo();
                recordInfo.LastModified = DateTime.UtcNow;
                recordInfo.Comments = recordComments;
            }

            if (ipv4AddressRecords.Count > 0)
                _dnsWebService.DnsServer.AuthZoneManager.SetRecords(_clusterDomain, ipv4AddressRecords);

            if (ipv6AddressRecords.Count > 0)
                _dnsWebService.DnsServer.AuthZoneManager.SetRecords(_clusterDomain, ipv6AddressRecords);

            //set PTR record
            foreach (IPAddress ipAddress in node.IPAddresses)
            {
                string ptrDomain = Zone.GetReverseZone(ipAddress, ipAddress.AddressFamily == AddressFamily.InterNetwork ? 32 : 128);

                AuthZoneInfo reverseZoneInfo = _dnsWebService.DnsServer.AuthZoneManager.FindAuthZoneInfo(ptrDomain);
                if (reverseZoneInfo is not null)
                {
                    if ((reverseZoneInfo.Type == AuthZoneType.Primary) || (reverseZoneInfo.Type == AuthZoneType.Forwarder))
                    {
                        DnsResourceRecord ptrRecord = new DnsResourceRecord(ptrDomain, DnsResourceRecordType.PTR, DnsClass.IN, aTtl, new DnsPTRRecordData(node.Name));

                        GenericRecordInfo ptrRecordInfo = ptrRecord.GetAuthGenericRecordInfo();
                        ptrRecordInfo.LastModified = DateTime.UtcNow;
                        ptrRecordInfo.Comments = recordComments;

                        _dnsWebService.DnsServer.AuthZoneManager.SetRecord(reverseZoneInfo.Name, ptrRecord);
                        _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(reverseZoneInfo.Name);
                    }
                }
            }

            //set TLSA DANE-EE record
            DnsResourceRecord tlsaRecord = new DnsResourceRecord($"_{node.Url.Port}._tcp.{node.Name}", DnsResourceRecordType.TLSA, DnsClass.IN, aTtl, new DnsTLSARecordData(DnsTLSACertificateUsage.DANE_EE, DnsTLSASelector.SPKI, DnsTLSAMatchingType.SHA2_256, certificate));

            GenericRecordInfo tlsaRecordInfo = tlsaRecord.GetAuthGenericRecordInfo();
            tlsaRecordInfo.LastModified = DateTime.UtcNow;
            tlsaRecordInfo.Comments = recordComments;

            _dnsWebService.DnsServer.AuthZoneManager.SetRecord(_clusterDomain, tlsaRecord);

            //save zone file
            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(_clusterDomain);
        }

        public void UpdateClusterRecordsFor(AuthZoneInfo zoneInfo)
        {
            if (zoneInfo.Type != AuthZoneType.Primary)
                throw new InvalidOperationException();

            //set NS records for cluster
            IReadOnlyList<DnsResourceRecord> existingNSRecords = zoneInfo.ApexZone.GetRecords(DnsResourceRecordType.NS);
            uint ttl;

            if (existingNSRecords.Count > 0)
                ttl = existingNSRecords[0].TTL;
            else
                ttl = _dnsWebService.DnsServer.AuthZoneManager.DefaultNsRecordTtl;

            IReadOnlyDictionary<int, ClusterNode> clusterNodes = _clusterNodes;
            DnsResourceRecord[] nsRecords = new DnsResourceRecord[clusterNodes.Count];
            int i = 0;

            foreach (KeyValuePair<int, ClusterNode> clusterNode in clusterNodes)
                nsRecords[i++] = new DnsResourceRecord(zoneInfo.Name, DnsResourceRecordType.NS, DnsClass.IN, ttl, new DnsNSRecordData(clusterNode.Value.Name));

            //set NS record
            _dnsWebService.DnsServer.AuthZoneManager.SetRecords(zoneInfo.Name, nsRecords);

            //ensure correct SOA primary name server
            IReadOnlyList<DnsResourceRecord> existingSoaRecords = zoneInfo.ApexZone.GetRecords(DnsResourceRecordType.SOA);
            if (existingSoaRecords.Count > 0)
            {
                DnsResourceRecord existingSoaRecord = existingSoaRecords[0];
                DnsSOARecordData existingSoa = existingSoaRecord.RDATA as DnsSOARecordData;

                //set SOA record
                _dnsWebService.DnsServer.AuthZoneManager.SetRecords(zoneInfo.Name, [new DnsResourceRecord(zoneInfo.Name, DnsResourceRecordType.SOA, DnsClass.IN, existingSoaRecord.TTL, new DnsSOARecordData(_dnsWebService.DnsServer.ServerDomain, existingSoa.ResponsiblePerson, existingSoa.Serial, existingSoa.Refresh, existingSoa.Retry, existingSoa.Expire, existingSoa.Minimum))]);
            }
        }

        private void TriggerRecordUpdateForClusterCatalogMemberZones()
        {
            int id = RandomNumberGenerator.GetInt32(int.MaxValue);
            _recordUpdateForMemberZonesId = id;

            ThreadPool.QueueUserWorkItem(delegate (object state)
            {
                try
                {
                    //get cluster catalog zone info
                    AuthZoneInfo clusterCatalogZoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo("cluster-catalog." + _clusterDomain);
                    if ((clusterCatalogZoneInfo is null) || (clusterCatalogZoneInfo.Type != AuthZoneType.Catalog))
                        throw new InvalidOperationException();

                    //get all member zone names for cluster catalog zone
                    IReadOnlyCollection<string> memberZoneNames = (clusterCatalogZoneInfo.ApexZone as CatalogZone).GetAllMemberZoneNames();

                    foreach (string memberZoneName in memberZoneNames)
                    {
                        if (_recordUpdateForMemberZonesId != id)
                            return; //stop current update since another update has been triggered

                        //get member zone info
                        AuthZoneInfo memberZoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(memberZoneName);
                        if ((memberZoneInfo is null) || (memberZoneInfo.Type != AuthZoneType.Primary))
                            continue; //process is only for primary zones

                        //update NS and SOA records for the member zone
                        UpdateClusterRecordsFor(memberZoneInfo);

                        //save zone file
                        _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(memberZoneName);
                    }

                    _dnsWebService.LogManager.Write("The Cluster Catalog member zones NS and SOA records were successfully updated to reflect the Cluster changes.");
                }
                catch (Exception ex)
                {
                    _dnsWebService.LogManager.Write(ex);
                }
            });
        }

        private void UpdateClusterCatalogZoneOptions()
        {
            string clusterCatalogDomain = "cluster-catalog." + _clusterDomain;

            AuthZoneInfo clusterCatalogZoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(clusterCatalogDomain);
            if (clusterCatalogZoneInfo is null)
                throw new InvalidOperationException();

            UpdateClusterCatalogZoneOptions(clusterCatalogZoneInfo);
        }

        private void UpdateClusterCatalogZoneOptions(AuthZoneInfo clusterCatalogZoneInfo)
        {
            //set cluster catalog zone options for Zone Transfer ACLs and notify addresses
            IReadOnlyDictionary<int, ClusterNode> clusterNodes = _clusterNodes;

            List<NetworkAccessControl> zoneTransferACL = new List<NetworkAccessControl>(clusterNodes.Count * 2);
            List<IPAddress> notifyNameServers = new List<IPAddress>(clusterNodes.Count * 2);

            foreach (KeyValuePair<int, ClusterNode> clusterNode in clusterNodes)
            {
                if (clusterNode.Value.Type == ClusterNodeType.Primary)
                    continue;

                foreach (IPAddress ipAddress in clusterNode.Value.IPAddresses)
                    zoneTransferACL.Add(new NetworkAccessControl(ipAddress, (byte)(ipAddress.AddressFamily == AddressFamily.InterNetwork ? 32 : 128)));

                notifyNameServers.AddRange(clusterNode.Value.IPAddresses);
            }

            clusterCatalogZoneInfo.ZoneTransferNetworkACL = zoneTransferACL;
            clusterCatalogZoneInfo.NotifyNameServers = notifyNameServers;

            clusterCatalogZoneInfo.ZoneTransfer = AuthZoneTransfer.UseSpecifiedNetworkACL;
            clusterCatalogZoneInfo.Notify = AuthZoneNotify.SpecifiedNameServers;

            //set cluster catalog zone options for zone transfer TSIG key names
            IReadOnlySet<string> existingKeyNames = clusterCatalogZoneInfo.ZoneTransferTsigKeyNames;
            if (existingKeyNames is null)
            {
                HashSet<string> updatedKeyNames = [clusterCatalogZoneInfo.Name];

                clusterCatalogZoneInfo.ZoneTransferTsigKeyNames = updatedKeyNames;
            }
            else if (!existingKeyNames.Contains(clusterCatalogZoneInfo.Name))
            {
                HashSet<string> updatedKeyNames = [.. existingKeyNames, clusterCatalogZoneInfo.Name];

                clusterCatalogZoneInfo.ZoneTransferTsigKeyNames = updatedKeyNames;
            }

            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(clusterCatalogZoneInfo.Name);
        }

        internal async Task NotifyIfPrimaryEndpointStaleAsync(ClusterNode secondary, ClusterInfo state)
        {
            IReadOnlyDictionary<int, ClusterNode> nodes = _clusterNodes;
            if (nodes is null || !nodes.TryGetValue(secondary.Id, out ClusterNode member) || !ReferenceEquals(member, secondary) ||
                !string.Equals(_clusterDomain, state.ClusterDomain, StringComparison.OrdinalIgnoreCase) || state.ClusterNodes is null)
                return;

            ClusterNode primary = nodes.Values.FirstOrDefault(node => node.Type == ClusterNodeType.Primary && node.State == ClusterNodeState.Self);
            if (primary is null || !state.ClusterNodes.Any(node => node.Id == secondary.Id && node.Type == "Secondary" && node.State == "Self"))
                return;

            ClusterInfo.ClusterNodeInfo advertisedPrimary = state.ClusterNodes.FirstOrDefault(node => node.Id == primary.Id && node.Type == "Primary");
            if (advertisedPrimary is not null && (advertisedPrimary.Url != primary.Url ||
                !primary.IPAddresses.Select(address => address.ToString()).ToHashSet(StringComparer.OrdinalIgnoreCase).SetEquals(advertisedPrimary.IPAddresses)))
                await secondary.NotifySecondaryNodeAsync(primary);
        }

        public void TriggerNotifyAllSecondaryNodesIfPrimarySelfNode()
        {
            if (GetSelfNode().Type == ClusterNodeType.Primary)
                TriggerNotifyAllSecondaryNodes();
        }

        public void TriggerNotifyAllSecondaryNodes(int notifyInterval = NOTIFY_ALL_SECONDARY_NODES_TIMER_INTERVAL)
        {
            if (_notifyAllSecondaryNodesTimerTriggered)
                return;

            _notifyAllSecondaryNodesTimer.Change(notifyInterval, Timeout.Infinite);
            _notifyAllSecondaryNodesTimerTriggered = true;
        }

        private async void NotifyAllSecondaryNodesTimerCallbackAsync(object state)
        {
            _notifyAllSecondaryNodesTimerTriggered = false; //reset immediately to allow triggerring notify again since the current notify task may take longer to complete due to one or more nodes being down or not responding fast enough causing lost notify for working nodes

            try
            {
                IReadOnlyDictionary<int, ClusterNode> clusterNodes = _clusterNodes;
                if ((clusterNodes is null) || (clusterNodes.Count < 1))
                    return; //cluster not initialized

                ClusterNode primaryNode = null;

                foreach (KeyValuePair<int, ClusterNode> clusterNode in clusterNodes)
                {
                    if (clusterNode.Value.Type == ClusterNodeType.Primary)
                    {
                        primaryNode = clusterNode.Value;
                        break;
                    }
                }

                if ((primaryNode is null) || (primaryNode.State != ClusterNodeState.Self))
                    throw new InvalidOperationException();

                List<Task> tasks = new List<Task>(clusterNodes.Count);

                foreach (KeyValuePair<int, ClusterNode> clusterNode in clusterNodes)
                {
                    if (clusterNode.Value.Type == ClusterNodeType.Primary)
                        continue; //skip primary cluster node

                    tasks.Add(clusterNode.Value.NotifySecondaryNodeAsync(primaryNode));
                }

                await Task.WhenAll(tasks); //notify node call does error logging
            }
            catch (Exception ex)
            {
                _dnsWebService.LogManager.Write(ex);
            }
        }

        #endregion

        #region secondary node

        internal void CheckSecondaryBootstrap(string domain)
        {
            var dns = _dnsWebService.DnsServer;
            dns.CheckManifestServerDomain(GetBootstrapNodeName(domain));
            if (dns.AuthZoneManager.GetAuthZoneInfo(domain) is not null ||
                dns.AuthZoneManager.GetAuthZoneInfo("cluster-catalog." + domain) is not null)
                throw new InvalidDataException("/cluster/domain: The cluster or catalog zone already exists on this node.");
        }

        public async Task InitializeAndJoinClusterAsync(IReadOnlyList<IPAddress> secondaryNodeIpAddresses, Uri primaryNodeUrl, string primaryNodeUsername, string primaryNodePassword, string primaryNodeTotp = null, IReadOnlyList<IPAddress> primaryNodeIpAddresses = null, bool ignoreCertificateErrors = false, CancellationToken cancellationToken = default, string expectedDomain = null)
        {
            if (ClusterInitialized)
                throw new DnsServerException("Failed to join Cluster: the Cluster is already initialized.");

            if (!_dnsWebService.IsWebServiceTlsEnabled)
                throw new InvalidOperationException();

            if (IPAddress.TryParse(primaryNodeUrl.Host, out _))
                throw new DnsServerException("Failed to join Cluster: the Primary Node URL must use the domain name of the Primary node and not its IP address.");

            if (primaryNodeIpAddresses is null)
            {
                try
                {
                    IReadOnlyList<IPAddress> ipAddresses = await DnsClient.ResolveIPAsync(_dnsWebService.DnsServer, primaryNodeUrl.Host, _dnsWebService.DnsServer.IPv6Mode, cancellationToken);
                    if (ipAddresses.Count < 1)
                        throw new DnsServerException($"Failed to join Cluster: the domain name '{primaryNodeUrl.Host}' does not have an A/AAAA record configured.");

                    primaryNodeIpAddresses = ipAddresses;
                }
                catch (Exception ex)
                {
                    throw new DnsServerException($"Failed to join Cluster: the Primary node domain name '{primaryNodeUrl.Host}' could not be resolved to an IP address. Please specify the Primary node IP address manually.", ex);
                }
            }

            //login to primary node API
            using HttpApiClient primaryNodeApiClient = new HttpApiClient(primaryNodeUrl, _dnsWebService.DnsServer.Proxy, _dnsWebService.DnsServer.IPv6Mode, ignoreCertificateErrors, new InternalDnsClient(_dnsWebService.DnsServer, primaryNodeIpAddresses));

            try
            {
                _ = await primaryNodeApiClient.LoginAsync(primaryNodeUsername, primaryNodePassword, primaryNodeTotp, false, cancellationToken);
            }
            catch (TwoFactorAuthRequiredHttpApiClientException ex)
            {
                throw new TwoFactorAuthRequiredWebServiceException("Failed to join Cluster: two-factor authentication is required by the Primary node user account.", ex);
            }

            try
            {
                //get cluster info
                ClusterInfo primaryNodeClusterInfo = await primaryNodeApiClient.GetClusterStateAsync(cancellationToken: cancellationToken);

                //do validations
                if (!primaryNodeClusterInfo.ClusterInitialized)
                    throw new DnsServerException("Failed to join Cluster: the Primary node does not have a Cluster initialized.");

                if (expectedDomain is not null &&
                    (!expectedDomain.Equals(primaryNodeClusterInfo.ClusterDomain, StringComparison.OrdinalIgnoreCase) ||
                     !primaryNodeClusterInfo.ClusterNodes.Any(node => node.Type == "Primary" && node.State == "Self")))
                    throw new InvalidDataException("/cluster/domain: The supplied endpoint is not the Primary of the declared cluster.");

                string clusterCatalogDomain = "cluster-catalog." + primaryNodeClusterInfo.ClusterDomain;

                if (_dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(clusterCatalogDomain) is not null)
                    throw new DnsServerException($"Failed to join Cluster: the zone '{clusterCatalogDomain}' already exists. Please delete the '{clusterCatalogDomain}' zone and try again.");

                if (_dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(primaryNodeClusterInfo.ClusterDomain) is not null)
                    throw new DnsServerException($"Failed to join Cluster: the zone '{primaryNodeClusterInfo.ClusterDomain}' already exists. Please delete the '{primaryNodeClusterInfo.ClusterDomain}' zone and try again.");

                //create self node
                string serverDomain = _dnsWebService.DnsServer.ServerDomain;
                if (!serverDomain.EndsWith("." + primaryNodeClusterInfo.ClusterDomain, StringComparison.OrdinalIgnoreCase))
                {
                    int x = serverDomain.IndexOf('.');
                    if (x < 0)
                        serverDomain = serverDomain + "." + primaryNodeClusterInfo.ClusterDomain;
                    else
                        serverDomain = string.Concat(serverDomain.AsSpan(0, x), ".", primaryNodeClusterInfo.ClusterDomain);
                }

                Uri secondaryNodeUrl = new Uri($"https://{serverDomain}:{_dnsWebService.WebServiceTlsPort}/");

                ClusterNode selfSecondaryNode = new ClusterNode(this, RandomNumberGenerator.GetInt32(int.MaxValue), secondaryNodeUrl, secondaryNodeIpAddresses, ClusterNodeType.Secondary, ClusterNodeState.Self);

                //join cluster
                primaryNodeClusterInfo = await primaryNodeApiClient.JoinClusterWithCapabilitiesAsync(selfSecondaryNode.Id, secondaryNodeUrl, secondaryNodeIpAddresses,
                    _dnsWebService.WebServiceTlsCertificate, supportsDeclarativeClusterOptions: true, cancellationToken);

                //initialize cluster
                Dictionary<int, ClusterNode> clusterNodes = new Dictionary<int, ClusterNode>(primaryNodeClusterInfo.ClusterNodes.Count + 1);

                clusterNodes[selfSecondaryNode.Id] = selfSecondaryNode;

                foreach (ClusterInfo.ClusterNodeInfo nodeInfo in primaryNodeClusterInfo.ClusterNodes)
                {
                    if (nodeInfo.Id == selfSecondaryNode.Id)
                        continue; //skip self node

                    ClusterNode node = new ClusterNode(this, nodeInfo);
                    clusterNodes[node.Id] = node;
                }

                DisposeAllNodes(); //dispose existing nodes, if any

                _clusterNodes = clusterNodes;

                _clusterDomain = primaryNodeClusterInfo.ClusterDomain;
                _heartbeatRefreshIntervalSeconds = primaryNodeClusterInfo.HeartbeatRefreshIntervalSeconds;
                _heartbeatRetryIntervalSeconds = primaryNodeClusterInfo.HeartbeatRetryIntervalSeconds;
                _configRefreshIntervalSeconds = primaryNodeClusterInfo.ConfigRefreshIntervalSeconds;
                _configRetryIntervalSeconds = primaryNodeClusterInfo.ConfigRetryIntervalSeconds;

                try
                {
                    //sync entire config from primary node first to get TSIG keys for secondary catalog zone transfer
                    _configLastSynced = DateTime.UnixEpoch; //reset last sync time to ensure full sync
                    bool manifestJoin = expectedDomain is not null;
                    string[] localOwnership = manifestJoin ? [ConfigurationClusterOptions.AddressName] : [];
                    string[] ownership = MergePrimaryIntervalOwnership(primaryNodeClusterInfo, localOwnership);
                    bool journalJoin = ownership.Length != 0;
                    await SyncConfigFromAsync(primaryNodeApiClient, cancellationToken: cancellationToken, persistMembership: !journalJoin);

                    if (journalJoin)
                    {
                        var zones = _dnsWebService.DnsServer.AuthZoneManager;
                        ConfigurationJournal.Persist(_dnsWebService.ConfigFolder, () =>
                        {
                            try
                            {
                                FinishJoin();
                                WriteManifestOwnership(ownership);
                            }
                            finally
                            {
                                zones.ClearClusterBootstrapSaves(clusterCatalogDomain);
                            }
                        }, "dns.config", "auth.config", "cluster.config", ConfigurationClusterOptions.OwnershipFile,
                            Path.Combine("zones", clusterCatalogDomain + ".zone"));
                        _managedOptionNames = ownership;
                    }
                    else
                    {
                        FinishJoin();
                    }

                    void FinishJoin()
                    {
                        var zones = _dnsWebService.DnsServer.AuthZoneManager;
                        var nameServers = primaryNodeIpAddresses.Convert(ipAddress => new NameServerAddress(primaryNodeUrl.Host, ipAddress));
                        AuthZoneInfo catalog = zones.CreateSecondaryCatalogZone(clusterCatalogDomain, nameServers, DnsTransportProtocol.Tcp, clusterCatalogDomain);
                        if (catalog is null)
                            throw new DnsServerException($"Failed to join Cluster: the zone '{clusterCatalogDomain}' already exists. Please delete the '{clusterCatalogDomain}' zone and try again.");

                        var auth = _dnsWebService.AuthManager;
                        auth.SetPermission(PermissionSection.Zones, catalog.Name, auth.GetGroup(Group.ADMINISTRATORS), PermissionFlag.ViewModifyDelete);
                        auth.SetPermission(PermissionSection.Zones, catalog.Name, auth.GetGroup(Group.DNS_ADMINISTRATORS), PermissionFlag.View);
                        _dnsWebService.DnsServer.ServerDomain = selfSecondaryNode.Name;

                        if (journalJoin)
                            zones.FlushZoneSaves(clusterCatalogDomain);
                        _dnsWebService.DnsServer.SaveConfigFile(journalJoin);
                        auth.SaveConfigFile(journalJoin);
                        SaveConfigFile(journalJoin);
                    }
                }
                catch
                {
                    try
                    {
                        await primaryNodeApiClient.DeleteSecondaryNodeAsync(selfSecondaryNode.Id, CancellationToken.None);
                    }
                    catch (Exception ex)
                    {
                        _dnsWebService.LogManager.Write("Failed to remove the incomplete Secondary registration from the Primary.", ex);
                    }

                    try
                    {
                        DeleteAllClusterConfig();
                    }
                    catch (Exception ex)
                    {
                        _dnsWebService.LogManager.Write(ex);
                    }

                    throw;
                }

                //initialize heartbeat timer for all nodes here since config sync and zone transfers needs to occur first for DANE validation to work
                InitializeHeartbeatTimerFor(clusterNodes);

                //start config refresh timer to refresh as per config refresh interval as config was just synced
                UpdateConfigRefreshTimer(_configRefreshIntervalSeconds * 1000);

            }
            finally
            {
                try
                {
                    //logout from primary node
                    await primaryNodeApiClient.LogoutAsync(cancellationToken);
                }
                catch
                { }
            }
        }

        public async Task LeaveClusterAsync(bool forceLeave)
        {
            if (!ClusterInitialized)
                throw new DnsServerException("Failed to leave Cluster: the Cluster is not initialized.");

            ClusterNode primaryNode = GetPrimaryNode();

            if (primaryNode.State == ClusterNodeState.Self)
                throw new DnsServerException("Failed to leave Cluster: a Primary self node cannot leave the Cluster.");

            ClusterNode secondaryNode = GetSelfNode();

            if (secondaryNode.Type != ClusterNodeType.Secondary)
                throw new DnsServerException("Failed to leave Cluster: only Secondary nodes can leave the Cluster.");

            if (_managedOptionNames.Contains(ConfigurationClusterOptions.AddressName))
                throw new DnsServerException("/cluster/node/addresses: Release manifest ownership before leaving the cluster.");

            if (!forceLeave)
            {
                //delete self node from cluster on primary node
                await primaryNode.DeleteSecondaryNodeAsync(secondaryNode);
            }

            //delete all cluster config
            DeleteAllClusterConfig();
        }

        public async Task<ClusterNode> UpdatePrimaryNodeAsync(Uri primaryNodeUrl, IReadOnlyList<IPAddress> primaryNodeIpAddresses = null, int primaryNodeId = -1, CancellationToken cancellationToken = default)
        {
            if (!ClusterInitialized)
                throw new DnsServerException("Failed to update Primary node: the Cluster is not initialized.");

            if (primaryNodeIpAddresses is null)
            {
                try
                {
                    IReadOnlyList<IPAddress> ipAddresses = await DnsClient.ResolveIPAsync(_dnsWebService.DnsServer, primaryNodeUrl.Host, _dnsWebService.DnsServer.IPv6Mode, cancellationToken);
                    if (ipAddresses.Count < 1)
                        throw new DnsServerException($"The domain name '{primaryNodeUrl.Host}' does not have an A/AAAA record configured.");

                    primaryNodeIpAddresses = ipAddresses;
                }
                catch (Exception ex)
                {
                    throw new DnsServerException($"Failed to update Primary node: the Primary node domain name '{primaryNodeUrl.Host}' could not be resolved to an IP address.", ex);
                }
            }

            ClusterNode primaryNode;

            if (primaryNodeId < 0)
                primaryNode = GetPrimaryNode();
            else if (!_clusterNodes.TryGetValue(primaryNodeId, out primaryNode))
                throw new DnsServerException("Failed to update Primary node: the specified Primary node ID does not exists in the Cluster.");

            if (primaryNode.State == ClusterNodeState.Self)
                throw new DnsServerException("Failed to update Primary node: the specified node is the self node and cannot be updated this way.");

            if (primaryNode.Type == ClusterNodeType.Secondary)
            {
                //secondary node was promoted to primary node
                ClusterNode formerPrimaryNode = GetPrimaryNode();

                //dispose former primary node immediately to stop heartbeat
                formerPrimaryNode.Dispose();

                //remove former primary node from cluster nodes
                IReadOnlyDictionary<int, ClusterNode> existingClusterNodes = _clusterNodes;
                Dictionary<int, ClusterNode> updatedClusterNodes = new Dictionary<int, ClusterNode>(existingClusterNodes.Count - 1);

                foreach (KeyValuePair<int, ClusterNode> existingClusterNode in existingClusterNodes)
                {
                    if (existingClusterNode.Key == formerPrimaryNode.Id)
                        continue;

                    updatedClusterNodes[existingClusterNode.Key] = existingClusterNode.Value;
                }

                //update cluster nodes
                _clusterNodes = updatedClusterNodes;

                //promote secondary node to primary immediately
                primaryNode.PromoteToPrimaryNode();

                //ensure to save changes
                SaveConfigFile();
            }

            //validate for duplicate names
            foreach (KeyValuePair<int, ClusterNode> clusterNode in _clusterNodes)
            {
                if (clusterNode.Key == primaryNode.Id)
                    continue; //skip self

                if (clusterNode.Value.Name.Equals(primaryNodeUrl.Host, StringComparison.OrdinalIgnoreCase))
                    throw new DnsServerException("Failed to update Primary node: the Primary node's domain name already exists in the Cluster. Please try again after changing the Primary DNS Server's domain name.");
            }

            //get cluster secondary catalog zone
            string clusterCatalogDomain = "cluster-catalog." + _clusterDomain;

            AuthZoneInfo clusterSecondaryCatalogZoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(clusterCatalogDomain);
            if (clusterSecondaryCatalogZoneInfo is null)
                throw new DnsServerException($"Failed to update Primary node: the Cluster Secondary Catalog zone '{clusterCatalogDomain}' does not exists.");

            //update primary node
            bool httpsPortChanged = primaryNode.Url.Port != primaryNodeUrl.Port;
            primaryNode.UpdateNode(primaryNodeUrl, primaryNodeIpAddresses);

            //update cluster catalog zone's primary name server
            clusterSecondaryCatalogZoneInfo.PrimaryNameServerAddresses = primaryNodeIpAddresses.Convert(delegate (IPAddress ipAddress)
            {
                int port = 53;

                if (clusterSecondaryCatalogZoneInfo.PrimaryNameServerAddresses is not null)
                {
                    foreach (NameServerAddress primaryNameServerAddress in clusterSecondaryCatalogZoneInfo.PrimaryNameServerAddresses)
                    {
                        if ((primaryNameServerAddress.IPEndPoint is not null) && primaryNameServerAddress.IPEndPoint.Address.Equals(ipAddress))
                        {
                            port = primaryNameServerAddress.Port;
                            break;
                        }
                    }
                }

                return new NameServerAddress(primaryNodeUrl.Host, new IPEndPoint(ipAddress, port));
            });

            //save all changes
            _dnsWebService.DnsServer.AuthZoneManager.SaveZoneFile(clusterSecondaryCatalogZoneInfo.Name);
            SaveConfigFile();

            // A new HTTPS port needs its TLSA record before the next authenticated sync.
            if (httpsPortChanged && _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(_clusterDomain) is { Type: AuthZoneType.Secondary } clusterZone)
                clusterZone.TriggerResync();

            //trigger config and zone refresh
            _ = InitializeConfigRefreshAsync(CONFIG_REFRESH_TIMER_INTERVAL);

            return primaryNode;
        }

        public void TriggerRefreshForConfig(IReadOnlyCollection<string> configRefreshIncludeZones = null)
        {
            //do validation
            if (!ClusterInitialized)
                throw new DnsServerException("Failed to refresh configuration: the Cluster is not initialized.");

            ClusterNode primaryNode = GetPrimaryNode();

            if (primaryNode.State == ClusterNodeState.Self)
                throw new DnsServerException("Failed to refresh configuration: only Secondary nodes can sync configuration from Primary nodes.");

            _ = InitializeConfigRefreshAsync(CONFIG_REFRESH_TIMER_INTERVAL, configRefreshIncludeZones);
        }

        public void TriggerResyncForConfig()
        {
            //do validation
            if (!ClusterInitialized)
                throw new DnsServerException("Failed to resync configuration: the Cluster is not initialized.");

            ClusterNode primaryNode = GetPrimaryNode();

            if (primaryNode.State == ClusterNodeState.Self)
                throw new DnsServerException("Failed to resync configuration: only Secondary nodes can sync configuration from Primary nodes.");

            _configLastSynced = DateTime.UnixEpoch; //to ensure complete config resync

            //trigger immediate config refresh
            _ = InitializeConfigRefreshAsync(0);
        }

        private async Task InitializeConfigRefreshAsync(int refreshInterval, IReadOnlyCollection<string> configRefreshIncludeZones = null)
        {
            await _configRefreshLock.WaitAsync();
            try
            {
                if (configRefreshIncludeZones is not null)
                {
                    if (_configRefreshIncludeZones is null)
                        _configRefreshIncludeZones = configRefreshIncludeZones;
                    else
                        _configRefreshIncludeZones = [.. _configRefreshIncludeZones, .. configRefreshIncludeZones];
                }

                if (_configRefreshTimerTriggered)
                    return;

                _configRefreshTimer.Change(refreshInterval, Timeout.Infinite);
                _configRefreshTimerTriggered = true;
            }
            finally
            {
                _configRefreshLock.Release();
            }
        }

        private async void ConfigRefreshTimerCallbackAsync(object state)
        {
            bool success = false;

            await _configRefreshLock.WaitAsync();
            try
            {
                ClusterNode primaryNode = GetPrimaryNode();

                if (primaryNode.State == ClusterNodeState.Self)
                    throw new InvalidOperationException();

                //update cluster options
                UpdateClusterFromPrimaryNode(await primaryNode.GetClusterStateAsync(), rescheduleRefresh: false);

                //sync config from primary node
                await primaryNode.SyncConfigAsync(_configRefreshIncludeZones);

                success = true;
            }
            catch (Exception ex)
            {
                _dnsWebService.LogManager.Write("Failed to sync server configuration from the Primary node.", ex);
            }
            finally
            {
                if (success)
                {
                    _configRefreshTimerTriggered = false;
                    _configRefreshIncludeZones = null;
                }

                try
                {
                    _configRefreshTimer.Change(success ? _configRefreshIntervalSeconds * 1000 : _configRetryIntervalSeconds * 1000, Timeout.Infinite);
                }
                catch (ObjectDisposedException)
                { }

                try
                {
                    _configRefreshLock.Release();
                }
                catch (ObjectDisposedException)
                { }
            }
        }

        public async Task SyncConfigFromAsync(HttpApiClient primaryNodeApiClient, IReadOnlyCollection<string> includeZones = null, CancellationToken cancellationToken = default, bool persistMembership = true)
        {
            string tmpFile = Path.GetTempFileName();
            try
            {
                await using (FileStream configZipStream = new FileStream(tmpFile, FileMode.Create, FileAccess.ReadWrite))
                {
                    //get config from primary node
                    (Stream, DateTime) response = await primaryNodeApiClient.TransferConfigFromPrimaryNodeAsync(_configLastSynced, includeZones, cancellationToken);

                    await using (Stream stream = response.Item1)
                    {
                        //copy stream with idle timeout
                        await stream.CopyToAsync(configZipStream, TimeSpan.FromSeconds(60), cancellationToken);
                    }

                    //dynamically load config
                    configZipStream.Position = 0;

                    await _dnsWebService.RestoreConfigAsync(zipStream: configZipStream,
                                                            authConfig: true,
                                                            clusterConfig: false,
                                                            webServiceSettings: false,
                                                            dnsSettings: true,
                                                            logSettings: false,
                                                            zones: true,
                                                            allowedZones: true,
                                                            blockedZones: true,
                                                            blockLists: true,
                                                            apps: true,
                                                            scopes: false,
                                                            stats: false,
                                                            logs: false,
                                                            deleteExistingFiles: false,
                                                            isConfigTransfer: true);

                    _configLastSynced = response.Item2;

                    //save config
                    if (persistMembership)
                        SaveConfigFile();
                }

                _dnsWebService.LogManager.Write("Server configuration was synced from the Primary node successfully.");
            }
            finally
            {
                try
                {
                    File.Delete(tmpFile);
                }
                catch (Exception ex)
                {
                    _dnsWebService.LogManager.Write(ex);
                }
            }
        }

        private void TriggerClusterUpdateForSecondaryNodeChanges()
        {
            lock (_secondaryUpdateLock)
            {
                if (_secondaryUpdateStopped)
                    return;

                _secondaryUpdatePending = true;
                if (!_secondaryUpdateScheduled)
                {
                    _secondaryUpdateScheduled = true;
                    _clusterUpdateForSecondaryNodeChangesTimer.Change(CLUSTER_UPDATE_FOR_SECONDARY_NODE_CHANGES_TIMER_INTERVAL, Timeout.Infinite);
                }
            }
        }

        private async void ClusterUpdateForSecondaryNodeChangesTimerCallbackAsync(object state)
        {
            lock (_secondaryUpdateLock)
            {
                if (_secondaryUpdateStopped)
                    return;
                _secondaryUpdatePending = false;
            }

            ClusterNode secondaryNode = null;
            bool retry = false;
            try
            {
                if (!ClusterInitialized || GetSelfNode().Type != ClusterNodeType.Secondary)
                    return;

                secondaryNode = GetSelfNode();
                ClusterNode primaryNode = GetPrimaryNode();
                ClusterInfo updated = await primaryNode.UpdateSecondaryNodeAsync(secondaryNode, _dnsWebService.WebServiceTlsCertificate);
                if (!_secondaryUpdateStopped && ClusterInitialized && ReferenceEquals(GetSelfNode(), secondaryNode) &&
                    secondaryNode.Type == ClusterNodeType.Secondary && ReferenceEquals(GetPrimaryNode(), primaryNode))
                {
                    UpdateClusterFromPrimaryNode(updated);
                    _dnsWebService.LogManager.Write("DNS Server updated this Secondary node's details on the Primary node successfully.");
                }
            }
            catch (Exception ex)
            {
                retry = secondaryNode?.Type == ClusterNodeType.Secondary;
                _dnsWebService.LogManager.Write("DNS Server failed to update this Secondary node's details on the Primary node.", ex);
            }
            finally
            {
                lock (_secondaryUpdateLock)
                {
                    if (!_secondaryUpdateStopped)
                    {
                        _secondaryUpdateScheduled = _secondaryUpdatePending || (retry && ClusterInitialized);
                        if (_secondaryUpdateScheduled)
                        {
                            int delay = _secondaryUpdatePending ? CLUSTER_UPDATE_FOR_SECONDARY_NODE_CHANGES_TIMER_INTERVAL : _configRetryIntervalSeconds * 1000;
                            _clusterUpdateForSecondaryNodeChangesTimer.Change(delay, Timeout.Infinite);
                        }
                    }
                }
            }
        }

        public void UpdateClusterFromPrimaryNode(ClusterInfo primaryNodeClusterInfo, bool rescheduleRefresh = true)
        {
            IReadOnlyDictionary<int, ClusterNode> existingClusterNodes = _clusterNodes;

            //validation
            foreach (KeyValuePair<int, ClusterNode> existingClusterNode in existingClusterNodes)
            {
                if (existingClusterNode.Value.Type == ClusterNodeType.Primary)
                {
                    if (existingClusterNode.Value.State == ClusterNodeState.Self)
                        throw new InvalidOperationException(); //this is a self primary node itself

                    break;
                }
            }

            List<ClusterNode> clusterNodesToAdd = new List<ClusterNode>();
            List<ClusterNode> clusterNodesToRemove = new List<ClusterNode>();

            foreach (ClusterInfo.ClusterNodeInfo clusterNodeInfo in primaryNodeClusterInfo.ClusterNodes)
            {
                if (existingClusterNodes.TryGetValue(clusterNodeInfo.Id, out ClusterNode existingClusterNode))
                {
                    if (existingClusterNode.State == ClusterNodeState.Self)
                        continue; //skip self node

                    //update existing cluster node
                    existingClusterNode.UpdateNode(clusterNodeInfo);
                }
                else
                {
                    //add new cluster node
                    clusterNodesToAdd.Add(new ClusterNode(this, clusterNodeInfo));
                }
            }

            foreach (KeyValuePair<int, ClusterNode> existingClusterNode in existingClusterNodes)
            {
                bool found = false;

                foreach (ClusterInfo.ClusterNodeInfo clusterNodeInfo in primaryNodeClusterInfo.ClusterNodes)
                {
                    if (existingClusterNode.Key == clusterNodeInfo.Id)
                    {
                        found = true;
                        break;
                    }
                }

                if (!found)
                    clusterNodesToRemove.Add(existingClusterNode.Value);
            }

            bool saveConfig = false;

            if ((clusterNodesToAdd.Count > 0) || (clusterNodesToRemove.Count > 0))
            {
                Dictionary<int, ClusterNode> updatedClusterNodes = new Dictionary<int, ClusterNode>(existingClusterNodes.Count + clusterNodesToAdd.Count - clusterNodesToRemove.Count);

                foreach (KeyValuePair<int, ClusterNode> existingClusterNode in existingClusterNodes)
                {
                    if (clusterNodesToRemove.Contains(existingClusterNode.Value))
                        continue; //skip removed node

                    updatedClusterNodes[existingClusterNode.Key] = existingClusterNode.Value;
                }

                foreach (ClusterNode clusterNode in clusterNodesToAdd)
                    updatedClusterNodes[clusterNode.Id] = clusterNode;

                //verify if node is part of the cluster
                {
                    bool foundSelfNode = false;

                    foreach (KeyValuePair<int, ClusterNode> clusterNode in updatedClusterNodes)
                    {
                        if (clusterNode.Value.State == ClusterNodeState.Self)
                        {
                            foundSelfNode = true;
                            break;
                        }
                    }

                    if (!foundSelfNode)
                    {
                        //this node is not part of the cluster anymore
                        //delete all cluster config
                        DeleteAllClusterConfig();

                        _dnsWebService.LogManager.Write("Failed to sync Cluster config: this Secondary node is not part of the Cluster anymore.");
                        return;
                    }
                }

                //dispose all removed nodes
                foreach (ClusterNode removedNodes in clusterNodesToRemove)
                    removedNodes.Dispose();

                _clusterNodes = updatedClusterNodes;

                InitializeHeartbeatTimerFor(updatedClusterNodes);
                saveConfig = true;
            }

            var desired = new ConfigurationClusterOptions.Settings(primaryNodeClusterInfo.HeartbeatRefreshIntervalSeconds,
                primaryNodeClusterInfo.HeartbeatRetryIntervalSeconds, primaryNodeClusterInfo.ConfigRefreshIntervalSeconds,
                primaryNodeClusterInfo.ConfigRetryIntervalSeconds);
            ConfigurationClusterOptions.Settings current;
            lock (_saveLock)
            {
                if (!ClusterInitialized || GetSelfNode().Type != ClusterNodeType.Secondary)
                    return;

                current = GetManifestOptions();
                string[] ownership = MergePrimaryIntervalOwnership(primaryNodeClusterInfo, _managedOptionNames);
                if (!_managedOptionNames.SequenceEqual(ownership))
                {
                    ConfigurationJournal.Persist(_dnsWebService.ConfigFolder, () =>
                    {
                        SaveConfigFileInternal(desired);
                        WriteManifestOwnership(ownership);
                    }, "cluster.config", ConfigurationClusterOptions.OwnershipFile);
                    _managedOptionNames = ownership;
                    _pendingSave = false;
                    saveConfig = false;
                }
                else if (desired != current)
                {
                    saveConfig = true;
                }

                SetManifestOptions(desired);
                if (saveConfig)
                    SaveConfigFile();
            }

            if (current.HeartbeatRefresh != desired.HeartbeatRefresh)
                UpdateHeartbeatTimerForAllClusterNodes();
            if (rescheduleRefresh && current.ConfigRefresh != desired.ConfigRefresh)
                UpdateConfigRefreshTimer(desired.ConfigRefresh * 1000);
        }

        private static string[] MergePrimaryIntervalOwnership(ClusterInfo primary, string[] local)
        {
            if (primary.ManagedOptionPaths is null)
                return local;

            const string prefix = "/cluster/";
            IEnumerable<string> intervals = primary.ManagedOptionPaths
                .Where(path => path.StartsWith(prefix, StringComparison.Ordinal))
                .Select(path => path[prefix.Length..]).Where(ConfigurationClusterOptions.IsInterval)
                .Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal);
            return [.. intervals, .. local.Where(name => !ConfigurationClusterOptions.IsInterval(name))];
        }

        public async Task PromoteToPrimaryNodeAsync(bool forceDeletePrimary)
        {
            if (!ClusterInitialized)
                throw new DnsServerException("Failed to promote to Primary node: the Cluster is not initialized.");

            //do validation
            ClusterNode selfNewPrimaryNode = GetSelfNode();
            if (selfNewPrimaryNode.Type != ClusterNodeType.Secondary)
                throw new DnsServerException("Failed to promote to Primary node: only Secondary nodes can be promoted to Primary nodes.");

            string clusterCatalogDomain = "cluster-catalog." + _clusterDomain;

            AuthZoneInfo clusterCatalogZoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(clusterCatalogDomain);
            if (clusterCatalogZoneInfo is null)
                throw new DnsServerException("Failed to promote to Primary node: the Cluster Secondary Catalog zone does not exist.");

            AuthZoneInfo clusterZoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(_clusterDomain);
            if (clusterZoneInfo is null)
                throw new DnsServerException("Failed to promote to Primary node: the Cluster Secondary zone does not exist.");

            //stop cluster config refresh timer
            StopConfigRefreshTimer();

            //resync config and delete current primary node from the cluster immediately
            ClusterNode existingPrimaryNode = GetPrimaryNode();

            if (!forceDeletePrimary)
            {
                try
                {
                    _configLastSynced = DateTime.UnixEpoch; //ensure a complete configuration transfer
                    await existingPrimaryNode.SyncConfigAsync();

                    ClusterInfo currentPrimary = await existingPrimaryNode.GetClusterStateAsync();
                    UpdateClusterFromPrimaryNode(currentPrimary, rescheduleRefresh: false);
                    string revision;
                    lock (_saveLock)
                    {
                        SaveConfigFile(immediately: true);
                        revision = GetPrimaryHandoffRevision(existingPrimaryNode.Id, selfNewPrimaryNode.Id);
                    }

                    if (currentPrimary.SupportsDeclarativeClusterHandoff)
                    {
                        await existingPrimaryNode.DeleteClusterAsync(true, successorNodeId: selfNewPrimaryNode.Id, revision: revision);
                    }
                    else
                    {
                        await existingPrimaryNode.DeleteClusterAsync(true);
                    }
                }
                catch
                {
                    UpdateConfigRefreshTimer();
                    throw;
                }
            }

            //dispose primary node immediately to stop heartbeat
            existingPrimaryNode.Dispose();

            //remove primary node from cluster nodes
            IReadOnlyDictionary<int, ClusterNode> existingClusterNodes = _clusterNodes;
            Dictionary<int, ClusterNode> updatedClusterNodes = new Dictionary<int, ClusterNode>(existingClusterNodes.Count - 1);

            foreach (KeyValuePair<int, ClusterNode> existingClusterNode in existingClusterNodes)
            {
                if (existingClusterNode.Key == existingPrimaryNode.Id)
                    continue;

                updatedClusterNodes[existingClusterNode.Key] = existingClusterNode.Value;
            }

            //update cluster nodes
            _clusterNodes = updatedClusterNodes;

            //promote self node to primary immediately
            selfNewPrimaryNode.PromoteToPrimaryNode();

            //convert cluster secondary catalog zone to catalog zone along with all its member zones
            if (clusterCatalogZoneInfo.Type == AuthZoneType.SecondaryCatalog)
                clusterCatalogZoneInfo = _dnsWebService.DnsServer.AuthZoneManager.ConvertZoneTypeTo(clusterCatalogZoneInfo.Name, AuthZoneType.Catalog);

            //get converted primary cluster zone info
            clusterZoneInfo = _dnsWebService.DnsServer.AuthZoneManager.GetAuthZoneInfo(_clusterDomain);
            if (clusterZoneInfo is null)
                throw new DnsServerException("Failed to promote to Primary node: the Cluster Primary zone does not exist.");

            //sign cluster zone in case when DNSSEC private keys were not available during ConvertZoneTypeTo() operation
            if (clusterZoneInfo.ApexZone.DnssecStatus == AuthZoneDnssecStatus.Unsigned)
            {
                DnssecPrivateKey kskPrivateKey = DnssecPrivateKey.Create(DnssecAlgorithm.ECDSAP256SHA256, DnssecPrivateKeyType.KeySigningKey);
                DnssecPrivateKey zskPrivateKey = DnssecPrivateKey.Create(DnssecAlgorithm.ECDSAP256SHA256, DnssecPrivateKeyType.ZoneSigningKey);
                zskPrivateKey.RolloverDays = 90;

                _dnsWebService.DnsServer.AuthZoneManager.SignPrimaryZone(clusterZoneInfo.Name, kskPrivateKey, zskPrivateKey, 3600, false);
            }

            //find existing record TTL values
            FindExistingRecordTtlValues(out uint nsTtl, out uint aTtl);

            //remove old primary node records from cluster primary zone and save zone file
            if (existingPrimaryNode is not null)
                RemoveClusterPrimaryZoneRecordsFor(existingPrimaryNode);

            //update cluster primary zone for new primary node
            AddClusterPrimaryZoneRecordsFor(selfNewPrimaryNode, nsTtl, aTtl, _dnsWebService.WebServiceTlsCertificate);

            //update cluster catalog zone ACLs, TSIG key name and save zone file
            UpdateClusterCatalogZoneOptions(clusterCatalogZoneInfo);

            //save all changes immediately before sending notify
            SaveConfigFile(true);

            //notify all secondary nodes as a primary node immediately
            TriggerNotifyAllSecondaryNodes(0);

            //trigger NS and SOA update for member zones
            TriggerRecordUpdateForClusterCatalogMemberZones();
        }

        #endregion

        #region public

        public ClusterNode GetPrimaryNode()
        {
            IReadOnlyDictionary<int, ClusterNode> clusterNodes = _clusterNodes;
            if (clusterNodes is null)
                throw new InvalidOperationException();

            foreach (KeyValuePair<int, ClusterNode> clusterNode in clusterNodes)
            {
                if (clusterNode.Value.Type == ClusterNodeType.Primary)
                    return clusterNode.Value;
            }

            throw new InvalidOperationException();
        }

        public ClusterNode GetSelfNode()
        {
            IReadOnlyDictionary<int, ClusterNode> clusterNodes = _clusterNodes;
            if (clusterNodes is null)
                throw new InvalidOperationException();

            foreach (KeyValuePair<int, ClusterNode> clusterNode in clusterNodes)
            {
                if (clusterNode.Value.State == ClusterNodeState.Self)
                    return clusterNode.Value;
            }

            throw new InvalidOperationException();
        }

        public bool TryGetClusterNode(string nodeName, out ClusterNode clusterNode)
        {
            foreach (KeyValuePair<int, ClusterNode> node in _clusterNodes)
            {
                if (node.Value.Name.Equals(nodeName, StringComparison.OrdinalIgnoreCase))
                {
                    clusterNode = node.Value;
                    return true;
                }
            }

            clusterNode = null;
            return false;
        }

        public bool IsClusterPrimaryZone(string zoneName)
        {
            return (zoneName is not null) && zoneName.Equals(_clusterDomain, StringComparison.OrdinalIgnoreCase);
        }

        public bool IsClusterCatalogZone(string zoneName)
        {
            return (zoneName is not null) && zoneName.Equals("cluster-catalog." + _clusterDomain, StringComparison.OrdinalIgnoreCase);
        }

        public ClusterNode UpdateSelfNodeIPAddresses(IReadOnlyList<IPAddress> ipAddresses)
        {
            ClusterNode selfNode = GetSelfNode();

            if (_managedOptionNames.Contains(ConfigurationClusterOptions.AddressName))
            {
                if (ConfigurationClusterOptions.SameAddresses(selfNode.IPAddresses, ipAddresses))
                    return selfNode;
                throw new DnsServerException("/cluster/node/addresses: This setting is managed by the configuration manifest.");
            }

            switch (selfNode.Type)
            {
                case ClusterNodeType.Primary:
                    //find existing record TTL values
                    FindExistingRecordTtlValues(out uint nsTtl, out uint aTtl);

                    //update cluster zone to remove current self node records
                    RemoveClusterPrimaryZoneRecordsFor(selfNode);

                    //update self node
                    selfNode.UpdateSelfNodeIPAddresses(ipAddresses);

                    //update cluster zone to add updated self node records
                    AddClusterPrimaryZoneRecordsFor(selfNode, nsTtl, aTtl, _dnsWebService.WebServiceTlsCertificate);

                    //update cluster catalog zone ACLs and save zone file
                    UpdateClusterCatalogZoneOptions();

                    //save all changes immediately before sending notify
                    SaveConfigFile(true);

                    //notify all secondary nodes immediately
                    TriggerNotifyAllSecondaryNodes(0);
                    break;

                case ClusterNodeType.Secondary:
                    //update self node
                    selfNode.UpdateSelfNodeIPAddresses(ipAddresses);

                    //save all changes
                    SaveConfigFile();

                    //trigger cluster node update on primary node
                    TriggerClusterUpdateForSecondaryNodeChanges();
                    break;
            }

            return selfNode;
        }

        public void UpdateSelfNodeUrlAndCertificate()
        {
            ClusterNode selfNode = GetSelfNode();

            //validation
            foreach (KeyValuePair<int, ClusterNode> clusterNode in _clusterNodes)
            {
                if (clusterNode.Key == selfNode.Id)
                    continue; //skip self

                if (clusterNode.Value.Name.Equals(_dnsWebService.DnsServer.ServerDomain, StringComparison.OrdinalIgnoreCase))
                    throw new DnsServerException("Failed to update self node URL: the node's domain name already exists in the Cluster. Please try again after changing the DNS Server's domain name.");
            }

            switch (selfNode.Type)
            {
                case ClusterNodeType.Primary:
                    //find existing record TTL values
                    FindExistingRecordTtlValues(out uint nsTtl, out uint aTtl);

                    //update cluster zone to remove current self node records
                    RemoveClusterPrimaryZoneRecordsFor(selfNode);

                    //update self node
                    selfNode.UpdateSelfNodeUrl();

                    //update cluster zone to add updated self node records
                    AddClusterPrimaryZoneRecordsFor(selfNode, nsTtl, aTtl, _dnsWebService.WebServiceTlsCertificate);

                    //save all changes
                    SaveConfigFile();

                    _dnsWebService.LogManager.Write("Primary node '" + selfNode.ToString() + "' URL was updated successfully.");

                    //notify all secondary nodes
                    TriggerNotifyAllSecondaryNodes();
                    break;

                case ClusterNodeType.Secondary:
                    //update self node
                    selfNode.UpdateSelfNodeUrl();

                    //save all changes
                    SaveConfigFile();

                    _dnsWebService.LogManager.Write("Secondary node '" + selfNode.ToString() + "' URL was updated successfully.");

                    //trigger cluster node update on primary node
                    TriggerClusterUpdateForSecondaryNodeChanges();
                    break;
            }
        }

        #endregion

        #region properties

        public DnsWebService DnsWebService
        { get { return _dnsWebService; } }

        public bool ClusterInitialized
        {
            get
            {
                IReadOnlyDictionary<int, ClusterNode> clusterNodes = _clusterNodes;

                return (clusterNodes is not null) && (clusterNodes.Count > 0);
            }
        }

        public string ClusterDomain
        { get { return _clusterDomain; } }

        public ushort HeartbeatRefreshIntervalSeconds
        { get { return _heartbeatRefreshIntervalSeconds; } }

        public ushort HeartBeatRetryIntervalSeconds
        { get { return _heartbeatRetryIntervalSeconds; } }

        public ushort ConfigRefreshIntervalSeconds
        { get { return _configRefreshIntervalSeconds; } }

        public ushort ConfigRetryIntervalSeconds
        { get { return _configRetryIntervalSeconds; } }

        public DateTime ConfigLastSynced
        { get { return _configLastSynced; } }

        public IReadOnlyDictionary<int, ClusterNode> ClusterNodes
        { get { return _clusterNodes; } }

        #endregion
    }
}
