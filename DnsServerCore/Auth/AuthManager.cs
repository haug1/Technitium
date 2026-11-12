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

using DnsServerCore.Configuration;
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using TechnitiumLibrary;
using TechnitiumLibrary.IO;
using TechnitiumLibrary.Net;
using TechnitiumLibrary.Security.OTP;

namespace DnsServerCore.Auth
{
    sealed class AuthManager : IDisposable
    {
        #region variables

        ConcurrentDictionary<string, Group> _groups = new ConcurrentDictionary<string, Group>(1, 4);
        ConcurrentDictionary<string, User> _users = new ConcurrentDictionary<string, User>(1, 4);
        ConcurrentDictionary<PermissionSection, Permission> _permissions = new ConcurrentDictionary<PermissionSection, Permission>(1, 11);
        ConcurrentDictionary<string, UserSession> _sessions = new ConcurrentDictionary<string, UserSession>(1, 10);

        private SortedDictionary<string, ConfigurationStaticSessions.Definition> _manifestStaticSessionDefinitions = new(StringComparer.Ordinal);
        private IReadOnlyDictionary<string, ConfigurationStaticSessions.Entry> _manifestStaticSessionEntries =
            new SortedDictionary<string, ConfigurationStaticSessions.Entry>(StringComparer.Ordinal);
        private IReadOnlyDictionary<string, UserSession> _manifestStaticSessions = new Dictionary<string, UserSession>(StringComparer.Ordinal);
        internal SortedDictionary<string, ConfigurationStaticSessions.Definition> ManifestStaticSessionDefinitions => _manifestStaticSessionDefinitions;
        internal IReadOnlyDictionary<string, ConfigurationStaticSessions.Entry> ManifestStaticSessionEntries => _manifestStaticSessionEntries;
        internal ConfigurationManifest StaticSessionReferenceContext => ConfigurationManifest.ReferenceContext(_configFolder);

        Dictionary<string, UserSession> _staticSessions; //predefined static session via environment variables

        readonly ConcurrentDictionary<IPAddress, int> _failedLoginAttemptNetworks = new ConcurrentDictionary<IPAddress, int>(1, 10);
        const int MAX_LOGIN_ATTEMPTS = 5;

        readonly ConcurrentDictionary<IPAddress, DateTime> _blockedNetworks = new ConcurrentDictionary<IPAddress, DateTime>(1, 10);
        const int BLOCK_NETWORK_INTERVAL = 5 * 60 * 1000;

        readonly DnsWebService _dnsWebService;
        readonly string _configFolder;
        readonly LogManager _log;

        bool _ssoEnabled;
        Uri _ssoAuthority;
        string _ssoClientId;
        string _ssoClientSecret;
        Uri _ssoMetadataAddress;
        IReadOnlySet<string> _ssoScopes = new HashSet<string>() { "openid", "profile", "email" };
        bool _ssoAllowSignup;
        bool _ssoAllowSignupOnlyForMappedUsers = true;
        IReadOnlyDictionary<string, string> _ssoGroupMap;

        bool _ldapEnabled;
        string _ldapServer;
        int _ldapPort = 389;
        LdapAuthSslOption _ldapSslOption;
        bool _ldapIgnoreSslErrors;
        string _ldapBindUsername;
        string _ldapBindPassword;
        string _ldapSearchBase;
        string _ldapUserSearchFilter;
        string _ldapGroupAttribute;
        bool _ldapAllowSignup;
        bool _ldapAllowSignupOnlyForMappedUsers = true;
        IReadOnlyDictionary<string, string> _ldapGroupMap;

        internal const string LdapOwnershipFile = "ldap-ownership.config";
        private string[] _managedLdapFields = [];
        internal bool LdapOwnershipFromPrimary { get; private set; }
        internal IReadOnlyList<string> ManagedLdapFields => _managedLdapFields;

        internal const string SsoOwnershipFile = "sso-ownership.config";
        private string[] _managedSsoFields = [];
        internal bool SsoOwnershipFromPrimary { get; private set; }
        internal IReadOnlyList<string> ManagedSsoFields => _managedSsoFields;

        internal const string GroupOwnershipFile = "group-ownership.config";
        private string[] _managedGroupPaths = [];
        internal bool GroupOwnershipFromPrimary { get; private set; }
        internal IReadOnlyList<string> ManagedGroupPaths => _managedGroupPaths;
        internal const string UserOwnershipFile = "user-ownership.config";
        private string[] _managedUserPaths = [];
        internal IReadOnlyList<string> ManagedUserPaths => _managedUserPaths;
        internal const string PermissionOwnershipFile = "permission-ownership.config";
        private string[] _managedPermissionPaths = [];
        internal IReadOnlyList<string> ManagedPermissionPaths => _managedPermissionPaths;
        internal bool HasManagedAuthOwnership => HasManifestAuthChangesOnOmission(preserveInheritedProviders: false);
        internal bool HasManifestAuthChangesOnOmission(bool preserveInheritedProviders) =>
            _managedSsoFields.Length > 0 && (!preserveInheritedProviders || !SsoOwnershipFromPrimary) ||
            _managedLdapFields.Length > 0 && (!preserveInheritedProviders || !LdapOwnershipFromPrimary) ||
            _managedGroupPaths.Length > 0 && (!preserveInheritedProviders || !GroupOwnershipFromPrimary) || _managedUserPaths.Length > 0 || _managedPermissionPaths.Length > 0;
        internal bool HasManagedAuthSettings => HasManagedAuthOwnership || _manifestStaticSessionDefinitions.Count > 0;

        readonly Lock _saveLock = new Lock();
        bool _pendingSave;
        bool _pendingLazySave;
        readonly Timer _saveTimer;
        const int SAVE_TIMER_INITIAL_INTERVAL = 5000;

        #endregion

        #region constructor

        public AuthManager(DnsWebService dnsWebService, string configFolder, LogManager log)
        {
            _dnsWebService = dnsWebService;
            _configFolder = configFolder;
            _log = log;

            _managedLdapFields = ReadOwnership(LdapOwnershipFile);
            _managedSsoFields = ReadOwnership(SsoOwnershipFile);
            _managedGroupPaths = ReadOwnership(GroupOwnershipFile);
            _managedUserPaths = ReadOwnership(UserOwnershipFile);
            _managedPermissionPaths = ReadOwnership(PermissionOwnershipFile);
            string staticSessionsFile = Path.Combine(configFolder, ConfigurationStaticSessions.FileName);
            if (File.Exists(staticSessionsFile))
            {
                var definitions = JsonSerializer.Deserialize<Dictionary<string, ConfigurationStaticSessions.Definition>>(File.ReadAllBytes(staticSessionsFile))
                    ?? throw new InvalidDataException("Invalid manifest static session configuration.");
                _manifestStaticSessionDefinitions = new SortedDictionary<string, ConfigurationStaticSessions.Definition>(definitions, StringComparer.Ordinal);
            }

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
                            _pendingLazySave = false;
                        }
                        catch (Exception ex)
                        {
                            _log.Write(ex);
                        }
                    }
                }
            });

            LoadConfigFile();
        }

        #endregion

        #region IDisposable

        bool _disposed;

        public void Dispose()
        {
            if (_disposed)
                return;

            lock (_saveLock)
            {
                _saveTimer?.Dispose();

                if (_pendingSave || _pendingLazySave)
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
                        _pendingLazySave = false;
                    }
                }
            }

            _disposed = true;
        }

        #endregion

        #region config

        private void LoadConfigFile()
        {
            string configFile = Path.Combine(_configFolder, "auth.config");

            try
            {
                bool passwordResetOption = false;

                if (!File.Exists(configFile))
                {
                    string passwordResetConfigFile = Path.Combine(_configFolder, "resetadmin.config");

                    if (File.Exists(passwordResetConfigFile))
                    {
                        passwordResetOption = true;
                        configFile = passwordResetConfigFile;
                    }
                }

                using (FileStream fS = new FileStream(configFile, FileMode.Open, FileAccess.Read))
                {
                    ReadConfigFrom(fS, false, out bool _, readOwnership: true);
                }

                _log.Write("DNS Server auth config file was loaded: " + configFile);

                //load static sessions
                if (_staticSessions is null)
                {
                    string strStaticSessions = Environment.GetEnvironmentVariable("DNS_SERVER_AUTH_STATIC_SESSIONS");
                    if (!string.IsNullOrEmpty(strStaticSessions))
                    {
                        string[] strStaticSessionEntries = strStaticSessions.Split(",", StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

                        Dictionary<string, UserSession> staticSessions = new Dictionary<string, UserSession>(strStaticSessionEntries.Length);

                        foreach (string strStaticSessionEntry in strStaticSessionEntries)
                        {
                            string[] parts = strStaticSessionEntry.Split(":", StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                            if (parts.Length != 2)
                                continue;

                            string username = parts[0];
                            string token = parts[1];

                            if (!_users.TryGetValue(username, out User user))
                            {
                                _log.Write($"Cannot load static session for user '{username}': no such user exist.");
                                continue;
                            }

                            if (token.Length != 64)
                            {
                                _log.Write($"Cannot load static session for user '{username}': token length must be 64 bytes.");
                                continue;
                            }

                            UserSession staticSession = new UserSession(token, user);

                            if (!staticSessions.TryAdd(staticSession.Token, staticSession))
                                _log.Write($"Cannot load static session for user '{username}': token is not unique.");
                        }

                        _staticSessions = staticSessions;
                    }
                }

                if (passwordResetOption)
                {
                    User adminUser = GetUser("admin");
                    if (adminUser is null)
                    {
                        adminUser = CreateUser("Administrator", "admin", "admin");
                    }
                    else
                    {
                        adminUser.ChangePassword("admin");
                        adminUser.Disabled = false;

                        if (adminUser.TOTPEnabled)
                            adminUser.DisableTOTP();
                    }

                    adminUser.AddToGroup(GetGroup(Group.ADMINISTRATORS));

                    _log.Write("DNS Server has reset the password for user: admin");

                    lock (_saveLock)
                    {
                        SaveConfigFileInternal();
                    }

                    try
                    {
                        File.Delete(configFile);
                    }
                    catch
                    { }
                }
            }
            catch (FileNotFoundException)
            {
                CreateDefaultConfig();

                string strSsoEnabled = Environment.GetEnvironmentVariable("DNS_SERVER_SSO_ENABLED");
                if (!string.IsNullOrEmpty(strSsoEnabled))
                    SsoEnabled = bool.Parse(strSsoEnabled);

                string strSsoAuthority = Environment.GetEnvironmentVariable("DNS_SERVER_SSO_AUTHORITY");
                if (!string.IsNullOrEmpty(strSsoAuthority))
                    SsoAuthority = new Uri(strSsoAuthority);

                string strSsoClientId = Environment.GetEnvironmentVariable("DNS_SERVER_SSO_CLIENT_ID");
                if (!string.IsNullOrEmpty(strSsoClientId))
                    SsoClientId = strSsoClientId;

                string strSsoClientSecret = Environment.GetEnvironmentVariable("DNS_SERVER_SSO_CLIENT_SECRET");
                string strSsoClientSecretFile = Environment.GetEnvironmentVariable("DNS_SERVER_SSO_CLIENT_SECRET_FILE");

                if (!string.IsNullOrEmpty(strSsoClientSecret))
                {
                    SsoClientSecret = strSsoClientSecret;
                }
                else if (!string.IsNullOrEmpty(strSsoClientSecretFile))
                {
                    using (StreamReader sR = new StreamReader(strSsoClientSecretFile, true))
                    {
                        SsoClientSecret = sR.ReadLine();
                    }
                }

                string strSsoMetadataAddress = Environment.GetEnvironmentVariable("DNS_SERVER_SSO_METADATA_ADDRESS");
                if (!string.IsNullOrEmpty(strSsoMetadataAddress))
                    SsoMetadataAddress = new Uri(strSsoMetadataAddress);

                string strSsoScopes = Environment.GetEnvironmentVariable("DNS_SERVER_SSO_SCOPES");
                if (!string.IsNullOrEmpty(strSsoScopes))
                {
                    string[] ssoScopesList = strSsoScopes.Split([',', ' '], StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                    if (ssoScopesList.Length > 0)
                        SsoScopes = new HashSet<string>(ssoScopesList);
                }

                string strSsoAllowSignup = Environment.GetEnvironmentVariable("DNS_SERVER_SSO_ALLOW_SIGNUP");
                if (!string.IsNullOrEmpty(strSsoAllowSignup))
                    SsoAllowSignup = bool.Parse(strSsoAllowSignup);

                string strSsoAllowSignupOnlyForMappedUsers = Environment.GetEnvironmentVariable("DNS_SERVER_SSO_ALLOW_SIGNUP_ONLY_FOR_MAPPED_USERS");
                if (!string.IsNullOrEmpty(strSsoAllowSignupOnlyForMappedUsers))
                    SsoAllowSignupOnlyForMappedUsers = bool.Parse(strSsoAllowSignupOnlyForMappedUsers);

                string strGroupMap = Environment.GetEnvironmentVariable("DNS_SERVER_SSO_GROUP_MAP");
                if (!string.IsNullOrEmpty(strGroupMap))
                {
                    string[] entries = strGroupMap.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                    Dictionary<string, string> groupMap = new Dictionary<string, string>(entries.Length);

                    foreach (string entry in entries)
                    {
                        string[] parts = entry.Split(':', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                        if (parts.Length == 2)
                            groupMap.TryAdd(parts[0], parts[1]);
                    }

                    SsoGroupMap = groupMap;
                }

                string strLdapEnabled = Environment.GetEnvironmentVariable("DNS_SERVER_LDAP_ENABLED");
                if (!string.IsNullOrEmpty(strLdapEnabled))
                    LdapEnabled = bool.Parse(strLdapEnabled);

                string strLdapServer = Environment.GetEnvironmentVariable("DNS_SERVER_LDAP_SERVER");
                if (!string.IsNullOrEmpty(strLdapServer))
                    LdapServer = strLdapServer;

                string strLdapPort = Environment.GetEnvironmentVariable("DNS_SERVER_LDAP_PORT");
                if (!string.IsNullOrEmpty(strLdapPort))
                    LdapPort = int.Parse(strLdapPort);

                string strLdapSslOption = Environment.GetEnvironmentVariable("DNS_SERVER_LDAP_SSL_OPTION");
                if (!string.IsNullOrEmpty(strLdapSslOption))
                    LdapSslOption = Enum.Parse<LdapAuthSslOption>(strLdapSslOption, true);

                string strLdapIgnoreSslErrors = Environment.GetEnvironmentVariable("DNS_SERVER_LDAP_IGNORE_SSL_ERRORS");
                if (!string.IsNullOrEmpty(strLdapIgnoreSslErrors))
                    LdapIgnoreSslErrors = bool.Parse(strLdapIgnoreSslErrors);

                string strLdapBindUsername = Environment.GetEnvironmentVariable("DNS_SERVER_LDAP_BIND_USERNAME");
                if (!string.IsNullOrEmpty(strLdapBindUsername))
                    LdapBindUsername = strLdapBindUsername;

                string strLdapBindPassword = Environment.GetEnvironmentVariable("DNS_SERVER_LDAP_BIND_PASSWORD");
                string strLdapBindPasswordFile = Environment.GetEnvironmentVariable("DNS_SERVER_LDAP_BIND_PASSWORD_FILE");

                if (!string.IsNullOrEmpty(strLdapBindPassword))
                {
                    LdapBindPassword = strLdapBindPassword;
                }
                else if (!string.IsNullOrEmpty(strLdapBindPasswordFile))
                {
                    using (StreamReader sR = new StreamReader(strLdapBindPasswordFile, true))
                    {
                        LdapBindPassword = sR.ReadLine();
                    }
                }

                string strLdapSearchBase = Environment.GetEnvironmentVariable("DNS_SERVER_LDAP_SEARCH_BASE");
                if (!string.IsNullOrEmpty(strLdapSearchBase))
                    LdapSearchBase = strLdapSearchBase;

                string strLdapUserSearchFilter = Environment.GetEnvironmentVariable("DNS_SERVER_LDAP_USER_SEARCH_FILTER");
                if (!string.IsNullOrEmpty(strLdapUserSearchFilter))
                    LdapUserSearchFilter = strLdapUserSearchFilter;

                string strLdapGroupAttribute = Environment.GetEnvironmentVariable("DNS_SERVER_LDAP_GROUP_ATTRIBUTE");
                if (!string.IsNullOrEmpty(strLdapGroupAttribute))
                    LdapGroupAttribute = strLdapGroupAttribute;

                string strLdapAllowSignup = Environment.GetEnvironmentVariable("DNS_SERVER_LDAP_ALLOW_SIGNUP");
                if (!string.IsNullOrEmpty(strLdapAllowSignup))
                    LdapAllowSignup = bool.Parse(strLdapAllowSignup);

                string strLdapAllowSignupOnlyForMappedUsers = Environment.GetEnvironmentVariable("DNS_SERVER_LDAP_ALLOW_SIGNUP_ONLY_FOR_MAPPED_USERS");
                if (!string.IsNullOrEmpty(strLdapAllowSignupOnlyForMappedUsers))
                    LdapAllowSignupOnlyForMappedUsers = bool.Parse(strLdapAllowSignupOnlyForMappedUsers);

                string strLdapGroupMap = Environment.GetEnvironmentVariable("DNS_SERVER_LDAP_GROUP_MAP");
                if (!string.IsNullOrEmpty(strLdapGroupMap))
                {
                    string[] entries = strLdapGroupMap.Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                    Dictionary<string, string> groupMap = new Dictionary<string, string>(entries.Length);

                    foreach (string entry in entries)
                    {
                        string[] parts = entry.Split(':', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
                        if (parts.Length == 2)
                            groupMap.TryAdd(parts[0], parts[1]);
                    }

                    LdapGroupMap = groupMap;
                }

                lock (_saveLock)
                {
                    SaveConfigFileInternal();
                }
            }
            catch (Exception ex)
            {
                _log.Write("DNS Server encountered an error while loading auth config file: " + configFile, ex);
                _log.Write("Note: You may try deleting the auth config file to fix this issue. However, you will lose auth settings but, rest of the DNS settings and zone data wont be affected.");
                throw;
            }
        }

        public void LoadOldConfig(string password, bool isPasswordHash)
        {
            User user = GetUser("admin");
            if (user is null)
                user = CreateUser("Administrator", "admin", "admin");

            user.AddToGroup(GetGroup(Group.ADMINISTRATORS));

            if (isPasswordHash)
                user.LoadOldSchemeCredentials(password);
            else
                user.ChangePassword(password);

            lock (_saveLock)
            {
                SaveConfigFileInternal();
            }
        }

        public void LoadConfig(Stream s, bool isConfigTransfer, out bool restartWebService, UserSession implantSession = null)
        {
            lock (_saveLock)
            {
                var previousSso = GetManifestSsoSettings();
                string[] previousSsoOwnership = _managedSsoFields;
                bool previousSsoInherited = SsoOwnershipFromPrimary;
                string[] previousGroupOwnership = _managedGroupPaths;
                bool previousGroupInherited = GroupOwnershipFromPrimary;
                var previousLdap = GetManifestLdapSettings();
                string[] previousLdapOwnership = _managedLdapFields;
                bool previousLdapInherited = LdapOwnershipFromPrimary;
                ReadConfigFrom(s, isConfigTransfer, out restartWebService);

                if (!isConfigTransfer)
                {
                    if (implantSession is not null)
                    {
                        //implant current user and session into config while restoring backup config
                        using (MemoryStream mS = new MemoryStream())
                        {
                            //implant current user
                            implantSession.User.WriteTo(new BinaryWriter(mS));

                            mS.Position = 0;
                            User newUser = new User(new BinaryReader(mS), _groups);
                            newUser.AddToGroup(GetGroup(Group.ADMINISTRATORS));
                            _users[newUser.Username] = newUser;

                            //implant current session
                            mS.SetLength(0);
                            implantSession.WriteTo(new BinaryWriter(mS));

                            mS.Position = 0;
                            UserSession newSession = new UserSession(new BinaryReader(mS), _users);
                            _sessions[newSession.Token] = newSession;
                        }
                    }
                }

                //save config file
                try
                {
                    SaveConfigFileInternal();
                }
                catch
                {
                    SetSsoSettings(previousSso);
                    _managedSsoFields = previousSsoOwnership;
                    SsoOwnershipFromPrimary = previousSsoInherited;
                    _managedGroupPaths = previousGroupOwnership;
                    GroupOwnershipFromPrimary = previousGroupInherited;
                    restartWebService = false;
                    SetLdapSettings(previousLdap);
                    _managedLdapFields = previousLdapOwnership;
                    LdapOwnershipFromPrimary = previousLdapInherited;
                    throw;
                }
                _pendingSave = false;
                _pendingLazySave = false;
            }
        }

        private void SaveConfigFileInternal(IReadOnlyDictionary<PermissionSection, Permission> stagedPermissions = null, ConfigurationLdap.Settings ldap = null, IReadOnlyDictionary<string, Group> groupChanges = null, IReadOnlyDictionary<string, User> stagedUsers = null, ConfigurationSso.Settings sso = null, string[] ldapOwnership = null, string[] ssoOwnership = null, string[] groupOwnership = null)
        {
            string tmpConfigFile = Path.Combine(_configFolder, "auth.tmp");
            string configFile = Path.Combine(_configFolder, "auth.config");

            using (FileStream fS = new FileStream(tmpConfigFile, FileMode.Create, FileAccess.Write))
            {
                WriteConfigTo(fS, stagedPermissions, ldap, groupChanges, stagedUsers, sso, ldapOwnership, ssoOwnership, groupOwnership);
                if (stagedPermissions is not null || ldap is not null || groupChanges is not null || stagedUsers is not null || sso is not null || ldapOwnership is not null || ssoOwnership is not null || groupOwnership is not null)
                    fS.Flush(flushToDisk: true);
            }

            File.Move(tmpConfigFile, configFile, true);

            _log.Write("DNS Server auth config file was saved: " + configFile);
        }

        internal void ApplyManifestAuth(IReadOnlyDictionary<string, bool> membership, User creator, ConfigurationLdap.Settings ldap, string[] ldapOwnership, IReadOnlyDictionary<string, Group> groupChanges, string[] groupOwnership, IReadOnlyDictionary<string, ConfigurationUsers.Change> userChanges, string[] userOwnership, IReadOnlyList<ConfigurationPermissions.Grant> grants, string[] permissionOwnership, ConfigurationStaticSessions.Candidate staticSessions, ConfigurationSso.Settings sso, string[] ssoOwnership, Action<Action> persist)
        {
            if (membership.Count == 0 && ldap is null && ldapOwnership is null && groupChanges.Count == 0 && groupOwnership is null && userChanges.Count == 0 && userOwnership is null && grants.Count == 0 && permissionOwnership is null && staticSessions is null && sso is null && ssoOwnership is null)
            {
                persist(null);
                return;
            }

            lock (_saveLock)
            {
                ConfigurationGroups.ValidateRemovals(this, groupChanges, ldap, userChanges, grants, sso,
                    membership.Where(entry => !entry.Value).Select(entry => entry.Key).ToHashSet(StringComparer.Ordinal));
                ConfigurationStaticSessions.CheckAccountRemovals(this, userChanges, staticSessions);
                ConfigurationUsers.CheckSsoIdentities(this, userChanges);

                Dictionary<string, User> stagedUsers = null;
                if (userChanges.Count > 0)
                {
                    stagedUsers = new Dictionary<string, User>();
                    if (_users.Count + userChanges.Values.Count(change => change.Current is null) -
                        userChanges.Values.Count(change => change.Remove) > byte.MaxValue)
                        throw new InvalidDataException($"{ConfigurationUsers.Path}: At most 255 users can be stored.");
                    foreach (var (name, change) in userChanges)
                    {
                        if (!ReferenceEquals(GetUser(name), change.Current))
                            throw new InvalidDataException($"{ConfigurationPlan.AppendPath(ConfigurationUsers.Path, name)}: The user changed during apply.");
                        if (change.Remove)
                        {
                            ConfigurationUsers.CheckRemoval(this, change.Current, creator);
                            stagedUsers.Add(name, null);
                            continue;
                        }
                        if (ReferenceEquals(change.Current, creator) && creator is not null &&
                            (change.Disabled || creator.IsMemberOfGroup(GetGroup(Group.ADMINISTRATORS)) &&
                                !change.Groups.Contains(Group.ADMINISTRATORS.ToLowerInvariant())))
                            throw new InvalidDataException($"{ConfigurationPlan.AppendPath(ConfigurationUsers.Path, name)}: The applying administrator must retain access.");
                        stagedUsers.Add(name, change.Stage(this, groupChanges));
                    }
                }

                var permissions = new Dictionary<PermissionSection, Permission>();
                User[] removedUsers = userChanges.Values.Where(change => change.Remove).Select(change => change.Current).ToArray();
                if (removedUsers.Length > 0)
                {
                    foreach (var (section, current) in _permissions)
                    {
                        if (!removedUsers.Any(user => current.UserPermissions.ContainsKey(user) ||
                            current.SubItemPermissions.Values.Any(item => item.UserPermissions.ContainsKey(user))))
                            continue;

                        Permission copy = current.CopySection(copySubItems: true);
                        foreach (User user in removedUsers)
                        {
                            copy.RemovePermission(user);
                            copy.RemoveAllSubItemPermissions(user);
                        }
                        permissions.Add(section, copy);
                    }
                }

                Permission zonePermissions = null;
                if (membership.Count > 0 && !permissions.TryGetValue(PermissionSection.Zones, out zonePermissions))
                {
                    zonePermissions = GetPermission(PermissionSection.Zones).CopySection();
                    permissions.Add(PermissionSection.Zones, zonePermissions);
                }
                Group admins = GetGroup(Group.ADMINISTRATORS);
                Group dnsAdmins = GetGroup(Group.DNS_ADMINISTRATORS);
                foreach (var (name, create) in membership)
                {
                    zonePermissions.RemoveAllSubItemPermissions(name);
                    if (!create)
                        continue;
                    if (creator is not null)
                        zonePermissions.SetSubItemPermission(name, creator, PermissionFlag.ViewModifyDelete);
                    zonePermissions.SetSubItemPermission(name, admins, PermissionFlag.ViewModifyDelete);
                    zonePermissions.SetSubItemPermission(name, dnsAdmins, PermissionFlag.ViewModifyDelete);
                }

                foreach (ConfigurationPermissions.Grant grant in grants)
                {
                    if (!permissions.TryGetValue(grant.Section, out Permission section))
                    {
                        section = GetPermission(grant.Section)?.CopySection() ?? new Permission(grant.Section);
                        permissions.Add(grant.Section, section);
                    }

                    if (grant.Zone is not null)
                    {
                        Permission zone = section.GetSubItemPermission(grant.Zone)?.CopySection() ??
                            new Permission(PermissionSection.Zones, grant.Zone);
                        section.ReplaceSubItemPermission(grant.Zone, zone);
                        section = zone;
                    }

                    if (grant.Group)
                    {
                        Group group = GetGroup(grant.Name);
                        if (grant.After is PermissionFlag flags)
                            section.SetPermission(group ?? groupChanges[grant.Name], flags);
                        else if (group is not null)
                            section.RemovePermission(group);
                    }
                    else
                    {
                        User user = GetUser(grant.Name);
                        if (grant.After is PermissionFlag flags)
                            section.SetPermission(user ?? stagedUsers?.GetValueOrDefault(grant.Name) ??
                                throw new InvalidDataException($"{grant.SettingPath}: The user changed during apply."), flags);
                        else if (user is not null)
                            section.RemovePermission(user);
                    }
                }

                var configuredSessions = staticSessions is null ? null : BuildManifestStaticSessions(staticSessions, stagedUsers);
                persist(() =>
                {
                    if (staticSessions is not null)
                        WriteStaticSessions(staticSessions);
                    if (permissions.Count > 0 || ldap is not null || groupChanges.Count > 0 || stagedUsers is not null || sso is not null || ldapOwnership is not null || ssoOwnership is not null || groupOwnership is not null)
                        SaveConfigFileInternal(permissions.Count > 0 ? permissions : null, ldap, groupChanges.Count > 0 ? groupChanges : null, stagedUsers, sso, ldapOwnership, ssoOwnership, groupOwnership);
                    if (ldapOwnership is not null)
                        WriteOwnership(LdapOwnershipFile, ldapOwnership);
                    if (ssoOwnership is not null)
                        WriteOwnership(SsoOwnershipFile, ssoOwnership);
                    if (groupOwnership is not null)
                        WriteOwnership(GroupOwnershipFile, groupOwnership);
                    if (userOwnership is not null)
                        WriteOwnership(UserOwnershipFile, userOwnership);
                    if (permissionOwnership is not null)
                        WriteOwnership(PermissionOwnershipFile, permissionOwnership);
                });
                foreach (var (name, group) in groupChanges)
                {
                    if (group is null)
                        _groups.TryRemove(name, out _);
                    else if (_groups.TryGetValue(name, out Group existing))
                        existing.Description = group.Description;
                    else
                        _groups.TryAdd(name, group);
                }

                if (stagedUsers is not null)
                {
                    foreach (var (name, user) in stagedUsers)
                    {
                        ConfigurationUsers.Change change = userChanges[name];
                        if (change.Remove)
                            _users.TryRemove(name, out _);
                        else if (change.Current is null)
                            _users.TryAdd(name, user);
                        else
                            change.Current.PublishManifest(user, change.Fields.Contains("password"),
                                change.Fields.Contains("totp/enabled") || change.Fields.Contains("totp/enrollment"));
                    }
                    foreach (var (token, session) in _sessions)
                    {
                        if (SessionRemovedByManifest(session, stagedUsers))
                            _sessions.TryRemove(token, out _);
                    }
                }

                if (staticSessions is not null)
                    PublishStaticSessions(staticSessions, configuredSessions);
                if (ldapOwnership is not null)
                {
                    _managedLdapFields = ldapOwnership;
                    LdapOwnershipFromPrimary = false;
                }
                if (ssoOwnership is not null)
                {
                    _managedSsoFields = ssoOwnership;
                    SsoOwnershipFromPrimary = false;
                }
                if (groupOwnership is not null)
                {
                    _managedGroupPaths = groupOwnership;
                    GroupOwnershipFromPrimary = false;
                }
                if (userOwnership is not null)
                    _managedUserPaths = userOwnership;
                if (permissionOwnership is not null)
                    _managedPermissionPaths = permissionOwnership;
                foreach (var (section, permission) in permissions)
                    _permissions[section] = permission;
                if (ldap is not null)
                    SetLdapSettings(ldap);
                if (sso is not null)
                    SetSsoSettings(sso);
            }
        }

        internal bool StaticTokenConflicts(string token) =>
            _staticSessions?.ContainsKey(token) == true || _sessions.ContainsKey(token);

        internal void LoadManifestStaticSessions()
        {
            if (_manifestStaticSessionDefinitions.Count == 0 && _manifestStaticSessionEntries.Count == 0)
                return;
            ConfigurationStaticSessions.Candidate candidate = ConfigurationStaticSessions.Prepare(null, this, loading: true);
            PublishStaticSessions(candidate, BuildManifestStaticSessions(candidate, null));
        }

        private Dictionary<string, UserSession> BuildManifestStaticSessions(ConfigurationStaticSessions.Candidate candidate,
            IReadOnlyDictionary<string, User> stagedUsers)
        {
            var result = new Dictionary<string, UserSession>(StringComparer.Ordinal);
            foreach (var (name, entry) in candidate.Entries)
            {
                string username = entry.Definition.User;
                User user = GetUser(username) ?? stagedUsers?.GetValueOrDefault(username);
                if (user is null || StaticTokenConflicts(entry.Token))
                    throw new InvalidDataException($"{ConfigurationPlan.AppendPath(ConfigurationStaticSessions.Path, name)}: The session account or token changed during apply.");
                result.Add(entry.Token, new UserSession(entry.Token, user));
            }
            return result;
        }

        private void PublishStaticSessions(ConfigurationStaticSessions.Candidate candidate, Dictionary<string, UserSession> sessions)
        {
            var definitions = new SortedDictionary<string, ConfigurationStaticSessions.Definition>(StringComparer.Ordinal);
            foreach (var (name, entry) in candidate.Entries)
                definitions.Add(name, entry.Definition);
            _manifestStaticSessionDefinitions = definitions;
            _manifestStaticSessionEntries = candidate.Entries;
            _manifestStaticSessions = sessions;
        }

        private void WriteStaticSessions(ConfigurationStaticSessions.Candidate candidate)
        {
            string file = Path.Combine(_configFolder, ConfigurationStaticSessions.FileName);
            if (candidate.Entries.Count == 0)
            {
                File.Delete(file);
                return;
            }

            string temporary = file + ".tmp";
            using (var output = new FileStream(temporary, FileMode.Create, FileAccess.Write))
            {
                JsonSerializer.Serialize(output, candidate.Entries.ToDictionary(entry => entry.Key, entry => entry.Value.Definition));
                output.Flush(flushToDisk: true);
            }
            File.Move(temporary, file, true);
        }

        private string[] ReadOwnership(string fileName)
        {
            string file = Path.Combine(_configFolder, fileName);
            return File.Exists(file)
                ? JsonSerializer.Deserialize<string[]>(File.ReadAllBytes(file))
                    ?? throw new InvalidDataException($"Invalid manifest ownership file: {fileName}.")
                : [];
        }

        private void WriteOwnership(string fileName, string[] fields)
        {
            string file = Path.Combine(_configFolder, fileName);
            if (fields.Length == 0)
            {
                File.Delete(file);
                return;
            }

            string temporary = file + ".tmp";
            using (var output = new FileStream(temporary, FileMode.Create, FileAccess.Write))
            {
                JsonSerializer.Serialize(output, fields);
                output.Flush(flushToDisk: true);
            }
            File.Move(temporary, file, true);
        }

        internal void CheckManifestRestoreOwnership(Stream stream, bool isConfigTransfer = false) =>
            ReadConfigFrom(stream, isConfigTransfer, out _, (ldap, sso, groups, users, permissions, sessions, hasLdapMetadata, hasSsoMetadata, hasGroupMetadata) =>
            {
                if (!isConfigTransfer || !hasSsoMetadata || !SsoOwnershipFromPrimary)
                    ConfigurationSso.CheckOwnership(GetManifestSsoSettings(), sso, _managedSsoFields);
                if (_managedSsoFields.Length > 0 && sso.GroupMap is not null)
                {
                    foreach (string group in sso.GroupMap.Values)
                    {
                        if (!groups.ContainsKey(group.ToLowerInvariant()))
                            ConfigurationSso.CheckGroupReference(sso, _managedSsoFields, group);
                    }
                }
                if (!isConfigTransfer || !hasLdapMetadata || !LdapOwnershipFromPrimary)
                    ConfigurationLdap.CheckOwnership(GetManifestLdapSettings(), ldap, _managedLdapFields);
                if (_managedGroupPaths.Length > 0 && (!isConfigTransfer || !hasGroupMetadata || !GroupOwnershipFromPrimary))
                    ConfigurationGroups.CheckRestore(this, groups);
                if (_managedUserPaths.Length > 0)
                    ConfigurationUsers.CheckRestore(this, users);
                if (_managedPermissionPaths.Length > 0)
                    ConfigurationPermissions.CheckRestore(this, permissions);
                foreach (var (name, definition) in _manifestStaticSessionDefinitions)
                {
                    if (!users.ContainsKey(definition.User))
                        throw new InvalidDataException($"{ConfigurationPlan.AppendPath(ConfigurationStaticSessions.Path, name)}/user: Restore would remove the session account.");
                    if (_manifestStaticSessionEntries.TryGetValue(name, out var entry) && sessions.ContainsKey(entry.Token))
                        throw new InvalidDataException($"{ConfigurationPlan.AppendPath(ConfigurationStaticSessions.Path, name)}/token: Restore would introduce a duplicate token.");
                }
            });

        internal ConfigurationLdap.Settings GetManifestLdapSettings() => new(
            _ldapEnabled, _ldapServer, _ldapPort, _ldapSslOption, _ldapIgnoreSslErrors, _ldapBindUsername, _ldapBindPassword,
            _ldapSearchBase, _ldapUserSearchFilter, _ldapGroupAttribute, _ldapAllowSignup, _ldapAllowSignupOnlyForMappedUsers, _ldapGroupMap);

        public void SaveConfigFile(bool immediately = false)
        {
            lock (_saveLock)
            {
                if (immediately)
                {
                    SaveConfigFileInternal();
                    _pendingSave = false;
                    _pendingLazySave = false;
                    return;
                }

                if (_pendingSave)
                    return;

                _pendingSave = true;
                _saveTimer.Change(SAVE_TIMER_INITIAL_INTERVAL, Timeout.Infinite);
            }
        }

        public void LazySaveConfigFile()
        {
            lock (_saveLock)
            {
                _pendingLazySave = true;
            }
        }

        private void ReadConfigFrom(Stream s, bool isConfigTransfer, out bool restartWebService, Action<ConfigurationLdap.Settings, ConfigurationSso.Settings, IReadOnlyDictionary<string, Group>, IReadOnlyDictionary<string, User>, IReadOnlyDictionary<PermissionSection, Permission>, IReadOnlyDictionary<string, UserSession>, bool, bool, bool> inspect = null, bool readOwnership = false)
        {
            if (Encoding.ASCII.GetString(s.ReadExactly(2)) != "AS") //format
                throw new InvalidDataException("DNS Server auth config file format is invalid.");

            restartWebService = false;

            ConcurrentDictionary<string, Group> groups = new ConcurrentDictionary<string, Group>(1, 4);
            ConcurrentDictionary<string, User> users = new ConcurrentDictionary<string, User>(1, 4);
            ConcurrentDictionary<PermissionSection, Permission> permissions = new ConcurrentDictionary<PermissionSection, Permission>(1, 11);
            ConcurrentDictionary<string, UserSession> sessions = new ConcurrentDictionary<string, UserSession>(1, 10);

            BinaryReader bR = new BinaryReader(s);

            int version = bR.ReadByte();
            switch (version)
            {
                case 1:
                case 2:
                case 3:
                case 4:
                    {
                        int count = bR.ReadByte();

                        for (int i = 0; i < count; i++)
                        {
                            Group group = new Group(bR);
                            groups.TryAdd(group.Name.ToLowerInvariant(), group);
                        }
                    }

                    {
                        int count = bR.ReadByte();

                        for (int i = 0; i < count; i++)
                        {
                            User user = new User(bR, groups);
                            users.TryAdd(user.Username, user);
                        }
                    }

                    {
                        int count = bR.ReadInt32();

                        for (int i = 0; i < count; i++)
                        {
                            Permission permission = new Permission(bR, users, groups);
                            permissions.TryAdd(permission.Section, permission);
                        }
                    }

                    {
                        int count = bR.ReadInt32();

                        for (int i = 0; i < count; i++)
                        {
                            UserSession session = new UserSession(bR, users);
                            if (!session.HasExpired())
                                sessions.TryAdd(session.Token, session);
                        }
                    }

                    ConfigurationSso.Settings currentSso = GetManifestSsoSettings();
                    ConfigurationSso.Settings sso = version >= 2 ? ReadSsoSettings(bR, version, currentSso.Scopes) : currentSso;
                    ConfigurationLdap.Settings ldap = version >= 4 ? ReadLdapSettings(bR) : GetManifestLdapSettings();
                    (bool ldapInherited, string[] ldapOwnership) = (false, null);
                    (bool ssoInherited, string[] ssoOwnership) = (false, null);
                    (bool groupInherited, string[] groupOwnership) = (false, null);
                    if (version >= 4 && (isConfigTransfer || readOwnership))
                    {
                        (ldapInherited, ldapOwnership) = ReadManifestOwnership(bR, ConfigurationLdap.Path);
                        (ssoInherited, ssoOwnership) = ReadManifestOwnership(bR, ConfigurationSso.Path);
                        (groupInherited, groupOwnership) = ReadManifestOwnership(bR, ConfigurationGroups.Path);

                        if (isConfigTransfer && groupOwnership is not null)
                        {
                            if (groupOwnership.Length > 0 && _managedGroupPaths.Length > 0 && !GroupOwnershipFromPrimary)
                                throw new InvalidDataException("/auth/groups: Release local group ownership before inheriting the Primary policy.");
                            if (groupOwnership.Length > 0 || GroupOwnershipFromPrimary)
                                CheckClusterGroupRemovals(groups);
                        }

                        if (isConfigTransfer && ldapOwnership is { Length: > 0 } && _managedLdapFields.Length > 0 && !LdapOwnershipFromPrimary)
                            throw new InvalidDataException("/auth/ldap: Release local LDAP ownership before inheriting the Primary policy.");
                        if (isConfigTransfer && ssoOwnership is { Length: > 0 } && _managedSsoFields.Length > 0 && !SsoOwnershipFromPrimary)
                            throw new InvalidDataException("/auth/sso: Release local SSO ownership before inheriting the Primary policy.");
                    }
                    if (inspect is not null)
                    {
                        inspect(ldap, sso, groups, users, permissions, sessions, ldapOwnership is not null, ssoOwnership is not null, groupOwnership is not null);
                        return;
                    }
                    if (version >= 2)
                    {
                        restartWebService = ConfigurationSso.NeedsRestart(currentSso, sso);
                        SetSsoSettings(sso);
                    }
                    if (version >= 4)
                        SetLdapSettings(ldap);
                    if (ldapOwnership is not null &&
                        (readOwnership && ldapInherited || isConfigTransfer && (_managedLdapFields.Length == 0 || LdapOwnershipFromPrimary)))
                    {
                        _managedLdapFields = ldapOwnership;
                        LdapOwnershipFromPrimary = ldapOwnership.Length != 0;
                    }
                    if (ssoOwnership is not null &&
                        (readOwnership && ssoInherited || isConfigTransfer && (_managedSsoFields.Length == 0 || SsoOwnershipFromPrimary)))
                    {
                        _managedSsoFields = ssoOwnership;
                        SsoOwnershipFromPrimary = ssoOwnership.Length != 0;
                    }
                    if (groupOwnership is not null &&
                        (readOwnership && groupInherited || isConfigTransfer && (_managedGroupPaths.Length == 0 || GroupOwnershipFromPrimary)))
                    {
                        _managedGroupPaths = groupOwnership;
                        GroupOwnershipFromPrimary = groupOwnership.Length != 0;
                    }

                    break;

                default:
                    throw new InvalidDataException("DNS Server auth config version not supported.");
            }

            _groups = groups;
            _users = users;

            if (isConfigTransfer)
            {
                //sync only required permissions from newly loaded config
                foreach (KeyValuePair<PermissionSection, Permission> permission in permissions)
                {
                    switch (permission.Key)
                    {
                        case PermissionSection.Zones:
                            //sync user and group permissions as-is for zones section
                            Permission zonesPermission = _permissions[PermissionSection.Zones];

                            zonesPermission.SyncPermissions(permission.Value.UserPermissions);
                            zonesPermission.SyncPermissions(permission.Value.GroupPermissions);
                            break;

                        default:
                            _permissions[permission.Key] = permission.Value;
                            break;
                    }
                }

                //update all user objects in existing sessions to reflect the newly loaded config
                foreach (KeyValuePair<string, UserSession> session in _sessions)
                    session.Value.UpdateUserObject(_users);

                //sync only API sessions from newly loaded config
                foreach (KeyValuePair<string, UserSession> existingSession in _sessions)
                {
                    switch (existingSession.Value.Type)
                    {
                        case UserSessionType.ApiToken:
                            if (!sessions.ContainsKey(existingSession.Key))
                                _sessions.TryRemove(existingSession);

                            break;
                    }
                }

                foreach (KeyValuePair<string, UserSession> session in sessions)
                {
                    switch (session.Value.Type)
                    {
                        case UserSessionType.ApiToken:
                        case UserSessionType.ClusterApiToken:
                            _sessions[session.Key] = session.Value;
                            break;
                    }
                }
            }
            else
            {
                _permissions = permissions;
                _sessions = sessions;
            }
        }

        private void CheckClusterGroupRemovals(IReadOnlyDictionary<string, Group> incoming)
        {
            Permission zones = GetPermission(PermissionSection.Zones);
            if (zones is null)
                return;

            // Cluster config sync preserves zone sub-item permissions on this node.
            foreach (Permission zone in zones.SubItemPermissions.Values)
            {
                foreach (Group group in zone.GroupPermissions.Keys)
                {
                    if (!incoming.ContainsKey(group.Name.ToLowerInvariant()))
                        throw new InvalidDataException($"{ConfigurationGroups.GroupPath(group.Name)}: The group is still referenced by a zone permission on this node.");
                }
            }
        }

        private static (bool Inherited, string[] Fields) ReadManifestOwnership(BinaryReader reader, string path)
        {
            int marker = reader.BaseStream.ReadByte();
            if (marker < 0)
                return default;
            if (marker > 1)
                throw new InvalidDataException($"{path}: Invalid manifest ownership data.");

            var fields = new string[reader.ReadUInt16()];
            for (int i = 0; i < fields.Length; i++)
                fields[i] = reader.ReadString();
            return (marker == 1, fields);
        }

        private static ConfigurationSso.Settings ReadSsoSettings(BinaryReader reader, int version, IReadOnlySet<string> scopes)
        {
            Stream stream = reader.BaseStream;
            bool enabled = reader.ReadBoolean();
            Uri authority = ReadUri();
            string clientId = ReadText();
            string clientSecret = ReadText();
            Uri metadataAddress = ReadUri();

            if (version >= 3)
            {
                int count = reader.ReadByte();
                var configured = new HashSet<string>(count, StringComparer.Ordinal);
                for (int i = 0; i < count; i++)
                    configured.Add(stream.ReadShortString());
                scopes = configured;
            }

            bool allowSignup = reader.ReadBoolean();
            bool mappedSignupOnly = reader.ReadBoolean();
            int mappings = reader.ReadByte();
            Dictionary<string, string> groupMap = mappings == 0 ? null : new(mappings);
            for (int i = 0; i < mappings; i++)
                groupMap.TryAdd(stream.ReadShortString(), stream.ReadShortString());

            return new ConfigurationSso.Settings(enabled, authority, clientId, clientSecret, metadataAddress,
                scopes, allowSignup, mappedSignupOnly, groupMap);

            string ReadText()
            {
                string value = stream.ReadShortString();
                return value.Length == 0 ? null : value;
            }

            Uri ReadUri() => ReadText() is string value ? new Uri(value) : null;
        }

        private static ConfigurationLdap.Settings ReadLdapSettings(BinaryReader reader)
        {
            bool enabled = reader.ReadBoolean();
            string server = ReadText();
            int port = reader.ReadInt32();
            var ssl = (LdapAuthSslOption)reader.ReadByte();
            bool ignoreSslErrors = reader.ReadBoolean();
            string bindUsername = ReadText();
            string bindPassword = ReadText();
            string searchBase = ReadText();
            string userSearchFilter = ReadText();
            string groupAttribute = ReadText();
            bool allowSignup = reader.ReadBoolean();
            bool mappedSignupOnly = reader.ReadBoolean();
            int count = reader.ReadByte();
            Dictionary<string, string> groupMap = count == 0 ? null : new(count);
            for (int index = 0; index < count; index++)
                groupMap.TryAdd(reader.BaseStream.ReadShortString(), reader.BaseStream.ReadShortString());

            return new ConfigurationLdap.Settings(enabled, server, port, ssl, ignoreSslErrors, bindUsername,
                bindPassword, searchBase, userSearchFilter, groupAttribute, allowSignup, mappedSignupOnly, groupMap);

            string ReadText()
            {
                string value = reader.BaseStream.ReadShortString();
                return value.Length == 0 ? null : value;
            }
        }

        internal ConfigurationSso.Settings GetManifestSsoSettings() => new(
            _ssoEnabled, _ssoAuthority, _ssoClientId, _ssoClientSecret, _ssoMetadataAddress, _ssoScopes,
            _ssoAllowSignup, _ssoAllowSignupOnlyForMappedUsers, _ssoGroupMap);

        private void SetSsoSettings(ConfigurationSso.Settings sso)
        {
            _ssoAuthority = sso.Authority;
            _ssoClientId = sso.ClientId;
            _ssoClientSecret = sso.ClientSecret;
            _ssoMetadataAddress = sso.MetadataAddress;
            _ssoScopes = sso.Scopes;
            _ssoAllowSignup = sso.AllowSignup;
            _ssoAllowSignupOnlyForMappedUsers = sso.AllowSignupOnlyForMappedUsers;
            _ssoGroupMap = sso.GroupMap?.Count > 0 ? sso.GroupMap : null;
            _ssoEnabled = sso.Enabled;
        }

        private void SetLdapSettings(ConfigurationLdap.Settings ldap)
        {
            _ldapServer = ldap.Server;
            _ldapPort = ldap.Port;
            _ldapSslOption = ldap.SslOption;
            _ldapIgnoreSslErrors = ldap.IgnoreSslErrors;
            _ldapBindUsername = ldap.BindUsername;
            _ldapBindPassword = ldap.BindPassword;
            _ldapSearchBase = ldap.SearchBase;
            _ldapUserSearchFilter = ldap.UserSearchFilter;
            _ldapGroupAttribute = ldap.GroupAttribute;
            _ldapAllowSignup = ldap.AllowSignup;
            _ldapAllowSignupOnlyForMappedUsers = ldap.AllowSignupOnlyForMappedUsers;
            _ldapGroupMap = ldap.GroupMap?.Count > 0 ? ldap.GroupMap : null;
            _ldapEnabled = ldap.Enabled;
        }

        private void WriteConfigTo(Stream s, IReadOnlyDictionary<PermissionSection, Permission> stagedPermissions = null, ConfigurationLdap.Settings ldap = null, IReadOnlyDictionary<string, Group> groupChanges = null, IReadOnlyDictionary<string, User> stagedUsers = null, ConfigurationSso.Settings sso = null, string[] ldapOwnership = null, string[] ssoOwnership = null, string[] groupOwnership = null)
        {
            BinaryWriter bW = new BinaryWriter(s);

            bW.Write(Encoding.ASCII.GetBytes("AS")); //format
            bW.Write((byte)4); //version

            if (groupChanges is null)
            {
                bW.Write(Convert.ToByte(_groups.Count));
                foreach (KeyValuePair<string, Group> group in _groups)
                    group.Value.WriteTo(bW);
            }
            else
            {
                var groups = new Dictionary<string, Group>(_groups);
                foreach (var (name, group) in groupChanges)
                {
                    if (group is null)
                        groups.Remove(name);
                    else
                        groups[name] = group;
                }
                bW.Write(Convert.ToByte(groups.Count));
                foreach (Group group in groups.Values)
                    group.WriteTo(bW);
            }

            var users = _users;
            if (stagedUsers is not null)
            {
                users = new ConcurrentDictionary<string, User>(_users);
                foreach (var (name, user) in stagedUsers)
                {
                    if (user is null)
                        users.TryRemove(name, out _);
                    else
                        users[name] = user;
                }
            }
            bW.Write(Convert.ToByte(users.Count));
            foreach (User user in users.Values)
                user.WriteTo(bW);

            if (stagedPermissions is null)
            {
                bW.Write(_permissions.Count);
                foreach (Permission permission in _permissions.Values)
                    permission.WriteTo(bW);
            }
            else
            {
                var permissions = new Dictionary<PermissionSection, Permission>(_permissions);
                foreach (var (section, permission) in stagedPermissions)
                    permissions[section] = permission;
                bW.Write(permissions.Count);
                foreach (Permission permission in permissions.Values)
                    permission.WriteTo(bW);
            }

            List<UserSession> activeSessions = new List<UserSession>(_sessions.Count);

            foreach (KeyValuePair<string, UserSession> session in _sessions)
            {
                if (session.Value.HasExpired())
                    _sessions.TryRemove(session.Key, out _);
                else if (!SessionRemovedByManifest(session.Value, stagedUsers))
                    activeSessions.Add(session.Value);
            }

            bW.Write(activeSessions.Count);

            foreach (UserSession session in activeSessions)
                session.WriteTo(bW);

            sso ??= GetManifestSsoSettings();
            bW.Write(sso.Enabled);
            s.WriteShortString(sso.Authority?.OriginalString ?? "");
            s.WriteShortString(sso.ClientId ?? "");
            s.WriteShortString(sso.ClientSecret ?? "");
            s.WriteShortString(sso.MetadataAddress?.OriginalString ?? "");

            if (sso.Scopes.Count == 0)
            {
                bW.Write((byte)0);
            }
            else
            {
                bW.Write(Convert.ToByte(sso.Scopes.Count));

                foreach (string scope in sso.Scopes)
                    s.WriteShortString(scope);
            }

            bW.Write(sso.AllowSignup);
            bW.Write(sso.AllowSignupOnlyForMappedUsers);

            if (sso.GroupMap is null || sso.GroupMap.Count == 0)
            {
                bW.Write((byte)0);
            }
            else
            {
                bW.Write(Convert.ToByte(sso.GroupMap.Count));

                foreach (KeyValuePair<string, string> entry in sso.GroupMap)
                {
                    s.WriteShortString(entry.Key);
                    s.WriteShortString(entry.Value);
                }
            }

            ldap ??= GetManifestLdapSettings();
            bW.Write(ldap.Enabled);
            s.WriteShortString(ldap.Server ?? "");
            bW.Write(ldap.Port);
            bW.Write((byte)ldap.SslOption);
            bW.Write(ldap.IgnoreSslErrors);
            s.WriteShortString(ldap.BindUsername ?? "");
            s.WriteShortString(ldap.BindPassword ?? "");
            s.WriteShortString(ldap.SearchBase ?? "");
            s.WriteShortString(ldap.UserSearchFilter ?? "");
            s.WriteShortString(ldap.GroupAttribute ?? "");
            bW.Write(ldap.AllowSignup);
            bW.Write(ldap.AllowSignupOnlyForMappedUsers);

            if ((ldap.GroupMap is null) || (ldap.GroupMap.Count == 0))
            {
                bW.Write((byte)0);
            }
            else
            {
                bW.Write(Convert.ToByte(ldap.GroupMap.Count));

                foreach (KeyValuePair<string, string> entry in ldap.GroupMap)
                {
                    s.WriteShortString(entry.Key);
                    s.WriteShortString(entry.Value);
                }
            }
            // Older version 4 readers stop after the LDAP settings or LDAP ownership.
            WriteManifestOwnership(bW, ldapOwnership is null && LdapOwnershipFromPrimary, ldapOwnership ?? _managedLdapFields);
            WriteManifestOwnership(bW, ssoOwnership is null && SsoOwnershipFromPrimary, ssoOwnership ?? _managedSsoFields);
            WriteManifestOwnership(bW, groupOwnership is null && GroupOwnershipFromPrimary, groupOwnership ?? _managedGroupPaths);
        }

        private static void WriteManifestOwnership(BinaryWriter writer, bool inherited, string[] fields)
        {
            writer.Write((byte)(inherited ? 1 : 0));
            writer.Write(checked((ushort)fields.Length));
            foreach (string field in fields)
                writer.Write(field);
        }

        #endregion

        #region private

        private void CreateDefaultConfig()
        {
            Group adminGroup = CreateGroup(Group.ADMINISTRATORS, "Super administrators");
            CreateGroup(Group.DNS_ADMINISTRATORS, "DNS service administrators");
            CreateGroup(Group.DHCP_ADMINISTRATORS, "DHCP service administrators");
            CreateGroup(Group.EVERYONE, "All users");
            ConfigurationPermissions.InstallDefaults(this);

            string adminPassword = Environment.GetEnvironmentVariable("DNS_SERVER_ADMIN_PASSWORD");
            string adminPasswordFile = Environment.GetEnvironmentVariable("DNS_SERVER_ADMIN_PASSWORD_FILE");

            User adminUser;

            if (!string.IsNullOrEmpty(adminPassword))
            {
                adminUser = CreateUser("Administrator", "admin", adminPassword);
            }
            else if (!string.IsNullOrEmpty(adminPasswordFile))
            {
                try
                {
                    using (StreamReader sR = new StreamReader(adminPasswordFile, true))
                    {
                        string password = sR.ReadLine();
                        adminUser = CreateUser("Administrator", "admin", password);
                    }
                }
                catch (Exception ex)
                {
                    _log.Write(ex);

                    adminUser = CreateUser("Administrator", "admin", "admin");
                }
            }
            else
            {
                adminUser = CreateUser("Administrator", "admin", "admin");
            }

            adminUser.AddToGroup(adminGroup);
        }

        internal void SyncRemoteDisplayName(User user, string displayName)
        {
            lock (_saveLock)
            {
                if (!ConfigurationUsers.OwnsField(_managedUserPaths, user, "displayName") && user.DisplayName != displayName)
                    user.DisplayName = displayName;
            }
        }

        internal IReadOnlyCollection<string> SyncRemoteGroups(User user, IEnumerable<string> remoteGroups, bool sso)
        {
            lock (_saveLock)
            {
                var mapping = sso ? _ssoGroupMap : _ldapGroupMap;
                if (mapping is null || ConfigurationUsers.OwnsField(_managedUserPaths, user, "groups"))
                    return null;

                var groups = new Dictionary<string, Group>();
                foreach (string remoteGroup in remoteGroups)
                {
                    if (mapping.TryGetValue(remoteGroup, out string localName) && GetGroup(localName) is Group group)
                        groups.TryAdd(group.Name.ToLowerInvariant(), group);
                }

                Group everyone = GetGroup(Group.EVERYONE);
                groups[everyone.Name.ToLowerInvariant()] = everyone;
                user.SyncGroups(groups);
                return groups.Keys;
            }
        }

        private async Task<User> AuthenticateUserAsync(string username, string password, string totp, IPAddress remoteAddress)
        {
            IPAddress network = GetClientNetwork(remoteAddress);

            if (IsNetworkBlocked(network))
                throw new DnsWebServiceException("Max limit of " + MAX_LOGIN_ATTEMPTS + " attempts exceeded. Access blocked for " + (BLOCK_NETWORK_INTERVAL / 1000) + " seconds.");

            User user = GetUser(username);

            if (user is null)
            {
                //no such user was found
                if (_ldapEnabled && !string.IsNullOrEmpty(_ldapServer))
                {
                    try
                    {
                        //try LDAP authentication and auto-provision if allowed
                        LdapAuthProvider ldapProvider = new LdapAuthProvider(_dnsWebService.DnsServer, _ldapServer, _ldapPort, _ldapSslOption, _ldapIgnoreSslErrors, _ldapBindUsername, _ldapBindPassword, _ldapSearchBase, _ldapUserSearchFilter, _ldapGroupAttribute);
                        LdapAuthProvider.AuthInfo authInfo = await ldapProvider.AuthenticateAsync(username, password);

                        if (!_ldapAllowSignup)
                            throw new DnsWebServiceException("LDAP authentication succeeded for '" + username + "' but new user sign up is disabled. Please contact your administrator.");

                        if (_ldapAllowSignupOnlyForMappedUsers && (_ldapGroupMap is not null))
                        {
                            bool hasMappedGroup = false;

                            foreach (string remoteGroup in authInfo.Groups)
                            {
                                if (_ldapGroupMap.ContainsKey(remoteGroup))
                                {
                                    hasMappedGroup = true;
                                    break;
                                }
                            }

                            if (!hasMappedGroup)
                                throw new DnsWebServiceException("LDAP authentication succeeded for '" + username + "' but new user sign up is restricted only to members of mapped groups. Please contact your administrator.");
                        }

                        //create new user
                        user = CreateLdapUser(authInfo.DisplayName, username);

                        SyncRemoteGroups(user, authInfo.Groups, sso: false);

                        _log.Write(new IPEndPoint(remoteAddress, 0), "LDAP user account was created successfully with username: " + user.Username + " (displayName: " + user.DisplayName + ")");

                        ResetFailedLoginAttempts(network);

                        return user;
                    }
                    catch (LdapAuthFailedException ex)
                    {
                        _log.Write(ex);
                        await ThrowAuthFailedExceptionAsync(innerException: ex);
                    }
                    catch (LdapAuthException ex)
                    {
                        //do not throw exception to hide LDAP failure message from unknown user
                        _log.Write(ex);
                    }
                    catch (DnsWebServiceException)
                    {
                        //throw web service exceptions to allow showing error message to the user
                        throw;
                    }
                    catch (Exception ex)
                    {
                        _log.Write(ex);
                    }
                }

                await ThrowAuthFailedExceptionAsync();
                throw new InvalidOperationException();
            }

            switch (user.Type)
            {
                case UserType.RemoteSSO:
                    //SSO users cannot authenticate locally
                    await ThrowAuthFailedExceptionAsync();
                    throw new InvalidOperationException();

                case UserType.RemoteLDAP:
                    //ldap authentication
                    if (!_ldapEnabled || string.IsNullOrEmpty(_ldapServer))
                        throw new DnsWebServiceException("LDAP authentication is not configured.");

                    try
                    {
                        LdapAuthProvider ldapProvider = new LdapAuthProvider(_dnsWebService.DnsServer, _ldapServer, _ldapPort, _ldapSslOption, _ldapIgnoreSslErrors, _ldapBindUsername, _ldapBindPassword, _ldapSearchBase, _ldapUserSearchFilter, _ldapGroupAttribute);
                        LdapAuthProvider.AuthInfo authInfo = await ldapProvider.AuthenticateAsync(username, password);

                        //sync display name
                        SyncRemoteDisplayName(user, authInfo.DisplayName);

                        SyncRemoteGroups(user, authInfo.Groups, sso: false);
                    }
                    catch (LdapAuthFailedException ex)
                    {
                        await ThrowAuthFailedExceptionAsync(innerException: ex);
                        throw;
                    }
                    catch (LdapAuthException ex)
                    {
                        throw new DnsWebServiceException("Failed to authenticate with LDAP. Please contact your administrator.", ex);
                    }

                    //proceed to TOTP
                    break;

                case UserType.Local:
                default:
                    //local authentication
                    if (!user.PasswordHash.Equals(user.GetPasswordHashFor(password), StringComparison.Ordinal))
                        await ThrowAuthFailedExceptionAsync();

                    //proceed to TOTP
                    break;
            }

            bool totpEnabled;
            AuthenticatorKeyUri enrollment;
            lock (_saveLock)
            {
                totpEnabled = user.TOTPEnabled;
                enrollment = user.TOTPKeyUri;
            }
            if (totpEnabled)
            {
                if (string.IsNullOrEmpty(totp))
                    throw new TwoFactorAuthRequiredWebServiceException("A time-based one-time password (TOTP) is required for user: " + username);

                if (enrollment is null)
                    throw new DnsWebServiceException("The account's TOTP enrollment is unavailable.");

                Authenticator authenticator = new Authenticator(enrollment);

                if (!authenticator.IsTOTPValid(totp))
                    await ThrowAuthFailedExceptionAsync("Invalid time-based one-time password (TOTP) was attempted for user: " + username);
            }

            ResetFailedLoginAttempts(network);

            if (user.Disabled)
                throw new DnsWebServiceException("User account is disabled. Please contact your administrator.");

            return user;

            async Task ThrowAuthFailedExceptionAsync(string message = null, Exception innerException = null)
            {
                MarkFailedLoginAttempt(network);

                if (HasLoginAttemptExceedLimit(network, MAX_LOGIN_ATTEMPTS))
                    BlockNetwork(network, BLOCK_NETWORK_INTERVAL);

                await Task.Delay(1000);

                throw new DnsWebServiceException(message ?? "Invalid username or password for user: " + username, innerException);
            }
        }

        private static IPAddress GetClientNetwork(IPAddress address)
        {
            switch (address.AddressFamily)
            {
                case AddressFamily.InterNetwork:
                    return address.GetNetworkAddress(32);

                case AddressFamily.InterNetworkV6:
                    return address.GetNetworkAddress(64);

                default:
                    throw new InvalidOperationException();
            }
        }

        private void MarkFailedLoginAttempt(IPAddress network)
        {
            _failedLoginAttemptNetworks.AddOrUpdate(network, 1, delegate (IPAddress key, int attempts)
            {
                return attempts + 1;
            });
        }

        private bool HasLoginAttemptExceedLimit(IPAddress network, int limit)
        {
            if (!_failedLoginAttemptNetworks.TryGetValue(network, out int attempts))
                return false;

            return attempts >= limit;
        }

        private void ResetFailedLoginAttempts(IPAddress network)
        {
            _failedLoginAttemptNetworks.TryRemove(network, out _);
        }

        private void BlockNetwork(IPAddress network, int interval)
        {
            _blockedNetworks.TryAdd(network, DateTime.UtcNow.AddMilliseconds(interval));
        }

        private bool IsNetworkBlocked(IPAddress network)
        {
            if (!_blockedNetworks.TryGetValue(network, out DateTime expiry))
                return false;

            if (expiry > DateTime.UtcNow)
            {
                return true;
            }
            else
            {
                UnblockNetwork(network);
                ResetFailedLoginAttempts(network);

                return false;
            }
        }

        private void UnblockNetwork(IPAddress network)
        {
            _blockedNetworks.TryRemove(network, out _);
        }

        #endregion

        #region public

        public User GetUser(string username)
        {
            User.IsUsernameValid(username, true);

            if (_users.TryGetValue(username.ToLowerInvariant(), out User user))
                return user;

            return null;
        }

        public User GetSsoUser(string ssoIdentifier)
        {
            foreach (KeyValuePair<string, User> user in _users)
            {
                if (ssoIdentifier.Equals(user.Value.SsoIdentifier, StringComparison.Ordinal) && (user.Value.Type == UserType.RemoteSSO))
                    return user.Value;
            }

            return null;
        }

        public User CreateUser(string displayName, string username, string password, int iterations = User.DEFAULT_ITERATIONS) =>
            RegisterUser(User.CreateLocalUser(displayName, username, password, iterations));

        public User CreateSsoUser(string displayName, string username, string ssoIdentifier) =>
            RegisterUser(User.CreateSsoUser(displayName, username, ssoIdentifier));

        public User CreateLdapUser(string displayName, string username) =>
            RegisterUser(User.CreateLdapUser(displayName, username));

        private User RegisterUser(User user)
        {
            lock (_saveLock)
            {
                ConfigurationUsers.CheckMembership(_managedUserPaths, user.Username, user.Type);
                if (_users.Count >= byte.MaxValue)
                    throw new DnsWebServiceException("Cannot create more than 255 users.");

                if (user.Type == UserType.RemoteSSO && GetSsoUser(user.SsoIdentifier) is not null)
                    throw new DnsWebServiceException("The SSO identifier is already in use.");
                user.AddToGroup(GetGroup(Group.EVERYONE));
                if (!_users.TryAdd(user.Username, user))
                    throw new DnsWebServiceException("User already exists: " + user.Username);
                return user;
            }
        }

        public bool HasDefaultCredentials()
        {
            User user = GetUser("admin");

            return (user is not null) && user.HasDefaultCredentials();
        }

        public void ChangeUsername(User user, string newUsername)
        {
            lock (_saveLock)
            {
                if (user.Username.Equals(newUsername, StringComparison.OrdinalIgnoreCase))
                    return;

                ConfigurationUsers.CheckMembership(_managedUserPaths, user.Username, user.Type);
                ConfigurationUsers.CheckMembership(_managedUserPaths, newUsername, user.Type);
                CheckManifestStaticSessionAccount(user);
                CheckPrincipalGrantChanges(user, newUsername);
                string oldUsername = user.Username;
                user.SetUsername(newUsername);

                if (!_users.TryAdd(user.Username, user))
                {
                    user.SetUsername(oldUsername); //revert
                    throw new DnsWebServiceException("User already exists: " + newUsername);
                }

                _users.TryRemove(oldUsername, out _);
            }
        }

        public async Task<User> ChangePasswordAsync(string username, string password, string totp, IPAddress remoteAddress, string newPassword, int iterations)
        {
            User user = await AuthenticateUserAsync(username, password, totp, remoteAddress);

            if (ConfigurationUsers.CheckPassword(_managedUserPaths, user, newPassword, iterations))
                user.ChangePassword(newPassword, iterations);

            return user;
        }

        public bool DeleteUser(string username)
        {
            if (GetUser(username) is User current)
            {
                ConfigurationUsers.CheckMembership(_managedUserPaths, username, current.Type);
                CheckManifestStaticSessionAccount(current);
                CheckPrincipalGrantChanges(current);
            }
            if (_users.TryRemove(username.ToLowerInvariant(), out User deletedUser))
            {
                //delete all sessions
                foreach (UserSession session in GetSessions(deletedUser))
                    DeleteSession(session.Token);

                //delete all permissions
                foreach (KeyValuePair<PermissionSection, Permission> permission in _permissions)
                {
                    permission.Value.RemovePermission(deletedUser);
                    permission.Value.RemoveAllSubItemPermissions(deletedUser);
                }

                return true;
            }

            return false;
        }

        public Group GetGroup(string name)
        {
            if (name.Length > 255)
                throw new ArgumentException("Group name length cannot exceed 255 characters.", nameof(name));

            if (_groups.TryGetValue(name.ToLowerInvariant(), out Group group))
                return group;

            return null;
        }

        public List<User> GetGroupMembers(Group group)
        {
            List<User> members = new List<User>();

            foreach (KeyValuePair<string, User> user in _users)
            {
                if (user.Value.IsMemberOfGroup(group))
                    members.Add(user.Value);
            }

            return members;
        }

        internal void CheckGroupMembershipChanges(Group group, IReadOnlyDictionary<string, User> users)
        {
            foreach (User user in _users.Values)
                ConfigurationUsers.CheckField(_managedUserPaths, user, "groups", user.IsMemberOfGroup(group) != users.ContainsKey(user.Username));
        }

        private void CheckGroupIdentityChanges(Group group)
        {
            foreach (User user in GetGroupMembers(group))
                ConfigurationUsers.CheckField(_managedUserPaths, user, "groups", changes: true);
        }

        public void SyncGroupMembers(Group group, IReadOnlyDictionary<string, User> users)
        {
            //remove
            foreach (KeyValuePair<string, User> user in _users)
            {
                if (!users.ContainsKey(user.Key))
                    user.Value.RemoveFromGroup(group);
            }

            //set
            foreach (KeyValuePair<string, User> user in users)
                user.Value.AddToGroup(group);
        }

        public Group CreateGroup(string name, string description)
        {
            if (_groups.Count >= byte.MaxValue)
                throw new DnsWebServiceException("Cannot create more than 255 groups.");

            Group group = new Group(name, description);

            if (_groups.TryAdd(name.ToLowerInvariant(), group))
            {
                if (_groups.Count > byte.MaxValue)
                {
                    _groups.TryRemove(name.ToLowerInvariant(), out _); //undo
                    throw new DnsWebServiceException("Cannot create more than 255 groups.");
                }

                return group;
            }

            throw new DnsWebServiceException("Group already exists: " + name);
        }

        public void RenameGroup(Group group, string newGroupName)
        {
            if (group.Name != newGroupName)
                CheckPrincipalGrantChanges(group, newGroupName);
            if (group.Name.Equals(newGroupName, StringComparison.OrdinalIgnoreCase))
            {
                group.Name = newGroupName;
                return;
            }

            CheckGroupIdentityChanges(group);
            ConfigurationSso.CheckGroupReference(GetManifestSsoSettings(), _managedSsoFields, group.Name);
            string oldGroupName = group.Name;
            group.Name = newGroupName;

            if (!_groups.TryAdd(group.Name.ToLowerInvariant(), group))
            {
                group.Name = oldGroupName; //revert
                throw new DnsWebServiceException("Group already exists: " + newGroupName);
            }

            _groups.TryRemove(oldGroupName.ToLowerInvariant(), out _);

            //update users
            foreach (KeyValuePair<string, User> user in _users)
                user.Value.RenameGroup(oldGroupName);
        }

        public bool DeleteGroup(string name)
        {
            name = name.ToLowerInvariant();

            switch (name)
            {
                case "everyone":
                case "administrators":
                case "dns administrators":
                case "dhcp administrators":
                    throw new InvalidOperationException("Access was denied.");

                default:
                    if (_groups.TryGetValue(name, out Group group))
                    {
                        CheckGroupIdentityChanges(group);
                        ConfigurationSso.CheckGroupReference(GetManifestSsoSettings(), _managedSsoFields, group.Name);
                        CheckPrincipalGrantChanges(group);
                    }
                    if (_groups.TryRemove(name, out Group deletedGroup))
                    {
                        //remove all users from deleted group
                        foreach (KeyValuePair<string, User> user in _users)
                            user.Value.RemoveFromGroup(deletedGroup);

                        //delete all permissions
                        foreach (KeyValuePair<PermissionSection, Permission> permission in _permissions)
                        {
                            permission.Value.RemovePermission(deletedGroup);
                            permission.Value.RemoveAllSubItemPermissions(deletedGroup);
                        }

                        return true;
                    }

                    return false;
            }
        }

        public UserSession GetSession(string token)
        {
            if (token is not null)
            {
                if (_sessions.TryGetValue(token, out UserSession session))
                    return session;

                if ((_staticSessions is not null) && _staticSessions.TryGetValue(token, out UserSession staticSession))
                    return staticSession;
                if (_manifestStaticSessions.TryGetValue(token, out UserSession configured))
                {
                    if (!_users.TryGetValue(configured.User.Username, out _))
                        return null;
                    configured.UpdateUserObject(_users);
                    return configured;
                }
            }

            return null;
        }

        private void CheckPrincipalGrantChanges(User user, string newName = null) =>
            CheckPrincipalGrantChanges(false, user.Username, newName, permission => permission.UserPermissions.ContainsKey(user));

        private void CheckPrincipalGrantChanges(Group group, string newName = null) =>
            CheckPrincipalGrantChanges(true, group.Name, newName, permission => permission.GroupPermissions.ContainsKey(group));

        private void CheckPrincipalGrantChanges(bool group, string name, string newName, Func<Permission, bool> hasGrant)
        {
            if (_managedPermissionPaths.Length == 0)
                return;
            foreach (Permission permission in _permissions.Values)
            {
                Check(permission);
                if (permission.Section == PermissionSection.Zones)
                {
                    foreach (Permission zone in permission.SubItemPermissions.Values)
                        Check(zone);
                }
            }

            void Check(Permission permission)
            {
                if (!hasGrant(permission))
                    return;
                ConfigurationPermissions.CheckGrant(_managedPermissionPaths, permission.Section, group, name, permission.SubItemName);
                if (newName is not null)
                    ConfigurationPermissions.CheckGrant(_managedPermissionPaths, permission.Section, group, newName, permission.SubItemName);
            }
        }

        private void CheckManifestStaticSessionAccount(User user)
        {
            foreach (var (name, definition) in _manifestStaticSessionDefinitions)
            {
                if (definition.User == user.Username)
                    throw new InvalidDataException($"{ConfigurationPlan.AppendPath(ConfigurationStaticSessions.Path, name)}/user: The account is referenced by a static session.");
            }
        }

        internal bool HasLegacyStaticSession(User user) =>
            _staticSessions?.Values.Any(session => session.User.Equals(user)) == true;

        private static bool SessionRemovedByManifest(UserSession session, IReadOnlyDictionary<string, User> stagedUsers) =>
            stagedUsers?.TryGetValue(session.User.Username, out User staged) == true &&
            (staged is null || staged.Disabled && session.Type is UserSessionType.Standard or UserSessionType.SingleUse);

        public List<UserSession> GetSessions(User user)
        {
            List<UserSession> userSessions = new List<UserSession>();

            foreach (KeyValuePair<string, UserSession> session in _sessions)
            {
                if (session.Value.User.Equals(user) && !session.Value.HasExpired())
                    userSessions.Add(session.Value);
            }

            return userSessions;
        }

        public async Task<UserSession> CreateSessionAsync(UserSessionType type, string tokenName, string username, string password, string totp, IPAddress remoteAddress, string userAgent)
        {
            User user = await AuthenticateUserAsync(username, password, totp, remoteAddress);

            if (type == UserSessionType.ClusterApiToken)
                throw new InvalidOperationException();

            return CreateSession(type, tokenName, user, remoteAddress, userAgent);
        }

        public UserSession CreateSession(UserSessionType type, string tokenName, string username, IPAddress remoteAddress, string userAgent)
        {
            User user = GetUser(username);
            if (user is null)
                throw new DnsWebServiceException("No such user exists: " + username);

            return CreateSession(type, tokenName, user, remoteAddress, userAgent);
        }

        public UserSession CreateSession(UserSessionType type, string tokenName, User user, IPAddress remoteAddress, string userAgent)
        {
            lock (_saveLock)
            {
                if (!ReferenceEquals(GetUser(user.Username), user))
                    throw new DnsWebServiceException("User account is unavailable. Please contact your administrator.");
                if (user.Disabled)
                    throw new DnsWebServiceException("User account is disabled. Please contact your administrator.");

                UserSession session = new UserSession(type, tokenName, user, remoteAddress, userAgent);
                if (!_sessions.TryAdd(session.Token, session))
                    throw new DnsWebServiceException("Error while creating session. Please try again.");

                user.LoggedInFrom(remoteAddress);
                return session;
            }
        }

        public UserSession DeleteSession(string token)
        {
            if (_sessions.TryRemove(token, out UserSession session))
                return session;

            return null;
        }

        public Permission GetPermission(PermissionSection section)
        {
            if (_permissions.TryGetValue(section, out Permission permission))
                return permission;

            return null;
        }

        public Permission GetPermission(PermissionSection section, string subItemName)
        {
            if (_permissions.TryGetValue(section, out Permission permission))
                return permission.GetSubItemPermission(subItemName);

            return null;
        }

        public void SetPermission(PermissionSection section, User user, PermissionFlag flags)
        {
            Permission permission = _permissions.GetOrAdd(section, delegate (PermissionSection key)
            {
                return new Permission(key);
            });

            permission.SetPermission(user, flags);
        }

        public void SetPermission(PermissionSection section, string subItemName, User user, PermissionFlag flags)
        {
            Permission permission = _permissions.GetOrAdd(section, delegate (PermissionSection key)
            {
                return new Permission(key);
            });

            permission.SetSubItemPermission(subItemName, user, flags);
        }

        public void SetPermission(PermissionSection section, Group group, PermissionFlag flags)
        {
            Permission permission = _permissions.GetOrAdd(section, delegate (PermissionSection key)
            {
                return new Permission(key);
            });

            permission.SetPermission(group, flags);
        }

        public void SetPermission(PermissionSection section, string subItemName, Group group, PermissionFlag flags)
        {
            Permission permission = _permissions.GetOrAdd(section, delegate (PermissionSection key)
            {
                return new Permission(key);
            });

            permission.SetSubItemPermission(subItemName, group, flags);
        }

        public bool RemovePermission(PermissionSection section, User user)
        {
            return _permissions.TryGetValue(section, out Permission permission) && permission.RemovePermission(user);
        }

        public bool RemovePermission(PermissionSection section, string subItemName, User user)
        {
            return _permissions.TryGetValue(section, out Permission permission) && permission.RemoveSubItemPermission(subItemName, user);
        }

        public bool RemovePermission(PermissionSection section, Group group)
        {
            return _permissions.TryGetValue(section, out Permission permission) && permission.RemovePermission(group);
        }

        public bool RemovePermission(PermissionSection section, string subItemName, Group group)
        {
            return _permissions.TryGetValue(section, out Permission permission) && permission.RemoveSubItemPermission(subItemName, group);
        }

        public bool RemoveAllPermissions(PermissionSection section, string subItemName)
        {
            return _permissions.TryGetValue(section, out Permission permission) && permission.RemoveAllSubItemPermissions(subItemName);
        }

        public bool IsPermitted(PermissionSection section, User user, PermissionFlag flag)
        {
            return _permissions.TryGetValue(section, out Permission permission) && permission.IsPermitted(user, flag);
        }

        public bool IsPermitted(PermissionSection section, string subItemName, User user, PermissionFlag flag)
        {
            return _permissions.TryGetValue(section, out Permission permission) && permission.IsSubItemPermitted(subItemName, user, flag);
        }

        #endregion

        #region properties

        public ICollection<Group> Groups
        { get { return _groups.Values; } }

        public ICollection<User> Users
        { get { return _users.Values; } }

        public ICollection<Permission> Permissions
        { get { return _permissions.Values; } }

        public ICollection<UserSession> Sessions
        { get { return _sessions.Values; } }

        public bool SsoEnabled
        {
            get { return _ssoEnabled; }
            set { _ssoEnabled = value; }
        }

        public Uri SsoAuthority
        {
            get { return _ssoAuthority; }
            set
            {
                if (value is not null)
                {
                    if (value.OriginalString.Length > 255)
                        throw new ArgumentException("The SSO Authority URL length cannot be more than 255 chars.", nameof(SsoAuthority));

                    switch (value.Scheme.ToLowerInvariant())
                    {
                        case "http":
                        case "https":
                            break;

                        default:
                            throw new ArgumentException("The SSO Authority URL scheme can be 'http' or 'https' only.", nameof(SsoAuthority));
                    }
                }

                _ssoAuthority = value;
            }
        }

        public string SsoClientId
        {
            get { return _ssoClientId; }
            set
            {
                if (value is not null)
                {
                    if (value.Length == 0)
                        value = null;
                    else if (value.Length > 255)
                        throw new ArgumentException("The SSO Client ID length cannot be more than 255 chars.", nameof(SsoClientId));
                }

                _ssoClientId = value;
            }
        }

        public string SsoClientSecret
        {
            get { return _ssoClientSecret; }
            set
            {
                if (value is not null)
                {
                    if (value.Length == 0)
                        value = null;
                    else if (value.Length > 255)
                        throw new ArgumentException("The SSO Client Secret length cannot be more than 255 chars.", nameof(SsoClientSecret));
                }

                _ssoClientSecret = value;
            }
        }

        public Uri SsoMetadataAddress
        {
            get { return _ssoMetadataAddress; }
            set
            {
                if (value is not null)
                {
                    if (value.OriginalString.Length > 255)
                        throw new ArgumentException("The SSO Metadata Address URL length cannot be more than 255 chars.", nameof(SsoMetadataAddress));

                    switch (value.Scheme.ToLowerInvariant())
                    {
                        case "http":
                        case "https":
                            break;

                        default:
                            throw new ArgumentException("The SSO Metadata Address URL scheme can be 'http' or 'https' only.", nameof(SsoMetadataAddress));
                    }
                }

                _ssoMetadataAddress = value;
            }
        }

        public IReadOnlySet<string> SsoScopes
        {
            get { return _ssoScopes; }
            set
            {
                if ((value is null) || (value.Count == 0))
                {
                    value = new HashSet<string>() { "openid", "profile", "email" };
                }
                else if (value.Count > 255)
                {
                    throw new ArgumentException("The SSO Scopes cannot have more than 255 entries.", nameof(SsoScopes));
                }
                else if (!value.Contains("openid") || !value.Contains("profile"))
                {
                    HashSet<string> ssoScopes = new HashSet<string>() { "openid", "profile" };

                    foreach (string scope in value)
                    {
                        if (scope.Length > 255)
                            throw new ArgumentException("The SSO Scope name length cannot be more than 255 chars.", nameof(SsoScopes));

                        ssoScopes.Add(scope);
                    }

                    value = ssoScopes;
                }

                _ssoScopes = value;
            }
        }

        public bool SsoAllowSignup
        {
            get { return _ssoAllowSignup; }
            set { _ssoAllowSignup = value; }
        }

        public bool SsoAllowSignupOnlyForMappedUsers
        {
            get { return _ssoAllowSignupOnlyForMappedUsers; }
            set { _ssoAllowSignupOnlyForMappedUsers = value; }
        }

        public IReadOnlyDictionary<string, string> SsoGroupMap
        {
            get { return _ssoGroupMap; }
            set
            {
                if (value is not null)
                {
                    if (value.Count == 0)
                        value = null;
                    else if (value.Count > 255)
                        throw new ArgumentException("The SSO Group Map cannot have more than 255 entries.", nameof(SsoGroupMap));
                }

                _ssoGroupMap = value;
            }
        }

        public bool SsoManagedGroups
        { get { return _ssoGroupMap is not null; } }

        public bool LdapEnabled
        {
            get { return _ldapEnabled; }
            set { _ldapEnabled = value; }
        }

        public string LdapServer
        {
            get { return _ldapServer; }
            set
            {
                if (value is not null)
                {
                    if (value.Length == 0)
                        value = null;
                    else if (value.Length > 255)
                        throw new ArgumentException("The LDAP Server length cannot be more than 255 chars.", nameof(LdapServer));
                }

                _ldapServer = value;
            }
        }

        public int LdapPort
        {
            get { return _ldapPort; }
            set
            {
                if ((value < 1) || (value > 65535))
                    throw new ArgumentOutOfRangeException(nameof(LdapPort), "LDAP port must be between 1 and 65535.");

                _ldapPort = value;
            }
        }

        public LdapAuthSslOption LdapSslOption
        {
            get { return _ldapSslOption; }
            set { _ldapSslOption = value; }
        }

        public bool LdapIgnoreSslErrors
        {
            get { return _ldapIgnoreSslErrors; }
            set { _ldapIgnoreSslErrors = value; }
        }

        public string LdapBindUsername
        {
            get { return _ldapBindUsername; }
            set
            {
                if (value is not null)
                {
                    if (value.Length == 0)
                        value = null;
                    else if (value.Length > 255)
                        throw new ArgumentException("The LDAP Bind Username length cannot be more than 255 chars.", nameof(LdapBindUsername));
                }

                _ldapBindUsername = value;
            }
        }

        public string LdapBindPassword
        {
            get { return _ldapBindPassword; }
            set
            {
                if (value is not null)
                {
                    if (value.Length == 0)
                        value = null;
                    else if (value.Length > 255)
                        throw new ArgumentException("The LDAP Bind Password length cannot be more than 255 chars.", nameof(LdapBindPassword));
                }

                _ldapBindPassword = value;
            }
        }

        public string LdapSearchBase
        {
            get { return _ldapSearchBase; }
            set
            {
                if (value is not null)
                {
                    if (value.Length == 0)
                        value = null;
                    else if (value.Length > 255)
                        throw new ArgumentException("The LDAP Search Base length cannot be more than 255 chars.", nameof(LdapSearchBase));
                }

                _ldapSearchBase = value;
            }
        }

        public string LdapUserSearchFilter
        {
            get { return _ldapUserSearchFilter; }
            set
            {
                if (value is not null)
                {
                    if (value.Length == 0)
                        value = null;
                    else if (value.Length > 255)
                        throw new ArgumentException("The LDAP User Filter length cannot be more than 255 chars.", nameof(LdapUserSearchFilter));
                }

                _ldapUserSearchFilter = value;
            }
        }

        public string LdapGroupAttribute
        {
            get { return _ldapGroupAttribute; }
            set
            {
                if (value is not null)
                {
                    if (value.Length == 0)
                        value = null;
                    else if (value.Length > 255)
                        throw new ArgumentException("The LDAP Group Attribute length cannot be more than 255 chars.", nameof(LdapGroupAttribute));
                }

                _ldapGroupAttribute = value;
            }
        }

        public bool LdapAllowSignup
        {
            get { return _ldapAllowSignup; }
            set { _ldapAllowSignup = value; }
        }

        public bool LdapAllowSignupOnlyForMappedUsers
        {
            get { return _ldapAllowSignupOnlyForMappedUsers; }
            set { _ldapAllowSignupOnlyForMappedUsers = value; }
        }

        public IReadOnlyDictionary<string, string> LdapGroupMap
        {
            get { return _ldapGroupMap; }
            set
            {
                if (value is not null)
                {
                    if (value.Count == 0)
                        value = null;
                    else if (value.Count > 255)
                        throw new ArgumentException("The LDAP Group Map cannot have more than 255 entries.", nameof(LdapGroupMap));
                }

                _ldapGroupMap = value;
            }
        }

        public bool LdapManagedGroups
        { get { return _ldapGroupMap is not null; } }

        #endregion
    }
}
