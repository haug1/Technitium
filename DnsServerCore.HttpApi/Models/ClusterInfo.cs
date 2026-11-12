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

using System;
using System.Collections.Generic;

namespace DnsServerCore.HttpApi.Models
{
    public class ClusterInfo
    {
        public bool ClusterInitialized { get; set; }
        public bool SupportsDeclarativeClusterOptions { get; set; }
        public bool SupportsDeclarativeBlockLists { get; set; }
        public bool SupportsDeclarativeDomainLists { get; set; }
        public bool SupportsDeclarativeDnsPolicy { get; set; }
        public bool SupportsDeclarativeResolverPolicy { get; set; }
        public bool SupportsDeclarativeRateLimits { get; set; }
        public bool SupportsDeclarativeProxy { get; set; }
        public bool SupportsDeclarativeDnsTuning { get; set; }
        public bool SupportsDeclarativeTsig { get; set; }
        public bool SupportsDeclarativeLdap { get; set; }
        public bool SupportsDeclarativeSso { get; set; }
        public bool SupportsDeclarativeGroups { get; set; }
        public bool SupportsDeclarativeUsers { get; set; }
        public bool SupportsDeclarativePermissions { get; set; }
        public bool SupportsDeclarativeApps { get; set; }
        public bool SupportsDeclarativeAppDigests { get; set; }
        public bool SupportsDeclarativeClusterHandoff { get; set; }
        public string[]? ManagedOptionPaths { get; set; }
        public string? ClusterDomain { get; set; }
        public ushort HeartbeatRefreshIntervalSeconds { get; set; }
        public ushort HeartbeatRetryIntervalSeconds { get; set; }
        public ushort ConfigRefreshIntervalSeconds { get; set; }
        public ushort ConfigRetryIntervalSeconds { get; set; }
        public DateTime? ConfigLastSynced { get; set; }
        public List<ClusterNodeInfo>? ClusterNodes { get; set; }

        public class ClusterNodeInfo
        {
            public int Id { get; set; }
            public required string Name { get; set; }
            public required Uri Url { get; set; }
            public required string[] IPAddresses { get; set; }
            public required string Type { get; set; }
            public required string State { get; set; }
            public string? Version { get; set; }
            public DateTime? UpSince { get; set; }
            public DateTime? LastSeen { get; set; }
        }
    }
}
