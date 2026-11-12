"""Check cluster intervals across two builds or verify same-build propagation."""

import argparse
import base64
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request


HTTP = urllib.request.build_opener(urllib.request.ProxyHandler({}))
EMPTY_MANIFEST = {"schemaVersion": 1}
INTERVAL_MANIFEST = {"schemaVersion": 1, "cluster": {"configRefreshSeconds": 120}}


def ok(result):
    if result["status"] != "ok":
        raise RuntimeError(result.get("errorMessage", result["status"]))
    return result.get("response", result)


def allocate_ports():
    sockets = [socket.socket() for _ in range(6)]
    try:
        for listener in sockets:
            listener.bind(("127.0.0.1", 0))
        return [listener.getsockname()[1] for listener in sockets]
    finally:
        for listener in sockets:
            listener.close()


class Node:
    def __init__(self, binary, folder, name, ports, password):
        self.binary = binary
        self.folder = folder
        self.folder.mkdir()
        self.http_port, self.tls_port, self.dns_port = ports
        self.password = password
        self.token = None
        self.process = None
        self.manifest = folder / "technitium.json"
        self.manifest.write_text(json.dumps({
            "schemaVersion": 1,
            "dns": {"serverDomain": name, "localEndpoints": [f"127.0.0.1:{self.dns_port}"],
                    "recursion": {"mode": "Deny"}, "checkForUpdates": False},
            "web": {"localAddresses": ["127.0.0.1"], "httpPort": self.http_port,
                    "tlsPort": self.tls_port, "tlsEnabled": True, "useSelfSignedCertificate": True},
        }), encoding="utf-8")

    def call(self, path, *, manifest=None, form=None, revision=None):
        headers = {}
        if self.token:
            headers["Authorization"] = "Bearer " + self.token
        if revision:
            headers["If-Match"] = f'"{revision}"'
        data = None
        if manifest is not None:
            data = json.dumps(manifest).encode()
            headers["Content-Type"] = "application/json"
        if form is not None:
            data = urllib.parse.urlencode(form).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        request = urllib.request.Request(f"http://127.0.0.1:{self.http_port}/api/{path}", data, headers)
        with HTTP.open(request, timeout=10) as response:
            return json.load(response)

    def start(self, release_seed=True):
        self.token = None
        env = {name: value for name, value in os.environ.items() if not name.startswith("DNS_SERVER_")}
        env["DNS_SERVER_ADMIN_PASSWORD"] = self.password
        with (self.folder / "console.log").open("wb") as log:
            self.process = subprocess.Popen(
                ["dotnet", str(self.binary), "--portable-app", "--stop-if-bind-fails", str(self.folder)],
                env=env,
                stdout=log, stderr=subprocess.STDOUT,
            )
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline and self.process.poll() is None:
            try:
                result = self.call("user/login", form={"user": "admin", "pass": self.password})
                self.token = ok(result)["token"]
                break
            except (urllib.error.URLError, TimeoutError):
                time.sleep(0.2)
        else:
            raise RuntimeError(f"Server failed to start. Inspect {self.folder / 'console.log'}")
        if release_seed and self.manifest.exists():
            revision = ok(self.call("settings/config/plan", manifest=EMPTY_MANIFEST))["revision"]
            ok(self.call("settings/config/apply", manifest=EMPTY_MANIFEST, revision=revision))
            self.manifest.unlink()

    def stop(self):
        if self.process is None or self.process.poll() is not None:
            return
        self.process.terminate()
        try:
            self.process.wait(timeout=10)
        except subprocess.TimeoutExpired:
            self.process.kill()
            self.process.wait()


def wait_for(check, description, timeout=45):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = check()
        if result:
            return result
        time.sleep(0.5)
    raise RuntimeError(f"Timed out waiting for {description}.")


def verify(current, previous, folder, propagation, graceful):
    ports = allocate_ports()
    password = secrets.token_hex(16)
    primary = Node(current, folder / "primary", "primary.cluster.test", ports[:3], password)
    secondary = Node(previous, folder / "secondary", "secondary.cluster.test", ports[3:], password)
    try:
        primary.start()
        secondary.start()
        initial = ok(primary.call("admin/cluster/init", form={
            "clusterDomain": "cluster.test", "primaryNodeIpAddresses": "127.0.0.1",
        }))
        assert initial["supportsDeclarativeClusterOptions"] is True
        revision = ok(primary.call("settings/config/plan", manifest=INTERVAL_MANIFEST))["revision"]
        blocklist_manifest = {"schemaVersion": 1, "blocklists": {"updateIntervalHours": 0}}
        blocklist_revision = ok(primary.call("settings/config/plan", manifest=blocklist_manifest))["revision"]
        domain_lists = {"schemaVersion": 1, "allowZones": ["allow.fixture.test"], "blockZones": ["block.fixture.test"]}
        domain_revision = ok(primary.call("settings/config/plan", manifest=domain_lists))["revision"]
        dns_policy = {"schemaVersion": 1, "dns": {"udpPayloadSize": 1300}}
        dns_policy_revision = ok(primary.call("settings/config/plan", manifest=dns_policy))["revision"]
        joined = ok(secondary.call("admin/cluster/initJoin", form={
            "secondaryNodeIpAddresses": "127.0.0.1", "primaryNodeUrl": initial["clusterNodes"][0]["url"],
            "primaryNodeIpAddress": "127.0.0.1", "primaryNodeUsername": "admin",
            "primaryNodePassword": password, "ignoreCertificateErrors": "true",
        }))
        if propagation:
            assert joined["supportsDeclarativeClusterOptions"] is True
            assert joined["supportsDeclarativeDnsPolicy"] is True
            rejected = primary.call("settings/config/apply", manifest=dns_policy, revision=dns_policy_revision)
            assert rejected["status"] == "error" and "stale" in rejected["errorMessage"], rejected
            verify_propagation(primary, secondary, graceful)
            return
        assert "supportsDeclarativeClusterOptions" not in joined
        assert any(node["type"] == "Secondary" and node["state"] == "Self" for node in joined["clusterNodes"])
        for rejected in (
            primary.call("settings/config/plan", manifest=INTERVAL_MANIFEST),
            primary.call("settings/config/apply", manifest=INTERVAL_MANIFEST, revision=revision),
        ):
            assert rejected["status"] == "error", rejected
            assert "has not advertised support" in rejected["errorMessage"], rejected
        blocked = primary.call("settings/config/apply", manifest=blocklist_manifest, revision=blocklist_revision)
        assert blocked["status"] == "error" and "declarative blocklist settings" in blocked["errorMessage"], blocked
        assert ok(primary.call("settings/get"))["blockListUpdateIntervalHours"] == 24
        rejected = primary.call("settings/config/apply", manifest=domain_lists, revision=domain_revision)
        assert rejected["status"] == "error" and "declarative domain lists" in rejected["errorMessage"], rejected
        assert "/allowZones" not in ok(primary.call("settings/get"))["managedSettings"]
        assert "/blockZones" not in ok(primary.call("settings/get"))["managedSettings"]
        rejected = primary.call("settings/config/apply", manifest=dns_policy, revision=dns_policy_revision)
        assert rejected["status"] == "error" and "declarative DNS policy" in rejected["errorMessage"], rejected
        for node in (primary, secondary):
            settings = ok(node.call("settings/get"))
            assert settings["udpPayloadSize"] == 1232 and "/dns/udpPayloadSize" not in settings["managedSettings"]
            state = ok(node.call("admin/cluster/state"))
            assert state["configRefreshIntervalSeconds"] == 900, state
            assert "/cluster/configRefreshSeconds" not in state.get("managedOptionPaths", []), state
        primary.stop()
        primary.start()
        restarted = ok(primary.call("admin/cluster/state"))
        assert restarted["configRefreshIntervalSeconds"] == 900, restarted
        assert len(restarted["clusterNodes"]) == 2, restarted
        assert "/cluster/configRefreshSeconds" not in restarted["managedOptionPaths"], restarted
        print("Mixed-build check passed. Both nodes retained 900 seconds, including the Primary after restart.")
    finally:
        secondary.stop()
        primary.stop()


def log_message_count(node, message):
    return sum(log.read_text(encoding="utf-8").count(message) for log in (node.folder / "logs").glob("*.log"))


def verify_propagation(primary, secondary, graceful):
    catalog = "cluster-catalog.cluster.test"
    web_port = ok(secondary.call("settings/get"))["webServiceHttpPort"]
    ok(secondary.call("zones/options/set", form={
        "zone": catalog, "primaryZoneTransferProtocol": "Tcp",
        "primaryNameServerAddresses": f"127.0.0.1:{primary.dns_port}",
    }))

    def catalog_ready():
        state = secondary.call("zones/options/get?zone=cluster.test")
        if state["status"] == "ok":
            return True
        ok(secondary.call("zones/resync", form={"zone": catalog}))
        return False

    wait_for(catalog_ready, "the Secondary to transfer the cluster zone")

    tls_change = secondary.call("settings/config/plan", manifest={"schemaVersion": 1, "web": {"tlsEnabled": False}})
    assert tls_change["status"] == "error" and "/web/tlsEnabled" in tls_change["errorMessage"], tls_change
    lost_address = secondary.call("settings/config/plan", manifest={
        "schemaVersion": 1, "web": {"localAddresses": ["127.0.0.2"]},
    })
    assert lost_address["status"] == "error" and "/web/localAddresses" in lost_address["errorMessage"], lost_address
    previous_certificate = ssl.get_server_certificate(("127.0.0.1", secondary.tls_port), timeout=5)
    def apply_web(manifest):
        plan = ok(secondary.call("settings/config/plan", manifest=manifest))
        assert any(change["path"] == "/web/tlsPort" and change["restartWebService"] for change in plan["changes"]), plan
        return ok(secondary.call("settings/config/apply", manifest=manifest, revision=plan["revision"]))["operationId"]

    def web_operation(operation):
        try:
            status = ok(secondary.call(f"settings/config/status?operationId={operation}"))
        except (urllib.error.URLError, TimeoutError):
            return None
        return None if status["state"] == "pending" else status["state"]

    def advertised_port(server):
        state = ok(server.call("admin/cluster/state"))
        node, = (node for node in state["clusterNodes"] if node["type"] == "Secondary")
        return urllib.parse.urlsplit(node["url"]).port

    with socket.socket() as blocked:
        blocked.bind(("127.0.0.1", 0))
        blocked.listen()
        occupied = {"schemaVersion": 1, "web": {"tlsPort": blocked.getsockname()[1]}}
        operation = apply_web(occupied)
        assert wait_for(lambda: web_operation(operation), "the occupied TLS port to fail") == "failed"
    assert advertised_port(secondary) == secondary.tls_port
    assert advertised_port(primary) == secondary.tls_port

    new_web_port, new_tls_port, *_ = allocate_ports()
    web = {"schemaVersion": 1, "web": {"httpPort": new_web_port, "tlsPort": new_tls_port,
           "localAddresses": ["127.0.0.1", "127.0.0.2"], "tlsEnabled": True}}
    operation = apply_web(web)
    secondary.http_port = new_web_port
    assert wait_for(lambda: web_operation(operation), "the Secondary web listeners to rebind") == "applied"
    settings = ok(secondary.call("settings/get"))
    assert settings["webServiceHttpPort"] == new_web_port != web_port
    assert set(settings["webServiceLocalAddresses"]) == {"127.0.0.1", "127.0.0.2"}, settings
    assert ssl.get_server_certificate(("127.0.0.1", new_tls_port), timeout=5) == previous_certificate
    assert ssl.get_server_certificate(("127.0.0.2", new_tls_port), timeout=5) == previous_certificate
    assert advertised_port(secondary) == new_tls_port
    wait_for(lambda: advertised_port(primary) == new_tls_port, "the Primary to receive the Secondary's HTTPS port")

    intervals = {"schemaVersion": 1, "cluster": {"configRefreshSeconds": 120, "configRetrySeconds": 30}}

    def plan_if_supported():
        plan = primary.call("settings/config/plan", manifest=intervals)
        if plan["status"] == "ok":
            return ok(plan)
        if "has not advertised support" not in plan["errorMessage"]:
            raise RuntimeError(plan["errorMessage"])
        return None

    plan = wait_for(plan_if_supported, "the Secondary to advertise interval support")
    ok(primary.call("settings/config/apply", manifest=intervals, revision=plan["revision"]))

    def secondary_interval_updated():
        state = ok(secondary.call("admin/cluster/state"))
        return state["configRefreshIntervalSeconds"] == 120 and state["configRetryIntervalSeconds"] == 30

    wait_for(secondary_interval_updated, "the Secondary to receive the 120-second interval")
    new_primary_tls_port = allocate_ports()[0]
    primary_certificate = ssl.get_server_certificate(("127.0.0.1", primary.tls_port), timeout=5)
    primary_move = {"schemaVersion": 1, "web": {"tlsPort": new_primary_tls_port}, "cluster": intervals["cluster"]}
    missed_notification = "DNS Server failed to notify Secondary node"
    previous_failures = log_message_count(primary, missed_notification)
    secondary.stop()
    plan = ok(primary.call("settings/config/plan", manifest=primary_move))
    operation = ok(primary.call("settings/config/apply", manifest=primary_move, revision=plan["revision"]))["operationId"]

    def primary_rebound():
        try:
            status = ok(primary.call(f"settings/config/status?operationId={operation}"))
        except (urllib.error.URLError, TimeoutError):
            return False
        if status["state"] == "failed":
            raise RuntimeError(status)
        return status["state"] == "applied"

    wait_for(primary_rebound, "the Primary HTTPS listener to rebind")
    assert ssl.get_server_certificate(("127.0.0.1", new_primary_tls_port), timeout=5) == primary_certificate

    wait_for(lambda: log_message_count(primary, missed_notification) > previous_failures, "a missed port-change notification")
    secondary.start()

    def secondary_has_primary_port():
        state = ok(secondary.call("admin/cluster/state"))
        node, = (node for node in state["clusterNodes"] if node["type"] == "Primary")
        return urllib.parse.urlsplit(node["url"]).port == new_primary_tls_port

    wait_for(secondary_has_primary_port, "the Primary heartbeat to repair the Secondary's stale endpoint", timeout=60)
    intervals["cluster"]["configRefreshSeconds"] = 125
    plan = wait_for(plan_if_supported, "the restarted Secondary to advertise interval support")
    ok(primary.call("settings/config/apply", manifest=intervals, revision=plan["revision"]))
    wait_for(lambda: ok(secondary.call("admin/cluster/state"))["configRefreshIntervalSeconds"] == 125,
             "the Secondary to authenticate and sync from the new Primary HTTPS port")

    donor = Node(primary.binary, primary.folder.parent / "certificate-fixture", "certificate.cluster.test",
                 allocate_ports()[:3], primary.password)
    try:
        donor.start()
        replacement = donor.folder / "self-signed-cert.pfx"
        rotation = {"schemaVersion": 1, "web": {"useSelfSignedCertificate": False,
                    "certificate": {"path": str(replacement)}},
                    "cluster": {"configRefreshSeconds": 130, "configRetrySeconds": 30}}
        plan = ok(primary.call("settings/config/plan", manifest=rotation))
        assert any(change["path"] == "/web/certificate/path" for change in plan["changes"]), plan
        operation = ok(primary.call("settings/config/apply", manifest=rotation, revision=plan["revision"]))["operationId"]
        wait_for(primary_rebound, "the Primary to activate its replacement certificate")
        assert ssl.get_server_certificate(("127.0.0.1", new_primary_tls_port), timeout=5) != primary_certificate
        wait_for(lambda: ok(secondary.call("admin/cluster/state"))["configRefreshIntervalSeconds"] == 130,
                 "the Secondary to authenticate the replacement certificate")
    finally:
        donor.stop()

    donor = Node(primary.binary, primary.folder.parent / "secondary-certificate-fixture", "replacement.cluster.test",
                 allocate_ports()[:3], primary.password)
    try:
        donor.start()
        owner = f"_{new_tls_port}._tcp.secondary.cluster.test"

        def advertised_certificate():
            result = ok(primary.call(f"zones/records/get?zone=cluster.test&domain={owner}"))
            return [record["rData"] for record in result["records"] if record["type"] == "TLSA"]

        previous_records = advertised_certificate()
        assert len(previous_records) == 1, previous_records
        rotation = {"schemaVersion": 1, "web": {
            **web["web"], "useSelfSignedCertificate": False,
            "certificate": {"path": str(donor.folder / "self-signed-cert.pfx")},
        }}
        plan = ok(secondary.call("settings/config/plan", manifest=rotation))
        operation = ok(secondary.call("settings/config/apply", manifest=rotation, revision=plan["revision"]))["operationId"]
        assert wait_for(lambda: web_operation(operation), "the Secondary certificate replacement") == "applied"
        assert ssl.get_server_certificate(("127.0.0.1", new_tls_port), timeout=5) != previous_certificate
        wait_for(lambda: (records := advertised_certificate()) and records != previous_records,
                 "the Primary to publish the Secondary replacement certificate")
    finally:
        donor.stop()

    source = primary.folder.parent / "blocklist.txt"
    source.write_text("blocked.cluster-test.example\n", encoding="utf-8")
    blocklists = {"schemaVersion": 1, "cluster": {"configRefreshSeconds": 130, "configRetrySeconds": 30},
                  "blocklists": {"sources": [source.as_uri()], "updateIntervalHours": 0}}

    def blocklist_plan():
        response = primary.call("settings/config/plan", manifest=blocklists)
        if response["status"] == "ok":
            return ok(response)
        if "declarative blocklist settings" not in response["errorMessage"]:
            raise RuntimeError(response["errorMessage"])
        return None

    plan = wait_for(blocklist_plan, "the Secondary to advertise blocklist support")
    denied = secondary.call("settings/config/plan", manifest={"schemaVersion": 1, "blocklists": blocklists["blocklists"]})
    assert denied["status"] == "error" and "Only the Primary" in denied["errorMessage"], denied
    ok(primary.call("settings/config/apply", manifest=blocklists, revision=plan["revision"]))

    def secondary_blocklists_match(sources, interval):
        state = ok(secondary.call("settings/get"))
        return (state["blockListUrls"] == sources and state["blockListUpdateIntervalHours"] == interval
                and "/blocklists/sources" in state["managedSettings"]
                and "/blocklists/updateIntervalHours" in state["managedSettings"])

    wait_for(lambda: secondary_blocklists_match([source.as_uri()], 0),
             "the Secondary to receive the sources, schedule, and blocklist ownership")
    wait_for(lambda: log_message_count(secondary, "DNS Server read block list file (1 domain(s) blocked) from: local file") > 0,
             "the Secondary to load its managed local blocklist with automatic updates disabled")
    primary.stop()
    primary.manifest.write_text(json.dumps(blocklists), encoding="utf-8")
    primary.start(release_seed=False)
    primary.manifest.unlink()
    persisted = ok(primary.call("settings/get"))
    assert persisted["blockListUrls"] == [source.as_uri()] and persisted["blockListUpdateIntervalHours"] == 0
    assert "/blocklists/sources" in persisted["managedSettings"]
    rejected = primary.call("admin/cluster/primary/join", form={
        "secondaryNodeId": 2147483647, "secondaryNodeUrl": "https://legacy.cluster.test:53443/",
        "secondaryNodeIpAddresses": "127.0.0.1",
        "secondaryNodeCertificate": base64.urlsafe_b64encode(ssl.PEM_cert_to_DER_cert(primary_certificate)).decode().rstrip("="),
    })
    assert rejected["status"] == "error" and "before joining" in rejected["errorMessage"], rejected
    local_web = {"schemaVersion": 1, "web": web["web"]}
    revision = ok(secondary.call("settings/config/plan", manifest=local_web))["revision"]
    ok(secondary.call("settings/config/apply", manifest=local_web, revision=revision))
    assert secondary_blocklists_match([source.as_uri()], 0)
    rejected = secondary.call("settings/set?blockListUpdateIntervalHours=24")
    assert rejected["status"] == "error" and "/blocklists/updateIntervalHours" in rejected["errorMessage"], rejected

    blocklists["blocklists"] = {"sources": [], "updateIntervalHours": 12}
    plan = wait_for(blocklist_plan, "blocklist support before the second update")
    ok(primary.call("settings/config/apply", manifest=blocklists, revision=plan["revision"]))
    wait_for(lambda: secondary_blocklists_match(None, 12), "the Secondary to receive the next managed update")

    release = {"schemaVersion": 1, "cluster": blocklists["cluster"]}
    plan = ok(primary.call("settings/config/plan", manifest=release))
    ok(primary.call("settings/config/apply", manifest=release, revision=plan["revision"]))

    def secondary_released_blocklists():
        state = ok(secondary.call("settings/get"))
        return (state["blockListUpdateIntervalHours"] == 12 and
                not any(path.startswith("/blocklists/") for path in state["managedSettings"]))

    wait_for(secondary_released_blocklists, "the Secondary to release ownership and retain the last interval")

    verify_domain_lists(primary, secondary, release, local_web, new_primary_tls_port)
    verify_dns_policy(primary, secondary, release, local_web)

    publication_failure = "DNS Server failed to update this Secondary node's details on the Primary node."
    previous_failures = log_message_count(secondary, publication_failure)
    primary.stop()
    addresses = {"schemaVersion": 1, "web": web["web"],
                 "cluster": {"node": {"addresses": ["127.0.0.1", "127.0.0.2"]}}}
    revision = ok(secondary.call("settings/config/plan", manifest=addresses))["revision"]
    ok(secondary.call("settings/config/apply", manifest=addresses, revision=revision))

    wait_for(lambda: log_message_count(secondary, publication_failure) > previous_failures, "a publication failure while the Primary is stopped")
    primary.start()

    def primary_received_addresses():
        state = ok(primary.call("admin/cluster/state"))
        return any(node["type"] == "Secondary" and "127.0.0.2" in node["ipAddresses"]
                   for node in state["clusterNodes"])

    wait_for(primary_received_addresses, "the Primary to receive the Secondary's new address")
    assert ok(secondary.call("settings/get"))["webServiceHttpPort"] == new_web_port
    if graceful:
        current = ok(primary.call("admin/cluster/state"))
        successor, = (node for node in current["clusterNodes"] if node["type"] == "Secondary")
        rejected = primary.call(f"admin/cluster/primary/delete?forceDelete=true&successorNodeId={successor['id']}&handoffRevision=invalid")
        assert rejected["status"] == "error" and "Cluster API token" in rejected["errorMessage"], rejected
        assert ok(primary.call("admin/cluster/state"))["clusterInitialized"] is True
        promoted = ok(secondary.call("admin/cluster/secondary/promote"))
        assert ok(primary.call("admin/cluster/state"))["clusterInitialized"] is False
    else:
        primary.stop()
        promoted = ok(secondary.call("admin/cluster/secondary/promote?forceDeletePrimary=true"))
    assert_promoted_policy(promoted)
    secondary.stop()
    secondary.start()
    assert_promoted_policy(ok(secondary.call("admin/cluster/state")))
    rejected = secondary.call("admin/cluster/primary/setOptions?configRefreshIntervalSeconds=180")
    assert rejected["status"] == "error" and "/cluster/configRefreshSeconds" in rejected["errorMessage"], rejected
    mode = "Graceful handoff" if graceful else "Forced failover"
    print(f"{mode} check passed. The promoted Primary retained interval and address ownership after restart.")


def verify_domain_lists(primary, secondary, cluster_manifest, local_web, primary_tls_port):
    paths = {"/allowZones", "/blockZones"}
    desired = {**cluster_manifest, "allowZones": ["allow.fixture.test"], "blockZones": ["block.fixture.test"]}

    denied = secondary.call("settings/config/plan", manifest={"schemaVersion": 1, "blockZones": []})
    assert denied["status"] == "error" and "Only the Primary" in denied["errorMessage"], denied

    def apply_primary(manifest):
        plan = ok(primary.call("settings/config/plan", manifest=manifest))
        ok(primary.call("settings/config/apply", manifest=manifest, revision=plan["revision"]))
        return plan

    def matches(allowed, blocked, managed):
        state = ok(secondary.call("settings/get"))
        if paths.intersection(state["managedSettings"]) != managed:
            return False
        exported = ok(secondary.call("settings/config/export"))["manifest"]
        return exported["allowZones"] == allowed and exported["blockZones"] == blocked

    plan = apply_primary(desired)
    assert paths == {change["path"].rsplit("/", 1)[0] for change in plan["changes"]}, plan
    wait_for(lambda: matches(desired["allowZones"], desired["blockZones"], paths),
             "the Secondary to inherit both managed domain lists")
    certificate = ssl.get_server_certificate(("127.0.0.1", primary_tls_port), timeout=5)
    rejected = primary.call("admin/cluster/primary/join", form={
        "secondaryNodeId": 2147483647, "secondaryNodeUrl": "https://legacy.cluster.test:53443/",
        "secondaryNodeIpAddresses": "127.0.0.1",
        "secondaryNodeCertificate": base64.urlsafe_b64encode(ssl.PEM_cert_to_DER_cert(certificate)).decode().rstrip("="),
        "supportsDeclarativeClusterOptions": "true", "supportsDeclarativeBlockLists": "true",
    })
    assert rejected["status"] == "error" and "declarative domain lists" in rejected["errorMessage"], rejected
    secondary.stop()
    secondary.start(release_seed=False)
    assert matches(desired["allowZones"], desired["blockZones"], paths)

    revision = ok(secondary.call("settings/config/plan", manifest=local_web))["revision"]
    ok(secondary.call("settings/config/apply", manifest=local_web, revision=revision))
    assert matches(desired["allowZones"], desired["blockZones"], paths)
    for zone, endpoint in (("/allowZones", "allowed/delete?domain=allow.fixture.test"),
                           ("/blockZones", "blocked/add?domain=another.fixture.test")):
        denied = secondary.call(endpoint)
        assert denied["status"] == "error" and zone in denied["errorMessage"], denied

    desired["blockZones"] = []
    apply_primary(desired)
    wait_for(lambda: matches(desired["allowZones"], [], paths),
             "the Secondary to remove a formerly blocked domain through cluster sync")
    assert not apply_primary(desired)["changes"]
    apply_primary(cluster_manifest)
    wait_for(lambda: matches(desired["allowZones"], [], set()),
             "the Secondary to release both domain lists while retaining their entries")


def verify_dns_policy(primary, secondary, cluster_manifest, local_web):
    desired = {**cluster_manifest,
               "dns": {"authoritative": {"defaultRecordTtl": 450}, "checkForUpdates": False,
                       "udpPayloadSize": 1300, "dnssecValidation": False,
                       "clientSubnet": {"enabled": True, "ipv4PrefixLength": 23}},
               "apps": {"autoUpdate": False}}
    paths = {"/dns/authoritative/defaultRecordTtl", "/dns/checkForUpdates", "/dns/udpPayloadSize",
             "/dns/dnssecValidation", "/dns/clientSubnet/enabled", "/dns/clientSubnet/ipv4PrefixLength",
             "/apps/autoUpdate"}
    denied = secondary.call("settings/config/plan", manifest={"schemaVersion": 1, "dns": desired["dns"]})
    assert denied["status"] == "error" and "Only the Primary" in denied["errorMessage"], denied

    def apply(node, manifest):
        plan = ok(node.call("settings/config/plan", manifest=manifest))
        ok(node.call("settings/config/apply", manifest=manifest, revision=plan["revision"]))
        return plan

    def matches(node, ttl, prefix, owned):
        state = ok(node.call("settings/get"))
        return (state["defaultRecordTtl"] == ttl and state["dnsServerEnableCheckForUpdate"] is False
                and state["udpPayloadSize"] == 1300 and state["dnssecValidation"] is False
                and state["eDnsClientSubnet"] is True and state["eDnsClientSubnetIPv4PrefixLength"] == prefix
                and state["dnsAppsEnableAutomaticUpdate"] is False
                and paths.intersection(state["managedSettings"]) == owned)

    plan = apply(primary, desired)
    assert paths - {"/dns/checkForUpdates"} == {change["path"] for change in plan["changes"]}, plan
    wait_for(lambda: matches(secondary, 450, 23, paths), "the Secondary to inherit DNS policy and ownership")
    secondary.stop()
    secondary.start(release_seed=False)
    assert matches(secondary, 450, 23, paths)
    apply(secondary, local_web)
    assert matches(secondary, 450, 23, paths)
    denied = secondary.call("settings/set?defaultRecordTtl=451")
    assert denied["status"] == "error" and "/dns/authoritative/defaultRecordTtl" in denied["errorMessage"], denied

    desired["dns"]["authoritative"]["defaultRecordTtl"] = 460
    desired["dns"]["clientSubnet"]["ipv4PrefixLength"] = 22
    apply(primary, desired)
    wait_for(lambda: matches(secondary, 460, 22, paths), "the Secondary to apply the next DNS policy")
    assert not apply(primary, desired)["changes"]
    apply(primary, cluster_manifest)
    wait_for(lambda: matches(secondary, 460, 22, set()), "the Secondary to release DNS policy ownership")


def assert_promoted_policy(state):
    assert state["configRefreshIntervalSeconds"] == 130, state
    assert state["configRetryIntervalSeconds"] == 30, state
    assert set(state["managedOptionPaths"]) == {
        "/cluster/configRefreshSeconds", "/cluster/configRetrySeconds", "/cluster/node/addresses",
    }, state
    node, = state["clusterNodes"]
    assert node["type"] == "Primary" and node["state"] == "Self", state
    assert "127.0.0.2" in node["ipAddresses"], state


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("current", type=Path, help="current published DnsServerApp.dll")
    parser.add_argument("previous", type=Path, nargs="?", help="published DnsServerApp.dll from a revision without the capability")
    parser.add_argument("--propagation", action="store_true", help="run the current build on both nodes and verify interval propagation")
    parser.add_argument("--graceful", action="store_true", help="verify graceful promotion instead of forced failover")
    args = parser.parse_args()
    if args.graceful and not args.propagation:
        parser.error("--graceful requires --propagation")
    if args.propagation == (args.previous is not None):
        parser.error("supply a previous build or --propagation")
    folder = Path(tempfile.mkdtemp(prefix="technitium-mixed-cluster-"))
    print(f"Fixture logs: {folder}", flush=True)
    current = args.current.resolve(strict=True)
    previous = current if args.propagation else args.previous.resolve(strict=True)
    verify(current, previous, folder, args.propagation, args.graceful)


if __name__ == "__main__":
    main()
