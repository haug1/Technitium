"""Check cluster intervals across two builds or verify same-build propagation."""

import argparse
import json
import os
from pathlib import Path
import secrets
import socket
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
        self.http_port, tls_port, self.dns_port = ports
        self.password = password
        self.token = None
        self.process = None
        self.manifest = folder / "technitium.json"
        self.manifest.write_text(json.dumps({
            "schemaVersion": 1,
            "dns": {"serverDomain": name, "localEndpoints": [f"127.0.0.1:{self.dns_port}"],
                    "recursion": {"mode": "Deny"}, "checkForUpdates": False},
            "web": {"localAddresses": ["127.0.0.1"], "httpPort": self.http_port,
                    "tlsPort": tls_port, "tlsEnabled": True, "useSelfSignedCertificate": True},
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

    def start(self):
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
        if self.manifest.exists():
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


def verify(current, previous, folder, propagation):
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
        joined = ok(secondary.call("admin/cluster/initJoin", form={
            "secondaryNodeIpAddresses": "127.0.0.1", "primaryNodeUrl": initial["clusterNodes"][0]["url"],
            "primaryNodeIpAddress": "127.0.0.1", "primaryNodeUsername": "admin",
            "primaryNodePassword": password, "ignoreCertificateErrors": "true",
        }))
        if propagation:
            assert joined["supportsDeclarativeClusterOptions"] is True
            verify_propagation(primary, secondary)
            return
        assert "supportsDeclarativeClusterOptions" not in joined
        assert any(node["type"] == "Secondary" and node["state"] == "Self" for node in joined["clusterNodes"])
        for rejected in (
            primary.call("settings/config/plan", manifest=INTERVAL_MANIFEST),
            primary.call("settings/config/apply", manifest=INTERVAL_MANIFEST, revision=revision),
        ):
            assert rejected["status"] == "error", rejected
            assert "has not advertised support" in rejected["errorMessage"], rejected
        for node in (primary, secondary):
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


def verify_propagation(primary, secondary):
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
    def publication_failures():
        return sum(log.read_text(encoding="utf-8").count(
            "DNS Server failed to update this Secondary node's details on the Primary node.")
            for log in (secondary.folder / "logs").glob("*.log"))

    previous_failures = publication_failures()
    primary.stop()
    addresses = {"schemaVersion": 1, "cluster": {"node": {"addresses": ["127.0.0.1", "127.0.0.2"]}}}
    revision = ok(secondary.call("settings/config/plan", manifest=addresses))["revision"]
    ok(secondary.call("settings/config/apply", manifest=addresses, revision=revision))

    wait_for(lambda: publication_failures() > previous_failures, "a publication failure while the Primary is stopped")
    primary.start()

    def primary_received_addresses():
        state = ok(primary.call("admin/cluster/state"))
        return any(node["type"] == "Secondary" and "127.0.0.2" in node["ipAddresses"]
                   for node in state["clusterNodes"])

    wait_for(primary_received_addresses, "the Primary to receive the Secondary's new address")
    assert ok(secondary.call("settings/get"))["webServiceHttpPort"] == web_port
    primary.stop()
    promoted = ok(secondary.call("admin/cluster/secondary/promote?forceDeletePrimary=true"))
    assert_promoted_policy(promoted)
    secondary.stop()
    secondary.start()
    assert_promoted_policy(ok(secondary.call("admin/cluster/state")))
    rejected = secondary.call("admin/cluster/primary/setOptions?configRefreshIntervalSeconds=180")
    assert rejected["status"] == "error" and "/cluster/configRefreshSeconds" in rejected["errorMessage"], rejected
    print("Forced failover check passed. The promoted Primary retained interval and address ownership after restart.")


def assert_promoted_policy(state):
    assert state["configRefreshIntervalSeconds"] == 120, state
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
    args = parser.parse_args()
    if args.propagation == (args.previous is not None):
        parser.error("supply a previous build or --propagation")
    folder = Path(tempfile.mkdtemp(prefix="technitium-mixed-cluster-"))
    print(f"Fixture logs: {folder}", flush=True)
    current = args.current.resolve(strict=True)
    previous = current if args.propagation else args.previous.resolve(strict=True)
    verify(current, previous, folder, args.propagation)


if __name__ == "__main__":
    main()
