"""Verify retry of a pinned DNS app package over loopback HTTPS on Linux."""

import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
from threading import Thread
import zipfile

from mixed_cluster import Node, allocate_ports, ok


def verify(binary):
    with tempfile.TemporaryDirectory(prefix="technitium-https-retry-") as folder:
        root = Path(folder)
        certificate = root / "cert.pem"
        key = root / "key.pem"
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
                        "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1",
                        "-keyout", key, "-out", certificate], check=True, capture_output=True)
        os.environ["SSL_CERT_FILE"] = str(certificate)  # Inherited only by this fixture’s server process.
        archive = io.BytesIO()
        with zipfile.ZipFile(archive, "w") as package:
            package.writestr("dnsApp.config", "default")
        payload = archive.getvalue()
        requests = []

        class PackageHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append(self.path)
                if len(requests) == 1:
                    self.send_error(503)
                    return
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

        with ThreadingHTTPServer(("127.0.0.1", 0), PackageHandler) as https:
            tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            tls.load_cert_chain(certificate, key)
            https.socket = tls.wrap_socket(https.socket, server_side=True)
            worker = Thread(target=https.serve_forever, daemon=True)
            worker.start()
            node = Node(binary, root / "server", "retry.test", allocate_ports()[:3], "fixture-retry-password")
            try:
                node.start()
                manifest = {"schemaVersion": 1, "apps": {"packages": {"Fixture": {
                    "source": {"url": f"https://127.0.0.1:{https.server_port}/fixture.zip",
                               "sha256": hashlib.sha256(payload).hexdigest()},
                    "version": "0.0", "configuration": {"text": "declared"}}}}}
                preview = ok(node.call("settings/config/plan", manifest=manifest))
                assert not requests
                revision = preview["revision"]
                failed = node.call("settings/config/apply", manifest=manifest, revision=revision)
                assert failed["status"] == "error" and "Could not download the app package" in failed["errorMessage"], failed
                assert len(requests) == 1, (requests, failed)
                assert not (node.folder / "apps" / "Fixture").exists()
                ok(node.call("settings/config/apply", manifest=manifest, revision=revision))
                assert len(requests) == 2
                assert ok(node.call("apps/config/get?name=Fixture"))["config"] == "declared"
                repeat = ok(node.call("settings/config/plan", manifest=manifest))
                assert not repeat["changes"], repeat
                ok(node.call("settings/config/apply", manifest=manifest, revision=repeat["revision"]))
                assert len(requests) == 2
                print("HTTPS package retry, digest, configuration and idempotence verified.")
            finally:
                node.stop()
                https.shutdown()
                worker.join()


if __name__ == "__main__":
    verify(Path(sys.argv[1]).resolve(strict=True))
