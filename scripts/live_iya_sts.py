#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
# SPDX-License-Identifier: MIT
"""Sign the library in to a fresh iya-sts and confirm two Shared Signals events.

Starts the latest main branch of iya-sts in memory mode, with persistence and
clustering off and no request workers, unless IYA_STS_URL is already set.
Writes an OIDCConfiguration.plist for it, registers that client with
scripts/register-iya-sts-client.mjs in a Node container, and runs
Tests/OIDCCAEPClientTests/LiveIyaSTSTests.swift in the swift:6.1-noble
container. That test signs in through the library (OIDCClient with PAR, PKCE
and DPoP, AccountManager, LoopbackWebAuthenticator on the plist's loopback
redirect URI), with only the browser replaced by an HTTP walk of iya-sts's
sign-in screens. It then starts the library's SSFReceiver, emits
credential-change and session-revoked with POST /admin-api/caep/emit, and
requires both to arrive: the account still signed in after the first, ended
after the second.

The library trusts iya-sts through the plist's TrustedCertificates (with
TrustSystemRoots false): the self-signed root of the chain iya-sts publishes at
GET /tls/server-certificate. That one bootstrap fetch is not verified; every
request the library makes is. InsecureSkipTLSVerification is never set.

The unit suite stays `docker run --rm -v "$PWD":/pkg -w /pkg swift:6.1-noble
swift test`, which skips the live test. This file is the live half. It uses the
host's Python (standard library only) and Docker; Swift and Node never run on
the host. The checkout is mounted read-only and copied inside the container, so
nothing is built into it. Do not bind port 3000, 8081, or 18481 to 18495.

Secrets reach docker as `-e NAME` from the child's environment, never as
`-e NAME=value` on a printed command line. Progress goes to stderr; stdout is
the final JSON only, ending with {"ok": true ...}.

IYA_STS_URL, when set, uses an iya-sts that is already running and does not
stop it (a client already registered there fails the second run: use a fresh
one). IYA_STS_IMAGE starts a fresh container from that image. Otherwise it
clones main (or builds IYA_STS_SRC). It removes only the containers it started:
iya-sts-live-swift-oidc-caep-native-app and swift-oidc-caep-native-app-live-demo.
It never removes iya-sts-live-main, iya-sts-live-probe, or a container whose
name starts with sts, never runs docker compose, and never uses --network host
for iya-sts.
"""

import http.client
import json
import os
import plistlib
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STS_REPO = "https://github.com/rcbj/iya-sts.git"
CAEP = "https://schemas.openid.net/secevent/caep/event-type/"
CREDENTIAL_CHANGE = CAEP + "credential-change"
SESSION_REVOKED = CAEP + "session-revoked"
FORBIDDEN_PORTS = {3000, 8081, *range(18481, 18496)}
PROTECTED_CONTAINERS = {"iya-sts-live-main", "iya-sts-live-probe"}
SWIFT_IMAGE = os.environ.get("LIVE_SWIFT_IMAGE") or "swift:6.1-noble"
NODE_IMAGE = os.environ.get("LIVE_NODE_IMAGE") or "node:24.22.1-bookworm-slim"
_CERT = re.compile(r"-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----")

PROFILE = {
    "repo": "swift-oidc-caep-native-app",
    "plist": "Demo/Sources/CAEPDemo/Resources/OIDCConfiguration-Linux.plist",
    "password_env": "CAEP_DEMO_USER_PASSWORD",
    "test_user": "caep-demo-user",
    "test": "LiveIyaSTSTests",
}


def log(message):
    print(message, file=sys.stderr, flush=True)


def run(command, **kwargs):
    log("+ " + " ".join(command))
    completed = subprocess.run(command, check=False, text=True, **kwargs)
    if completed.returncode != 0:
        if completed.stdout:
            log(completed.stdout)
        if completed.stderr:
            log(completed.stderr)
        raise RuntimeError(f"{command[0]} exited {completed.returncode}")
    return completed


def docker(*args, **kwargs):
    return run(["docker", *args], **kwargs)


def docker_rm(name):
    if not name:
        return
    if name in PROTECTED_CONTAINERS or name.startswith("sts"):
        raise RuntimeError(f"refusing to remove {name}")
    subprocess.run(["docker", "rm", "-f", name], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def wait_port(port, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), 2):
                return
        except OSError:
            time.sleep(1)
    raise RuntimeError(f"127.0.0.1:{port} did not accept a connection")


def unverified_get(origin, path, accept):
    """A GET that trusts nothing it receives: readiness, and the chain's bootstrap."""
    parts = urllib.parse.urlsplit(origin)
    context = ssl._create_unverified_context()
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    conn = http.client.HTTPSConnection(parts.hostname, parts.port or 443, context=context, timeout=10)
    try:
        conn.request("GET", path, headers={"accept": accept})
        response = conn.getresponse()
        return response.status, response.read()
    finally:
        conn.close()


def wait_ready(origin, timeout):
    deadline = time.time() + timeout
    last = None
    while time.time() < deadline:
        try:
            status, _body = unverified_get(origin, "/healthcheck", "*/*")
            if status == 200:
                return
            last = f"answered {status}"
        except OSError as err:
            last = str(err)
        time.sleep(2)
    raise RuntimeError(f"{origin}/healthcheck was not ready: {last}")


def sts_root(origin, work):
    """The self-signed root of the chain iya-sts publishes at /tls/server-certificate, as PEM."""
    status, body = unverified_get(origin, "/tls/server-certificate", "text/plain")
    if status != 200:
        raise RuntimeError(f"/tls/server-certificate answered {status}")
    blocks = _CERT.findall(body.decode("utf-8", "replace"))
    for index, block in enumerate(blocks):
        probe = work / f"chain-{index}.pem"
        probe.write_text(block + "\n", encoding="utf-8")
        decoded = ssl._ssl._test_decode_cert(str(probe))
        probe.unlink()
        if decoded.get("subject") == decoded.get("issuer"):
            subject = ", ".join("=".join(pair) for rdn in decoded["subject"] for pair in rdn)
            return block + "\n", subject, len(blocks)
    raise RuntimeError(f"no self-signed root among the {len(blocks)} certificate(s) of /tls/server-certificate")


def write_plist(dest, sts_origin, demo_origin, root_file):
    """The demo's Linux plist, pointed at this iya-sts and this loopback port, trusting only its root."""
    with open(ROOT / PROFILE["plist"], "rb") as handle:
        raw = plistlib.load(handle)
    raw["MetadataURL"] = sts_origin.rstrip("/") + "/.well-known/openid-configuration"
    raw["RedirectURI"] = demo_origin + "/callback"
    raw["PostLogoutRedirectURI"] = demo_origin + "/logged-out"
    raw.pop("InsecureSkipTLSVerification", None)
    raw["TrustedCertificates"] = [root_file]
    raw["TrustSystemRoots"] = False
    with open(dest, "wb") as handle:
        plistlib.dump(raw, handle)


def prepare_sts(sts_port, secret):
    given = os.environ.get("IYA_STS_URL", "").rstrip("/")
    if given:
        log(f"using {given}")
        return given, None
    if sts_port in FORBIDDEN_PORTS:
        raise SystemExit(f"refusing to bind port {sts_port}")
    image = os.environ.get("IYA_STS_IMAGE", "")
    source = os.environ.get("IYA_STS_SRC", "")
    if not image:
        if not source:
            source = tempfile.mkdtemp(prefix="iya-sts-main-")
            run(["git", "clone", "--depth", "1", "--branch", "main", STS_REPO, source])
            run(["git", "-C", source, "submodule", "update", "--init", "--recursive"])
        image = "iya-sts-live:main"
        docker("build", "-t", image, source)
    name = "iya-sts-live-" + PROFILE["repo"]
    docker_rm(name)
    env = os.environ.copy()
    env["STS_ADMIN_API_CLIENT_SECRET"] = secret
    docker(
        "run", "-d", "--name", name,
        "-e", f"STS_PORT={sts_port}",
        "-e", "STS_PERSISTENCE_MODE=memory",
        "-e", "STS_CLUSTER_MODE=off",
        "-e", "STS_WORKERS_REQUEST_COUNT=0",
        "-e", "STS_WORKERS_SURFACE_COUNT=0",
        "-e", "STS_ADMIN_API_CLIENT_SECRET",
        "-e", "STS_LOG_LEVEL=info",
        "-p", f"127.0.0.1:{sts_port}:{sts_port}",
        image,
        env=env,
        capture_output=True,
    )
    return f"https://127.0.0.1:{sts_port}", name


def register(work, env):
    """scripts/register-iya-sts-client.mjs, in a Node container on the host's network."""
    completed = docker(
        "run", "--rm", "--network", "host",
        "--user", f"{os.getuid()}:{os.getgid()}",
        "-v", f"{ROOT / 'scripts'}:/scripts:ro",
        "-v", f"{work}:/live:ro",
        "-e", "STS_ADMIN_API_CLIENT_SECRET",
        "-e", PROFILE["password_env"],
        NODE_IMAGE,
        "node", "/scripts/register-iya-sts-client.mjs",
        "--config", "/live/OIDCConfiguration.plist",
        "--test-user", PROFILE["test_user"],
        env=env,
        capture_output=True,
    )
    log(completed.stdout.strip())


def run_live_test(work, env, name):
    """The XCTest, in the Swift container on the host's network (its loopback listener and iya-sts's port)."""
    script = (
        "set -e; "
        "(apt-get update -qq && apt-get install -y -qq --no-install-recommends curl ca-certificates) >/dev/null; "
        "mkdir -p /work; cp -a /src/Package.swift /src/Sources /src/Tests /work/; "
        "if [ -f /src/Package.resolved ]; then cp /src/Package.resolved /work/; fi; "
        "cd /work; swift test --filter " + PROFILE["test"]
    )
    docker_rm(name)
    completed = subprocess.run(
        [
            "docker", "run", "--rm", "--name", name, "--network", "host",
            "-v", f"{ROOT}:/src:ro",
            "-v", f"{work}:/live:ro",
            "-e", "IYA_STS_LIVE_PLIST=/live/OIDCConfiguration.plist",
            "-e", f"IYA_STS_LIVE_USERNAME={PROFILE['test_user']}",
            "-e", PROFILE["password_env"],
            "-e", "STS_ADMIN_API_CLIENT_SECRET",
            SWIFT_IMAGE, "bash", "-c", script,
        ],
        check=False, text=True, env=env, capture_output=True,
    )
    log("+ docker run --rm --name " + name + " --network host ... " + SWIFT_IMAGE + " swift test --filter " + PROFILE["test"])
    output = completed.stdout + completed.stderr
    found = [line for line in output.splitlines() if line.startswith("LIVE-RESULT ")]
    if completed.returncode != 0 or not found:
        log(output[-8000:])
        raise RuntimeError(f"the live test exited {completed.returncode}" + ("" if found else " without a result"))
    for line in output.splitlines():
        if line.startswith("emitted ") or "Executed" in line:
            log(line)
    return json.loads(found[-1][len("LIVE-RESULT "):])


def main():
    sts_port = int(os.environ.get("LIVE_STS_PORT") or 18506)
    demo_port = int(os.environ.get("LIVE_DEMO_PORT") or 18606)
    sts_given = bool(os.environ.get("IYA_STS_URL", "").strip())
    bound = [demo_port] if sts_given else [sts_port, demo_port]
    if any(port in FORBIDDEN_PORTS for port in bound) or len(set(bound)) != len(bound):
        raise SystemExit("LIVE_STS_PORT and LIVE_DEMO_PORT must not bind 3000, 8081, or 18481 to 18495")
    secret = os.environ.get("ADMIN_API_CLIENT_SECRET") or os.environ.get("STS_ADMIN_API_CLIENT_SECRET") or secrets.token_urlsafe(24)
    password = os.environ.get(PROFILE["password_env"]) or secrets.token_urlsafe(18)
    env = os.environ.copy()
    env["STS_ADMIN_API_CLIENT_SECRET"] = secret
    env[PROFILE["password_env"]] = password
    sts_origin, sts_name = prepare_sts(sts_port, secret)
    demo_origin = f"http://127.0.0.1:{demo_port}"
    test_name = PROFILE["repo"] + "-live-demo"
    work = Path(tempfile.mkdtemp(prefix=PROFILE["repo"] + "-live-"))
    work.chmod(0o755)
    try:
        wait_port(urllib.parse.urlsplit(sts_origin).port or 443, 120)
        wait_ready(sts_origin, 90)
        root_pem, root_subject, chain_count = sts_root(sts_origin, work)
        (work / "sts-root.pem").write_text(root_pem, encoding="utf-8")
        log(f"trusting {root_subject}, the root of the {chain_count}-certificate chain at /tls/server-certificate")
        write_plist(work / "OIDCConfiguration.plist", sts_origin, demo_origin, "sts-root.pem")
        for item in work.iterdir():
            item.chmod(0o644)
        register(work, env)
        result = run_live_test(work, env, test_name)
        events = result.get("events") or []
        types = [item.get("type") for item in events]
        ok = (
            result.get("ok") is True
            and result.get("signedInAfterCredentialChange") is True
            and result.get("signedInAfterSessionRevoked") is False
            and types == [CREDENTIAL_CHANGE, SESSION_REVOKED]
        )
        if not ok:
            raise RuntimeError("the live test's result is not the one required: " + json.dumps(result)[:800])
        print(json.dumps({
            "ok": True,
            "subject": result.get("subject"),
            "issuer": result.get("issuer"),
            "tokenType": result.get("tokenType"),
            "trustAnchor": root_subject,
            "chainCertificates": chain_count,
            "signedInAfterCredentialChange": result.get("signedInAfterCredentialChange"),
            "signedInAfterSessionRevoked": result.get("signedInAfterSessionRevoked"),
            "accountStatus": result.get("accountStatus"),
            "sessionRevokedMatchedSubject": result.get("sessionRevokedMatchedSubject"),
            "events": events,
        }, indent=2), flush=True)
    finally:
        docker_rm(test_name)
        if sts_name:
            docker_rm(sts_name)
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    try:
        main()
    except Exception as err:
        print(str(err), file=sys.stderr)
        sys.exit(1)
