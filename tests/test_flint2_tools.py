"""Offline security and workflow checks for the optional Flint 2 tools."""

import hashlib
import json
import os
import shlex
from unittest.mock import Mock

import pytest

pytest.importorskip("cryptography", reason="Install the flint2 extra for router-tool tests")
pytest.importorskip("paramiko", reason="Install the flint2 extra for router-tool tests")
pytest.importorskip("passlib", reason="Install the flint2 extra for router-tool tests")

from cryptography.fernet import Fernet

from scripts import flint2_audit as audit
from scripts import flint2_collect as collect
from scripts import flint2_credentials as credentials
from scripts import flint2_speedtest as speed

PASSWORD = " $@! 'quotes' \\ café🔒 "


@pytest.fixture
def vault(monkeypatch, tmp_path):
    store = {}
    backend = Mock()
    backend.set_password.side_effect = lambda service, key, value: store.__setitem__((service, key), value)
    backend.get_password.side_effect = lambda service, key: store.get((service, key))
    backend.delete_password.side_effect = lambda service, key: store.pop((service, key))
    monkeypatch.setattr(credentials, "keychain", lambda: backend)
    return tmp_path / ".secrets" / "flint2", store


@pytest.fixture
def profile():
    return {
        "profile": "gui",
        "url": "https://192.168.8.1",
        "username": "root",
        "password": "synthetic$@!",
        "fingerprint": "aa" * 32,
        "interface": None,
        "ssh_port": 22,
    }


def reply(data=None, status=200, text="", headers=None, content=b""):
    return Mock(status_code=status, text=text, content=content, headers=headers or {}, json=Mock(return_value=data))


def test_encrypted_files_roundtrip_exact_password_without_plaintext(vault):
    directory, store = vault
    settings = {"url": "https://192.168.8.1", "username": "root", "fingerprint": "ab" * 32}
    path = credentials.save_profile("gui", settings, PASSWORD, directory)
    assert credentials.load_profile("gui", directory)["password"] == PASSWORD
    assert PASSWORD.encode() not in path.read_bytes()
    assert path.stat().st_mode & 0o777 == 0o600
    assert directory.stat().st_mode & 0o777 == 0o700
    assert directory.parent.stat().st_mode & 0o777 == 0o700
    assert len(store) == 1
    with pytest.raises(credentials.SafeError, match="exists"):
        credentials.save_profile("gui", settings, "other", directory)
    credentials.save_profile("gui", settings, " replacement$@! ", directory, replace=True)
    assert len(store) == 1
    assert credentials.load_profile("gui", directory)["password"] == " replacement$@! "


def test_vault_rejects_tampering_missing_key_and_profile_swapping(vault):
    directory, store = vault
    path = credentials.save_profile("gui", {"url": "https://192.168.8.1"}, PASSWORD, directory)
    original = path.read_bytes()
    envelope = json.loads(original)
    envelope["ciphertext"] = Fernet.generate_key().decode()
    path.write_text(json.dumps(envelope))
    with pytest.raises(credentials.SafeError, match="authentication"):
        credentials.load_profile("gui", directory)
    path.write_bytes(original)
    other = directory / "luci.enc"
    other.write_bytes(original)
    other.chmod(0o600)
    with pytest.raises(credentials.SafeError, match="profile"):
        credentials.load_profile("luci", directory)
    store.clear()
    with pytest.raises(credentials.SafeError, match="Keychain"):
        credentials.load_profile("gui", directory)


def test_vault_refuses_loose_permissions_symlinks_and_output_overwrite(tmp_path):
    path = tmp_path / "profile"
    path.write_text("not a credential")
    path.chmod(0o644)
    with pytest.raises(credentials.SafeError, match="600"):
        credentials.private_read(path)
    link = tmp_path / "link"
    link.symlink_to(path)
    with pytest.raises(OSError):
        credentials.private_read(link)
    with pytest.raises(credentials.SafeError, match="Destination"):
        credentials.private_write(link, b"secret", replace=True)
    with pytest.raises(credentials.SafeError, match="Destination"):
        credentials.private_write(path, b"new")
    assert path.read_text() == "not a credential"
    directory = tmp_path / "shared"
    directory.mkdir(mode=0o755)
    with pytest.raises(credentials.SafeError, match="700"):
        credentials.private_directory(directory)
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo, mode=0o600)
    with pytest.raises(credentials.SafeError, match="regular"):
        credentials.private_read(fifo)


@pytest.mark.parametrize(
    "url",
    [
        "http://192.168.8.1",
        "https://example.com",
        "https://8.8.8.8",
        "https://root:secret@192.168.8.1",
        "https://192.168.8.1/rpc",
        "https://192.168.8.1?password=secret",
    ],
)
def test_credentials_are_bound_to_private_https_origin(url):
    with pytest.raises(credentials.SafeError):
        credentials.validate_url(url)


@pytest.mark.parametrize(
    ("alg", "cipher", "digest"),
    [
        (1, "$1$testsalt$RKyWS4t7Gc1en5OxLSWls.", "b9cb044dcc4fd7d0e591a4faf2cfc1195a0fe3441257be350557f9a53c46bce2"),
        (
            5,
            "$5$testsalt$nc9z20m.tnBESm5r5Ob0utfUa4y7md9LoetbHViSwX4",
            "6504b12803a13aa68a4b9a929679932250327771d428520c4ff492c0e47b29f3",
        ),
    ],
)
def test_gui_hash_matches_installed_browser_javascript_vectors(alg, cipher, digest):
    # Independent expected values came from the router's public browser crypt module.
    assert collect.login_hash(
        "fake-$@!-quote'\"-space ", "root", {"alg": alg, "salt": "testsalt", "nonce": "synthetic-nonce"}
    ) == (digest, cipher)


@pytest.mark.parametrize(
    "change", [{"alg": 7}, {"count": 1000}, {"hash-method": "md5"}, {"nonce": ""}, {"salt": "bad$salt"}]
)
def test_unknown_gui_hash_variants_are_rejected(change):
    challenge = {"alg": 5, "salt": "testsalt", "nonce": "nonce"}
    challenge.update(change)
    with pytest.raises(credentials.SafeError):
        collect.login_hash("synthetic", "root", challenge)
    with pytest.raises(credentials.SafeError, match="non-ASCII"):
        collect.login_hash("café", "root", {"alg": 5, "salt": "testsalt", "nonce": "nonce"})


@pytest.mark.parametrize("app_path", ["/js/app.bfe03abe.js", "/js/app.ab987315.js"])
def test_gui_flow_pins_tls_reads_allowlist_and_redacts_secrets(profile, monkeypatch, app_path):
    app, login = b"synthetic-app", b"synthetic-login"
    monkeypatch.setitem(
        collect.GUI_ASSETS, app_path, (hashlib.sha256(app).hexdigest(), hashlib.sha256(login).hexdigest())
    )
    client = collect.Collector(profile)
    adapter = client.session.get_adapter(client.origin)
    assert adapter.poolmanager.connection_pool_kw["assert_fingerprint"] == profile["fingerprint"]
    assert adapter.max_retries.total == 0
    assert not client.session.trust_env
    sid = "S" * 32
    post = Mock(
        side_effect=[
            reply(text=f'<script src="{app_path}"></script>'),
            reply(content=app),
            reply(content=login),
            reply({"id": 1, "result": {"alg": 5, "salt": "testsalt", "nonce": "nonce"}}),
            reply({"id": 2, "result": {"sid": sid}}),
            reply(
                {
                    "id": 3,
                    "result": {
                        "firmware_version": "synthetic",
                        "password": "hidden",
                        "nested": {"private_key": "hidden"},
                    },
                }
            ),
            reply({"id": 4, "result": {"uptime": 123, "message": sid + profile["password"]}}),
        ]
    )
    monkeypatch.setattr(client.session, "request", post)
    try:
        report = client.collect()
        serialized = json.dumps(report)
        assert sid not in serialized
        assert profile["password"] not in serialized
        assert "hidden" not in serialized
        assert report["data"]["system.get_status"]["uptime"] == 123
        assert all(call.kwargs["allow_redirects"] is False for call in post.call_args_list)
        assert [call.kwargs["json"]["params"][1:3] for call in post.call_args_list[-2:]] == [
            ["system", "get_info"],
            ["system", "get_status"],
        ]
        with pytest.raises(credentials.SafeError, match="allowlisted"):
            client.read("system", "reboot")
        with pytest.raises(credentials.SafeError, match="already"):
            client.authenticate_gui()
        assert post.call_count == 7
        assert post.call_args_list[1].args[1] == client.origin + app_path
    finally:
        client.close()


@pytest.mark.parametrize("app_path", ["/js/app.bfe03abe.js", "/js/app.unknown.js"])
def test_gui_changed_assets_stop_before_any_credential_post(profile, monkeypatch, app_path):
    client = collect.Collector(profile)
    request = Mock(side_effect=[reply(text=f'<script src="{app_path}"></script>'), reply(content=b"unknown firmware")])
    monkeypatch.setattr(client.session, "request", request)
    with pytest.raises(credentials.SafeError, match="differ"):
        client.authenticate_gui()
    assert [call.args[0] for call in request.call_args_list] == (
        ["GET", "GET"] if app_path in collect.GUI_ASSETS else ["GET"]
    )
    client.close()


def test_luci_form_session_and_advertised_ubus_path(profile, monkeypatch):
    profile = dict(profile, profile="luci", url="https://192.168.8.1:8443", password=PASSWORD)
    sid = "ab" * 16
    html = "L = new LuCI(" + json.dumps({"sessionid": sid, "ubuspath": "/ubus/", "token": "csrf-secret"}) + ");"
    client = collect.Collector(profile)
    responses = [
        reply(status=403, text='<input name="luci_password">'),
        reply(status=302, headers={"Location": "/cgi-bin/luci/admin/status/overview"}),
        reply(text=html),
    ]
    responses += [reply({"id": index + 1, "result": [0, {"status": "ok"}]}) for index in range(4)]
    request = Mock(side_effect=responses)
    monkeypatch.setattr(client.session, "request", request)
    try:
        report = client.collect()
        assert report["source"] == "luci"
        assert len(report["data"]) == 4
        assert request.call_args_list[1].kwargs["data"]["luci_password"] == PASSWORD
        assert all(call.args[1] == profile["url"] + "/ubus/" for call in request.call_args_list[-4:])
        assert all(call.kwargs["json"]["params"][0] == sid for call in request.call_args_list[-4:])
    finally:
        client.close()


@pytest.mark.parametrize("failure", [403, 307])
def test_luci_login_failure_never_replays_password(profile, monkeypatch, failure):
    client = collect.Collector(dict(profile, profile="luci"))
    request = Mock(
        side_effect=[
            reply(status=403, text="luci_password"),
            reply(status=failure, text="synthetic password reflection"),
        ]
    )
    monkeypatch.setattr(client.session, "request", request)
    with pytest.raises(credentials.SafeError, match="one credential POST"):
        client.authenticate_luci()
    with pytest.raises(credentials.SafeError, match="already"):
        client.authenticate_luci()
    assert request.call_count == 2
    client.close()


def test_cross_origin_redirect_and_rpc_ids_are_rejected(profile, monkeypatch):
    client = collect.Collector(profile)
    request = Mock(return_value=reply({"id": 999, "result": {}}))
    monkeypatch.setattr(client.session, "request", request)
    with pytest.raises(credentials.SafeError, match="Cross-origin"):
        client.request("GET", "https://192.168.9.1/")
    request.assert_not_called()
    with pytest.raises(credentials.SafeError, match="ID"):
        client.rpc("/rpc", "challenge", {})
    assert request.call_count == 1
    request.return_value = reply({"id": 2, "error": {"code": -32000, "message": PASSWORD}})
    with pytest.raises(credentials.SafeError, match=r"rejected login \(code -32000\)") as failure:
        client.rpc("/rpc", "login", {})
    assert PASSWORD not in str(failure.value)
    client.close()


def test_api_denial_stops_batch_instead_of_reauth(profile, monkeypatch):
    client = collect.Collector(dict(profile, profile="luci"))

    def authenticate():
        client.sid, client.rpc_path = "ab" * 16, "/ubus/"

    monkeypatch.setattr(client, "authenticate_luci", authenticate)
    request = Mock(return_value=reply({"id": 1, "result": [6]}))
    monkeypatch.setattr(client.session, "request", request)
    with pytest.raises(credentials.SafeError, match="denied"):
        client.collect()
    request.assert_called_once()
    client.close()


def test_ssh_host_key_mismatch_prevents_password_authentication(profile, monkeypatch):
    profile = dict(profile, profile="ssh", fingerprint="SHA256:" + "A" * 43)
    connection = Mock()
    transport = Mock()
    transport.get_remote_server_key.return_value.asbytes.return_value = b"different key"
    monkeypatch.setattr(speed, "connect_socket", Mock(return_value=connection))
    monkeypatch.setattr(speed.paramiko, "Transport", Mock(return_value=transport))
    client = speed.RouterSSH(profile)
    with pytest.raises(credentials.SafeError, match="no password"):
        client.connect()
    transport.auth_password.assert_not_called()
    transport.close.assert_called_once()


def test_benchmark_is_bounded_uses_existing_tools_and_records_route():
    ssh = Mock()

    def run(command, timeout=30):
        if command == speed.READ_COMMANDS["wan"]:
            return 0, json.dumps({"l3_device": "eth1"})
        if command in (speed.READ_COMMANDS["board"], speed.READ_COMMANDS["system"]):
            return 0, "{}"
        if "curl " in command:
            download = "__down?" in command
            amount = 2 * 1048576 if download else 1048576
            return 0, json.dumps(
                {
                    "status": 200,
                    "download_bytes": amount if download else 0,
                    "upload_bytes": 0 if download else amount,
                    "seconds": 1,
                    "download_Bps": amount if download else 0,
                    "upload_Bps": 0 if download else amount,
                    "remote_ip": "192.0.2.1",
                }
            )
        return 0, "synthetic"

    ssh.run.side_effect = run
    report = speed.benchmark(ssh, runs=2, download_mib=2, upload_mib=1, route="wan")
    assert len(report["transfers"]) == 4
    assert report["median_mbps"]["download"] == 2 * 1048576 * 8 / 1000000
    assert report["bound_device"] == "eth1"
    commands = [call.args[0] for call in ssh.run.call_args_list]
    assert all("--interface eth1" in command for command in commands if "curl --noproxy" in command)
    assert all(
        not any(word in command for word in ("opkg ", "reboot", "uci set", "sysupgrade", "modem_pass"))
        for command in commands
    )
    ssh.run.return_value = (127, "")
    ssh.run.side_effect = None
    with pytest.raises(credentials.SafeError, match="no packages"):
        speed.benchmark(ssh)
    for options in ({"runs": 0}, {"download_mib": 0}, {"upload_mib": 129}):
        # Exercise command-line validation before credentials or network access.
        key, value = next(iter(options.items()))
        with pytest.raises(SystemExit):
            speed.main(["--" + key.replace("_", "-"), str(value)])


def test_speedtest_rejects_short_transfer_and_command_injection():
    ssh = Mock()
    ssh.run.return_value = (
        0,
        json.dumps({"status": 200, "download_bytes": 1, "download_Bps": 1, "seconds": 1, "remote_ip": "192.0.2.1"}),
    )
    with pytest.raises(credentials.SafeError, match="incomplete"):
        speed.measure(ssh, "download", 1)
    with pytest.raises(credentials.SafeError, match="device"):
        speed.transfer_command("download", 1048576, "eth1; reboot")
    upload = speed.transfer_command("upload", 1048576)
    assert "--upload-file -" in upload
    assert "'Content-Length: 1048576'" in upload
    assert "--data-binary" not in upload
    assert "Transfer-Encoding:" in shlex.split(upload)
    for rate in (float("inf"), float("nan"), True):
        ssh.run.return_value = (
            0,
            json.dumps(
                {"status": 200, "download_bytes": 1048576, "download_Bps": rate, "seconds": 1, "remote_ip": "192.0.2.1"}
            ),
        )
        with pytest.raises(credentials.SafeError, match="incomplete"):
            speed.measure(ssh, "download", 1)


def test_cli_failures_do_not_print_exceptions_with_secrets(monkeypatch, capsys):
    monkeypatch.setattr(collect, "load_profile", Mock(side_effect=RuntimeError(PASSWORD)))
    assert collect.main(["gui"]) == 1
    monkeypatch.setattr(speed, "load_profile", Mock(side_effect=RuntimeError(PASSWORD)))
    assert speed.main([]) == 1
    assert PASSWORD not in capsys.readouterr().err


def test_credential_prompt_verifies_pin_before_password_and_preserves_input(monkeypatch, capsys):
    monkeypatch.setattr(credentials.sys.stdin, "isatty", lambda: True)
    monkeypatch.setattr(credentials, "probe", Mock(return_value={"certificate_sha256": "ab" * 32}))
    prompt = Mock(side_effect=[PASSWORD, PASSWORD])
    monkeypatch.setattr(credentials.getpass, "getpass", prompt)
    save = Mock(return_value="encrypted-profile.enc")
    monkeypatch.setattr(credentials, "save_profile", save)
    monkeypatch.setattr("builtins.input", lambda _message: "cd" * 32)
    assert credentials.main(["store", "luci"]) == 1
    prompt.assert_not_called()
    save.assert_not_called()
    monkeypatch.setattr("builtins.input", lambda _message: "AB:" * 31 + "AB")
    assert credentials.main(["store", "luci"]) == 0
    assert save.call_args.args[2] == PASSWORD
    assert save.call_args.args[1]["fingerprint"] == "ab" * 32
    assert PASSWORD not in str(capsys.readouterr())
    monkeypatch.setattr(credentials.sys.stdin, "isatty", lambda: False)
    prompt.reset_mock()
    assert credentials.main(["store", "luci"]) == 1
    prompt.assert_not_called()


def test_luci_exec_protocol_timeout_and_permission_denial(profile, monkeypatch):
    runner = speed.LuCIRunner(dict(profile, profile="luci"))
    authenticate = Mock()
    monkeypatch.setattr(runner.client, "authenticate_luci", authenticate)
    runner.connect()
    authenticate.assert_called_once()
    runner.client.sid, runner.client.rpc_path = "ab" * 16, "/ubus/"
    request = Mock(
        side_effect=[reply({"id": 1, "result": [0, {"code": 0, "stdout": "ok"}]}), reply({"id": 2, "result": [6]})]
    )
    monkeypatch.setattr(runner.client.session, "request", request)
    try:
        assert runner.run("command -v curl", timeout=70) == (0, "ok")
        sent = request.call_args.kwargs
        assert sent["timeout"] == (5, 75)
        assert sent["json"]["params"] == [
            "ab" * 16,
            "file",
            "exec",
            {"command": "/bin/sh", "params": ["-c", "command -v curl"]},
        ]
        with pytest.raises(credentials.SafeError, match="denied"):
            runner.run("command -v curl")
        assert request.call_count == 2
        authenticate.assert_called_once()
    finally:
        runner.close()


def test_speed_cli_defaults_to_luci_and_does_not_fall_back(profile, monkeypatch, capsys):
    load = Mock(return_value=dict(profile, profile="luci"))
    monkeypatch.setattr(speed, "load_profile", load)
    runner = Mock()
    runner.connect.side_effect = credentials.SafeError("LuCI permission denied")
    monkeypatch.setattr(speed, "LuCIRunner", Mock(return_value=runner))
    ssh = Mock()
    monkeypatch.setattr(speed, "RouterSSH", ssh)
    assert speed.main([]) == 1
    load.assert_called_once_with("luci")
    ssh.assert_not_called()
    runner.close.assert_called_once()
    assert "denied" in capsys.readouterr().err


@pytest.mark.parametrize("metadata_available", [True, False])
def test_settings_capture_uses_only_reads_and_redacts_secrets_but_keeps_policy(metadata_available):
    client = Mock(sid="ab" * 16, rpc_path="/ubus/", secrets=[PASSWORD])
    client.read.return_value = {"uptime": 123}

    def rpc(path, method, params, ubus=False):
        assert path == "/ubus/"
        assert method == "call"
        assert ubus
        _, module, operation, arguments = params
        if (module, operation) == ("file", "read"):
            if not metadata_available:
                raise credentials.SafeError("Metadata denied")
            return {"data": "version"}
        if (module, operation) == ("file", "list"):
            return {"entries": [{"name": "dropbear", "type": "file"}, {"name": "../shadow", "type": "file"}]}
        assert (module, operation, arguments) == ("uci", "get", {"config": "dropbear"})
        return {
            "values": {
                "server": {
                    "PasswordAuth": "on",
                    "RootPasswordAuth": "off",
                    "password": PASSWORD,
                    "psk": "hidden",
                    "url": "https://user:secret@example.invalid",
                    "note": PASSWORD,
                }
            }
        }

    client.rpc.side_effect = rpc
    report = audit.capture(client)
    assert report["complete"]
    assert report["inventory"] == ["dropbear"]
    assert bool(report["unavailable"]) is not metadata_available
    policy = report["configuration"]["dropbear"]["values"]["server"]
    assert policy["PasswordAuth"] == "on"
    assert policy["RootPasswordAuth"] == "off"
    serialized = json.dumps(report)
    assert PASSWORD not in serialized
    assert "hidden" not in serialized
    assert "user:secret" not in serialized
    client.authenticate_luci.assert_called_once()
    assert audit.sanitize({"PasswordAuth": "not-a-flag-secret"}) == {"PasswordAuth": "<redacted>"}
