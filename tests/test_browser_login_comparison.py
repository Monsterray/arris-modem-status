"""Independent modem-JavaScript vectors and offline HAR comparison checks."""

import base64
import json
from pathlib import Path

import pytest

from arris_modem_status.cli.compare_login import compare_login
from arris_modem_status.cli.compare_login import main as comparison_main
from arris_modem_status.client.auth import HNAPAuthenticator

VECTORS = json.loads(Path(__file__).with_name("browser_hnap_vectors.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("vector", VECTORS)
def test_python_matches_actual_modem_javascript(vector):
    """Expected hashes came from running the modem's hmac_md5.js, not Python."""
    auth = HNAPAuthenticator("admin", vector["password"], hmac_algorithm="md5")
    assert auth.compute_credentials("challenge", "public") == vector["login"]
    assert auth.private_key == vector["key"]
    assert auth.generate_auth_token("Login", 123) == vector["token"]


def browser_har(result="SUCCESS"):
    """A synthetic browser capture; never contains a real modem password or cookie."""
    vector = VECTORS[0]
    auth = HNAPAuthenticator("admin", vector["password"], hmac_algorithm="md5")
    requests = [
        ({"Action": "request", "Username": "admin"}, auth.generate_auth_token("Login", 123), {}),
        (
            {"Action": "login", "Username": "admin", "LoginPassword": vector["login"], "PrivateLogin": "LoginPassword"},
            vector["token"],
            {"uid": "synthetic-session", "PrivateKey": vector["key"]},
        ),
    ]
    responses = [
        {"Challenge": "challenge", "PublicKey": "public", "Cookie": "synthetic-session"},
        {"LoginResult": result},
    ]
    entries = []
    for (payload, token, cookies), response in zip(requests, responses):
        entries.append(
            {
                "request": {
                    "method": "POST",
                    "url": "https://192.168.100.1/HNAP1/",
                    "postData": {"text": json.dumps({"Login": payload})},
                    "headers": [{"name": "HNAP_AUTH", "value": token}],
                    "cookies": [{"name": name, "value": value} for name, value in cookies.items()],
                },
                "response": {"content": {"text": json.dumps({"LoginResponse": response})}},
            }
        )
    return {"log": {"entries": entries}}


def test_offline_comparison_matches_and_redacts_browser_flow():
    report = compare_login(browser_har(), VECTORS[0]["password"], "md5")
    assert report["browser_login_succeeded"]
    assert all(report["checks"].values())
    output = json.dumps(report)
    for secret in [VECTORS[0]["password"], VECTORS[0]["key"], VECTORS[0]["login"], "synthetic-session"]:
        assert secret not in output


def test_wrong_password_identified_offline():
    report = compare_login(browser_har(), "different-password", "md5")
    assert report["browser_login_succeeded"]
    assert not report["checks"]["password_matches_browser_login_hash"]
    assert not report["checks"]["login_signature_matches"]


def test_failed_browser_login_is_not_proof_of_valid_credentials():
    report = compare_login(browser_har("FAILED"), VECTORS[0]["password"], "md5")
    assert not report["browser_login_succeeded"]
    assert all(report["checks"].values())


def test_base64_encoded_har_response():
    har = browser_har()
    for entry in har["log"]["entries"]:
        content = entry["response"]["content"]
        content["text"] = base64.b64encode(content["text"].encode()).decode()
        content["encoding"] = "base64"
    assert all(compare_login(har, VECTORS[0]["password"], "md5")["checks"].values())


def test_last_complete_login_used():
    har = browser_har("FAILED")
    har["log"]["entries"].extend(browser_har()["log"]["entries"])
    assert compare_login(har, VECTORS[0]["password"], "md5")["browser_login_succeeded"]


def test_incomplete_capture_rejected():
    with pytest.raises(ValueError, match="No complete"):
        compare_login({"log": {"entries": []}}, "test", "md5")


@pytest.mark.parametrize("text", ["{", "[]", '{"Login": []}', '{"Login":{"Action":"other"}}'])
def test_irrelevant_malformed_request_does_not_hide_valid_flow(text):
    har = browser_har()
    malformed = json.loads(json.dumps(har["log"]["entries"][0]))
    malformed["request"]["postData"]["text"] = text
    har["log"]["entries"].insert(0, malformed)
    assert all(compare_login(har, VECTORS[0]["password"], "md5")["checks"].values())


def test_har_ignores_other_urls_methods_and_cross_host_pairs():
    har = browser_har()
    entries = har["log"]["entries"]
    ignored = []
    for method, url in [("GET", entries[0]["request"]["url"]), ("POST", "https://192.0.2.1/other")]:
        entry = json.loads(json.dumps(entries[0]))
        entry["request"].update(method=method, url=url)
        ignored.append(entry)
    wrong_host = json.loads(json.dumps(entries[1]))
    wrong_host["request"]["url"] = "https://192.0.2.1/HNAP1/"
    entries[1:1] = [*ignored, wrong_host]
    assert all(compare_login(har, VECTORS[0]["password"], "md5")["checks"].values())


@pytest.mark.parametrize("token", ["", "invalid", "digest invalid-time"])
def test_invalid_browser_signature_is_reported_as_mismatch(token):
    har = browser_har()
    har["log"]["entries"][1]["request"]["headers"] = [{"name": "HNAP_AUTH", "value": token}]
    assert not compare_login(har, VECTORS[0]["password"], "md5")["checks"]["login_signature_matches"]


def test_cookie_header_is_accepted_without_har_cookie_array():
    har = browser_har()
    request = har["log"]["entries"][1]["request"]
    request["headers"].append(
        {"name": "Cookie", "value": "; ".join(f"{c['name']}={c['value']}" for c in request.pop("cookies"))}
    )
    assert all(compare_login(har, VECTORS[0]["password"], "md5")["checks"].values())


@pytest.mark.parametrize("result", ["SUCCESS", "FAILED"])
def test_comparison_cli_outputs_only_redacted_results(result, tmp_path, monkeypatch, capsys):
    path = tmp_path / "browser.har"
    path.write_text(json.dumps(browser_har(result)))
    monkeypatch.setattr("sys.argv", ["compare-login", "--har", str(path), "--hmac-algorithm", "md5"])
    monkeypatch.setattr("arris_modem_status.cli.compare_login.getpass", lambda _: VECTORS[0]["password"])
    assert comparison_main() == (0 if result == "SUCCESS" else 1)
    output = capsys.readouterr()
    assert json.loads(output.out)["browser_login_succeeded"] is (result == "SUCCESS")
    assert all(
        secret not in output.out + output.err
        for secret in (VECTORS[0]["password"], VECTORS[0]["key"], "synthetic-session")
    )


@pytest.mark.parametrize("failure", [EOFError("synthetic-secret"), KeyboardInterrupt()])
def test_comparison_cli_handles_cancelled_prompt(failure, tmp_path, monkeypatch, capsys):
    path = tmp_path / "browser.har"
    path.write_text(json.dumps(browser_har()))
    monkeypatch.setattr("sys.argv", ["compare-login", "--har", str(path), "--hmac-algorithm", "md5"])

    def fail(_):
        raise failure

    monkeypatch.setattr("arris_modem_status.cli.compare_login.getpass", fail)
    assert comparison_main() == (130 if isinstance(failure, KeyboardInterrupt) else 1)
    output = capsys.readouterr()
    assert output.out == ""
    assert "synthetic-secret" not in output.err


def test_comparison_cli_rejects_invalid_response_shape(tmp_path, monkeypatch, capsys):
    har = browser_har()
    har["log"]["entries"][1]["response"]["content"]["text"] = '{"LoginResponse":[]}'
    path = tmp_path / "browser.har"
    path.write_text(json.dumps(har))
    monkeypatch.setattr("sys.argv", ["compare-login", "--har", str(path), "--hmac-algorithm", "md5"])
    monkeypatch.setattr("arris_modem_status.cli.compare_login.getpass", lambda _: "synthetic")
    assert comparison_main() == 1
    assert "Comparison failed" in capsys.readouterr().err
