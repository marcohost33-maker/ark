"""ARK-F-001: the real v1.1 adapter must not accept a coordinated profile + digest edit.

The attack rewrites the producer-supplied GateInputMaterializationProfile AND the
GateReport manifest/digest together, so the bundle stays internally consistent.
Only a consumer-held pin (profile digest, input digest, report digest) can tell.
These tests go through the public consumer entry points of ``normalize_v1_1``
(``normalize`` and the CLI ``main``), not only through the pin functions.
"""
from __future__ import annotations

import json
from pathlib import Path
import sys

import pytest

HERE = Path(__file__).resolve().parent
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))

import gate_input  # noqa: E402
import normalize_v1_1 as norm  # noqa: E402

FIXTURE = HERE / "fixtures" / "dde_v1_1_real.json"
POLICY = HERE / "policies" / "dde_v1_1_candidate.json"
PIN = HERE / "pins" / "dde_v1_1_pilot_pin.json"
# Out-of-band expectation for the exact pin file bytes (also pinned in the interop workflow).
PIN_SHA256 = "sha256:16e833e262c0b06a6c46f4a57cbe3f4273a2a36d3643005085f9cf901621f9b1"
OPTIONAL = "external_cross_solver_optional"


def load(path: Path):
    return json.loads(path.read_text(encoding="utf-8"))


def _rebind_report(bundle) -> None:
    profile = bundle["gate_input_profiles"][0]
    index = {}
    for doc in (bundle["model_spec"], bundle["run_plan"], bundle["claim_card"], *bundle["evidence_attestations"]):
        index[gate_input._document_key(doc)] = doc
    documents = [index[(item["kind"], item["id"])] for item in profile["inputs"]]
    bundle["gate_reports"][0].update(gate_input.binding(profile, documents))


def coordinated_omission(bundle):
    """Drop gate-bound evidence and rewrite profile + report digest consistently."""
    bundle["evidence_attestations"] = [
        item for item in bundle["evidence_attestations"] if OPTIONAL not in item["evidence_id"]
    ]
    profile = bundle["gate_input_profiles"][0]
    profile["inputs"] = [item for item in profile["inputs"] if OPTIONAL not in item["id"]]
    _rebind_report(bundle)
    return bundle


def coordinated_reorder(bundle):
    bundle["gate_input_profiles"][0]["inputs"].reverse()
    _rebind_report(bundle)
    return bundle


def coordinated_evidence_edit(bundle):
    """Change gate-bound evidence content but keep profile; recompute the report digest."""
    bundle["evidence_attestations"][0]["producer_note"] = "edited after gate"
    _rebind_report(bundle)
    return bundle


ATTACKS = [coordinated_omission, coordinated_reorder, coordinated_evidence_edit]


def _rejected(call) -> bool:
    try:
        result = call()
    except ValueError:
        return True
    return result.get("blocking") is True


@pytest.mark.parametrize("attack", ATTACKS, ids=lambda f: f.__name__)
def test_attack_bundle_is_self_consistent_without_pin(attack):
    """Precondition: the attack defeats the bundle-internal gate re-check."""
    bundle = attack(load(FIXTURE))
    profile = bundle["gate_input_profiles"][0]
    report = bundle["gate_reports"][0]
    index = norm._all_contract_documents(bundle)
    documents = [index[(item["kind"], item["id"])] for item in profile["inputs"]]
    assert gate_input.verify_report(report, profile, documents)["input_digest"] == report["input_digest"]


@pytest.mark.parametrize("attack", ATTACKS, ids=lambda f: f.__name__)
def test_public_adapter_call_without_pin_does_not_accept_attack(attack):
    """Name-free check over the public call shape ``normalize(bundle, policy)``."""
    bundle = attack(load(FIXTURE))
    assert _rejected(lambda: norm.normalize(bundle, load(POLICY)))


@pytest.mark.parametrize("attack", ATTACKS, ids=lambda f: f.__name__)
def test_pinned_adapter_rejects_coordinated_attack(attack):
    from trusted_gate_pin import TrustedPinError

    bundle = attack(load(FIXTURE))
    with pytest.raises(TrustedPinError) as caught:
        norm.normalize(bundle, load(POLICY), trusted_pin=load(PIN))
    assert str(caught.value).startswith(("upstream-binding-rejected:", "gate:"))


def test_positive_control_pinned_real_contract_is_accepted():
    result = norm.normalize(load(FIXTURE), load(POLICY), trusted_pin=load(PIN))
    assert result["blocking"] is False
    assert result["contradictions"] == []
    pin_binding = result["contract_bindings"]["trusted_gate_pin"]
    assert pin_binding["status"] == "GATE_INPUT_BOUND_TO_CONSUMER_PIN"
    assert pin_binding["input_digest"] == load(PIN)["input_digest"]
    assert pin_binding["gate_report_digest"] == load(PIN)["gate_report_digest"]


def test_missing_pin_fails_closed_before_normalization(monkeypatch):
    from trusted_gate_pin import TrustedPinError

    called = []
    monkeypatch.setattr(norm.core, "normalize", lambda *a: called.append(a))
    with pytest.raises(TrustedPinError, match="pin:required"):
        norm.normalize(load(FIXTURE), load(POLICY))
    assert called == []


def test_rejected_pin_stops_before_normalization(monkeypatch):
    from trusted_gate_pin import TrustedPinError

    called = []
    monkeypatch.setattr(norm.core, "normalize", lambda *a: called.append(a))
    with pytest.raises(TrustedPinError):
        norm.normalize(coordinated_omission(load(FIXTURE)), load(POLICY), trusted_pin=load(PIN))
    assert called == []


PIN_FIELD_CASES = {
    "profile_digest": ("sha256:" + "0" * 64, "bundle:profile-digest-mismatch"),
    "input_digest": ("sha256:" + "0" * 64, "gate:expected-input-digest-mismatch"),
    "gate_report_digest": ("sha256:" + "0" * 64, "gate:trusted-report-digest-mismatch"),
    "gate_id": ("GATE-OTHER", "bundle:gate-identity-mismatch"),
    "profile_id": ("DDE.GATE-OTHER", "bundle:profile-identity-mismatch"),
}


@pytest.mark.parametrize("field", sorted(PIN_FIELD_CASES))
def test_pin_field_mismatch_rejects_unmodified_bundle(field):
    """Each pinned field is checked by its own guard, not only by a neighbouring one."""
    from trusted_gate_pin import TrustedPinError

    value, reason = PIN_FIELD_CASES[field]
    pin = load(PIN)
    pin[field] = value
    with pytest.raises(TrustedPinError, match=reason):
        norm.normalize(load(FIXTURE), load(POLICY), trusted_pin=pin)


def test_failed_gate_report_is_not_normalized_even_with_matching_digests():
    from trusted_gate_pin import TrustedPinError

    bundle = load(FIXTURE)
    bundle["gate_reports"][0]["result"] = "FAIL"
    with pytest.raises(TrustedPinError, match="gate:not-pass"):
        norm.normalize(bundle, load(POLICY), trusted_pin=load(PIN))


def _cli(tmp_path: Path, bundle, pin_bytes: bytes, expected: str):
    bundle_path = tmp_path / "bundle.json"
    pin_path = tmp_path / "pin.json"
    out = tmp_path / "out.json"
    bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
    pin_path.write_bytes(pin_bytes)
    rc = norm.main([
        str(bundle_path), "--identity-policy", str(POLICY), "--trusted-pin", str(pin_path),
        "--expected-pin-sha256", expected, "--out", str(out),
    ])
    return rc, json.loads(out.read_text(encoding="utf-8"))


def test_cli_positive_control_and_attack(tmp_path):
    pin_bytes = PIN.read_bytes()
    rc, out = _cli(tmp_path, load(FIXTURE), pin_bytes, PIN_SHA256)
    assert rc == 0 and out["blocking"] is False
    # A stale accepting output must be replaced by a REJECT verdict.
    rc, out = _cli(tmp_path, coordinated_omission(load(FIXTURE)), pin_bytes, PIN_SHA256)
    assert rc == 2
    assert out.get("status") == "REJECT" and out.get("blocking") is True
    assert "output_digest" not in out


def test_cli_rejects_pin_file_not_matching_out_of_band_digest(tmp_path):
    pin = load(PIN)
    pin["profile_digest"] = "sha256:" + "0" * 64
    rc, out = _cli(tmp_path, load(FIXTURE), json.dumps(pin).encode("utf-8"), PIN_SHA256)
    assert rc == 2
    assert out["reason"] == "pin:out-of-band-file-digest-mismatch"


def test_pin_file_bytes_match_out_of_band_expectation():
    import hashlib

    assert "sha256:" + hashlib.sha256(PIN.read_bytes()).hexdigest() == PIN_SHA256
