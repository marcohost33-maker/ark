from __future__ import annotations

import copy
import json
import random
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import gate_input  # noqa: E402
import trusted_gate_pin as pincheck  # noqa: E402


def fixture():
    model = {"schema_name": "ModelSpec", "model_id": "model.1", "schema_version": "1.0.0"}
    run = {"schema_name": "RunPlan", "run_id": "run.1", "schema_version": "1.0.0"}
    evs = [
        {"schema_name": "EvidenceAttestation", "schema_version": "1.1.0", "evidence_id": x, "payload": {"value": i}}
        for i, x in enumerate(("ev.1", "ev.2", "ev.3", "ev.optional"), 1)
    ]
    claim = {"schema_name": "ClaimCard", "schema_version": "1.0.0", "claim_id": "claim.1"}
    profile = {
        "schema_name": "GateInputMaterializationProfile",
        "schema_version": "1.0.0",
        "profile_id": "dde.scalar.test", "profile_version": "1.0.0",
        "serialization": "coworker-json-sortkeys-v1",
        "digest_algorithm": "sha256", "projection_policy": "FULL_DOCUMENT",
        "ordering": "PROFILE_DECLARED_INPUT_ORDER",
        "inputs": [
            {"kind": "ModelSpec", "id": "model.1"},
            {"kind": "RunPlan", "id": "run.1"},
            *({"kind": "EvidenceAttestation", "id": e["evidence_id"]} for e in evs),
            {"kind": "ClaimCard", "id": "claim.1"},
        ],
    }
    report = {
        "schema_name": "GateReport", "schema_version": "1.1.0",
        "gate_id": "gate.1", "subject_id": "claim.1", "result": "PASS",
        **gate_input.binding(profile, [model, run, *evs, claim]),
    }
    bundle = {
        "model_spec": model, "run_plan": run,
        "evidence_attestations": evs, "claim_card": claim,
        "gate_input_profiles": [profile], "gate_reports": [report],
    }
    pin = {
        "schema_name": "ARKTrustedGatePin", "schema_version": "1.0.0",
        "gate_id": "gate.1", "claim_id": "claim.1", "run_id": "run.1",
        "profile_id": profile["profile_id"],
        "profile_version": profile["profile_version"],
        "profile_digest": pincheck.digest(profile),
        "input_manifest": copy.deepcopy(profile["inputs"]),
        "scope_policy": "ALL_BUNDLE_EVIDENCE",
    }
    return bundle, pin


def bypass_gate_input_only(bundle):
    profile = bundle["gate_input_profiles"][0]
    documents = [bundle["model_spec"], bundle["run_plan"], *bundle["evidence_attestations"], bundle["claim_card"]]
    bundle["gate_reports"][0].update(gate_input.binding(profile, documents))
    return gate_input.verify_report(bundle["gate_reports"][0], profile, documents)


class TrustPinTests(unittest.TestCase):
    def assertReject(self, bundle, pin, message=None):
        with self.assertRaises(pincheck.TrustedPinError, msg=message):
            pincheck.verify_bundle(bundle, pin)

    def test_01_happy_path(self):
        bundle, pin = fixture()
        result = pincheck.verify_bundle(bundle, pin)
        self.assertEqual(result["status"], "BOUND_TO_CONSUMER_PIN")
        self.assertEqual(result["input_count"], 7)
        self.assertEqual(result["scientific_truth"], "NOT_ESTABLISHED")
        self.assertEqual(result["independent_release_trust"], "NOT_VERIFIED")

    def test_02_compound_omission_bypasses_unpinned_gate(self):
        bundle, pin = fixture()
        # Omit an unused evidence item, while jointly rewriting the producer-
        # supplied input profile AND gate report manifest/digest to conceal it.
        bundle["evidence_attestations"] = bundle["evidence_attestations"][:-1]
        bundle["gate_input_profiles"][0]["inputs"] = [
            item for item in bundle["gate_input_profiles"][0]["inputs"]
            if item["id"] != "ev.optional"
        ]
        old = pin["profile_digest"]
        self.assertNotEqual(pincheck.digest(bundle["gate_input_profiles"][0]), old)
        self.assertIn("input_digest", bypass_gate_input_only(bundle))  # reproduces weakness
        self.assertReject(bundle, pin)  # fixes bypass when consumer pin is independent

    def test_03_coordinated_reorder_bypasses_unpinned_gate(self):
        bundle, pin = fixture()
        bundle["gate_input_profiles"][0]["inputs"].reverse()
        self.assertIn("input_digest", bypass_gate_input_only(bundle))
        self.assertReject(bundle, pin)

    def test_04_evidence_body_mutation_rejected_by_digest(self):
        bundle, pin = fixture()
        bundle["evidence_attestations"][0]["payload"]["value"] = 999
        self.assertReject(bundle, pin)

    def test_05_extra_evidence_closed_world(self):
        bundle, pin = fixture()
        bundle["evidence_attestations"].append({"schema_name": "EvidenceAttestation", "evidence_id": "extra", "schema_version": "1.1.0"})
        self.assertReject(bundle, pin)

    def test_06_missing_document_rejected(self):
        bundle, pin = fixture()
        bundle["evidence_attestations"].pop()
        self.assertReject(bundle, pin)

    def test_07_duplicate_document_rejected(self):
        bundle, pin = fixture()
        bundle["evidence_attestations"].append(copy.deepcopy(bundle["evidence_attestations"][0]))
        self.assertReject(bundle, pin)

    def test_08_wrong_pin_digest_rejected(self):
        bundle, pin = fixture()
        pin["profile_digest"] = "sha256:" + "0" * 64
        self.assertReject(bundle, pin)

    def test_09_untrusted_pin_schema_rejected(self):
        bundle, pin = fixture()
        pin["scope_policy"] = "SUBSET_ALLOWED"
        self.assertReject(bundle, pin)

    def test_10_attacker_changes_gate_identity(self):
        bundle, pin = fixture()
        bundle["gate_reports"][0]["gate_id"] = "gate.bad"
        self.assertReject(bundle, pin)

    def test_11_attacker_changes_claim_identity(self):
        bundle, pin = fixture()
        bundle["claim_card"]["claim_id"] = "evil.claim"
        self.assertReject(bundle, pin)

    def test_12_extra_gate_rejected(self):
        bundle, pin = fixture()
        bundle["gate_reports"].append(copy.deepcopy(bundle["gate_reports"][0]))
        self.assertReject(bundle, pin)

    def test_13_bad_profile_manifest_rejected(self):
        bundle, pin = fixture()
        bundle["gate_input_profiles"][0]["inputs"][0]["id"] = "wrong"
        self.assertReject(bundle, pin)

    def test_14_reject_malformed_manifest(self):
        bundle, pin = fixture()
        pin["input_manifest"].append(copy.deepcopy(pin["input_manifest"][0]))
        self.assertReject(bundle, pin)

    def test_15_fail_closed_missing_profile(self):
        bundle, pin = fixture()
        bundle.pop("gate_input_profiles")
        self.assertReject(bundle, pin)

    def test_16_fail_closed_unexpected_symbol_specs(self):
        bundle, pin = fixture()
        bundle["symbol_specs"] = [{"schema_name": "SymbolSpec", "symbol_id": "s1"}]
        self.assertReject(bundle, pin)

    def test_17_repeatability(self):
        bundle, pin = fixture()
        self.assertEqual(pincheck.verify_bundle(bundle, pin), pincheck.verify_bundle(bundle, pin))

    def test_18_cli_atomic_replace_stale_accept_on_failure(self):
        bundle, pin = fixture()
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            bundle_path, pin_path, out_path = t / "bundle.json", t / "pin.json", t / "gate.json"
            bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
            pin_path.write_text(json.dumps(pin), encoding="utf-8")
            cli = HERE / "trusted_gate_pin.py"
            cmd = [sys.executable, str(cli), str(bundle_path), "--trusted-pin", str(pin_path), "--out", str(out_path)]
            r = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True, check=False)
            self.assertEqual(r.returncode, 0, r.stderr)
            self.assertEqual(json.loads(out_path.read_text())["status"], "BOUND_TO_CONSUMER_PIN")
            # Previously ACCEPT verdict must be overwritten on tampered input.
            bundle["evidence_attestations"][0]["payload"] = "tampered"
            bundle_path.write_text(json.dumps(bundle), encoding="utf-8")
            r = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True, check=False)
            self.assertEqual(r.returncode, 2, r.stderr)
            self.assertEqual(json.loads(out_path.read_text())["status"], "REJECT")

    def test_20_deterministic_mutation_sweep(self):
        rng = random.Random(20261015)
        for i in range(100):
            bundle, pin = fixture()
            mutation = rng.randrange(6)
            if mutation == 0:
                bundle["evidence_attestations"] = bundle["evidence_attestations"][:-1]
                bundle["gate_input_profiles"][0]["inputs"] = [
                    k for k in bundle["gate_input_profiles"][0]["inputs"] if k["id"] != "ev.optional"
                ]
                bypass_gate_input_only(bundle)
            elif mutation == 1:
                bundle["gate_input_profiles"][0]["inputs"].reverse()
                bypass_gate_input_only(bundle)
            elif mutation == 2:
                bundle["evidence_attestations"][rng.randrange(4)]["payload"]["value"] += i + 1
            elif mutation == 3:
                bundle["gate_reports"][0]["subject_id"] = f"claim.rogue.{i}"
            elif mutation == 4:
                bundle["evidence_attestations"].append({"schema_name": "EvidenceAttestation", "evidence_id": f"extra.{i}"})
            else:
                bundle["gate_input_profiles"][0]["profile_id"] += f"-rogue-{i}"
            self.assertReject(bundle, pin, f"sweep case {i} mutation {mutation}")

    def test_19_hqst_minimal_cross_language_vector_legacy_codec(self):
        # Golden digest copied from the existing ARK PR #29 unit test.
        profile = {
            "schema_name": "GateInputMaterializationProfile", "schema_version": "1.0.0",
            "profile_id": "HQST.GATE-EVID-001.DDE-REFERENCE-001", "profile_version": "1.0.0",
            "serialization": "coworker-json-sortkeys-v1", "digest_algorithm": "sha256",
            "projection_policy": "FULL_DOCUMENT", "ordering": "PROFILE_DECLARED_INPUT_ORDER",
            "inputs": [
                {"kind": "ModelSpec", "id": "dde.reference.linear"},
                {"kind": "RunPlan", "id": "RUN-DDE-001"},
                {"kind": "EvidenceAttestation", "id": "EVID-DDE-001"},
                {"kind": "ClaimCard", "id": "CLM-DDE-001"},
            ],
        }
        documents = [
            {"schema_name": "ModelSpec", "schema_version": "1.0.0", "model_id": "dde.reference.linear", "revision": "1.0.0"},
            {"schema_name": "RunPlan", "schema_version": "1.0.0", "run_id": "RUN-DDE-001", "model_id": "dde.reference.linear"},
            {"schema_name": "EvidenceAttestation", "schema_version": "1.0.0", "evidence_id": "EVID-DDE-001", "subject": {"claim_id": "CLM-DDE-001", "run_id": "RUN-DDE-001"}},
            {"schema_name": "ClaimCard", "schema_version": "1.0.0", "claim_id": "CLM-DDE-001", "status": "SUPPORTED"},
        ]
        self.assertEqual(gate_input.binding(profile, documents)["input_digest"], "sha256:8744844a3f1b4323dabaca05e0072638de5b3dba87ad6b581203463672f06048")


if __name__ == "__main__":
    unittest.main(verbosity=2)
