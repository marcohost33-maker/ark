from __future__ import annotations

import copy
import hashlib
import json
import os
from pathlib import Path
import random
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))

import gate_input  # noqa:E402
import trusted_gate_pin as r1  # noqa:E402
import trusted_gate_pin_r2 as r2  # noqa:E402
from checked_normalize import checked_normalize  # noqa:E402
from test_trusted_gate_pin import fixture as original_fixture, bypass_gate_input_only  # noqa:E402


def fixture():
    b, p = original_fixture()
    p["schema_version"] = "2.0.0"
    p["input_digest"] = b["gate_reports"][0]["input_digest"]
    p["gate_report_digest"] = r1.digest(b["gate_reports"][0])
    return b, p


def cli(root: Path, bundle: bytes, pin: bytes, out: str = "result.json", expected: str | None = None):
    inp, pc, result_path = root / "bundle.json", root / "consumer-pin.json", root / out
    inp.write_bytes(bundle)
    pc.write_bytes(pin)
    if expected is None:
        expected = r2.sha256_bytes(pin)
    cmd = [sys.executable, str(HERE / "trusted_gate_pin_r2.py"),
           str(inp), "--trusted-pin", str(pc), "--expected-pin-sha256", expected,
           "--out", str(result_path)]
    run = subprocess.run(cmd, stdin=subprocess.DEVNULL, capture_output=True, text=True, check=False)
    return run, result_path, inp, pc


class R2Tests(unittest.TestCase):
    def test_01_normal(self):
        b, p = fixture()
        v = r2.verify_bundle_r2(b, p)
        self.assertEqual(v["status"], "GATE_INPUT_BOUND_TO_CONSUMER_PIN")
        self.assertEqual(v["release_trust"], "NOT_ESTABLISHED")
        self.assertEqual(v["gate_result"], "PASS")

    def test_02_reproduce_r1_evidence_digest_bypass(self):
        b, p = fixture()
        b["evidence_attestations"][0]["payload"]["value"] = 123456
        bypass_gate_input_only(b)
        old_pin = {k:v for k,v in p.items() if k not in ("input_digest", "gate_report_digest")}
        old_pin["schema_version"] = "1.0.0"
        self.assertEqual(r1.verify_bundle(b, old_pin)["status"], "BOUND_TO_CONSUMER_PIN")
        with self.assertRaisesRegex(r2.R2Error, "expected-input-digest-mismatch"):
            r2.verify_bundle_r2(b, p)

    def test_03_reproduce_r1_failed_gate_bypass(self):
        b, p = fixture()
        b["gate_reports"][0]["result"] = "FAIL"
        old_pin = {k:v for k,v in p.items() if k not in ("input_digest", "gate_report_digest")}
        old_pin["schema_version"] = "1.0.0"
        self.assertEqual(r1.verify_bundle(b, old_pin)["status"], "BOUND_TO_CONSUMER_PIN")
        with self.assertRaisesRegex(r2.R2Error, "gate:not-pass"):
            r2.verify_bundle_r2(b, p)

    def test_04_reject_coordinated_profile_digest_rewrite(self):
        b, p = fixture()
        b["evidence_attestations"].pop()
        b["gate_input_profiles"][0]["inputs"] = [x for x in b["gate_input_profiles"][0]["inputs"] if x["id"] != "ev.optional"]
        bypass_gate_input_only(b)
        with self.assertRaises(r2.R2Error):
            r2.verify_bundle_r2(b, p)

    def test_05_trusted_digest_pin_exact_bytes(self):
        b, p = fixture()
        with tempfile.TemporaryDirectory() as t:
            t = Path(t)
            raw = json.dumps(p).encode()
            run, result, inp, pin = cli(t, json.dumps(b).encode(), raw)
            self.assertEqual(run.returncode, 0, run.stderr)
            self.assertEqual(json.loads(result.read_text())["pin_authority"], "FILE_DIGEST_MATCHED_OUT_OF_BAND_EXPECTATION")
            # Mutating the policy file without changing the independent expected digest fails.
            bad = bytearray(raw);bad[-2:-1] = b" "
            run, result, *_ = cli(t, json.dumps(b).encode(), bytes(bad), expected=r2.sha256_bytes(raw))
            self.assertEqual(run.returncode, 2)
            self.assertIn("out-of-band-file-digest-mismatch", result.read_text())

    def test_06_duplicate_json_keys_rejected(self):
        with self.assertRaisesRegex(r2.R2Error, "duplicate-member"):
            r2.strict_json(b'{"a":1,"a":2}', max_bytes=100)

    def test_07_nested_duplicate_json_keys_rejected(self):
        with self.assertRaisesRegex(r2.R2Error, "duplicate-member"):
            r2.strict_json(b'{"a":{"b":1,"b":2}}', max_bytes=100)

    def test_08_nonfinite_json_rejected(self):
        for src in (b'{"a":NaN}', b'{"a":Infinity}', b'{"a":1e9999}'):
            with self.subTest(src=src), self.assertRaises(r2.R2Error):
                r2.strict_json(src, max_bytes=100)

    def test_09_invalid_utf8_or_bom_rejected(self):
        for src in (b'\xff', b'\xef\xbb\xbf{}'):
            with self.subTest(src=src), self.assertRaises(r2.R2Error):
                r2.strict_json(src, max_bytes=100)

    def test_10_unpaired_surrogate_rejected(self):
        with self.assertRaisesRegex(r2.R2Error, "unpaired-surrogate"):
            r2.strict_json(b'{"x":"\\ud800"}', max_bytes=100)

    def test_11_depth_limit(self):
        payload = ("[" * 105 + "0" + "]" * 105).encode()
        with self.assertRaises(r2.R2Error):
            r2.strict_json(payload, max_bytes=1000)

    def test_12_byte_limit(self):
        with self.assertRaisesRegex(r2.R2Error, "byte-limit"):
            r2.strict_json(b"{" + b" " * 100 + b"}", max_bytes=50)

    def test_13_no_overwrite_pin_or_bundle(self):
        b,p=fixture()
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            data=json.dumps(b).encode();pin=json.dumps(p).encode()
            run,out,inp,pc=cli(root,data,pin,out="bundle.json")
            self.assertEqual(run.returncode,3)
            self.assertEqual(inp.read_bytes(),data)
            run,out,inp,pc=cli(root,data,pin,out="consumer-pin.json")
            self.assertEqual(run.returncode,3)
            self.assertEqual(pc.read_bytes(),pin)

    def test_14_no_overwrite_hardlink(self):
        b,p=fixture()
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            data=json.dumps(b).encode(); pin=json.dumps(p).encode()
            inp=root/'bundle.json';pc=root/'consumer-pin.json';out=root/'report.json'
            inp.write_bytes(data);pc.write_bytes(pin)
            os.link(inp,out)
            with self.assertRaises(r2.R2Error):
                r2._check_output_is_not_input(out, inp, pc)

    @unittest.skipIf(os.name == "nt", "symlink creation needs SeCreateSymbolicLinkPrivilege on Windows (WinError 1314); covered on POSIX CI")
    def test_15_no_overwrite_symlink(self):
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            a=root/'bundle';a.write_text('{}')
            out=root/'report';out.symlink_to(a)
            with self.assertRaises(r2.R2Error):
                r2._check_output_is_not_input(out,a,root/'pin')

    def test_16_failed_input_replaces_stale_positive_report(self):
        b,p=fixture()
        with tempfile.TemporaryDirectory() as tmp:
            root=Path(tmp)
            raw=json.dumps(p).encode();data=json.dumps(b).encode()
            run,out,inp,pc=cli(root,data,raw)
            self.assertEqual(run.returncode,0)
            b['evidence_attestations'][0]['payload']['value']=999
            bypass_gate_input_only(b)
            run,out,*_=cli(root,json.dumps(b).encode(),raw)
            self.assertEqual(run.returncode,2)
            self.assertEqual(json.loads(out.read_text())['status'],'REJECT')

    def test_17_checked_normalizer_never_invoked_on_bad_pin(self):
        b,p=fixture();called=[]
        p['input_digest']='sha256:'+'a'*64
        def normalizer(*args):
            called.append(1);return {'blocking':False,'contradictions':[]}
        with self.assertRaises(r2.R2Error):
            checked_normalize(b,p,{},normalizer,r1.digest({}))
        self.assertEqual(called,[])

    def test_18_checked_normalizer_rejects_contradiction(self):
        b,p=fixture()
        def norm(*args):
            return {'blocking': True,'contradictions':[{'code':'RC.FAIL'}]}
        with self.assertRaisesRegex(r2.R2Error,'blocked'):
            checked_normalize(b,p,{},norm,r1.digest({}))

    def test_19_checked_normalizer_rejects_wrong_digest(self):
        b,p=fixture()
        def norm(*args):
            return {'blocking':False,'contradictions':[], 'contract_bindings':{'evidence_identity_policy':{'valid':True},'gate_input_materialization':[{'verified':True,'gate_id':'gate.1','input_digest':'sha256:'+'0'*64}]}}
        with self.assertRaisesRegex(r2.R2Error,'preflight-mismatch'):
            checked_normalize(b,p,{},norm,r1.digest({}))

    def test_20_checked_normalizer_accepts_bounded_audit(self):
        b,p=fixture()
        def norm(*args):
            payload = {'blocking': False, 'contradictions': [], 'contract_bindings': {
                'evidence_identity_policy': {'valid': True},
                'gate_input_materialization': [{'verified': True,'gate_id':'gate.1','input_digest':p['input_digest']}],
            }}
            payload['output_digest'] = r1.digest(payload)
            return payload
        result=checked_normalize(b,p,{},norm,r1.digest({}))
        self.assertEqual(result['status'],'AUDIT_CONTRACT_CHECKS_PASSED')
        self.assertEqual(result['scientific_truth'],'NOT_ESTABLISHED')

    def test_21_gate_result_or_metadata_forgery_blocked(self):
        b,p=fixture()
        b["gate_reports"][0]["evaluator_revision"]="unreviewed-change"
        with self.assertRaisesRegex(r2.R2Error,"trusted-report-digest-mismatch"):
            r2.verify_bundle_r2(b,p)

    def test_22_identity_policy_pin_rejects_mutation(self):
        b,p=fixture();calls=[]
        def norm(*args):
            calls.append(True)
            return {}
        with self.assertRaisesRegex(r2.R2Error,"identity-policy-not-pinned"):
            checked_normalize(b,p,{"policy":"changed"},norm,r1.digest({}))
        self.assertEqual(calls,[])

    def test_23_normalizer_forged_digest_is_rejected(self):
        b,p=fixture()
        def norm(*args):
            return {"blocking":False,"contradictions":[],"output_digest":"sha256:"+"0"*64,
                    "contract_bindings":{"evidence_identity_policy":{"valid":True},
                    "gate_input_materialization":[{"verified":True,"gate_id":"gate.1","input_digest":p["input_digest"]}]}}
        with self.assertRaisesRegex(r2.R2Error,"output-digest-mismatch"):
            checked_normalize(b,p,{},norm,r1.digest({}))

    def test_24_mutation_sweep(self):
        rng=random.Random(20261015)
        total=0
        for i in range(200):
            b,p=fixture()
            choice=rng.randrange(4)
            if choice==0:
                b['evidence_attestations'][rng.randrange(4)]['payload']['value']=i+999
                bypass_gate_input_only(b)
            elif choice==1:
                b['gate_reports'][0]['result']='FAIL'
            elif choice==2:
                b['evidence_attestations'].pop()
                b['gate_input_profiles'][0]['inputs']=[x for x in b['gate_input_profiles'][0]['inputs'] if x['id']!='ev.optional']
                bypass_gate_input_only(b)
            else:
                b['gate_input_profiles'][0]['inputs'].reverse()
                # Rebind all docs ordered according to modified profile
                ix={(d['schema_name'],d[next(k for k in ('model_id','run_id','evidence_id','claim_id') if k in d)]):d for d in [b['model_spec'],b['run_plan'],*b['evidence_attestations'],b['claim_card']]}
                docs=[ix[(x['kind'],x['id'])] for x in b['gate_input_profiles'][0]['inputs']]
                b['gate_reports'][0].update(gate_input.binding(b['gate_input_profiles'][0],docs))
            with self.assertRaises(r2.R2Error):
                r2.verify_bundle_r2(b,p)
            total+=1
        self.assertEqual(total,200)

if __name__=='__main__':
    unittest.main()
