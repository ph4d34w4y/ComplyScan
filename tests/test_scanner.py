import json
import os
import tempfile
import unittest
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import complyscan as s


class ScannerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def file(self, name, content):
        path = Path(self.tmp.name) / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content)
        return str(path)

    def scan(self, path):
        return s.scan_file(path, set(s.FRAMEWORKS))[0]

    def test_tls_semantics_and_nested_json(self):
        p = self.file('safe.conf', 'verify_ssl=true\ninsecure_skip_verify=false\n')
        self.assertFalse(any(f.check_id == 'CFG-TLS-VERIFY-OFF' for f in self.scan(p)))
        p = self.file('bad.json', json.dumps({'server': {'tls': {'verify_ssl': False}}}))
        self.assertTrue(any(f.check_id == 'CFG-TLS-VERIFY-OFF' for f in self.scan(p)))
        p = self.file('bad.conf', 'insecure_skip_verify=true\n')
        self.assertTrue(any(f.check_id == 'CFG-TLS-VERIFY-OFF' for f in self.scan(p)))

    def test_time_window_and_fallback(self):
        spaced = '\n'.join(f'2026-09-28T12:{i*10:02}:00 failed password for alice from 10.0.0.1' for i in range(5))
        self.assertFalse(any(f.check_id == 'LOG-BRUTEFORCE' for f in self.scan(self.file('spaced.log', spaced))))
        burst = '\n'.join(f'2026-09-28T12:00:{i:02} failed password for alice from 10.0.0.1' for i in range(5))
        fs = self.scan(self.file('burst.log', burst))
        self.assertTrue(any(f.check_id == 'LOG-BRUTEFORCE' and f.confidence == 'high' for f in fs))
        untimed = self.scan(self.file('untimed.log', ('failed password for alice\n') * 5))
        self.assertTrue(any(f.check_id == 'LOG-BRUTEFORCE' and f.confidence == 'low' for f in untimed))

    def test_privilege_changes_and_masking(self):
        fs = self.scan(self.file('audit.log', 'useradd bob\nsudo: bob NOT in sudoers; password=SuperSecret123\n'))
        self.assertIn('LOG-PRIV-CHANGE', {f.check_id for f in fs})
        self.assertIn('LOG-PRIV-FAIL', {f.check_id for f in fs})
        self.assertNotIn('LOG-PRIV-ESC', {f.check_id for f in fs})
        self.assertNotIn('SuperSecret123', json.dumps([f.__dict__ for f in fs]))

    def test_baseline_path_and_expiry(self):
        a = s.Finding('CFG-DEBUG', 'prod/config.yml', 'line 1', 'debug=true')
        b = s.Finding('CFG-DEBUG', 'dev/config.yml', 'line 1', 'debug=true')
        self.assertNotEqual(s.fingerprint(a), s.fingerprint(b))
        old = {s.legacy_fingerprint(a): {'fingerprint': s.legacy_fingerprint(a)}}
        self.assertEqual(len(s.split_by_baseline([a], old)[1]), 1)
        expired = {s.fingerprint(a): {'expires': '2020-01-01T00:00:00Z'}}
        self.assertEqual(len(s.split_by_baseline([a], expired)[0]), 1)

    def test_coverage_and_luhn(self):
        p = self.file('cards.txt', '4111 1111 1111 1111\n4111 1111 1111 1112\n')
        fs, meta = s.scan_file(p, set(s.FRAMEWORKS))
        self.assertEqual(meta['status'], 'fully_scanned')
        self.assertEqual(len([f for f in fs if f.check_id == 'DATA-PAN']), 1)
        self.assertNotIn('4111 1111 1111 1111', s.render_report(fs, {p: meta}, ['pci-dss'], [p]))

    def test_structured_config_formats_and_fallback(self):
        files = {
            'service.json': '{"security":{"verify_ssl":false,"mfa_enabled":false,"debug":true}}',
            'service.toml': '[security]\nverify_ssl = false\nmfa_enabled = false\ndebug = true\n',
            'service.ini': '[security]\nverify_ssl = false\nmfa_enabled = false\ndebug = true\n',
            '.env': 'VERIFY_SSL=false\nMFA_ENABLED=false\nDEBUG=true\n',
        }
        for name, body in files.items():
            with self.subTest(name=name):
                p = self.file(name, body)
                fs, meta = s.scan_file(p, set(s.FRAMEWORKS))
                self.assertEqual(meta['config_parser'], 'structured')
                self.assertTrue({'CFG-TLS-VERIFY-OFF', 'CFG-MFA-OFF', 'CFG-DEBUG'} <= {f.check_id for f in fs})
        try:
            import yaml
        except ImportError:
            pass
        else:
            p = self.file('service.yaml', 'security:\n  verify_ssl: false\n  mfa_enabled: false\n')
            self.assertIn('CFG-TLS-VERIFY-OFF', {f.check_id for f in self.scan(p)})
        p = self.file('bad.json', '{invalid json\nverify_ssl=false\n')
        fs, meta = s.scan_file(p, set(s.FRAMEWORKS))
        self.assertEqual(meta['config_parser'], 'line_fallback')
        self.assertIn('CFG-TLS-VERIFY-OFF', {f.check_id for f in fs})

    def test_accumulator_caps_distinct_evidence_and_reports_omission(self):
        acc = s.FindingAccumulator({'pci-dss'}, limit=2)
        for n in range(100):
            acc.append(s.Finding('CFG-DEBUG', 'test.conf', f'line {n}', f'debug=true # {n}'))
        result = acc.finish('test.conf')
        self.assertEqual(len(result), 3)
        self.assertEqual(result[-1].count, 98)
        self.assertEqual(sum(f.count for f in result), 100)

    def test_mapping_provenance_explicit(self):
        reviewed = s.mapping_metadata('DATA-PAN', 'nist-csf', 'PR.DS-01')
        self.assertEqual(reviewed['review_status'], 'source_reviewed')
        self.assertEqual(reviewed['mapping_type'], 'supporting')
        self.assertFalse(reviewed['independently_verified'])
        unreviewed = s.mapping_metadata('DATA-PAN', 'pci-dss', 'Req 3.4.1')
        self.assertEqual(unreviewed['review_status'], 'unreviewed')
        self.assertIsNone(unreviewed['reviewed_on'])

    def test_scan_wide_cap(self):
        store = s.ScanFindingStore(limit=2)
        store.extend(s.Finding('CFG-DEBUG', f'f{i}.conf', 'line 1', 'debug=true') for i in range(20))
        result = store.finish()
        self.assertEqual(len(result), 3)
        self.assertEqual(result[-1].count, 18)
        self.assertEqual(result[-1].file, '(scan-wide)')


if __name__ == '__main__':
    unittest.main()
