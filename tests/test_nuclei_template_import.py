import json
from pathlib import Path
import tempfile
import unittest

import nuclei_template_import


class NucleiTemplateImportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "engagement"
        self.root.mkdir()
        self.engagement = {
            "id": "fixture-engagement",
            "assets": [{"value": "https://app.example.invalid"}],
        }

    def tearDown(self):
        self.temp.cleanup()

    def write_template(self, text: str, name: str = "evidence/template.yaml") -> Path:
        path = self.root / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
        return path

    def test_import_retains_metadata_and_drops_request_content(self):
        self.write_template("""id: CVE-2026-12345
info:
  name: Example Widget Authorization Check
  author: researcher,maintainer
  severity: high
  reference:
    - https://vendor.example/advisory
  classification:
    cve-id: CVE-2026-12345
    cwe-id: CWE-862
    cvss-score: 8.1
  metadata:
    verified: true
    max-request: 2
    vendor: Example
    product: Widget
  tags: cve,authorization,example
flow: http(1) && http(2)
http:
  - method: GET
    raw:
      - |
        GET /super-secret-request-marker HTTP/1.1
        Host: {{Hostname}}
    matchers:
      - type: status
        status:
          - 200
# digest: fixture-signature-value
""")
        result = nuclei_template_import.import_template(
            self.engagement, self.root,
            source_reference="evidence/template.yaml",
            asset="https://app.example.invalid",
            upstream_commit="a" * 40,
            upstream_path="http/cves/2026/CVE-2026-12345.yaml",
        )
        template = result["template"]
        self.assertEqual(template["id"], "CVE-2026-12345")
        self.assertEqual(template["classification"]["cve_ids"], ["CVE-2026-12345"])
        self.assertEqual(template["request_bound"]["declared_max_requests"], 2)
        self.assertEqual(template["request_bound"]["state"], "metadata_only_unenforced")
        self.assertTrue(template["digest"]["present"])
        self.assertFalse(result["execution"]["allowed"])
        saved = Path(result["saved_to"]).read_text(encoding="utf-8")
        self.assertNotIn("super-secret-request-marker", saved)
        self.assertNotIn('"matchers":', saved)
        restored = nuclei_template_import.get_template_intelligence(self.root, result["import_id"])
        self.assertEqual(restored["source"]["sha256"], result["source_sha256"])
        self.assertEqual(restored["source"]["license"], "MIT")
        self.assertIn("not network-verified", restored["source"]["provenance_state"])

    def test_risky_protocols_and_expansion_are_blocked_for_execution(self):
        self.write_template("""id: risky-fixture
info:
  name: Risky Fixture
  author: researcher
  severity: critical
  metadata:
    max-request: 50
  tags: fuzz,dos
flow: http(1) && code(1) && javascript(1)
http:
  - method: POST
    unsafe: true
    redirects: true
    fuzzing:
      - part: body
    payloads:
      value:
        - ignored-payload-marker
    path:
      - "{{BaseURL}}/{{interactsh-url}}"
code:
  - engine:
      - sh
    source: ignored-command-marker
javascript:
  - code: ignored-javascript-marker
""")
        result = nuclei_template_import.import_template(
            self.engagement, self.root,
            source_reference="evidence/template.yaml",
            asset="https://app.example.invalid",
            upstream_commit="b" * 40,
            upstream_path="http/risky-fixture.yaml",
        )
        risk = result["template"]["execution_risk"]
        self.assertEqual(risk["review_class"], "blocked_feature")
        self.assertEqual(risk["blocked_protocols"], ["code", "javascript"])
        self.assertIn("fuzzing", risk["flags"])
        self.assertIn("out-of-band", risk["flags"])
        self.assertIn("state-changing-method", risk["flags"])
        saved = Path(result["saved_to"]).read_text(encoding="utf-8")
        self.assertNotIn("ignored-command-marker", saved)
        self.assertNotIn("ignored-payload-marker", saved)
        self.assertNotIn("ignored-javascript-marker", saved)

    def test_fail_closed_on_path_commit_and_ambiguous_yaml(self):
        self.write_template("""id: duplicate
id: duplicate-two
info:
  name: Duplicate
  author: researcher
  severity: low
http:
  - method: GET
""")
        with self.assertRaisesRegex(ValueError, "Duplicate top-level"):
            nuclei_template_import.import_template(
                self.engagement, self.root,
                source_reference="evidence/template.yaml",
                asset="https://app.example.invalid", upstream_commit="c" * 40,
                upstream_path="http/duplicate.yaml",
            )
        with self.assertRaisesRegex(ValueError, "40-character"):
            nuclei_template_import.import_template(
                self.engagement, self.root,
                source_reference="evidence/template.yaml",
                asset="https://app.example.invalid", upstream_commit="main",
                upstream_path="http/duplicate.yaml",
            )
        with self.assertRaisesRegex(ValueError, "declared root"):
            nuclei_template_import.import_template(
                self.engagement, self.root,
                source_reference="../template.yaml",
                asset="https://app.example.invalid", upstream_commit="c" * 40,
                upstream_path="http/duplicate.yaml",
            )
        with self.assertRaisesRegex(ValueError, "declared root"):
            nuclei_template_import.import_template(
                self.engagement, self.root,
                source_reference="evidence/template.yaml",
                asset="https://app.example.invalid", upstream_commit="c" * 40,
                upstream_path="../duplicate.yaml",
            )


if __name__ == "__main__":
    unittest.main()
