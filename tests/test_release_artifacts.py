import json
from pathlib import Path
import tempfile
import unittest

from scripts.generate_sbom import build


class ReleaseArtifactTests(unittest.TestCase):
    def test_dependency_free_spdx_sbom_is_narrow_and_versioned(self):
        document = build("0.8.3")
        self.assertEqual(document["spdxVersion"], "SPDX-2.3")
        self.assertEqual(document["dataLicense"], "CC0-1.0")
        self.assertEqual(document["documentDescribes"], ["SPDXRef-Package-BountyBreak"])
        self.assertEqual(len(document["packages"]), 1)
        package = document["packages"][0]
        self.assertEqual(package["name"], "BountyBreak")
        self.assertEqual(package["versionInfo"], "0.8.3")
        self.assertEqual(package["licenseDeclared"], "Apache-2.0")
        self.assertFalse(package["filesAnalyzed"])
        self.assertIn("standard library", package["comment"])

    def test_sbom_can_be_serialized_without_private_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "bountybreak.spdx.json"
            path.write_text(json.dumps(build("0.8.3"), indent=2), encoding="utf-8")
            text = path.read_text(encoding="utf-8")
            self.assertNotIn("C:\\\\Users", text)
            self.assertNotIn("data/", text)

    def test_invalid_version_fails_closed(self):
        with self.assertRaisesRegex(ValueError, "semantic version"):
            build("latest")


if __name__ == "__main__":
    unittest.main()
