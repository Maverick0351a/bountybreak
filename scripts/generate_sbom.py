"""Generate a minimal SPDX 2.3 JSON SBOM for the dependency-free release archive."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
from pathlib import Path
import re


VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9.-]+)?$")


def build(version: str) -> dict:
    if not VERSION.fullmatch(version):
        raise ValueError("version must be a semantic version without a leading v")
    package_id = "SPDXRef-Package-BountyBreak"
    return {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"BountyBreak-{version}",
        "documentNamespace": f"https://github.com/Maverick0351a/bountybreak/sbom/{version}",
        "creationInfo": {
            "created": datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "creators": ["Tool: BountyBreak dependency-free SBOM generator"],
        },
        "documentDescribes": [package_id],
        "packages": [{
            "name": "BountyBreak",
            "SPDXID": package_id,
            "versionInfo": version,
            "downloadLocation": f"https://github.com/Maverick0351a/bountybreak/releases/tag/v{version}",
            "filesAnalyzed": False,
            "licenseConcluded": "Apache-2.0",
            "licenseDeclared": "Apache-2.0",
            "copyrightText": "NOASSERTION",
            "supplier": "Organization: BountyBreak Project",
            "externalRefs": [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": f"pkg:github/Maverick0351a/bountybreak@v{version}",
            }],
            "comment": (
                "The distributed Python application uses only the Python 3.11+ standard library. "
                "Separately installed tools and optional MCP clients are not bundled dependencies."
            ),
        }],
        "relationships": [{
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": package_id,
        }],
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    document = build(args.version)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(document, indent=2) + "\n", encoding="utf-8")
    print(args.output)


if __name__ == "__main__":
    main()
