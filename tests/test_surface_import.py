import json
from pathlib import Path
import tempfile
import unittest

from surface_import import get_inventory, import_surface


class SurfaceImportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name) / "engagement"
        (self.root / "evidence").mkdir(parents=True)
        self.engagement = {
            "id": "engagement", "assets": [{"value": "https://app.example.invalid"}],
        }

    def tearDown(self):
        self.temp.cleanup()

    def test_har_keeps_route_shape_and_drops_sensitive_and_off_origin_data(self):
        har = {
            "log": {"entries": [
                {
                    "request": {
                        "method": "GET",
                        "url": "https://app.example.invalid/api/users/123456?token=VERYSECRET&q=hello",
                        "headers": [{"name": "Authorization", "value": "Bearer VERYSECRET"}],
                        "cookies": [{"name": "session", "value": "VERYSECRET"}],
                        "postData": {"text": "VERYSECRET"},
                        "queryString": [{"name": "token", "value": "VERYSECRET"}],
                    },
                    "response": {"status": 200, "content": {
                        "mimeType": "application/json", "text": "VERYSECRET"}},
                },
                {
                    "request": {"method": "GET", "url": "https://third.example/VERYSECRET"},
                    "response": {"status": 200, "content": {"text": "VERYSECRET"}},
                },
            ]},
        }
        source = self.root / "evidence" / "capture.har"
        source.write_text(json.dumps(har), encoding="utf-8")
        imported = import_surface(
            self.engagement, self.root, source_reference="evidence/capture.har",
            artifact_format="har", asset="https://app.example.invalid")
        self.assertEqual(imported["route_count"], 1)
        self.assertEqual(imported["statistics"]["off_origin_or_credential_url_entries"], 1)
        saved = Path(imported["saved_to"]).read_text(encoding="utf-8")
        self.assertNotIn("VERYSECRET", saved)
        self.assertNotIn("third.example", saved)
        result = get_inventory(self.root, imported["inventory_id"])
        self.assertEqual(result["routes"][0]["path"], "/api/users/{value}")
        self.assertEqual(result["routes"][0]["query_parameters"], ["q", "token"])

    def test_openapi_keeps_schema_shape_without_examples_or_defaults(self):
        spec = {
            "openapi": "3.1.0",
            "paths": {
                "/api/admin/{id}": {
                    "parameters": [{"name": "id", "in": "path", "required": True,
                                    "schema": {"type": "string", "default": "VERYSECRET"}}],
                    "get": {
                        "operationId": "readAdmin",
                        "parameters": [{"name": "expand", "in": "query", "example": "VERYSECRET"}],
                        "responses": {"200": {"description": "VERYSECRET"}, "403": {}},
                    },
                    "post": {
                        "requestBody": {"content": {"application/json": {
                            "example": {"password": "VERYSECRET"}}}},
                        "responses": {"201": {}},
                    },
                },
            },
            "components": {"securitySchemes": {"token": {"value": "VERYSECRET"}}},
        }
        source = self.root / "evidence" / "openapi.json"
        source.write_text(json.dumps(spec), encoding="utf-8")
        imported = import_surface(
            self.engagement, self.root, source_reference="evidence/openapi.json",
            artifact_format="openapi_json", asset="https://app.example.invalid")
        self.assertEqual(imported["route_count"], 2)
        saved = Path(imported["saved_to"]).read_text(encoding="utf-8")
        self.assertNotIn("VERYSECRET", saved)
        result = get_inventory(self.root, imported["inventory_id"], query="POST", limit=10)
        self.assertEqual(result["matched_count"], 1)
        self.assertEqual(result["routes"][0]["request_content_types"], ["application/json"])

    def test_import_rejects_unrecorded_asset_and_escaping_reference(self):
        with self.assertRaisesRegex(ValueError, "exactly match"):
            import_surface(self.engagement, self.root, source_reference="evidence/no.json",
                           artifact_format="openapi_json", asset="https://other.example")
        with self.assertRaisesRegex(ValueError, "stay inside"):
            import_surface(self.engagement, self.root, source_reference="../outside.json",
                           artifact_format="openapi_json", asset="https://app.example.invalid")


if __name__ == "__main__":
    unittest.main()
