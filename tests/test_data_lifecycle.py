import json
import stat
import tempfile
import unittest
import zipfile
from pathlib import Path
from unittest import mock

from data_lifecycle import (
    DataLifecycleError,
    create_backup,
    inspect_store,
    migrate_store,
    restore_backup,
    verify_backup,
)


def file_map(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in root.rglob("*")
        if path.is_file() and ".backups" not in path.parts
    }


class DataLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.data = self.root / "data"
        self.data.mkdir()

    def tearDown(self):
        self.temp.cleanup()

    def write_record(self, ident="alpha-12345678", schema=1):
        directory = self.data / ident
        directory.mkdir(parents=True)
        value = {"id": ident, "name": "Alpha", "kind": "bounty", "authority": "Current brief"}
        if schema is not None:
            value["schema_version"] = schema
        path = directory / "engagement.json"
        path.write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
        return path

    def test_backup_verify_and_restore_round_trip(self):
        self.write_record()
        evidence = self.data / "alpha-12345678" / "evidence" / "proof.txt"
        evidence.parent.mkdir()
        evidence.write_bytes(b"sanitized evidence\r\n")
        (self.data / "tool-registry.json").write_text('{"tools": []}\n', encoding="utf-8")
        (self.data / ".env").write_text("NOT_INCLUDED=1\n", encoding="utf-8")
        hidden_backup = self.data / ".backups" / "old.zip"
        hidden_backup.parent.mkdir()
        hidden_backup.write_bytes(b"old")

        archive = self.root / "backup.zip"
        created = create_backup(self.data, archive)
        verified = verify_backup(archive)
        destination = self.root / "restored"
        restored = restore_backup(archive, destination)

        self.assertTrue(created["ok"])
        self.assertEqual(verified["engagement_count"], 1)
        self.assertEqual(restored["engagement_count"], 1)
        expected = file_map(self.data)
        expected.pop(".env")
        self.assertEqual(file_map(destination), expected)
        with zipfile.ZipFile(archive) as zipped:
            self.assertNotIn("payload/.env", zipped.namelist())
            self.assertFalse(any(".backups" in name for name in zipped.namelist()))

    def test_restore_refuses_existing_destination(self):
        self.write_record()
        archive = Path(create_backup(self.data, self.root / "backup.zip")["archive"])
        destination = self.root / "existing"
        destination.mkdir()
        with self.assertRaisesRegex(DataLifecycleError, "must not already exist"):
            restore_backup(archive, destination)

    def test_backup_refuses_output_inside_engagement_data(self):
        self.write_record()
        output = self.data / "alpha-12345678" / "backup.zip"
        with self.assertRaisesRegex(DataLifecycleError, "under .backups"):
            create_backup(self.data, output)

    def test_corrupt_record_blocks_backup_and_is_preserved(self):
        path = self.data / "broken-12345678" / "engagement.json"
        path.parent.mkdir()
        path.write_text("{not json", encoding="utf-8")
        report = inspect_store(self.data)
        self.assertFalse(report["ok"])
        self.assertEqual(report["counts"]["corrupt"], 1)
        with self.assertRaisesRegex(DataLifecycleError, "run doctor"):
            create_backup(self.data, self.root / "backup.zip")
        self.assertEqual(path.read_text(encoding="utf-8"), "{not json")

    def test_future_schema_blocks_migration(self):
        self.write_record(schema=999)
        report = inspect_store(self.data)
        self.assertFalse(report["ok"])
        self.assertEqual(report["counts"]["future"], 1)
        with self.assertRaisesRegex(DataLifecycleError, "blocked"):
            migrate_store(self.data)

    def test_legacy_migration_creates_exact_rollback_archive(self):
        path = self.write_record(schema=None)
        original = path.read_bytes()
        result = migrate_store(self.data)
        migrated = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(result["migrated"], 1)
        self.assertEqual(migrated["schema_version"], 1)
        rollback = self.root / "rollback"
        restored = restore_backup(Path(result["backup"]), rollback)
        self.assertTrue(restored["needs_migration"])
        self.assertEqual((rollback / "alpha-12345678" / "engagement.json").read_bytes(), original)

    def test_archive_path_traversal_is_rejected(self):
        archive = self.root / "traversal.zip"
        with zipfile.ZipFile(archive, "w") as zipped:
            zipped.writestr("../outside.txt", "bad")
            zipped.writestr("bountybreak-backup-manifest.json", "{}")
        with self.assertRaisesRegex(DataLifecycleError, "unsafe path"):
            verify_backup(archive)

    def test_archive_symlink_is_rejected(self):
        archive = self.root / "symlink.zip"
        link = zipfile.ZipInfo("payload/alpha-12345678/link")
        link.create_system = 3
        link.external_attr = (stat.S_IFLNK | 0o777) << 16
        with zipfile.ZipFile(archive, "w") as zipped:
            zipped.writestr(link, "target")
            zipped.writestr("bountybreak-backup-manifest.json", "{}")
        with self.assertRaisesRegex(DataLifecycleError, "symlink"):
            verify_backup(archive)

    def test_tampered_payload_fails_manifest_hash(self):
        self.write_record()
        original = Path(create_backup(self.data, self.root / "original.zip")["archive"])
        tampered = self.root / "tampered.zip"
        with zipfile.ZipFile(original, "r") as source, zipfile.ZipFile(tampered, "w") as target:
            for info in source.infolist():
                content = source.read(info.filename)
                if info.filename.endswith("engagement.json"):
                    content += b" "
                target.writestr(info, content)
        with self.assertRaisesRegex(DataLifecycleError, "size mismatch|hash mismatch"):
            verify_backup(tampered)

    def test_restore_rejects_archive_replaced_after_verification(self):
        self.write_record()
        archive = Path(create_backup(self.data, self.root / "backup.zip")["archive"])
        original_verify = verify_backup

        def verify_then_replace(path):
            result = original_verify(path)
            Path(path).write_bytes(b"replacement")
            return result

        with mock.patch("data_lifecycle.verify_backup", side_effect=verify_then_replace):
            with self.assertRaisesRegex(DataLifecycleError, "changed after verification"):
                restore_backup(archive, self.root / "restored")
        self.assertFalse((self.root / "restored").exists())


if __name__ == "__main__":
    unittest.main()
