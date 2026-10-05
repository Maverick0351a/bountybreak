"""Human-controlled backup, verification, restore, and schema migration.

This module is deliberately a local CLI rather than an MCP tool. Restores never
overwrite an existing directory, migrations create a verified rollback archive
first, and every archive carries a hash manifest.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import shutil
import stat
import tempfile
import uuid
import zipfile
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import BinaryIO

from workbench import CURRENT_ENGAGEMENT_SCHEMA, SLUG, save_json


BACKUP_FORMAT_VERSION = 1
MANIFEST_NAME = "bountybreak-backup-manifest.json"
PAYLOAD_PREFIX = "payload"
ROOT_FILES = {"tool-registry.json"}
MAX_FILES = 10_000
MAX_ENTRY_BYTES = 2 * 1024 * 1024 * 1024
MAX_ARCHIVE_BYTES = 10 * 1024 * 1024 * 1024
MAX_MANIFEST_BYTES = 5 * 1024 * 1024


class DataLifecycleError(ValueError):
    """A fail-closed data lifecycle error suitable for CLI display."""


def utc_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def sha256_stream(stream: BinaryIO) -> tuple[str, int]:
    digest = hashlib.sha256()
    size = 0
    while True:
        chunk = stream.read(1024 * 1024)
        if not chunk:
            break
        digest.update(chunk)
        size += len(chunk)
    return digest.hexdigest(), size


def _is_reparse_point(path: Path) -> bool:
    try:
        attributes = getattr(path.stat(follow_symlinks=False), "st_file_attributes", 0)
    except OSError:
        return True
    marker = getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)
    return path.is_symlink() or bool(marker and attributes & marker)


def _read_engagement(path: Path) -> tuple[dict | None, dict]:
    ident = path.parent.name
    detail = {"engagement_id": ident, "path": path.relative_to(path.parent.parent).as_posix()}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return None, {**detail, "status": "corrupt", "message": f"Unreadable JSON: {type(exc).__name__}"}
    if not isinstance(value, dict) or value.get("id") != ident:
        return None, {**detail, "status": "corrupt", "message": "Record ID does not match its directory"}
    version = value.get("schema_version")
    if version is None:
        return value, {**detail, "status": "legacy", "schema_version": 0,
                       "message": f"Migration to schema {CURRENT_ENGAGEMENT_SCHEMA} is available"}
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        return None, {**detail, "status": "corrupt", "schema_version": version,
                      "message": "Schema version must be a positive integer"}
    if version > CURRENT_ENGAGEMENT_SCHEMA:
        return None, {**detail, "status": "future", "schema_version": version,
                      "message": "This BountyBreak version cannot read the newer schema"}
    if version < CURRENT_ENGAGEMENT_SCHEMA:
        return value, {**detail, "status": "legacy", "schema_version": version,
                       "message": f"Migration to schema {CURRENT_ENGAGEMENT_SCHEMA} is available"}
    return value, {**detail, "status": "ok", "schema_version": version}


def inspect_store(data_dir: Path) -> dict:
    root = data_dir.expanduser().resolve()
    records: list[dict] = []
    issues: list[dict] = []
    if not root.exists():
        issues.append({"status": "missing", "path": ".", "message": "Data directory does not exist"})
    elif not root.is_dir():
        issues.append({"status": "invalid", "path": ".", "message": "Data path is not a directory"})
    else:
        for path in sorted(root.glob("*/engagement.json")):
            if _is_reparse_point(path) or _is_reparse_point(path.parent):
                issues.append({"status": "unsafe", "path": path.relative_to(root).as_posix(),
                               "message": "Symlinks and reparse points are not supported"})
                continue
            if not SLUG.fullmatch(path.parent.name):
                issues.append({"status": "invalid", "path": path.relative_to(root).as_posix(),
                               "message": "Engagement directory has an invalid ID"})
                continue
            _value, detail = _read_engagement(path)
            records.append(detail)
    counts = {status: sum(item.get("status") == status for item in records)
              for status in ("ok", "legacy", "corrupt", "future")}
    blocking = issues + [item for item in records if item["status"] in {"corrupt", "future"}]
    return {
        "ok": not blocking,
        "data_dir": str(root),
        "current_schema_version": CURRENT_ENGAGEMENT_SCHEMA,
        "engagement_count": len(records),
        "counts": counts,
        "needs_migration": counts["legacy"] > 0,
        "records": records,
        "issues": issues,
        "blocking_issue_count": len(blocking),
    }


def _collect_backup_files(root: Path) -> list[Path]:
    report = inspect_store(root)
    if not report["ok"]:
        raise DataLifecycleError("Store has corrupt, unsupported, or unsafe records; run doctor first")
    files: list[Path] = []
    for detail in report["records"]:
        directory = root / detail["engagement_id"]
        for path in sorted(directory.rglob("*")):
            if _is_reparse_point(path):
                raise DataLifecycleError(f"Backup refuses symlink or reparse point: {path.relative_to(root)}")
            if path.is_file():
                files.append(path)
    for name in sorted(ROOT_FILES):
        path = root / name
        if path.exists():
            if not path.is_file() or _is_reparse_point(path):
                raise DataLifecycleError(f"Backup refuses unsafe root file: {name}")
            files.append(path)
    unique = {path.relative_to(root).as_posix(): path for path in files}
    if len(unique) > MAX_FILES:
        raise DataLifecycleError(f"Backup exceeds the {MAX_FILES}-file safety limit")
    return [unique[name] for name in sorted(unique)]


def _default_backup_path(root: Path, label: str = "backup") -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return root / ".backups" / f"bountybreak-{label}-{stamp}-{uuid.uuid4().hex[:8]}.zip"


def create_backup(data_dir: Path, output: Path | None = None, label: str = "backup") -> dict:
    root = data_dir.expanduser().resolve()
    files = _collect_backup_files(root)
    destination = (output.expanduser().resolve() if output else _default_backup_path(root, label).resolve())
    try:
        within_store = destination.relative_to(root)
    except ValueError:
        within_store = None
    if within_store is not None and (not within_store.parts or within_store.parts[0] != ".backups"):
        raise DataLifecycleError("Backups inside the data directory must be stored under .backups")
    if destination.exists():
        raise DataLifecycleError("Backup destination already exists")
    destination.parent.mkdir(parents=True, exist_ok=True)
    manifest_files: list[dict] = []
    try:
        with zipfile.ZipFile(destination, "x", compression=zipfile.ZIP_DEFLATED, compresslevel=6,
                             allowZip64=True) as archive:
            for path in files:
                relative = path.relative_to(root).as_posix()
                before = path.stat()
                if before.st_size > MAX_ENTRY_BYTES:
                    raise DataLifecycleError(f"Backup file exceeds the per-file safety limit: {relative}")
                info = zipfile.ZipInfo(f"{PAYLOAD_PREFIX}/{relative}")
                info.compress_type = zipfile.ZIP_DEFLATED
                info.external_attr = (stat.S_IFREG | 0o600) << 16
                digest = hashlib.sha256()
                size = 0
                with path.open("rb") as source, archive.open(info, "w", force_zip64=True) as target:
                    while True:
                        chunk = source.read(1024 * 1024)
                        if not chunk:
                            break
                        target.write(chunk)
                        digest.update(chunk)
                        size += len(chunk)
                after = path.stat()
                if (before.st_size, before.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
                    raise DataLifecycleError(f"Source changed during backup: {relative}")
                manifest_files.append({"path": relative, "size": size, "sha256": digest.hexdigest()})
            store = inspect_store(root)
            manifest = {
                "format": "bountybreak-local-backup",
                "format_version": BACKUP_FORMAT_VERSION,
                "created_at": utc_now(),
                "current_schema_version": CURRENT_ENGAGEMENT_SCHEMA,
                "engagement_count": store["engagement_count"],
                "schema_counts": store["counts"],
                "files": manifest_files,
            }
            archive.writestr(MANIFEST_NAME,
                             json.dumps(manifest, indent=2, sort_keys=True, ensure_ascii=False) + "\n")
    except Exception:
        destination.unlink(missing_ok=True)
        raise
    verified = verify_backup(destination)
    return {"ok": True, "archive": str(destination), "file_count": len(manifest_files),
            "engagement_count": verified["engagement_count"], "sha256": _hash_file(destination)}


def _safe_archive_name(name: str) -> bool:
    pure = PurePosixPath(name)
    return (not pure.is_absolute() and "\\" not in name and all(part not in {"", ".", ".."} for part in pure.parts))


def _zip_is_link(info: zipfile.ZipInfo) -> bool:
    return stat.S_IFMT(info.external_attr >> 16) == stat.S_IFLNK


def _hash_file(path: Path) -> str:
    with path.open("rb") as stream:
        return sha256_stream(stream)[0]


def verify_backup(archive_path: Path) -> dict:
    path = archive_path.expanduser().resolve()
    if not path.is_file():
        raise DataLifecycleError("Backup archive does not exist")
    try:
        with zipfile.ZipFile(path, "r") as archive:
            infos = archive.infolist()
            if len(infos) > MAX_FILES + 1:
                raise DataLifecycleError("Archive exceeds the file-count safety limit")
            names = [item.filename for item in infos]
            if len(names) != len(set(names)):
                raise DataLifecycleError("Archive contains duplicate paths")
            if any(not _safe_archive_name(item.filename) for item in infos):
                raise DataLifecycleError("Archive contains an unsafe path")
            if any(_zip_is_link(item) for item in infos):
                raise DataLifecycleError("Archive contains a symlink")
            if any(item.flag_bits & 0x1 for item in infos):
                raise DataLifecycleError("Encrypted backup archives are not supported")
            if sum(item.file_size for item in infos) > MAX_ARCHIVE_BYTES:
                raise DataLifecycleError("Archive exceeds the expanded-size safety limit")
            if MANIFEST_NAME not in names:
                raise DataLifecycleError("Archive manifest is missing")
            if archive.getinfo(MANIFEST_NAME).file_size > MAX_MANIFEST_BYTES:
                raise DataLifecycleError("Archive manifest exceeds the safety limit")
            try:
                manifest = json.loads(archive.read(MANIFEST_NAME).decode("utf-8"))
            except (UnicodeError, json.JSONDecodeError) as exc:
                raise DataLifecycleError("Archive manifest is unreadable") from exc
            if (not isinstance(manifest, dict) or manifest.get("format") != "bountybreak-local-backup"
                    or manifest.get("format_version") != BACKUP_FORMAT_VERSION
                    or not isinstance(manifest.get("files"), list)):
                raise DataLifecycleError("Archive manifest format is unsupported")
            expected_names: set[str] = {MANIFEST_NAME}
            manifest_paths: set[str] = set()
            engagement_records: list[dict] = []
            for entry in manifest["files"]:
                if (not isinstance(entry, dict) or not isinstance(entry.get("path"), str)
                        or not _safe_archive_name(entry["path"])):
                    raise DataLifecycleError("Manifest contains an unsafe file path")
                archive_name = f"{PAYLOAD_PREFIX}/{entry['path']}"
                if entry["path"] in manifest_paths:
                    raise DataLifecycleError("Manifest contains duplicate file paths")
                manifest_paths.add(entry["path"])
                expected_names.add(archive_name)
                try:
                    info = archive.getinfo(archive_name)
                except KeyError as exc:
                    raise DataLifecycleError(f"Archive payload is missing: {entry['path']}") from exc
                if info.file_size > MAX_ENTRY_BYTES or info.file_size != entry.get("size"):
                    raise DataLifecycleError(f"Archive size mismatch: {entry['path']}")
                with archive.open(info, "r") as stream:
                    digest, size = sha256_stream(stream)
                if size != entry["size"] or digest != entry.get("sha256"):
                    raise DataLifecycleError(f"Archive hash mismatch: {entry['path']}")
                relative = PurePosixPath(entry["path"])
                if len(relative.parts) == 2 and relative.name == "engagement.json":
                    try:
                        value = json.loads(archive.read(archive_name).decode("utf-8"))
                    except (UnicodeError, json.JSONDecodeError) as exc:
                        raise DataLifecycleError(f"Archived engagement is corrupt: {entry['path']}") from exc
                    ident = relative.parts[0]
                    version = value.get("schema_version") if isinstance(value, dict) else None
                    if not isinstance(value, dict) or value.get("id") != ident or not SLUG.fullmatch(ident):
                        raise DataLifecycleError(f"Archived engagement is invalid: {entry['path']}")
                    if version is not None and (not isinstance(version, int) or isinstance(version, bool)
                                                or version < 1 or version > CURRENT_ENGAGEMENT_SCHEMA):
                        raise DataLifecycleError(f"Archived engagement schema is unsupported: {entry['path']}")
                    engagement_records.append({"id": ident, "schema_version": version or 0})
            if set(names) != expected_names:
                raise DataLifecycleError("Archive contains files not declared in its manifest")
            if manifest.get("engagement_count") != len(engagement_records):
                raise DataLifecycleError("Archive engagement count does not match its manifest")
    except zipfile.BadZipFile as exc:
        raise DataLifecycleError("Backup archive is not a valid ZIP file") from exc
    return {"ok": True, "archive": str(path), "file_count": len(manifest["files"]),
            "engagement_count": len(engagement_records), "sha256": _hash_file(path),
            "schemas": sorted({item["schema_version"] for item in engagement_records})}


def restore_backup(archive_path: Path, destination: Path) -> dict:
    verified = verify_backup(archive_path)
    source_archive = archive_path.expanduser().resolve()
    target = destination.expanduser().resolve()
    if target.exists():
        raise DataLifecycleError("Restore destination must not already exist")
    target.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix=f".{target.name}.restore-", dir=target.parent))
    try:
        stable_archive = staging / ".verified-restore-source.zip"
        digest = hashlib.sha256()
        with source_archive.open("rb") as source, stable_archive.open("xb") as sink:
            while True:
                chunk = source.read(1024 * 1024)
                if not chunk:
                    break
                sink.write(chunk)
                digest.update(chunk)
        if digest.hexdigest() != verified["sha256"]:
            raise DataLifecycleError("Backup archive changed after verification")
        with zipfile.ZipFile(stable_archive, "r") as archive:
            manifest = json.loads(archive.read(MANIFEST_NAME).decode("utf-8"))
            for entry in manifest["files"]:
                relative = PurePosixPath(entry["path"])
                output = staging.joinpath(*relative.parts)
                output.parent.mkdir(parents=True, exist_ok=True)
                with (archive.open(f"{PAYLOAD_PREFIX}/{entry['path']}", "r") as source,
                      output.open("xb") as sink):
                    shutil.copyfileobj(source, sink, length=1024 * 1024)
        stable_archive.unlink()
        report = inspect_store(staging)
        if not report["ok"]:
            raise DataLifecycleError("Restored store failed validation")
        os.replace(staging, target)
    except Exception:
        shutil.rmtree(staging, ignore_errors=True)
        raise
    return {"ok": True, "archive": verified["archive"], "destination": str(target),
            "file_count": verified["file_count"], "engagement_count": report["engagement_count"],
            "needs_migration": report["needs_migration"]}


def migrate_store(data_dir: Path, backup_output: Path | None = None) -> dict:
    root = data_dir.expanduser().resolve()
    report = inspect_store(root)
    if not report["ok"]:
        raise DataLifecycleError("Migration is blocked by corrupt, unsupported, or unsafe records")
    legacy = [item for item in report["records"] if item["status"] == "legacy"]
    if not legacy:
        return {"ok": True, "data_dir": str(root), "migrated": 0, "backup": None,
                "schema_version": CURRENT_ENGAGEMENT_SCHEMA}
    backup = create_backup(root, backup_output, label="pre-migration")
    try:
        for detail in legacy:
            path = root / detail["engagement_id"] / "engagement.json"
            value = json.loads(path.read_text(encoding="utf-8"))
            value["schema_version"] = CURRENT_ENGAGEMENT_SCHEMA
            save_json(path, value)
    except Exception as exc:
        raise DataLifecycleError(f"Migration stopped; restore the rollback archive at {backup['archive']}") from exc
    after = inspect_store(root)
    if not after["ok"] or after["needs_migration"]:
        raise DataLifecycleError(f"Migration verification failed; restore the rollback archive at {backup['archive']}")
    return {"ok": True, "data_dir": str(root), "migrated": len(legacy),
            "backup": backup["archive"], "backup_sha256": backup["sha256"],
            "schema_version": CURRENT_ENGAGEMENT_SCHEMA}


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="BountyBreak local data lifecycle")
    commands = parser.add_subparsers(dest="command", required=True)
    doctor = commands.add_parser("doctor", help="Inspect records without changing them")
    doctor.add_argument("--data-dir", type=Path, default=Path("data"))
    backup = commands.add_parser("backup", help="Create and verify a local backup")
    backup.add_argument("--data-dir", type=Path, default=Path("data"))
    backup.add_argument("--output", type=Path)
    verify = commands.add_parser("verify", help="Verify a backup manifest and payload")
    verify.add_argument("--archive", type=Path, required=True)
    restore = commands.add_parser("restore", help="Restore into a new directory only")
    restore.add_argument("--archive", type=Path, required=True)
    restore.add_argument("--destination", type=Path, required=True)
    migrate = commands.add_parser("migrate", help="Backup, then migrate legacy records")
    migrate.add_argument("--data-dir", type=Path, default=Path("data"))
    migrate.add_argument("--backup-output", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        if args.command == "doctor":
            result = inspect_store(args.data_dir)
        elif args.command == "backup":
            result = create_backup(args.data_dir, args.output)
        elif args.command == "verify":
            result = verify_backup(args.archive)
        elif args.command == "restore":
            result = restore_backup(args.archive, args.destination)
        else:
            result = migrate_store(args.data_dir, args.backup_output)
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 0 if result.get("ok") else 1
    except (DataLifecycleError, OSError) as exc:
        print(json.dumps({"ok": False, "error": str(exc)}, indent=2, ensure_ascii=False))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
