"""Manifest-only runner for bundled synthetic labs inside an isolated WSL process.

The MCP caller selects a reviewed lab id. It cannot supply code, a path, a
command, an environment variable, or a network destination. Every run executes
all declared candidate and negative-control cases and stores bounded evidence.
"""

from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import shutil
import subprocess
from typing import Any
import uuid


ID_RE = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
SHA256_RE = re.compile(r"^[a-f0-9]{64}$")
TAG_RE = re.compile(r"^SCOPEROOK_(EXIT|STDOUT_B64|STDERR_B64)=(.*)$")
MAX_CAPTURE_BYTES = 65_536
MAX_MANIFEST_BYTES = 65_536
REQUIRED_BINARIES = (
    "/usr/bin/unshare",
    "/usr/bin/setpriv",
    "/usr/bin/prlimit",
    "/usr/bin/timeout",
    "/usr/bin/python3",
    "/usr/bin/base64",
)


class SandboxError(ValueError):
    """A bounded, user-readable synthetic-lab error."""


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(128 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _atomic_json(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        with temp.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(value, stream, ensure_ascii=False, indent=2)
            stream.write("\n")
        os.replace(temp, path)
    finally:
        temp.unlink(missing_ok=True)


def _bounded_text(value: Any, label: str, maximum: int, *, empty: bool = False) -> str:
    if not isinstance(value, str):
        raise SandboxError(f"{label} must be text")
    if (not empty and not value) or len(value) > maximum or not value.isprintable():
        raise SandboxError(f"{label} must be printable text up to {maximum} characters")
    return value


def _windows_to_wsl(path: Path) -> str:
    resolved = str(path.resolve())
    match = re.fullmatch(r"([A-Za-z]):\\(.*)", resolved)
    if not match:
        raise SandboxError("The WSL backend requires an absolute Windows drive path")
    drive, remainder = match.groups()
    return f"/mnt/{drive.lower()}/{remainder.replace(chr(92), '/')}"


class LabRunner:
    """Validate and run only reviewed labs found under ``labs_root``."""

    def __init__(self, labs_root: Path, data_dir: Path, distro: str = ""):
        self.labs_root = labs_root.resolve()
        self.data_dir = data_dir.resolve()
        self.distro = distro.strip()
        self.wsl = shutil.which("wsl.exe") or shutil.which("wsl")
        self.helper = (Path(__file__).resolve().parent / "sandbox" / "wsl_python_sandbox.sh").resolve()

    def _lab_directory(self, lab_id: Any) -> Path:
        ident = _bounded_text(lab_id, "lab_id", 64)
        if not ID_RE.fullmatch(ident):
            raise SandboxError("lab_id must use lowercase letters, digits, and hyphens")
        path = (self.labs_root / ident).resolve()
        if path.parent != self.labs_root or not path.is_dir() or path.is_symlink():
            raise SandboxError("Synthetic lab not found")
        return path

    def _load_manifest(self, lab_id: Any) -> tuple[dict, Path, str]:
        directory = self._lab_directory(lab_id)
        path = directory / "lab.json"
        if not path.is_file() or path.is_symlink():
            raise SandboxError("Synthetic lab manifest not found")
        raw = path.read_bytes()
        if len(raw) > MAX_MANIFEST_BYTES:
            raise SandboxError("Synthetic lab manifest is too large")
        try:
            manifest = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise SandboxError("Synthetic lab manifest is invalid JSON") from exc
        if not isinstance(manifest, dict) or manifest.get("schema_version") != 1:
            raise SandboxError("Synthetic lab manifest schema_version must be 1")
        if manifest.get("id") != directory.name:
            raise SandboxError("Synthetic lab manifest id does not match its directory")
        _bounded_text(manifest.get("title"), "title", 160)
        _bounded_text(manifest.get("purpose"), "purpose", 500)
        if manifest.get("runtime") != "python3":
            raise SandboxError("Only the reviewed python3 runtime is supported")

        entrypoint = _bounded_text(manifest.get("entrypoint"), "entrypoint", 120)
        posix = PurePosixPath(entrypoint)
        if (posix.is_absolute() or "\\" in entrypoint or not posix.parts
                or any(part in ("", ".", "..") for part in posix.parts)):
            raise SandboxError("entrypoint must be a safe relative path")
        entry_path = (directory / Path(*posix.parts)).resolve()
        try:
            entry_path.relative_to(directory)
        except ValueError as exc:
            raise SandboxError("entrypoint escapes the lab directory") from exc
        if not entry_path.is_file() or entry_path.is_symlink():
            raise SandboxError("entrypoint must be a regular file inside the lab")
        recorded_hash = manifest.get("entrypoint_sha256")
        if not isinstance(recorded_hash, str) or not SHA256_RE.fullmatch(recorded_hash):
            raise SandboxError("entrypoint_sha256 must be a lowercase SHA-256 digest")
        actual_hash = _sha256_file(entry_path)
        if actual_hash != recorded_hash:
            raise SandboxError("entrypoint hash does not match the reviewed manifest")

        limits = manifest.get("limits")
        if not isinstance(limits, dict) or set(limits) != {"timeout_seconds", "cpu_seconds", "memory_mib"}:
            raise SandboxError("limits must contain timeout_seconds, cpu_seconds, and memory_mib")
        for name, low, high in (("timeout_seconds", 1, 10), ("cpu_seconds", 1, 10),
                                ("memory_mib", 64, 512)):
            value = limits.get(name)
            if type(value) is not int or not low <= value <= high:
                raise SandboxError(f"{name} must be an integer from {low} to {high}")

        cases = manifest.get("cases")
        if not isinstance(cases, list) or not 2 <= len(cases) <= 12:
            raise SandboxError("cases must contain 2 to 12 bounded cases")
        case_ids: set[str] = set()
        roles: set[str] = set()
        for index, case in enumerate(cases):
            if not isinstance(case, dict):
                raise SandboxError(f"case {index + 1} must be an object")
            allowed = {"id", "role", "args", "expected_exit_code", "stdout_contains", "stdout_not_contains"}
            if set(case) != allowed:
                raise SandboxError(f"case {index + 1} has unexpected or missing fields")
            case_id = _bounded_text(case.get("id"), f"case {index + 1} id", 64)
            if not ID_RE.fullmatch(case_id) or case_id in case_ids:
                raise SandboxError("case ids must be unique lowercase identifiers")
            case_ids.add(case_id)
            role = case.get("role")
            if role not in ("candidate", "negative_control"):
                raise SandboxError("case role must be candidate or negative_control")
            roles.add(role)
            args = case.get("args")
            if not isinstance(args, list) or len(args) > 20:
                raise SandboxError("case args must be a list with at most 20 values")
            for argument in args:
                _bounded_text(argument, "case argument", 200, empty=True)
            exit_code = case.get("expected_exit_code")
            if type(exit_code) is not int or not 0 <= exit_code <= 255:
                raise SandboxError("expected_exit_code must be an integer from 0 to 255")
            for field in ("stdout_contains", "stdout_not_contains"):
                needles = case.get(field)
                if not isinstance(needles, list) or len(needles) > 20:
                    raise SandboxError(f"{field} must be a list with at most 20 values")
                for needle in needles:
                    _bounded_text(needle, field, 300)
        if roles != {"candidate", "negative_control"}:
            raise SandboxError("Every lab must include candidate and negative-control cases")
        return manifest, directory, _sha256_bytes(raw)

    def backend_status(self) -> dict:
        if not self.distro:
            return {"backend": "wsl", "configured": False, "ready": False,
                    "reason": "No WSL distribution was explicitly configured"}
        if not self.wsl:
            return {"backend": "wsl", "configured": True, "ready": False,
                    "distro": self.distro, "reason": "wsl.exe was not found"}
        if not self.helper.is_file():
            return {"backend": "wsl", "configured": True, "ready": False,
                    "distro": self.distro, "reason": "Sandbox helper is missing"}
        check = " && ".join(f"test -x {path}" for path in REQUIRED_BINARIES)
        try:
            process = subprocess.run(
                [self.wsl, "-d", self.distro, "-u", "root", "--", "/bin/sh", "-c", check],
                capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=8, check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            return {"backend": "wsl", "configured": True, "ready": False,
                    "distro": self.distro, "reason": "WSL backend check failed"}
        if process.returncode:
            return {"backend": "wsl", "configured": True, "ready": False,
                    "distro": self.distro, "reason": "Required sandbox binaries are unavailable"}
        return {
            "backend": "wsl", "configured": True, "ready": True, "distro": self.distro,
            "isolation": ["fresh network namespace", "private mount namespace and chroot",
                          "read-only reviewed lab", "uid 65534", "no capabilities", "no_new_privs",
                          "CPU, memory, process, file, output, and wall-clock limits"],
            "boundary": "Synthetic user-mode application fixtures only; not a kernel or hypervisor sandbox",
        }

    def list_labs(self) -> dict:
        labs = []
        if self.labs_root.is_dir():
            for child in sorted(self.labs_root.iterdir(), key=lambda item: item.name):
                if not child.is_dir() or child.is_symlink() or not ID_RE.fullmatch(child.name):
                    continue
                try:
                    manifest, _directory, manifest_hash = self._load_manifest(child.name)
                    labs.append({
                        "id": manifest["id"], "title": manifest["title"], "purpose": manifest["purpose"],
                        "runtime": manifest["runtime"], "case_count": len(manifest["cases"]),
                        "manifest_sha256": manifest_hash, "valid": True,
                    })
                except SandboxError as exc:
                    labs.append({"id": child.name, "valid": False, "error": str(exc)})
        return {
            "labs": labs,
            "backend": self.backend_status(),
            "interpretation": (
                "Bundled synthetic fixtures only. A passing run demonstrates behavior in that fixture, "
                "not in a bounty target. Every run includes its negative control."
            ),
        }

    @staticmethod
    def _decode_capture(encoded: str, label: str) -> str:
        try:
            raw = base64.b64decode(encoded, validate=True)
        except (ValueError, base64.binascii.Error) as exc:
            raise SandboxError(f"Sandbox returned invalid {label}") from exc
        if len(raw) > MAX_CAPTURE_BYTES:
            raise SandboxError(f"Sandbox {label} exceeded the capture limit")
        return raw.decode("utf-8", errors="replace")

    def _invoke(self, directory: Path, manifest: dict, case: dict, token: str) -> dict:
        if not self.wsl:
            raise SandboxError("wsl.exe was not found")
        limits = manifest["limits"]
        command = [
            self.wsl, "-d", self.distro, "-u", "root", "--",
            "/usr/bin/unshare", "--net", "--mount", "--pid", "--fork",
            "/bin/sh", _windows_to_wsl(self.helper), token, _windows_to_wsl(directory),
            manifest["entrypoint"], str(limits["timeout_seconds"]), str(limits["cpu_seconds"]),
            str(limits["memory_mib"] * 1024 * 1024), *case["args"],
        ]
        try:
            process = subprocess.run(
                command, capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=limits["timeout_seconds"] + 12, check=False,
            )
        except subprocess.TimeoutExpired as exc:
            subprocess.run(
                [self.wsl, "-d", self.distro, "-u", "root", "--", "/usr/bin/pkill", "-KILL", "-f",
                 f"scoperook-sandbox-{token}"],
                capture_output=True, timeout=5, check=False,
            )
            raise SandboxError("Sandbox host timeout; the isolated process was stopped") from exc
        if process.returncode:
            detail = process.stderr.strip().replace("\r", " ").replace("\n", " ")[:500]
            raise SandboxError(f"Sandbox wrapper failed{': ' + detail if detail else ''}")
        values: dict[str, str] = {}
        for line in process.stdout.splitlines():
            match = TAG_RE.fullmatch(line)
            if match:
                values[match.group(1)] = match.group(2)
        if set(values) != {"EXIT", "STDOUT_B64", "STDERR_B64"}:
            raise SandboxError("Sandbox wrapper returned an incomplete result")
        try:
            exit_code = int(values["EXIT"])
        except ValueError as exc:
            raise SandboxError("Sandbox returned an invalid exit code") from exc
        stdout = self._decode_capture(values["STDOUT_B64"], "stdout")
        stderr = self._decode_capture(values["STDERR_B64"], "stderr")
        contains = {needle: needle in stdout for needle in case["stdout_contains"]}
        absent = {needle: needle not in stdout for needle in case["stdout_not_contains"]}
        passed = exit_code == case["expected_exit_code"] and all(contains.values()) and all(absent.values())
        return {
            "id": case["id"], "role": case["role"], "passed": passed,
            "exit_code": exit_code, "expected_exit_code": case["expected_exit_code"],
            "stdout": stdout, "stderr": stderr,
            "stdout_sha256": _sha256_bytes(stdout.encode("utf-8")),
            "stderr_sha256": _sha256_bytes(stderr.encode("utf-8")),
            "checks": {"stdout_contains": contains, "stdout_not_contains": absent},
        }

    def run_lab(self, lab_id: Any) -> dict:
        manifest, directory, manifest_hash = self._load_manifest(lab_id)
        status = self.backend_status()
        if not status["ready"]:
            raise SandboxError(status["reason"])
        run_id = f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{secrets.token_hex(5)}"
        results = []
        for case in manifest["cases"]:
            results.append(self._invoke(directory, manifest, case, secrets.token_hex(16)))
        record = {
            "schema_version": 1,
            "run_id": run_id,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
            "lab_id": manifest["id"],
            "title": manifest["title"],
            "purpose": manifest["purpose"],
            "backend": status,
            "manifest_sha256": manifest_hash,
            "entrypoint_sha256": manifest["entrypoint_sha256"],
            "limits": manifest["limits"],
            "overall_passed": all(case["passed"] for case in results),
            "cases": results,
            "scope": "Result applies only to the bundled synthetic fixture; no target traffic was sent",
        }
        evidence = self.data_dir / "lab-runs" / f"{run_id}-{manifest['id']}.json"
        _atomic_json(evidence, record)
        record["evidence_path"] = str(evidence)
        return record
