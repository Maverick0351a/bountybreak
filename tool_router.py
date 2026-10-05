"""Local capability registry and deterministic router for existing security tools.

ScopeRook never executes a registered tool.  It records how a separate agent or
human can reach an installed capability, then recommends the smallest suitable
handoff for the current workflow phase.  Target-facing handoffs always retain a
separate preflight gate even when the engagement intake is complete.
"""

from __future__ import annotations

from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
from typing import Any
import uuid

from workbench import intake_gate


TOOL_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,63}$")
PHASES = {
    "policy", "research", "source_review", "surface_mapping", "traffic_capture",
    "candidate_validation", "synthetic_validation", "evidence", "remediation",
    "patch_validation", "reporting",
}
OPERATION_CLASSES = {"offline", "passive_capture", "active_low_volume", "active_scan"}
INTERFACES = {"human_ui", "local_cli", "mcp_server", "local_service"}
OUTPUT_FORMATS = {"har", "json", "sarif", "text", "manual_evidence", "pcap", "html"}
MAX_TOOLS = 100


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _text(value: Any, label: str, maximum: int, *, optional: bool = False) -> str:
    if value is None and optional:
        return ""
    if not isinstance(value, str):
        raise ValueError(f"{label} must be text")
    value = value.strip()
    if (not optional and not value) or len(value) > maximum or not value.isprintable():
        qualifier = "optional printable text" if optional else "printable text"
        raise ValueError(f"{label} must be {qualifier} up to {maximum} characters")
    return value


def _choice_list(value: Any, label: str, choices: set[str], maximum: int = 20) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > maximum:
        raise ValueError(f"{label} must be a non-empty list of at most {maximum} values")
    result: list[str] = []
    for item in value:
        if item not in choices:
            raise ValueError(f"Unsupported {label} value: {item}")
        if item not in result:
            result.append(item)
    return result


def _text_list(value: Any, label: str, maximum: int = 20) -> list[str]:
    if not isinstance(value, list) or not value or len(value) > maximum:
        raise ValueError(f"{label} must be a non-empty list of at most {maximum} values")
    result = []
    for item in value:
        cleaned = _text(item, label, 80)
        if cleaned not in result:
            result.append(cleaned)
    return result


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


class ToolRegistry:
    """Store local tool references without launching or probing the tool itself."""

    def __init__(self, data_dir: Path):
        self.path = data_dir.resolve() / "tool-registry.json"

    def _load(self) -> dict:
        if not self.path.exists():
            return {"schema_version": 1, "tools": []}
        try:
            value = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError("Local tool registry is unreadable") from exc
        if not isinstance(value, dict) or value.get("schema_version") != 1:
            raise ValueError("Unsupported local tool registry schema")
        tools = value.get("tools")
        if not isinstance(tools, list) or len(tools) > MAX_TOOLS:
            raise ValueError("Local tool registry has an invalid tool list")
        return value

    @staticmethod
    def _availability(record: dict) -> dict:
        path = record.get("local_path", "")
        if path:
            candidate = Path(path)
            exists = candidate.exists()
            return {
                "available": exists,
                "verification": "local path exists" if exists else "local path is missing",
                "path_kind": "directory" if exists and candidate.is_dir() else (
                    "file" if exists and candidate.is_file() else None),
            }
        if record["interface"] == "mcp_server":
            return {
                "available": bool(record.get("mcp_server")),
                "verification": "registry declaration only; client registration is not probed",
                "path_kind": None,
            }
        return {
            "available": record.get("declared_available", False),
            "verification": "registry declaration only",
            "path_kind": None,
        }

    def register(self, values: dict) -> dict:
        tool_id = _text(values.get("tool_id"), "tool_id", 64)
        if not TOOL_ID.fullmatch(tool_id):
            raise ValueError("tool_id must use lowercase letters, digits, and hyphens")
        interface = values.get("interface")
        if interface not in INTERFACES:
            raise ValueError("Unsupported interface")
        local_path = _text(values.get("local_path"), "local_path", 500, optional=True)
        if local_path and not Path(local_path).is_absolute():
            raise ValueError("local_path must be absolute")
        mcp_server = _text(values.get("mcp_server"), "mcp_server", 100, optional=True)
        mcp_tools = values.get("mcp_tools", [])
        if not isinstance(mcp_tools, list) or len(mcp_tools) > 30:
            raise ValueError("mcp_tools must be a list of at most 30 names")
        mcp_tools = [_text(item, "mcp tool name", 120) for item in mcp_tools]
        if interface == "mcp_server" and not mcp_server:
            raise ValueError("mcp_server is required for an MCP interface")
        declared = values.get("declared_available", False)
        if type(declared) is not bool:
            raise ValueError("declared_available must be true or false")
        record = {
            "id": tool_id,
            "display_name": _text(values.get("display_name"), "display_name", 100),
            "version": _text(values.get("version"), "version", 80, optional=True),
            "interface": interface,
            "phases": _choice_list(values.get("phases"), "phases", PHASES),
            "capabilities": _text_list(values.get("capabilities"), "capabilities"),
            "operation_classes": _choice_list(
                values.get("operation_classes"), "operation_classes", OPERATION_CLASSES),
            "output_formats": _choice_list(values.get("output_formats"), "output_formats", OUTPUT_FORMATS),
            "local_path": local_path,
            "mcp_server": mcp_server,
            "mcp_tools": mcp_tools,
            "declared_available": declared,
            "constraints": _text(values.get("constraints"), "constraints", 1_000),
            "notes": _text(values.get("notes"), "notes", 1_000, optional=True),
            "verified_at": _now(),
        }
        registry = self._load()
        tools = registry["tools"]
        previous = next((item for item in tools if item.get("id") == tool_id), None)
        if previous:
            tools[tools.index(previous)] = record
        else:
            if len(tools) >= MAX_TOOLS:
                raise ValueError("Local tool registry limit reached")
            tools.append(record)
        tools.sort(key=lambda item: item["id"])
        registry["updated_at"] = _now()
        _atomic_json(self.path, registry)
        return {**record, **self._availability(record)}

    def list(self) -> dict:
        registry = self._load()
        tools = [{**record, **self._availability(record)} for record in registry["tools"]]
        return {
            "tools": tools,
            "registry_path": str(self.path),
            "execution_boundary": (
                "Registry entries are local handoff references. ScopeRook does not launch them, infer "
                "authorization, or send target traffic."
            ),
        }

    def route(self, *, phase: str, required_capabilities: list[str], operation_class: str,
              engagement: dict | None = None, plan_id: str = "") -> dict:
        if phase not in PHASES:
            raise ValueError("Unsupported phase")
        if operation_class not in OPERATION_CLASSES:
            raise ValueError("Unsupported operation_class")
        needs = _text_list(required_capabilities, "required_capabilities", maximum=10)
        plan = None
        if plan_id:
            if not engagement:
                raise ValueError("plan_id requires engagement_id")
            plan = next((item for item in engagement.get("plans", []) if item.get("id") == plan_id), None)
            if plan is None:
                raise ValueError("Plan not found")

        candidates = []
        for record in self._load()["tools"]:
            availability = self._availability(record)
            if not availability["available"] or phase not in record["phases"]:
                continue
            if operation_class not in record["operation_classes"]:
                continue
            matched = [need for need in needs if need.casefold() in {item.casefold() for item in record["capabilities"]}]
            if len(matched) != len(needs):
                continue
            handoff: dict[str, Any] = {"interface": record["interface"]}
            if record.get("local_path"):
                handoff["local_path"] = record["local_path"]
            if record.get("mcp_server"):
                handoff["mcp_server"] = record["mcp_server"]
                handoff["mcp_tools"] = record.get("mcp_tools", [])
            candidates.append({
                "tool_id": record["id"], "display_name": record["display_name"],
                "version": record.get("version"), "matched_capabilities": matched,
                "operation_class": operation_class, "output_formats": record["output_formats"],
                "constraints": record["constraints"], "handoff": handoff,
            })
        candidates.sort(key=lambda item: (len(item["handoff"].get("mcp_tools", [])) == 0,
                                           item["display_name"].casefold()))

        active = operation_class != "offline"
        gate = intake_gate(engagement) if engagement else None
        execution_ready = not active
        blockers = []
        if active:
            if engagement is None:
                blockers.append("Select an engagement before any target-facing handoff")
            elif not gate["complete"]:
                blockers.append("Complete the current program intake")
            blockers.append(
                "A separate executor preflight must bind the exact asset, permitted activity, numeric limits, "
                "identity, redirects, deadline, and stop conditions"
            )
        context = None
        if engagement:
            context = {
                "engagement_id": engagement["id"],
                "exact_assets": [entry.get("value") for entry in engagement.get("assets", [])],
                "scope_gate": gate,
                "plan_id": plan_id or None,
                "stop_conditions": plan.get("stop_conditions") if plan else None,
            }
        return {
            "phase": phase,
            "required_capabilities": needs,
            "operation_class": operation_class,
            "selected": candidates[0] if candidates else None,
            "alternatives": candidates[1:5],
            "context": context,
            "execution_ready": execution_ready,
            "blockers": blockers,
            "next_action": (
                "Use the selected offline tool through its recorded interface and import only sanitized output"
                if candidates and execution_ready else (
                    "Build and approve the separate executor preflight before using the selected target-facing tool"
                    if candidates else "Register an installed tool that provides every required capability"
                )
            ),
            "boundary": "This is a recommendation and handoff record, not a tool invocation or authorization grant",
        }
