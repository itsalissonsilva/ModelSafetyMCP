from __future__ import annotations

import json
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import urllib.parse
import urllib.request
import zipfile
from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Iterator


RISKY_EXTENSIONS = {
    ".bin",
    ".ckpt",
    ".h5",
    ".joblib",
    ".keras",
    ".mar",
    ".pb",
    ".pickle",
    ".pkl",
    ".pt",
    ".pth",
    ".ptl",
}

ARCHIVE_EXTENSIONS = {".tar", ".gz", ".tgz", ".xz", ".zip"}
PICKLE_LIKE_EXTENSIONS = {".joblib", ".pickle", ".pkl"}
SCRIPT_LIKE_EXTENSIONS = {".bat", ".cmd", ".js", ".ps1", ".py", ".pyc", ".sh"}
MAX_ARCHIVE_MEMBERS = 250
SEVERITY_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


@dataclass
class ScanResult:
    scanner: str
    target: str
    ok: bool
    summary: str
    details: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class MaterializedTarget:
    requested_target: str
    local_path: Path
    source: str
    cleanup_dir: Path | None = None

    @property
    def display_target(self) -> str:
        return self.requested_target


def available_scanners() -> dict[str, Any]:
    return {
        "picklescan": {
            "python_module": _module_available("picklescan"),
            "cli": _command_available("picklescan"),
        },
        "modelscan": {
            "python_module": _module_available("modelscan"),
            "cli": _command_available("modelscan"),
        },
    }


def run_picklescan(path: str | None = None, url: str | None = None) -> ScanResult:
    with materialize_target(path=path, url=url) as target:
        command = _resolve_picklescan_command()
        if not command:
            return ScanResult(
                scanner="picklescan",
                target=target.display_target,
                ok=False,
                summary="picklescan is not installed or not available on PATH.",
                details=available_scanners()["picklescan"],
            )

        completed = subprocess.run(
            [*command, "-p", str(target.local_path)],
            capture_output=True,
            text=True,
            check=False,
        )
        ok = completed.returncode == 0
        summary = "picklescan completed successfully." if ok else "picklescan reported findings or failed."
        return ScanResult(
            scanner="picklescan",
            target=target.display_target,
            ok=ok,
            summary=summary,
            details={
                "returncode": completed.returncode,
                "stdout": completed.stdout.strip(),
                "stderr": completed.stderr.strip(),
                "local_path": str(target.local_path),
                "source": target.source,
            },
        )


def run_modelscan(path: str | None = None, url: str | None = None) -> ScanResult:
    with materialize_target(path=path, url=url) as target:
        command = _resolve_modelscan_command()
        if not command:
            return ScanResult(
                scanner="modelscan",
                target=target.display_target,
                ok=False,
                summary="modelscan is not installed or not available on PATH.",
                details=available_scanners()["modelscan"],
            )

        completed = subprocess.run(
            [*command, "-p", str(target.local_path), "-r", "json"],
            capture_output=True,
            text=True,
            check=False,
        )
        parsed = _extract_json_object(completed.stdout)
        ok = completed.returncode == 0
        summary = "modelscan completed successfully." if ok else "modelscan reported findings or failed."
        return ScanResult(
            scanner="modelscan",
            target=target.display_target,
            ok=ok,
            summary=summary,
            details={
                "returncode": completed.returncode,
                "stdout": parsed if parsed is not None else completed.stdout.strip(),
                "stderr": completed.stderr.strip(),
                "local_path": str(target.local_path),
                "source": target.source,
            },
        )


def deep_inspect_artifact(path: str | None = None, url: str | None = None) -> ScanResult:
    with materialize_target(path=path, url=url) as target:
        findings: list[dict[str, Any]] = []

        if target.local_path.is_file():
            _inspect_path(target.local_path, findings)
        else:
            for child in sorted(target.local_path.rglob("*")):
                if child.is_file():
                    _inspect_path(child, findings)

        highest = _highest_severity(finding["severity"] for finding in findings)
        ok = highest in {"none", "low"}
        summary = (
            "No obvious high-risk model packaging indicators were found."
            if not findings
            else f"Deep inspection found {len(findings)} issue(s); highest severity: {highest}."
        )
        return ScanResult(
            scanner="deep_model_inspect",
            target=target.display_target,
            ok=ok,
            summary=summary,
            details={
                "highest_severity": highest,
                "finding_count": len(findings),
                "findings": findings,
                "local_path": str(target.local_path),
                "source": target.source,
            },
        )


def artifact_safety_report(path: str | None = None, url: str | None = None) -> dict[str, Any]:
    with materialize_target(path=path, url=url) as target:
        report = {
            "target": target.display_target,
            "target_type": target.source,
            "local_path": str(target.local_path),
            "available_scanners": available_scanners(),
            "results": [],
        }

        deep_result = _deep_inspect_materialized(target)
        report["results"].append(deep_result.to_dict())

        scanners = available_scanners()
        if scanners["picklescan"]["python_module"] or scanners["picklescan"]["cli"]:
            report["results"].append(_run_picklescan_materialized(target).to_dict())
        if scanners["modelscan"]["python_module"] or scanners["modelscan"]["cli"]:
            report["results"].append(_run_modelscan_materialized(target).to_dict())

        normalized_findings = normalize_report_findings(report["results"])
        highest_severity = _highest_severity(finding["severity"] for finding in normalized_findings)
        report["normalized_findings"] = normalized_findings
        report["finding_count"] = len(normalized_findings)
        report["highest_severity"] = highest_severity
        report["recommended_actions"] = recommend_actions(normalized_findings)
        report["overall_ok"] = all(result["ok"] for result in report["results"]) and highest_severity in {"none", "low"}
        return report


def scan_directory(path: str) -> dict[str, Any]:
    directory = Path(path).expanduser().resolve()
    if not directory.exists():
        raise FileNotFoundError(f"Path does not exist: {directory}")
    if not directory.is_dir():
        raise ValueError(f"scan_directory expects a directory path, got: {directory}")

    file_reports: list[dict[str, Any]] = []
    for file_path in sorted(child for child in directory.rglob("*") if child.is_file()):
        try:
            report = artifact_safety_report(path=str(file_path))
            file_reports.append(report)
        except Exception as exc:  # noqa: BLE001
            file_reports.append(
                {
                    "target": str(file_path),
                    "target_type": "path",
                    "local_path": str(file_path),
                    "available_scanners": available_scanners(),
                    "results": [],
                    "normalized_findings": [
                        _normalized_finding(
                            scanner="scan_directory",
                            severity="medium",
                            category="scan_error",
                            evidence=str(exc),
                            source=str(file_path),
                        )
                    ],
                    "finding_count": 1,
                    "highest_severity": "medium",
                    "recommended_actions": [
                        "Review the file manually or rerun the scan after fixing the reported scanner error."
                    ],
                    "overall_ok": False,
                }
            )

    all_findings: list[dict[str, Any]] = []
    for report in file_reports:
        all_findings.extend(report.get("normalized_findings", []))

    highest_severity = _highest_severity(finding["severity"] for finding in all_findings)
    risky_files = [
        {
            "target": report["target"],
            "highest_severity": report.get("highest_severity", "none"),
            "finding_count": report.get("finding_count", 0),
            "overall_ok": report.get("overall_ok", False),
        }
        for report in file_reports
        if not report.get("overall_ok", False) or report.get("finding_count", 0) > 0
    ]
    risky_files.sort(key=lambda item: SEVERITY_ORDER.get(item["highest_severity"], 0), reverse=True)

    return {
        "target": str(directory),
        "target_type": "directory",
        "file_count": len(file_reports),
        "scanned_files": [report["target"] for report in file_reports],
        "highest_severity": highest_severity,
        "finding_count": len(all_findings),
        "normalized_findings": sorted(
            all_findings,
            key=lambda finding: SEVERITY_ORDER.get(finding["severity"], 0),
            reverse=True,
        ),
        "recommended_actions": recommend_actions(all_findings),
        "risky_files": risky_files,
        "reports": file_reports,
        "overall_ok": all(report.get("overall_ok", False) for report in file_reports),
    }


@contextmanager
def materialize_target(path: str | None = None, url: str | None = None) -> Iterator[MaterializedTarget]:
    requested_target = _validate_target_args(path=path, url=url)
    if path:
        local_path = Path(path).expanduser().resolve()
        if not local_path.exists():
            raise FileNotFoundError(f"Path does not exist: {local_path}")
        yield MaterializedTarget(requested_target=requested_target, local_path=local_path, source="path")
        return

    temp_dir = Path(tempfile.mkdtemp(prefix="model-safety-mcp-"))
    try:
        downloaded = _download_to_temp(url or "", temp_dir)
        yield MaterializedTarget(
            requested_target=requested_target,
            local_path=downloaded,
            source="url",
            cleanup_dir=temp_dir,
        )
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)


def normalize_report_findings(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    for result in results:
        scanner = result["scanner"]
        details = result.get("details", {})

        if scanner == "deep_model_inspect":
            for finding in details.get("findings", []):
                findings.append(
                    _normalized_finding(
                        scanner=scanner,
                        severity=finding["severity"],
                        category=finding["kind"],
                        evidence=finding["message"],
                        source=finding.get("path", result["target"]),
                    )
                )
        elif scanner == "modelscan":
            parsed = details.get("stdout") if isinstance(details.get("stdout"), dict) else None
            if parsed:
                for issue in parsed.get("issues", []):
                    findings.append(
                        _normalized_finding(
                            scanner=scanner,
                            severity=issue.get("severity", "medium").lower(),
                            category=issue.get("scanner", "modelscan_issue"),
                            evidence=issue.get("description", "modelscan reported an issue"),
                            source=issue.get("source", result["target"]),
                        )
                    )
                for error in parsed.get("errors", []):
                    findings.append(
                        _normalized_finding(
                            scanner=scanner,
                            severity="medium",
                            category=error.get("category", "modelscan_error").lower(),
                            evidence=error.get("description", "modelscan reported an error"),
                            source=error.get("source", result["target"]),
                        )
                    )
        elif scanner == "picklescan":
            summary = _parse_picklescan_summary(details.get("stdout", ""))
            if summary["dangerous_globals"] > 0 or summary["infected_files"] > 0:
                findings.append(
                    _normalized_finding(
                        scanner=scanner,
                        severity="high",
                        category="pickle_findings",
                        evidence=(
                            f"picklescan reported {summary['infected_files']} infected files and "
                            f"{summary['dangerous_globals']} dangerous globals"
                        ),
                        source=result["target"],
                    )
                )
    return sorted(findings, key=lambda finding: SEVERITY_ORDER[finding["severity"]], reverse=True)


def recommend_actions(findings: list[dict[str, Any]]) -> list[str]:
    actions: list[str] = []
    categories = {finding["category"] for finding in findings}

    if "embedded_pickle" in categories or "pickle_findings" in categories:
        actions.append("Avoid loading this artifact in a privileged Python process until the pickle content is reviewed.")
    if any("lambda" in finding["evidence"].lower() for finding in findings):
        actions.append("Inspect Keras Lambda layers and confirm their code path is expected before deserializing the model.")
    if "risky_extension" in categories:
        actions.append("Prefer safer serialization formats when possible, such as safetensors or explicit weight-only exports.")
    if not actions and findings:
        actions.append("Review the flagged artifact in an isolated environment before using it in production.")
    return actions


def _deep_inspect_materialized(target: MaterializedTarget) -> ScanResult:
    findings: list[dict[str, Any]] = []

    if target.local_path.is_file():
        _inspect_path(target.local_path, findings)
    else:
        for child in sorted(target.local_path.rglob("*")):
            if child.is_file():
                _inspect_path(child, findings)

    highest = _highest_severity(finding["severity"] for finding in findings)
    ok = highest in {"none", "low"}
    summary = (
        "No obvious high-risk model packaging indicators were found."
        if not findings
        else f"Deep inspection found {len(findings)} issue(s); highest severity: {highest}."
    )
    return ScanResult(
        scanner="deep_model_inspect",
        target=target.display_target,
        ok=ok,
        summary=summary,
        details={
            "highest_severity": highest,
            "finding_count": len(findings),
            "findings": findings,
            "local_path": str(target.local_path),
            "source": target.source,
        },
    )


def _run_picklescan_materialized(target: MaterializedTarget) -> ScanResult:
    command = _resolve_picklescan_command()
    if not command:
        return ScanResult(
            scanner="picklescan",
            target=target.display_target,
            ok=False,
            summary="picklescan is not installed or not available on PATH.",
            details=available_scanners()["picklescan"],
        )

    completed = subprocess.run(
        [*command, "-p", str(target.local_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    ok = completed.returncode == 0
    summary = "picklescan completed successfully." if ok else "picklescan reported findings or failed."
    return ScanResult(
        scanner="picklescan",
        target=target.display_target,
        ok=ok,
        summary=summary,
        details={
            "returncode": completed.returncode,
            "stdout": completed.stdout.strip(),
            "stderr": completed.stderr.strip(),
            "local_path": str(target.local_path),
            "source": target.source,
        },
    )


def _run_modelscan_materialized(target: MaterializedTarget) -> ScanResult:
    command = _resolve_modelscan_command()
    if not command:
        return ScanResult(
            scanner="modelscan",
            target=target.display_target,
            ok=False,
            summary="modelscan is not installed or not available on PATH.",
            details=available_scanners()["modelscan"],
        )

    temp_dir = Path.cwd() / ".modelscan-temp"
    temp_dir.mkdir(exist_ok=True)
    output_file = temp_dir / f"report-{next(tempfile._get_candidate_names())}.json"
    try:
        completed = subprocess.run(
            [*command, "-p", str(target.local_path), "-r", "json", "-o", str(output_file)],
            capture_output=True,
            text=True,
            check=False,
        )
        parsed = _parse_json_output(output_file.read_text(encoding="utf-8")) if output_file.exists() else None
    finally:
        output_file.unlink(missing_ok=True)
    ok = completed.returncode == 0
    summary = "modelscan completed successfully." if ok else "modelscan reported findings or failed."
    return ScanResult(
        scanner="modelscan",
        target=target.display_target,
        ok=ok,
        summary=summary,
        details={
            "returncode": completed.returncode,
            "stdout": parsed if parsed is not None else completed.stdout.strip(),
            "stderr": completed.stderr.strip(),
            "local_path": str(target.local_path),
            "source": target.source,
        },
    )


def _inspect_path(path: Path, findings: list[dict[str, Any]]) -> None:
    suffix = path.suffix.lower()

    if suffix in RISKY_EXTENSIONS:
        findings.append(
            {
                "severity": "medium",
                "kind": "risky_extension",
                "path": str(path),
                "message": f"File uses a higher-risk model extension: {suffix}",
            }
        )

    if suffix in SCRIPT_LIKE_EXTENSIONS:
        findings.append(
            {
                "severity": "medium",
                "kind": "script_shipped_with_model",
                "path": str(path),
                "message": f"Script-like file distributed with artifact: {suffix}",
            }
        )

    if _is_archive(path):
        findings.extend(_inspect_archive(path))


def _inspect_archive(path: Path) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            members_all = archive.infolist()
            members = members_all[:MAX_ARCHIVE_MEMBERS]
            if len(members_all) > MAX_ARCHIVE_MEMBERS:
                findings.append(
                    {
                        "severity": "low",
                        "kind": "archive_truncated",
                        "path": str(path),
                        "message": f"Archive inspection capped at {MAX_ARCHIVE_MEMBERS} members.",
                    }
                )
            for member in members:
                findings.extend(_inspect_archive_member(path, member.filename))
        return findings

    if tarfile.is_tarfile(path):
        with tarfile.open(path) as archive:
            members_all = archive.getmembers()
            members = members_all[:MAX_ARCHIVE_MEMBERS]
            if len(members_all) > MAX_ARCHIVE_MEMBERS:
                findings.append(
                    {
                        "severity": "low",
                        "kind": "archive_truncated",
                        "path": str(path),
                        "message": f"Archive inspection capped at {MAX_ARCHIVE_MEMBERS} members.",
                    }
                )
            for member in members:
                findings.extend(_inspect_archive_member(path, member.name))
    return findings


def _inspect_archive_member(archive_path: Path, member_name: str) -> list[dict[str, Any]]:
    findings: list[dict[str, Any]] = []
    member_path = Path(member_name)
    suffix = member_path.suffix.lower()

    if suffix in PICKLE_LIKE_EXTENSIONS:
        findings.append(
            {
                "severity": "high",
                "kind": "embedded_pickle",
                "path": str(archive_path),
                "message": f"Archive contains pickle-like member: {member_name}",
            }
        )

    if suffix in SCRIPT_LIKE_EXTENSIONS:
        findings.append(
            {
                "severity": "medium",
                "kind": "embedded_script",
                "path": str(archive_path),
                "message": f"Archive contains script-like member: {member_name}",
            }
        )

    return findings


def _is_archive(path: Path) -> bool:
    suffixes = {suffix.lower() for suffix in path.suffixes}
    if bool(suffixes & ARCHIVE_EXTENSIONS):
        return True

    return zipfile.is_zipfile(path) or tarfile.is_tarfile(path)


def _resolve_picklescan_command() -> list[str] | None:
    if _module_available("picklescan"):
        return [sys.executable, "-m", "picklescan"]
    binary = shutil.which("picklescan")
    if binary:
        return [binary]
    return None


def _resolve_modelscan_command() -> list[str] | None:
    script = _find_sibling_script("modelscan")
    if script:
        return [script]
    binary = shutil.which("modelscan")
    if binary:
        return [binary]
    return None


def _find_sibling_script(name: str) -> str | None:
    executable = Path(sys.executable).resolve()
    candidates = []
    if executable.parent.name.lower() == "scripts":
        candidates.append(executable.parent / f"{name}.exe")
        candidates.append(executable.parent / name)
    else:
        candidates.append(executable.parent / "Scripts" / f"{name}.exe")
        candidates.append(executable.parent / "Scripts" / name)

    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    return None


def _module_available(name: str) -> bool:
    try:
        __import__(name)
        return True
    except ImportError:
        return False


def _command_available(name: str) -> bool:
    return shutil.which(name) is not None


def _parse_json_output(output: str) -> Any | None:
    stripped = output.strip()
    if not stripped:
        return None
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        return None


def _extract_json_object(output: str) -> Any | None:
    stripped = output.strip()
    if not stripped:
        return None

    direct = _parse_json_output(stripped)
    if direct is not None:
        return direct

    match = re.search(r"(\{[\s\S]*\})\s*$", stripped)
    if not match:
        return None
    return _parse_json_output(match.group(1))


def _parse_picklescan_summary(output: str) -> dict[str, int]:
    return {
        "infected_files": _extract_summary_number(output, "Infected files"),
        "dangerous_globals": _extract_summary_number(output, "Dangerous globals"),
    }


def _extract_summary_number(output: str, label: str) -> int:
    match = re.search(rf"{re.escape(label)}:\s+(\d+)", output)
    return int(match.group(1)) if match else 0


def _highest_severity(severities: Any) -> str:
    highest = "none"
    for severity in severities:
        if SEVERITY_ORDER.get(severity, 0) > SEVERITY_ORDER[highest]:
            highest = severity
    return highest


def _normalized_finding(
    *,
    scanner: str,
    severity: str,
    category: str,
    evidence: str,
    source: str,
) -> dict[str, Any]:
    return {
        "scanner": scanner,
        "severity": severity,
        "category": category,
        "evidence": evidence,
        "source": source,
        "recommended_action": _recommended_action_for(category=category, evidence=evidence),
    }


def _recommended_action_for(*, category: str, evidence: str) -> str:
    if category == "embedded_pickle":
        return "Do not load this artifact in a trusted Python runtime until the embedded pickle payload is reviewed."
    if category == "risky_extension":
        return "Treat this serialization format as untrusted input and prefer a safer export format when available."
    if "lambda" in evidence.lower():
        return "Review the Lambda layer implementation and confirm it is expected before deserializing the model."
    if "dependency" in category.lower():
        return "Install the missing scanner dependency or rerun the scan in a fully provisioned environment."
    return "Review this finding in an isolated environment before using the model in production."


def _validate_target_args(*, path: str | None, url: str | None) -> str:
    provided = [value for value in (path, url) if value]
    if len(provided) != 1:
        raise ValueError("Provide exactly one of 'path' or 'url'.")
    return provided[0]


def _download_to_temp(url: str, temp_dir: Path) -> Path:
    normalized_url = _normalize_download_url(url)
    parsed = urllib.parse.urlparse(normalized_url)
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("URL scanning currently supports only http and https targets.")

    file_name = Path(parsed.path).name or "downloaded-model"
    if "." not in file_name:
        file_name = f"{file_name}.bin"
    destination = temp_dir / file_name

    request = urllib.request.Request(
        normalized_url,
        headers={"User-Agent": "model-safety-mcp/0.1.0"},
    )
    with urllib.request.urlopen(request, timeout=60) as response, destination.open("wb") as handle:
        shutil.copyfileobj(response, handle)

    if destination.stat().st_size == 0:
        raise ValueError("Downloaded artifact is empty.")
    return destination


def _normalize_download_url(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    netloc = parsed.netloc.lower()

    if netloc == "huggingface.co":
        segments = [segment for segment in parsed.path.split("/") if segment]
        if "blob" not in segments:
            return url

        blob_index = segments.index("blob")
        if blob_index < 2 or blob_index == len(segments) - 1:
            return url

        segments[blob_index] = "resolve"
        normalized_path = "/" + "/".join(segments)
        return urllib.parse.urlunparse(parsed._replace(path=normalized_path))

    if netloc == "github.com":
        segments = [segment for segment in parsed.path.split("/") if segment]
        if len(segments) < 5 or segments[2] != "blob":
            return url

        owner, repo = segments[0], segments[1]
        branch = segments[3]
        rest = "/".join(segments[4:])
        normalized_path = f"/{owner}/{repo}/{branch}/{rest}"
        return urllib.parse.urlunparse(
            parsed._replace(
                scheme="https",
                netloc="raw.githubusercontent.com",
                path=normalized_path,
                params="",
                query="",
                fragment="",
            )
        )

        return url
    
    return url
