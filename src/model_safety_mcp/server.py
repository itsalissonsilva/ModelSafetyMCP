from __future__ import annotations

from mcp.server.fastmcp import FastMCP

from model_safety_mcp.scanners import (
    artifact_safety_report,
    available_scanners,
    deep_inspect_artifact,
    run_modelscan,
    run_picklescan,
    scan_directory,
)


def create_server() -> FastMCP:
    server = FastMCP(
        name="model-safety",
        instructions=(
            "Use this server to scan ML model artifacts for risky serialization, "
            "embedded pickle payloads, and suspicious packaging."
        ),
    )

    @server.tool()
    def available_scanners_tool() -> dict:
        """Show which scanner backends are installed and ready to use."""
        return available_scanners()

    @server.tool()
    def picklescan_scan(path: str | None = None, url: str | None = None) -> dict:
        """Run picklescan against a local path or downloadable URL."""
        return run_picklescan(path=path, url=url).to_dict()

    @server.tool()
    def modelscan_scan(path: str | None = None, url: str | None = None) -> dict:
        """Run modelscan against a local path or downloadable URL."""
        return run_modelscan(path=path, url=url).to_dict()

    @server.tool()
    def deep_model_inspect(path: str | None = None, url: str | None = None) -> dict:
        """Run heuristic inspection for risky file types and embedded pickle members."""
        return deep_inspect_artifact(path=path, url=url).to_dict()

    @server.tool(name="artifact_safety_report")
    def artifact_safety_report_tool(path: str | None = None, url: str | None = None) -> dict:
        """Run the broadest available model artifact safety report."""
        return artifact_safety_report(path=path, url=url)

    @server.tool()
    def scan_directory_tool(path: str) -> dict:
        """Run artifact_safety_report across every file in a directory and aggregate the findings."""
        return scan_directory(path)

    return server
