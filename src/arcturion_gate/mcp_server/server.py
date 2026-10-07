"""stdio MCP server. Tools take and return references and value-free receipts only.

Errors are reduced to a stable code; exception text is never returned because
it could, in principle, contain data the model should not see.
"""
import resource
import subprocess

from mcp.server import MCPServer

from .. import config
from .service import Service
from .state import PrivateError

mcp = MCPServer("ArcturionGate", log_level="ERROR", debug=False, subscriptions=False)


def safe(call):
    try:
        return {"ok": True, "data": call()}
    except Exception as exc:
        code = getattr(exc, "code", "PRIVATE_OPERATION_FAILED")
        if not isinstance(code, str) or not code.replace("_", "").isalnum(): code = "PRIVATE_OPERATION_FAILED"
        return {"ok": False, "error": {"code": code}}


def service():
    return Service()


def open_operation(fragment):
    """Open the extension's operation page in Chrome. Only an opaque handle or a fixed route is passed."""
    extension_id = config.extension_id()
    if not extension_id: raise PrivateError("EXTENSION_NOT_CONFIGURED")
    args = ["/usr/bin/open", "-a", "Google Chrome"]
    profile = config.chrome_profile_directory()
    if profile:
        args += ["--args", "--profile-directory=" + profile]
    args.append("chrome-extension://" + extension_id + "/operation.html#" + fragment)
    subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, check=True)


def launch(result):
    if result.get("operation_handle"):
        open_operation(result["operation_handle"])
    return result


@mcp.tool()
def credential_search(query: str = "", limit: int = 50, offset: int = 0) -> dict:
    """Search safe titles/tags and currently published browser destination references. No secrets."""
    return safe(lambda: service().search(query, limit, offset))


@mcp.tool()
def credential_inspect(record_ref: str) -> dict:
    """Inspect field names, capabilities, version and lifecycle metadata; never credential values."""
    return safe(lambda: service().inspect(record_ref))


@mcp.tool()
def credential_organize(record_ref: str, expected_version: int, title: str | None = None, aliases: list[str] | None = None,
                        tags: list[str] | None = None, ownership: str | None = None, category: str | None = None) -> dict:
    """Version-checked organization. Private notes require credential_capture with kind note."""
    return safe(lambda: service().organize(record_ref, expected_version, title, aliases, tags, ownership, category))


@mcp.tool()
def credential_generate(title: str, length: int = 32, previous_record: str | None = None, synthetic: bool = False, destination_ref: str | None = None) -> dict:
    """Generate and encrypt a pending password locally; return a reference only."""
    return safe(lambda: service().generate(title, length, previous_record, synthetic, destination_ref))


@mcp.tool()
def credential_capture(title: str, target_id: str | None = None, kind: str = "password", previous_record: str | None = None, expected_version: int | None = None) -> dict:
    """Privately capture a supported existing field through the enrolled Chrome bridge."""
    return safe(lambda: launch(service().prepare_capture(title, target_id, kind, previous_record, expected_version)))


@mcp.tool()
def credential_use(record_ref: str, destination_ref: str, kind: str = "password", expected_version: int | None = None) -> dict:
    """Privately fill a bound browser destination, or inject into an approved pinned local client (kind="api")."""
    return safe(lambda: launch(service().use(record_ref, destination_ref, kind, expected_version)))


@mcp.tool()
def credential_workflow(record_ref: str | None = None, action: str = "status", expected_version: int | None = None, receipt_handle: str | None = None,
                        destination_ref: str | None = None, use_receipt_handle: str | None = None) -> dict:
    """Resume/status/reject a workflow; verification requires independent service evidence, never a fill receipt."""
    return safe(lambda: launch(service().workflow(record_ref, action, expected_version, receipt_handle, destination_ref, use_receipt_handle)))


@mcp.tool()
def credential_backup() -> dict:
    """Create an encrypted backup without exporting plaintext credentials."""
    return safe(lambda: service().backup())


@mcp.tool()
def credential_health(refresh_bridge: bool = False, synthetic_fixture: bool = False) -> dict:
    """Check encrypted store integrity and local bridge capabilities."""
    def run():
        if synthetic_fixture:
            open_operation("fixture")
        elif refresh_bridge:
            open_operation("discover")
        return service().health()
    return safe(run)


def main():
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
