"""
M365 Security MCP Server
Provides MCP tools for Microsoft 365 security and compliance operations.
"""

import argparse
import json
import logging

from fastmcp import FastMCP
from modules.graph_client import ConfigurationError, get_singleton_client, validate_environment
from modules import security_assistant

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger(__name__)

mcp = FastMCP("m365-security-operations-mcp")

try:
    validate_environment()
    logger.info("Security server initialized successfully")
except ConfigurationError as e:
    logger.error(f"Configuration error: {e}")
    raise


@mcp.tool()
async def get_sign_in_logs() -> str:
    """Get all Azure AD sign-in logs from the last 24 hours."""
    client = get_singleton_client()
    results = await security_assistant.get_sign_in_logs(client)
    return json.dumps(results, indent=2, default=str)


@mcp.tool()
async def run_hunting_query(query: str) -> str:
    """Run a KQL query against Microsoft Defender Advanced Threat Hunting."""
    client = get_singleton_client()
    result = await security_assistant.run_hunting_query(client, query)
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
async def get_url_click_events(user_upn: str, days: int = 7) -> str:
    """Check whether a user clicked suspicious URLs."""
    client = get_singleton_client()
    result = await security_assistant.get_url_click_events(client, user_upn=user_upn, days=days)
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
async def get_security_alerts(top: int = 50, severity: str | None = None, status: str | None = None) -> str:
    """Fetch Microsoft 365 Defender security alerts (v2 API)."""
    client = get_singleton_client()
    results = await security_assistant.get_security_alerts(client, top=top, severity=severity, status=status)
    return json.dumps(results, indent=2, default=str)


@mcp.tool()
async def get_alert_by_id(alert_id: str) -> str:
    """Fetch a specific security alert by ID with complete evidence details."""
    client = get_singleton_client()
    result = await security_assistant.get_alert_by_id(client, alert_id=alert_id)
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
async def get_risky_users(top: int = 50) -> str:
    """List users flagged by Azure AD Identity Protection as risky."""
    client = get_singleton_client()
    results = await security_assistant.get_risky_users(client, top=top)
    return json.dumps(results, indent=2, default=str)


@mcp.tool()
async def get_audit_logs(top: int = 50) -> str:
    """Get directory audit logs."""
    client = get_singleton_client()
    results = await security_assistant.get_audit_logs(client, top=top)
    return json.dumps(results, indent=2, default=str)


@mcp.tool()
async def get_user_audit_events(user_upn: str, days: int = 7) -> str:
    """Get Entra ID audit events for a specific user."""
    client = get_singleton_client()
    result = await security_assistant.get_user_audit_events(client, user_upn=user_upn, days=days)
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
async def get_managed_devices(top: int = 50) -> str:
    """List Intune managed devices."""
    client = get_singleton_client()
    results = await security_assistant.get_managed_devices(client, top=top)
    return json.dumps(results, indent=2, default=str)


@mcp.tool()
async def get_conditional_access_policies() -> str:
    """Get all Azure AD Conditional Access policies."""
    client = get_singleton_client()
    results = await security_assistant.get_conditional_access_policies(client)
    return json.dumps(results, indent=2, default=str)


@mcp.tool()
async def get_named_locations() -> str:
    """Get all Conditional Access Named Locations."""
    client = get_singleton_client()
    results = await security_assistant.get_named_locations(client)
    return json.dumps(results, indent=2, default=str)


@mcp.tool()
async def get_group_by_id(group_id: str) -> str:
    """Get a single Entra ID group by object ID."""
    client = get_singleton_client()
    result = await security_assistant.get_group_by_id(client, group_id=group_id)
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
async def get_entra_groups(top: int = 100, search: str | None = None) -> str:
    """Query Entra ID groups with an optional search filter."""
    client = get_singleton_client()
    results = await security_assistant.get_entra_groups(client, top=top, search=search)
    return json.dumps(results, indent=2, default=str)


@mcp.tool()
async def get_user_authentication_methods(user_id: str = "me") -> str:
    """Get all authentication methods configured for a user."""
    client = get_singleton_client()
    result = await security_assistant.get_user_authentication_methods(client, user_id=user_id)
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
async def get_user_devices(user_id: str = "me") -> str:
    """Get registered and enrolled devices for a user."""
    client = get_singleton_client()
    result = await security_assistant.get_user_devices(client, user_id=user_id)
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
async def get_attack_simulator_simulations(top: int = 25) -> str:
    """Get Microsoft 365 Attack Simulator simulation runs."""
    client = get_singleton_client()
    results = await security_assistant.get_attack_simulator_simulations(client, top=top)
    return json.dumps(results, indent=2, default=str)


@mcp.tool()
async def get_anti_phishing_policies(days: int = 30) -> str:
    """Surface anti-phishing and impersonation protection activity from email events."""
    client = get_singleton_client()
    result = await security_assistant.get_anti_phishing_policies(client, days=days)
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
async def get_quarantine_release_status(days: int = 7, top: int = 100, recipient: str | None = None) -> str:
    """Get quarantined email events with post-delivery release status."""
    client = get_singleton_client()
    result = await security_assistant.get_quarantine_release_status(client, days=days, top=top, recipient=recipient)
    return json.dumps(result, indent=2, default=str)


@mcp.tool()
async def get_email_events_enriched(
    days: int = 7,
    top: int = 100,
    recipient: str | None = None,
    sender: str | None = None,
    subject_contains: str | None = None,
    network_message_id: str | None = None,
) -> str:
    """Run an enriched EmailEvents Advanced Hunting query with delivery pipeline context."""
    client = get_singleton_client()
    result = await security_assistant.get_email_events_enriched(
        client,
        days=days,
        top=top,
        recipient=recipient,
        sender=sender,
        subject_contains=subject_contains,
        network_message_id=network_message_id,
    )
    return json.dumps(result, indent=2, default=str)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="M365 Security MCP Server")
    parser.add_argument(
        "--transport",
        choices=["stdio", "http"],
        default="stdio",
        help="Transport mode: stdio (default) or http",
    )
    parser.add_argument(
        "--host",
        default="0.0.0.0",
        help="Host to bind to for HTTP transport (default: 0.0.0.0)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8000,
        help="Port to bind to for HTTP transport (default: 8000)",
    )

    args = parser.parse_args()

    if args.transport == "http":
        logger.info(f"Starting security MCP server in HTTP mode on {args.host}:{args.port}")
        mcp.run(transport="http", host=args.host, port=args.port)
    else:
        logger.info("Starting security MCP server in stdio mode")
        mcp.run()
