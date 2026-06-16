# M365 Security Operations MCP

Standalone MCP server for Microsoft 365 security and compliance tools.

This folder is repository-ready and can be moved directly into its own Git repository.

## Setup

1. Create local environment variables:

```bash
cp .env.example .env
```

2. Install dependencies with uv:

```bash
uv sync
```

Alternative with pip:

```bash
pip install -r requirements.txt
```

3. Configure environment variables in `.env`:

```env
client_id=your-application-client-id-here
tenant_id=your-directory-tenant-id-here
```

## Graph Permission Matrix

Configured scopes are defined in `modules/graph_client.py`.

| Scope | Tool coverage |
| --- | --- |
| `AuditLog.Read.All` | `get_sign_in_logs`, `get_audit_logs`, `get_user_audit_events` |
| `ThreatHunting.Read.All` | `run_hunting_query`, `get_url_click_events`, `get_anti_phishing_policies`, `get_quarantine_release_status`, `get_email_events_enriched` |
| `SecurityAlert.Read.All` | `get_security_alerts`, `get_alert_by_id` |
| `IdentityRiskyUser.Read.All` | `get_risky_users` |
| `DeviceManagementManagedDevices.Read.All` | `get_managed_devices` |
| `Policy.Read.All` | `get_conditional_access_policies`, `get_named_locations` |
| `Group.Read.All` | `get_group_by_id`, `get_entra_groups` |
| `User.Read`, `User.Read.All` | `get_user_authentication_methods`, `get_user_devices` |
| `UserAuthenticationMethod.Read.All` | `get_user_authentication_methods` |
| `Device.Read.All` | `get_user_devices` |

`get_attack_simulator_simulations` uses the Security attack simulation endpoint and is covered by `SecurityAlert.Read.All` and broader Microsoft 365 Defender security permissions already requested.

## Run

```bash
uv run python main.py
```

Optional HTTP mode:

```bash
uv run python main.py --transport http --port 8002
```

## Claude/Copilot Integration

See `CLAUDE_SETUP.md` in this folder for standalone MCP configuration examples.

## Standalone Repo Contents

- `main.py` - MCP server entrypoint
- `modules/` - Security assistant and Graph client modules
- `pyproject.toml` - Project metadata and dependencies
- `uv.lock` - Locked dependency graph for reproducible installs
- `.env.example` - Environment template
- `.gitignore` - Local repo ignores
