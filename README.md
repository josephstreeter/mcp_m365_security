# M365 Security Operations MCP

Standalone MCP server for Microsoft 365 security and compliance tools.

This folder is repository-ready and can be moved directly into its own Git repository.

## Setup

1. Create local environment variables:

```bash
cp .env.example .env
```

1. Install dependencies with uv:

```bash
uv sync
```

Alternative with pip:

```bash
pip install -r requirements.txt
```

1. Configure environment variables in `.env`:

```env
client_id=your-application-client-id-here
tenant_id=your-directory-tenant-id-here
```

Optional test dependencies:

```bash
uv sync --extra test
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
| `eDiscovery.Read.All` | `list_ediscovery_cases`, `get_ediscovery_case`, `list_ediscovery_case_members`, `list_ediscovery_custodians`, `list_ediscovery_searches`, `list_ediscovery_case_operations`, `get_ediscovery_operation`, `list_ediscovery_noncustodial_data_sources`, `list_ediscovery_review_sets`, `estimate_ediscovery_search_statistics` |
| `Group.Read.All` | `get_group_by_id`, `get_entra_groups` |
| `User.Read`, `User.Read.All` | `get_user_authentication_methods`, `get_user_devices` |
| `UserAuthenticationMethod.Read.All` | `get_user_authentication_methods` |
| `Device.Read.All` | `get_user_devices` |

`get_attack_simulator_simulations` uses the Security attack simulation endpoint and is covered by `SecurityAlert.Read.All` and broader Microsoft 365 Defender security permissions already requested.

Purview eDiscovery tools also require the signed-in user to hold an appropriate Microsoft Purview role such as `eDiscovery Manager` or `eDiscovery Administrator`. `estimate_ediscovery_search_statistics` submits a case operation, returns the Graph operation location, and can optionally poll the resulting operation to completion.

## Purview eDiscovery Tools

- `list_ediscovery_cases` - Inventory accessible eDiscovery cases
- `get_ediscovery_case` - Fetch a single case record
- `list_ediscovery_case_members` - Show users and role groups assigned to a case
- `list_ediscovery_custodians` - Show custodians and hold status for a case
- `list_ediscovery_searches` - Show searches and query details for a case
- `list_ediscovery_case_operations` - Monitor indexing, hold, estimate, export, and purge operations
- `get_ediscovery_operation` - Fetch a single operation with status and result details
- `list_ediscovery_noncustodial_data_sources` - Show site and workload sources attached outside custodians
- `list_ediscovery_review_sets` - List review sets available for downstream review workflows
- `estimate_ediscovery_search_statistics` - Submit a search estimate job, return its operation location, and optionally wait for the resulting operation status

## Purview Integration Tests

The repository includes an env-gated integration harness in `tests/test_purview_integration.py` for validating the Purview eDiscovery flow against a real tenant.

Minimum environment variables:

```bash
export RUN_PURVIEW_INTEGRATION=true
export client_id=your-app-client-id
export tenant_id=your-tenant-id
```

Optional case-scoped navigation coverage:

```bash
export PURVIEW_EDISCOVERY_CASE_ID=your-case-id
```

Optional estimate submission coverage:

```bash
export PURVIEW_EDISCOVERY_CASE_ID=your-case-id
export PURVIEW_EDISCOVERY_SEARCH_ID=your-search-id
export RUN_PURVIEW_ESTIMATE=true
```

Run the harness with:

```bash
uv run --extra test pytest tests/test_purview_integration.py
```

By default, all integration tests skip unless the corresponding environment variables are set.

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
