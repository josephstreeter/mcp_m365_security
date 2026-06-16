"""
Security and compliance functions for Microsoft 365.
Handles sign-in logs, security alerts, risky users, audit logs,
managed devices, conditional access policies, and threat hunting.
"""

import logging
from datetime import datetime, timedelta, timezone
from kiota_abstractions.base_request_configuration import RequestConfiguration
from msgraph.graph_service_client import GraphServiceClient
from msgraph.generated.audit_logs.sign_ins.sign_ins_request_builder import SignInsRequestBuilder
from msgraph.generated.security.alerts_v2.alerts_v2_request_builder import Alerts_v2RequestBuilder  # type: ignore
from msgraph.generated.identity_protection.risky_users.risky_users_request_builder import RiskyUsersRequestBuilder
from msgraph.generated.audit_logs.directory_audits.directory_audits_request_builder import DirectoryAuditsRequestBuilder
from msgraph.generated.device_management.managed_devices.managed_devices_request_builder import ManagedDevicesRequestBuilder
from msgraph.generated.security.microsoft_graph_security_run_hunting_query.run_hunting_query_post_request_body import RunHuntingQueryPostRequestBody
from msgraph.generated.groups.groups_request_builder import GroupsRequestBuilder

logger = logging.getLogger(__name__)


# Sign-in Logs

async def get_sign_in_logs(client: GraphServiceClient) -> list[dict]:
    """
    Get all sign-in logs from the last 24 hours.
    
    Args:
        client: Authenticated Graph API client
        
    Returns:
        list[dict]: List of sign-in log entries or empty list on error
    """
    try:
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")

        query_params = SignInsRequestBuilder.SignInsRequestBuilderGetQueryParameters(
            filter=f"createdDateTime ge {cutoff}",
            orderby=["createdDateTime desc"],
            top=50,
        )
        request_config = RequestConfiguration[SignInsRequestBuilder.SignInsRequestBuilderGetQueryParameters](
            query_parameters=query_params,
        )
        sign_ins = await client.audit_logs.sign_ins.get(request_configuration=request_config)
        results = []
        if sign_ins and sign_ins.value:
            for entry in sign_ins.value:
                results.append({
                    "created": str(entry.created_date_time),
                    "user": entry.user_display_name,
                    "app": entry.app_display_name,
                    "status": entry.status.error_code if entry.status else "N/A",
                })
        return results
    except Exception as e:
        logger.error(f"Failed to get sign-in logs: {e}")
        return [{"error": f"Failed to get sign-in logs: {str(e)}"}]


# Advanced Threat Hunting

async def run_hunting_query(client: GraphServiceClient, query: str) -> dict:
    """
    Run a KQL query against Microsoft Defender Advanced Threat Hunting.
    
    Args:
        client: Authenticated Graph API client
        query: Kusto Query Language (KQL) query
        
    Returns:
        dict: Query results with columns and rows, or error message
    """
    try:
        body = RunHuntingQueryPostRequestBody()
        body.query = query

        result = await client.security.microsoft_graph_security_run_hunting_query.post(body)
        if not result:
            return {"error": "No results returned from hunting query."}

        columns = []
        if result.schema:
            columns = [col.name for col in result.schema if col.name]

        rows = []
        if result.results:
            for row in result.results:
                if row.additional_data:
                    rows.append(row.additional_data)

        return {"columns": columns, "results": rows, "record_count": len(rows)}
    except Exception as e:
        logger.error(f"Failed to run hunting query: {e}")
        return {"error": f"Failed to run hunting query: {str(e)}"}


# Security Alerts

async def get_security_alerts(client: GraphServiceClient, top: int = 50, severity: str | None = None, status: str | None = None) -> list[dict]:
    """
    Fetch Microsoft 365 Defender security alerts (v2 API) with full evidence extraction.
    Extracts users, IPs, devices, files, and other entities involved in alerts.
    
    Args:
        client: Authenticated Graph API client
        top: Maximum number of alerts to return
        severity: Optional severity filter ("informational", "low", "medium", "high")
        status: Optional status filter ("new", "inProgress", "resolved")
        
    Returns:
        list[dict]: List of security alerts with extracted evidence entities or empty list on error
    """
    try:
        # Build filter conditions
        filter_parts = []
        if severity:
            filter_parts.append(f"severity eq '{severity}'")
        if status:
            filter_parts.append(f"status eq '{status}'")
        
        filter_query = " and ".join(filter_parts) if filter_parts else None
        
        query_params = Alerts_v2RequestBuilder.Alerts_v2RequestBuilderGetQueryParameters(
            top=top,
            orderby=["createdDateTime desc"],
            filter=filter_query,
        )
        request_config = RequestConfiguration[Alerts_v2RequestBuilder.Alerts_v2RequestBuilderGetQueryParameters](
            query_parameters=query_params,
        )
        alerts = await client.security.alerts_v2.get(request_configuration=request_config)
        results = []
        if alerts and alerts.value:
            for alert in alerts.value:
                # Extract evidence entities using v2 API evidence types
                affected_users = []
                affected_ips = []
                affected_devices = []
                
                # Process evidence collection (v2 API uses typed evidence)
                if alert.evidence:
                    for evidence_item in alert.evidence:
                        evidence_type = evidence_item.odata_type
                        
                        # Extract user evidence
                        if evidence_type == "#microsoft.graph.security.userEvidence":
                            user_account = getattr(evidence_item, "user_account", None)
                            if user_account:
                                affected_users.append({
                                    "account_name": getattr(user_account, "account_name", None),
                                    "user_principal_name": getattr(user_account, "user_principal_name", None),
                                    "display_name": getattr(user_account, "display_name", None),
                                    "domain_name": getattr(user_account, "domain_name", None),
                                })
                        
                        # Extract IP evidence
                        elif evidence_type == "#microsoft.graph.security.ipEvidence":
                            affected_ips.append({
                                "ip_address": getattr(evidence_item, "ip_address", None),
                                "country_code": getattr(evidence_item, "country_letter_code", None),
                            })
                        
                        # Extract device evidence
                        elif evidence_type == "#microsoft.graph.security.deviceEvidence":
                            affected_devices.append({
                                "device_dns_name": getattr(evidence_item, "device_dns_name", None),
                                "device_id": getattr(evidence_item, "azure_ad_device_id", None),
                            })
                
                # Build comprehensive alert result with v2 fields
                alert_result = {
                    "id": alert.id,
                    "title": alert.title,
                    "severity": alert.severity.value if alert.severity else None,
                    "status": alert.status.value if alert.status else None,
                    "category": alert.category,
                    "classification": alert.classification.value if alert.classification else None,
                    "determination": alert.determination.value if alert.determination else None,
                    "created": str(alert.created_date_time) if alert.created_date_time else None,
                    "last_modified": str(getattr(alert, "last_updated_date_time", getattr(alert, "last_modified_date_time", None))) if getattr(alert, "last_updated_date_time", getattr(alert, "last_modified_date_time", None)) else None,
                    "description": alert.description,
                    "alert_web_url": alert.alert_web_url,
                    "assigned_to": alert.assigned_to,
                    "comments": [comment.comment for comment in alert.comments] if alert.comments else [],
                    "recommended_actions": alert.recommended_actions,
                    "affected_users": affected_users,
                    "affected_ips": affected_ips,
                    "affected_devices": affected_devices,
                    "service_source": alert.service_source.value if alert.service_source else None,
                    "detection_source": alert.detection_source.value if alert.detection_source else None,
                    "detector_id": alert.detector_id,
                    "provider_alert_id": alert.provider_alert_id,
                }
                results.append(alert_result)
        return results
    except Exception as e:
        logger.error(f"Failed to get security alerts: {e}")
        return [{"error": f"Failed to get security alerts: {str(e)}"}]


async def get_alert_by_id(client: GraphServiceClient, alert_id: str) -> dict:
    """
    Fetch a specific security alert by ID (v2 API) with full evidence details.
    Useful for SOC analysts conducting deep-dive investigations.
    
    Args:
        client: Authenticated Graph API client
        alert_id: The unique identifier of the security alert
        
    Returns:
        dict: Detailed alert information with all evidence entities or error message
    """
    try:
        # Use v2 API - evidence is included by default as a complex property
        alert = await client.security.alerts_v2.by_alert_id(alert_id).get()
        
        if not alert:
            return {"error": f"Alert with ID {alert_id} not found"}
        
        # Extract evidence entities using v2 API evidence types
        affected_users = []
        affected_ips = []
        affected_devices = []
        all_evidence = []
        
        # Process evidence collection (v2 API uses typed evidence)
        if alert.evidence:
            for evidence_item in alert.evidence:
                evidence_type = evidence_item.odata_type
                
                # Extract user evidence
                if evidence_type == "#microsoft.graph.security.userEvidence":
                    user_account = getattr(evidence_item, "user_account", None)
                    if user_account:
                        affected_users.append({
                            "account_name": getattr(user_account, "account_name", None),
                            "user_principal_name": getattr(user_account, "user_principal_name", None),
                            "display_name": getattr(user_account, "display_name", None),
                            "domain_name": getattr(user_account, "domain_name", None),
                        })
                
                # Extract IP evidence
                elif evidence_type == "#microsoft.graph.security.ipEvidence":
                    affected_ips.append({
                        "ip_address": getattr(evidence_item, "ip_address", None),
                        "country_code": getattr(evidence_item, "country_letter_code", None),
                    })
                
                # Extract device evidence
                elif evidence_type == "#microsoft.graph.security.deviceEvidence":
                    affected_devices.append({
                        "device_dns_name": getattr(evidence_item, "device_dns_name", None),
                        "device_id": getattr(evidence_item, "azure_ad_device_id", None),
                    })
                
                # Store all evidence with type information for deep investigation
                all_evidence.append({
                    "type": evidence_type,
                    "verdict": evidence_item.verdict.value if evidence_item.verdict else None,
                    "remediation_status": evidence_item.remediation_status.value if evidence_item.remediation_status else None,
                })
        
        # Build comprehensive result with v2 fields
        result = {
            "id": alert.id,
            "title": alert.title,
            "severity": alert.severity.value if alert.severity else None,
            "status": alert.status.value if alert.status else None,
            "category": alert.category,
            "classification": alert.classification.value if alert.classification else None,
            "determination": alert.determination.value if alert.determination else None,
            "created": str(alert.created_date_time) if alert.created_date_time else None,
            "last_modified": str(getattr(alert, "last_updated_date_time", getattr(alert, "last_modified_date_time", None))) if getattr(alert, "last_updated_date_time", getattr(alert, "last_modified_date_time", None)) else None,
            "resolved": str(getattr(alert, "resolved_date_time", getattr(alert, "closed_date_time", None))) if getattr(alert, "resolved_date_time", getattr(alert, "closed_date_time", None)) else None,
            "first_activity": str(getattr(alert, "first_activity_date_time", None)) if getattr(alert, "first_activity_date_time", None) else None,
            "last_activity": str(getattr(alert, "last_activity_date_time", None)) if getattr(alert, "last_activity_date_time", None) else None,
            "description": alert.description,
            "alert_web_url": alert.alert_web_url,
            "assigned_to": alert.assigned_to,
            "comments": [comment.comment for comment in alert.comments] if alert.comments else [],
            "recommended_actions": alert.recommended_actions,
            "affected_users": affected_users,
            "affected_ips": affected_ips,
            "affected_devices": affected_devices,
            "evidence": all_evidence,
            "service_source": alert.service_source.value if alert.service_source else None,
            "detection_source": alert.detection_source.value if alert.detection_source else None,
            "detector_id": alert.detector_id,
            "provider_alert_id": alert.provider_alert_id,
            "incident_id": alert.incident_id,
            "incident_web_url": alert.incident_web_url,
        }
        
        return result
    except Exception as e:
        logger.error(f"Failed to get alert {alert_id}: {e}")
        return {"error": f"Failed to get alert {alert_id}: {str(e)}"}


# Identity Protection

async def get_risky_users(client: GraphServiceClient, top: int = 50) -> list[dict]:
    """
    List users flagged by Azure AD Identity Protection as risky.
    
    Args:
        client: Authenticated Graph API client
        top: Maximum number of risky users to return
        
    Returns:
        list[dict]: List of risky users or empty list on error
    """
    try:
        query_params = RiskyUsersRequestBuilder.RiskyUsersRequestBuilderGetQueryParameters(
            top=top,
            orderby=["riskLastUpdatedDateTime desc"],
        )
        request_config = RequestConfiguration[RiskyUsersRequestBuilder.RiskyUsersRequestBuilderGetQueryParameters](
            query_parameters=query_params,
        )
        risky = await client.identity_protection.risky_users.get(request_configuration=request_config)
        results = []
        if risky and risky.value:
            for user in risky.value:
                results.append({
                    "id": user.id,
                    "user_display_name": user.user_display_name,
                    "user_principal_name": user.user_principal_name,
                    "risk_level": user.risk_level.value if user.risk_level else None,
                    "risk_state": user.risk_state.value if user.risk_state else None,
                    "risk_detail": user.risk_detail.value if user.risk_detail else None,
                    "risk_last_updated": str(user.risk_last_updated_date_time) if user.risk_last_updated_date_time else None,
                })
        return results
    except Exception as e:
        logger.error(f"Failed to get risky users: {e}")
        return [{"error": f"Failed to get risky users: {str(e)}"}]


# Audit Logs

async def get_audit_logs(client: GraphServiceClient, top: int = 50) -> list[dict]:
    """
    Get directory audit logs (password changes, role assignments, etc.).
    
    Args:
        client: Authenticated Graph API client
        top: Maximum number of audit log entries to return
        
    Returns:
        list[dict]: List of audit log entries or empty list on error
    """
    try:
        query_params = DirectoryAuditsRequestBuilder.DirectoryAuditsRequestBuilderGetQueryParameters(
            top=top,
            orderby=["activityDateTime desc"],
        )
        request_config = RequestConfiguration[DirectoryAuditsRequestBuilder.DirectoryAuditsRequestBuilderGetQueryParameters](
            query_parameters=query_params,
        )
        audits = await client.audit_logs.directory_audits.get(request_configuration=request_config)
        results = []
        if audits and audits.value:
            for entry in audits.value:
                initiated_by = None
                if entry.initiated_by:
                    if entry.initiated_by.user:
                        initiated_by = entry.initiated_by.user.user_principal_name or entry.initiated_by.user.display_name
                    elif entry.initiated_by.app:
                        initiated_by = entry.initiated_by.app.display_name
                results.append({
                    "id": entry.id,
                    "activity": entry.activity_display_name,
                    "category": entry.category,
                    "result": entry.result.value if entry.result else None,
                    "timestamp": str(entry.activity_date_time) if entry.activity_date_time else None,
                    "initiated_by": initiated_by,
                })
        return results
    except Exception as e:
        logger.error(f"Failed to get audit logs: {e}")
        return [{"error": f"Failed to get audit logs: {str(e)}"}]


# Device Management

async def get_managed_devices(client: GraphServiceClient, top: int = 50) -> list[dict]:
    """
    List Intune managed devices.
    
    Args:
        client: Authenticated Graph API client
        top: Maximum number of devices to return
        
    Returns:
        list[dict]: List of managed devices or empty list on error
    """
    try:
        query_params = ManagedDevicesRequestBuilder.ManagedDevicesRequestBuilderGetQueryParameters(
            top=top,
            select=["deviceName", "operatingSystem", "osVersion", "complianceState", "lastSyncDateTime", "userDisplayName", "managedDeviceOwnerType", "model", "manufacturer"],
        )
        request_config = RequestConfiguration[ManagedDevicesRequestBuilder.ManagedDevicesRequestBuilderGetQueryParameters](
            query_parameters=query_params,
        )
        devices = await client.device_management.managed_devices.get(request_configuration=request_config)
        results = []
        if devices and devices.value:
            for dev in devices.value:
                results.append({
                    "id": dev.id,
                    "device_name": dev.device_name,
                    "os": dev.operating_system,
                    "os_version": dev.os_version,
                    "compliance": dev.compliance_state.value if dev.compliance_state else None,
                    "last_sync": str(dev.last_sync_date_time) if dev.last_sync_date_time else None,
                    "user": dev.user_display_name,
                    "owner_type": dev.managed_device_owner_type.value if dev.managed_device_owner_type else None,
                    "model": dev.model,
                    "manufacturer": dev.manufacturer,
                })
        return results
    except Exception as e:
        logger.error(f"Failed to get managed devices: {e}")
        return [{"error": f"Failed to get managed devices: {str(e)}"}]


# Conditional Access

async def get_conditional_access_policies(client: GraphServiceClient) -> list[dict]:
    """
    Get all Azure AD Conditional Access policies, including conditions
    (users, apps, platforms, locations, risk levels) and grant controls.
    
    Args:
        client: Authenticated Graph API client
        
    Returns:
        list[dict]: List of conditional access policies or empty list on error
    """
    try:
        policies = await client.identity.conditional_access.policies.get()
        results = []
        if policies and policies.value:
            for policy in policies.value:
                conditions = policy.conditions
                grant_controls = policy.grant_controls

                results.append({
                    "id": policy.id,
                    "display_name": policy.display_name,
                    "state": policy.state.value if policy.state else None,
                    "created": str(policy.created_date_time) if policy.created_date_time else None,
                    "modified": str(policy.modified_date_time) if policy.modified_date_time else None,
                    "conditions": {
                        "users_include": conditions.users.include_users if conditions and conditions.users else None,
                        "users_exclude": conditions.users.exclude_users if conditions and conditions.users else None,
                        "groups_include": conditions.users.include_groups if conditions and conditions.users else None,
                        "groups_exclude": conditions.users.exclude_groups if conditions and conditions.users else None,
                        "apps_include": conditions.applications.include_applications if conditions and conditions.applications else None,
                        "apps_exclude": conditions.applications.exclude_applications if conditions and conditions.applications else None,
                        "platforms": [p.value for p in conditions.platforms.include_platforms] if conditions and conditions.platforms and conditions.platforms.include_platforms else None,
                        "locations_include": conditions.locations.include_locations if conditions and conditions.locations else None,
                        "locations_exclude": conditions.locations.exclude_locations if conditions and conditions.locations else None,
                        "client_app_types": [c.value for c in conditions.client_app_types] if conditions and conditions.client_app_types else None,
                        "sign_in_risk_levels": [r.value for r in conditions.sign_in_risk_levels] if conditions and conditions.sign_in_risk_levels else None,
                        "user_risk_levels": [r.value for r in conditions.user_risk_levels] if conditions and conditions.user_risk_levels else None,
                    },
                    "grant_controls": {
                        "operator": grant_controls.operator if grant_controls else None,
                        "built_in_controls": [c.value for c in grant_controls.built_in_controls] if grant_controls and grant_controls.built_in_controls else None,
                    } if grant_controls else None,
                })
        return results
    except Exception as e:
        logger.error(f"Failed to get conditional access policies: {e}")
        return [{"error": f"Failed to get conditional access policies: {str(e)}"}]


async def get_named_locations(client: GraphServiceClient) -> list[dict]:
    """
    Get all Conditional Access Named Locations (IP-based and country-based).
    
    Args:
        client: Authenticated Graph API client
        
    Returns:
        list[dict]: List of named locations or empty list on error
    """
    try:
        named_locations = await client.identity.conditional_access.named_locations.get()
        results = []
        if named_locations and named_locations.value:
            for location in named_locations.value:
                # Determine location type and extract specific details
                location_type = location.odata_type if hasattr(location, 'odata_type') else None
                
                location_info: dict = {
                    "id": location.id,
                    "display_name": location.display_name,
                    "created": str(location.created_date_time) if location.created_date_time else None,
                    "modified": str(location.modified_date_time) if location.modified_date_time else None,
                }
                
                # Handle IP-based named locations
                if location_type == "#microsoft.graph.ipNamedLocation":
                    ip_ranges = []
                    if hasattr(location, 'ip_ranges') and getattr(location, 'ip_ranges', None):
                        for ip_range in getattr(location, 'ip_ranges', []):
                            cidr = getattr(ip_range, 'cidr_address', None)
                            ip_ranges.append({"cidr": cidr})
                    
                    location_info["type"] = "IP"
                    location_info["is_trusted"] = getattr(location, 'is_trusted', False)
                    location_info["ip_ranges"] = ip_ranges
                
                # Handle country-based named locations
                elif location_type == "#microsoft.graph.countryNamedLocation":
                    location_info["type"] = "Country"
                    location_info["countries_and_regions"] = getattr(location, 'countries_and_regions', None)
                    location_info["include_unknown_countries"] = getattr(location, 'include_unknown_countries_and_regions', False)
                else:
                    location_info["type"] = "Unknown"
                
                results.append(location_info)
        
        return results
    except Exception as e:
        logger.error(f"Failed to get named locations: {e}")
        return [{"error": f"Failed to get named locations: {str(e)}"}]


# Entra ID Groups

def _classify_group(group) -> dict:
    """
    Helper function to classify and format a group object.
    
    Args:
        group: Group object from Microsoft Graph API
        
    Returns:
        dict: Formatted group information with proper type classification
    """
    group_types = group.group_types if group.group_types else []
    
    # Determine group type with clear, non-overlapping categories
    if "Unified" in group_types:
        type_label = "Microsoft 365"
    elif group.security_enabled and not group.mail_enabled:
        type_label = "Security"
    elif group.mail_enabled and not group.security_enabled:
        type_label = "Distribution"
    elif group.mail_enabled and group.security_enabled:
        type_label = "Mail-enabled Security"
    else:
        type_label = "Other"
    
    return {
        "id": group.id,
        "display_name": group.display_name,
        "description": group.description,
        "mail": group.mail,
        "type": type_label,
        "security_enabled": group.security_enabled,
        "mail_enabled": group.mail_enabled,
        "group_types": group.group_types,
        "membership_rule": group.membership_rule,
        "created": str(group.created_date_time) if group.created_date_time else None,
        "visibility": group.visibility,
    }


async def get_group_by_id(client: GraphServiceClient, group_id: str) -> dict:
    """
    Get a single Entra ID group by its object ID.
    
    Args:
        client: Authenticated Graph API client
        group_id: The group's object ID (GUID)
        
    Returns:
        dict: Group information or error message
    """
    try:
        from msgraph.generated.groups.item.group_item_request_builder import GroupItemRequestBuilder
        
        query_params = GroupItemRequestBuilder.GroupItemRequestBuilderGetQueryParameters(
            select=["id", "displayName", "description", "mail", "groupTypes", 
                    "securityEnabled", "mailEnabled", "membershipRule", "createdDateTime", "visibility"],
        )
        request_config = RequestConfiguration[GroupItemRequestBuilder.GroupItemRequestBuilderGetQueryParameters](
            query_parameters=query_params,
        )
        
        group = await client.groups.by_group_id(group_id).get(request_configuration=request_config)
        if group:
            return _classify_group(group)
        return {"error": "Group not found"}
    except Exception as e:
        logger.error(f"Failed to get group by ID: {e}")
        return {"error": f"Failed to get group by ID: {str(e)}"}


async def get_entra_groups(client: GraphServiceClient, top: int = 100, search: str | None = None) -> list[dict]:
    """
    Query Entra ID (Azure AD) groups with optional search filter.
    
    Args:
        client: Authenticated Graph API client
        top: Maximum number of groups to return
        search: Optional search string to filter groups whose display name starts with this value,
                or exact group ID (GUID). Supports special characters including hyphens.
        
    Returns:
        list[dict]: List of Entra ID groups or empty list on error
    """
    try:
        # Check if search is a GUID (Group ID) - if so, use get_group_by_id instead
        if search:
            try:
                import uuid
                uuid.UUID(search)
                # It's a valid GUID, use direct lookup
                result = await get_group_by_id(client, search)
                if "error" not in result:
                    return [result]
                return [result]
            except (ValueError, AttributeError):
                pass  # Not a GUID, continue with name search
        
        query_params = GroupsRequestBuilder.GroupsRequestBuilderGetQueryParameters(
            top=top,
            select=["id", "displayName", "description", "mail", "mailEnabled", "securityEnabled", 
                    "groupTypes", "membershipRule", "createdDateTime", "visibility"],
        )
        
        if search:
            # Search by display name using startswith
            # Note: orderby is not compatible with complex filters in Graph API
            query_params.filter = f"startswith(displayName, '{search}')"
        else:
            # Only apply orderby when not filtering (Graph API limitation)
            query_params.orderby = ["displayName"]
        
        request_config = RequestConfiguration[GroupsRequestBuilder.GroupsRequestBuilderGetQueryParameters](
            query_parameters=query_params,
        )
        
        groups = await client.groups.get(request_configuration=request_config)
        results = []
        if groups and groups.value:
            for group in groups.value:
                results.append(_classify_group(group))
        
        # Sort results client-side if we filtered (couldn't use orderby)
        if search and results:
            results.sort(key=lambda x: x.get("display_name", "").lower())
        
        return results
    except Exception as e:
        logger.error(f"Failed to get Entra ID groups: {e}")
        return [{"error": f"Failed to get Entra ID groups: {str(e)}"}]


async def get_user_authentication_methods(client: GraphServiceClient, user_id: str = "me") -> dict:
    """
    Get authentication methods configured for a user.
    
    Args:
        client: Authenticated Graph API client
        user_id: User ID or principal name (default: "me" for current user)
        
    Returns:
        dict: Dictionary containing email, phone, and other authentication methods
    """
    try:
        result = {
            "user_id": user_id,
            "email_methods": [],
            "phone_methods": [],
            "fido2_methods": [],
            "microsoft_authenticator_methods": [],
            "software_oath_methods": [],
            "temporary_access_pass_methods": []
        }
        
        # Get email authentication methods
        try:
            email_methods = await client.users.by_user_id(user_id).authentication.email_methods.get()
            if email_methods and email_methods.value:
                for method in email_methods.value:
                    result["email_methods"].append({
                        "id": method.id,
                        "email_address": method.email_address,
                        "created_date_time": str(method.created_date_time) if getattr(method, "created_date_time", None) else None
                    })
        except Exception as e:
            logger.warning(f"Failed to get email methods for user {user_id}: {e}")
        
        # Get phone authentication methods
        try:
            phone_methods = await client.users.by_user_id(user_id).authentication.phone_methods.get()
            if phone_methods and phone_methods.value:
                for method in phone_methods.value:
                    result["phone_methods"].append({
                        "id": method.id,
                        "phone_number": method.phone_number,
                        "phone_type": method.phone_type.value if method.phone_type else None,
                        "created_date_time": str(method.created_date_time) if getattr(method, "created_date_time", None) else None
                    })
        except Exception as e:
            logger.warning(f"Failed to get phone methods for user {user_id}: {e}")
        
        # Get FIDO2 authentication methods
        try:
            fido2_methods = await client.users.by_user_id(user_id).authentication.fido2_methods.get()
            if fido2_methods and fido2_methods.value:
                for method in fido2_methods.value:
                    result["fido2_methods"].append({
                        "id": method.id,
                        "display_name": method.display_name,
                        "created_date_time": str(method.created_date_time) if method.created_date_time else None
                    })
        except Exception as e:
            logger.warning(f"Failed to get FIDO2 methods for user {user_id}: {e}")
        
        # Get Microsoft Authenticator methods
        try:
            authenticator_methods = await client.users.by_user_id(user_id).authentication.microsoft_authenticator_methods.get()
            if authenticator_methods and authenticator_methods.value:
                for method in authenticator_methods.value:
                    result["microsoft_authenticator_methods"].append({
                        "id": method.id,
                        "display_name": method.display_name,
                        "device_tag": method.device_tag,
                        "phone_app_version": method.phone_app_version,
                        "created_date_time": str(method.created_date_time) if method.created_date_time else None
                    })
        except Exception as e:
            logger.warning(f"Failed to get Microsoft Authenticator methods for user {user_id}: {e}")
        
        # Get Software OATH methods
        try:
            oath_methods = await client.users.by_user_id(user_id).authentication.software_oath_methods.get()
            if oath_methods and oath_methods.value:
                for method in oath_methods.value:
                    result["software_oath_methods"].append({
                        "id": method.id,
                        "created_date_time": str(method.created_date_time) if getattr(method, "created_date_time", None) else None
                    })
        except Exception as e:
            logger.warning(f"Failed to get Software OATH methods for user {user_id}: {e}")
        
        # Get Temporary Access Pass methods
        try:
            tap_methods = await client.users.by_user_id(user_id).authentication.temporary_access_pass_methods.get()
            if tap_methods and tap_methods.value:
                for method in tap_methods.value:
                    result["temporary_access_pass_methods"].append({
                        "id": method.id,
                        "created_date_time": str(method.created_date_time) if method.created_date_time else None,
                        "start_date_time": str(method.start_date_time) if method.start_date_time else None,
                        "lifetime_in_minutes": method.lifetime_in_minutes,
                        "is_usable_once": method.is_usable_once
                    })
        except Exception as e:
            logger.warning(f"Failed to get Temporary Access Pass methods for user {user_id}: {e}")
        
        return result
    except Exception as e:
        logger.error(f"Failed to get authentication methods for user {user_id}: {e}")
        return {"error": f"Failed to get authentication methods: {str(e)}"}


async def get_user_devices(client: GraphServiceClient, user_id: str = "me") -> dict:
    """
    Get registered and enrolled devices for a user.
    
    Args:
        client: Authenticated Graph API client
        user_id: User ID or principal name (default: "me" for current user)
        
    Returns:
        dict: Dictionary containing registered and owned devices
    """
    try:
        result = {
            "user_id": user_id,
            "registered_devices": [],
            "owned_devices": []
        }
        
        # Get registered devices
        try:
            registered = await client.users.by_user_id(user_id).registered_devices.get()
            if registered and registered.value:
                for device in registered.value:
                    device_info = {
                        "id": device.id,
                        "device_id": getattr(device, "device_id", None),
                        "display_name": getattr(device, "display_name", None),
                        "operating_system": getattr(device, "operating_system", None),
                        "operating_system_version": getattr(device, "operating_system_version", None),
                        "is_compliant": getattr(device, "is_compliant", None),
                        "is_managed": getattr(device, "is_managed", None),
                        "trust_type": getattr(device, "trust_type", None),
                        "approximate_last_sign_in": str(getattr(device, "approximate_last_sign_in_date_time", None)) if getattr(device, "approximate_last_sign_in_date_time", None) else None,
                        "registration_date_time": str(getattr(device, "registration_date_time", None)) if getattr(device, "registration_date_time", None) else None,
                        "manufacturer": getattr(device, "manufacturer", None),
                        "model": getattr(device, "model", None),
                        "mdm_app_id": getattr(device, "mdm_app_id", None),
                    }
                    result["registered_devices"].append(device_info)
        except Exception as e:
            logger.warning(f"Failed to get registered devices for user {user_id}: {e}")
        
        # Get owned devices
        try:
            owned = await client.users.by_user_id(user_id).owned_devices.get()
            if owned and owned.value:
                for device in owned.value:
                    device_info = {
                        "id": device.id,
                        "device_id": getattr(device, "device_id", None),
                        "display_name": getattr(device, "display_name", None),
                        "operating_system": getattr(device, "operating_system", None),
                        "operating_system_version": getattr(device, "operating_system_version", None),
                        "is_compliant": getattr(device, "is_compliant", None),
                        "is_managed": getattr(device, "is_managed", None),
                        "trust_type": getattr(device, "trust_type", None),
                        "approximate_last_sign_in": str(getattr(device, "approximate_last_sign_in_date_time", None)) if getattr(device, "approximate_last_sign_in_date_time", None) else None,
                        "registration_date_time": str(getattr(device, "registration_date_time", None)) if getattr(device, "registration_date_time", None) else None,
                        "manufacturer": getattr(device, "manufacturer", None),
                        "model": getattr(device, "model", None),
                    }
                    result["owned_devices"].append(device_info)
        except Exception as e:
            logger.warning(f"Failed to get owned devices for user {user_id}: {e}")
        
        return result
    except Exception as e:
        logger.error(f"Failed to get devices for user {user_id}: {e}")
        return {"error": f"Failed to get devices: {str(e)}"}


async def get_url_click_events(client: GraphServiceClient, user_upn: str, days: int = 7) -> dict:
    """
    Get URL click events for a specific user to detect potential phishing link clicks.
    
    Args:
        client: Authenticated Graph API client
        user_upn: User Principal Name (email address)
        days: Number of days to look back (default: 7)
        
    Returns:
        dict: Dictionary containing URL click events with timestamps, URLs, and action types
    """
    try:
        # Build KQL query for UrlClickEvents
        query = f"""
        UrlClickEvents
        | where AccountUpn == "{user_upn}"
        | where Timestamp >= ago({days}d)
        | project Timestamp, AccountUpn, Url, ActionType, UrlChain, IPAddress, NetworkMessageId, IsClickedThrough
        | order by Timestamp desc
        """
        
        # Execute the hunting query
        body = RunHuntingQueryPostRequestBody()
        body.query = query

        result = await client.security.microsoft_graph_security_run_hunting_query.post(body)
        if not result:
            return {"error": "No results returned from URL click events query."}

        columns = []
        if result.schema:
            columns = [col.name for col in result.schema if col.name]

        clicks = []
        if result.results:
            for row in result.results:
                if row.additional_data:
                    clicks.append(row.additional_data)

        return {
            "user_upn": user_upn,
            "days_searched": days,
            "click_count": len(clicks),
            "columns": columns,
            "clicks": clicks
        }
    except Exception as e:
        logger.error(f"Failed to get URL click events for user {user_upn}: {e}")
        return {"error": f"Failed to get URL click events: {str(e)}"}


# Attack Simulator

async def get_attack_simulator_simulations(client: GraphServiceClient, top: int = 25) -> list[dict]:
    """
    Get Microsoft 365 Attack Simulator simulation runs (not third-party simulators like KnowBe4/Hoxhunt).

    Args:
        client: Authenticated Graph API client
        top: Maximum number of simulations to return

    Returns:
        list[dict]: Simulation runs with status, technique, launch dates, and report overview
    """
    try:
        from msgraph.generated.security.attack_simulation.simulations.simulations_request_builder import SimulationsRequestBuilder

        query_params = SimulationsRequestBuilder.SimulationsRequestBuilderGetQueryParameters(
            top=top,
        )
        request_config = RequestConfiguration[SimulationsRequestBuilder.SimulationsRequestBuilderGetQueryParameters](
            query_parameters=query_params,
        )
        simulations = await client.security.attack_simulation.simulations.get(request_configuration=request_config)
        results = []
        if simulations and simulations.value:
            for sim in simulations.value:
                created_by_email = getattr(getattr(sim, "created_by", None), "email", None)
                last_modified_by_email = getattr(getattr(sim, "last_modified_by", None), "email", None)

                report_overview = None
                report = getattr(sim, "report", None)
                if report:
                    ov = getattr(report, "overview", None)
                    if ov:
                        report_overview = {
                            "users_targeted_count": getattr(ov, "users_targeted_count", None),
                            "compromised_rate": getattr(ov, "compromised_rate", None),
                            "phishing_report_number_count": getattr(ov, "phishing_report_number_count", None),
                        }

                results.append({
                    "id": sim.id,
                    "display_name": sim.display_name,
                    "description": getattr(sim, "description", None),
                    "status": sim.status.value if sim.status else None,
                    "attack_type": sim.attack_type.value if sim.attack_type else None,
                    "attack_technique": sim.attack_technique.value if sim.attack_technique else None,
                    "is_automated": getattr(sim, "is_automated", None),
                    "launch_date": str(sim.launch_date_time) if getattr(sim, "launch_date_time", None) else None,
                    "completion_date": str(sim.completion_date_time) if getattr(sim, "completion_date_time", None) else None,
                    "created": str(sim.created_date_time) if getattr(sim, "created_date_time", None) else None,
                    "created_by": created_by_email,
                    "last_modified": str(sim.last_modified_date_time) if getattr(sim, "last_modified_date_time", None) else None,
                    "last_modified_by": last_modified_by_email,
                    "report": report_overview,
                })
        return results
    except Exception as e:
        logger.error(f"Failed to get attack simulator simulations: {e}")
        return [{"error": f"Failed to get attack simulator simulations: {str(e)}"}]


# Anti-Phishing / Impersonation Protection

async def get_anti_phishing_policies(client: GraphServiceClient, days: int = 30) -> dict:
    """
    Surface anti-phishing and impersonation protection activity derived from email events.

    Returns two data sets:
    - org_level_action_summary: What org-level policies are doing with phish/impersonation detections
      (quarantine, delete, deliver, etc.) grouped by OrgLevelAction.
    - bypassed_phish_senders: Senders whose phish-verdict emails were delivered anyway — indicative
      of sender/domain allowlist entries in anti-phishing policies.

    NOTE: Raw policy configuration (protected users/domains, mailbox intelligence thresholds,
    impersonation action settings) requires Exchange Online PowerShell (Get-AntiPhishPolicy).

    Args:
        client: Authenticated Graph API client
        days: Number of days of EmailEvents to analyze (default: 30)

    Returns:
        dict: org_level_action_summary and bypassed_phish_senders from Advanced Hunting
    """
    try:
        action_summary_query = f"""
EmailEvents
| where Timestamp >= ago({days}d)
| where DetectionMethods has "Impersonation"
    or ThreatTypes has "Phish"
    or ThreatTypes has "Malware"
| summarize
    TotalEvents = count(),
    PhishThreatCount = countif(ThreatTypes has "Phish"),
    ImpersonationCount = countif(DetectionMethods has "Impersonation"),
    MailboxIntelligenceCount = countif(DetectionMethods has "Mailbox intelligence"),
    SenderSamples = make_set(SenderFromDomain, 15)
  by OrgLevelAction
| order by TotalEvents desc
"""
        bypassed_senders_query = f"""
EmailEvents
| where Timestamp >= ago({days}d)
| where ThreatTypes has "Phish"
    and OrgLevelAction in~ ("None", "Deliver")
    and DeliveryAction !~ "Quarantine"
| summarize
    BypassCount = count(),
    Recipients = make_set(RecipientEmailAddress, 10),
    LastSeen = max(Timestamp),
    OrgActions = make_set(OrgLevelAction, 5)
  by SenderFromDomain, SenderFromAddress
| order by BypassCount desc
| take 50
"""
        body1 = RunHuntingQueryPostRequestBody()
        body1.query = action_summary_query
        r1 = await client.security.microsoft_graph_security_run_hunting_query.post(body1)

        body2 = RunHuntingQueryPostRequestBody()
        body2.query = bypassed_senders_query
        r2 = await client.security.microsoft_graph_security_run_hunting_query.post(body2)

        action_summary = []
        if r1 and r1.results:
            for row in r1.results:
                if row.additional_data:
                    action_summary.append(row.additional_data)

        bypassed_senders = []
        if r2 and r2.results:
            for row in r2.results:
                if row.additional_data:
                    bypassed_senders.append(row.additional_data)

        return {
            "days_analyzed": days,
            "note": "Policy configuration details (protected users/domains, mailbox intelligence settings) require Exchange Online PowerShell (Get-AntiPhishPolicy).",
            "org_level_action_summary": action_summary,
            "bypassed_phish_senders": bypassed_senders,
        }
    except Exception as e:
        logger.error(f"Failed to get anti-phishing policy data: {e}")
        return {"error": f"Failed to get anti-phishing policy data: {str(e)}"}


# Quarantine

async def get_quarantine_release_status(
    client: GraphServiceClient,
    days: int = 7,
    top: int = 100,
    recipient: str | None = None,
) -> dict:
    """
    Get quarantined email events with post-delivery release status from Advanced Hunting.

    Joins EmailEvents (quarantine deliveries) with EmailPostDeliveryEvents (admin/user releases)
    to show the full lifecycle: quarantined → released (or still held).

    Args:
        client: Authenticated Graph API client
        days: Number of days to look back (default: 7)
        top: Maximum number of quarantined messages to return (default: 100)
        recipient: Optional recipient email address to filter results

    Returns:
        dict: Quarantined messages with OrgLevelAction, LatestDeliveryAction, and release event details
    """
    try:
        recipient_filter = ""
        if recipient:
            recipient_filter = f'\n| where RecipientEmailAddress =~ "{recipient}"'

        query = f"""
EmailEvents
| where Timestamp >= ago({days}d)
| where DeliveryLocation == "Quarantine" or LatestDeliveryLocation == "Quarantine"{recipient_filter}
| join kind=leftouter (
    EmailPostDeliveryEvents
    | where Timestamp >= ago({days}d)
    | project NetworkMessageId, ReleaseAction = Action, ReleaseActionType = ActionType,
              ReleaseTrigger = ActionTrigger, ReleaseResult = ActionResult,
              ReleaseDeliveryLocation = DeliveryLocation, ReleaseTime = Timestamp
  ) on NetworkMessageId
| project Timestamp, RecipientEmailAddress, SenderFromAddress, SenderDisplayName, Subject,
          OrgLevelAction, LatestDeliveryAction, LatestDeliveryLocation,
          ThreatTypes, DetectionMethods,
          ConfidenceLevel, NetworkMessageId,
          ReleaseAction, ReleaseActionType, ReleaseTrigger, ReleaseResult, ReleaseDeliveryLocation, ReleaseTime
| order by Timestamp desc
| take {top}
"""
        body = RunHuntingQueryPostRequestBody()
        body.query = query
        result = await client.security.microsoft_graph_security_run_hunting_query.post(body)

        if not result:
            return {"error": "No results returned from quarantine query."}

        columns = [col.name for col in result.schema if col.name] if result.schema else []
        messages = []
        if result.results:
            for row in result.results:
                if row.additional_data:
                    messages.append(row.additional_data)

        return {
            "days_searched": days,
            "recipient_filter": recipient,
            "quarantined_count": len(messages),
            "columns": columns,
            "messages": messages,
        }
    except Exception as e:
        logger.error(f"Failed to get quarantine release status: {e}")
        return {"error": f"Failed to get quarantine release status: {str(e)}"}


# Enriched EmailEvents

async def get_email_events_enriched(
    client: GraphServiceClient,
    days: int = 7,
    top: int = 100,
    recipient: str | None = None,
    sender: str | None = None,
    subject_contains: str | None = None,
    network_message_id: str | None = None,
) -> dict:
    """
    Run an enriched EmailEvents Advanced Hunting query surfacing OrgLevelAction,
    LatestDeliveryAction, LatestDeliveryLocation, and an IsPhishingSimulation computed flag
    that detects events tagged internally as simulation by Defender (including cases not
    visible in the standard schema).

    Args:
        client: Authenticated Graph API client
        days: Number of days to look back (default: 7)
        top: Maximum number of events to return (default: 100)
        recipient: Optional recipient email address filter (exact match)
        sender: Optional sender email address or domain filter (exact match)
        subject_contains: Optional substring to search within email Subject
        network_message_id: Optional specific NetworkMessageId for single-message lookup

    Returns:
        dict: Enriched email events with delivery pipeline fields and simulation detection flag
    """
    try:
        filters = []
        if recipient:
            filters.append(f'RecipientEmailAddress =~ "{recipient}"')
        if sender:
            filters.append(f'(SenderFromAddress =~ "{sender}" or SenderFromDomain =~ "{sender}")')
        if subject_contains:
            filters.append(f'Subject contains "{subject_contains}"')
        if network_message_id:
            filters.append(f'NetworkMessageId == "{network_message_id}"')

        filter_clause = ""
        if filters:
            filter_clause = "\n| where " + "\n    and ".join(filters)

        query = f"""EmailEvents
| where Timestamp >= ago({days}d){filter_clause}
| extend IsPhishingSimulation = (
    OrgLevelAction =~ "SimulationFiltered"
    or ThreatTypes has "PhishingSimulation"
    or DetectionMethods has "PhishingSimulation"
  )
| project Timestamp, RecipientEmailAddress, SenderFromAddress, SenderDisplayName, Subject,
          DeliveryAction, DeliveryLocation, OrgLevelAction, LatestDeliveryAction, LatestDeliveryLocation,
          ThreatTypes, DetectionMethods,
          NetworkMessageId, InternetMessageId, AttachmentCount, UrlCount,
          ConfidenceLevel, EmailDirection, IsPhishingSimulation
| order by Timestamp desc
| take {top}
"""
        body = RunHuntingQueryPostRequestBody()
        body.query = query
        result = await client.security.microsoft_graph_security_run_hunting_query.post(body)

        if not result:
            return {"error": "No results returned from enriched EmailEvents query."}

        columns = [col.name for col in result.schema if col.name] if result.schema else []
        events = []
        if result.results:
            for row in result.results:
                if row.additional_data:
                    events.append(row.additional_data)

        return {
            "days_searched": days,
            "filters_applied": {
                "recipient": recipient,
                "sender": sender,
                "subject_contains": subject_contains,
                "network_message_id": network_message_id,
            },
            "event_count": len(events),
            "columns": columns,
            "events": events,
        }
    except Exception as e:
        logger.error(f"Failed to get enriched email events: {e}")
        return {"error": f"Failed to get enriched email events: {str(e)}"}


async def get_user_audit_events(client: GraphServiceClient, user_upn: str, days: int = 7) -> dict:
    """
    Get Entra ID audit events for a specific user including MFA registration, SSPR changes, and profile edits.
    
    Args:
        client: Authenticated Graph API client
        user_upn: User Principal Name (email address)
        days: Number of days to look back (default: 7)
        
    Returns:
        dict: Dictionary containing audit events for the specified user
    """
    try:
        from datetime import datetime, timedelta, timezone
        
        # Calculate the start date for filtering
        start_date = datetime.now(timezone.utc) - timedelta(days=days)
        start_date_str = start_date.strftime("%Y-%m-%dT%H:%M:%SZ")
        
        # Build filter for the specific user - checking both initiatedBy and targetResources
        filter_query = f"activityDateTime ge {start_date_str} and (targetResources/any(t: t/userPrincipalName eq '{user_upn}') or initiatedBy/user/userPrincipalName eq '{user_upn}')"
        
        query_params = DirectoryAuditsRequestBuilder.DirectoryAuditsRequestBuilderGetQueryParameters(
            filter=filter_query,
            orderby=["activityDateTime desc"],
            top=100
        )
        request_config = RequestConfiguration[DirectoryAuditsRequestBuilder.DirectoryAuditsRequestBuilderGetQueryParameters](
            query_parameters=query_params,
        )
        
        audits = await client.audit_logs.directory_audits.get(request_configuration=request_config)
        events = []
        
        if audits and audits.value:
            for entry in audits.value:
                # Extract initiator information
                initiated_by = None
                initiated_by_type = None
                if entry.initiated_by:
                    if entry.initiated_by.user:
                        initiated_by = entry.initiated_by.user.user_principal_name or entry.initiated_by.user.display_name
                        initiated_by_type = "user"
                    elif entry.initiated_by.app:
                        initiated_by = entry.initiated_by.app.display_name
                        initiated_by_type = "app"
                
                # Extract target resources
                target_resources = []
                if entry.target_resources:
                    for target in entry.target_resources:
                        target_info = {
                            "type": target.type,
                            "display_name": target.display_name,
                            "user_principal_name": getattr(target, "user_principal_name", None),
                            "id": target.id
                        }
                        # Include modified properties if available
                        if hasattr(target, "modified_properties") and target.modified_properties:
                            modified_props = []
                            for prop in target.modified_properties:
                                modified_props.append({
                                    "name": prop.display_name,
                                    "old_value": prop.old_value,
                                    "new_value": prop.new_value
                                })
                            target_info["modified_properties"] = modified_props
                        target_resources.append(target_info)
                
                events.append({
                    "id": entry.id,
                    "activity": entry.activity_display_name,
                    "category": entry.category,
                    "result": entry.result.value if entry.result else None,
                    "result_reason": entry.result_reason,
                    "timestamp": str(entry.activity_date_time) if entry.activity_date_time else None,
                    "initiated_by": initiated_by,
                    "initiated_by_type": initiated_by_type,
                    "target_resources": target_resources,
                    "correlation_id": entry.correlation_id
                })
        
        return {
            "user_upn": user_upn,
            "days_searched": days,
            "event_count": len(events),
            "events": events
        }
    except Exception as e:
        logger.error(f"Failed to get audit events for user {user_upn}: {e}")
        return {"error": f"Failed to get audit events: {str(e)}"}
