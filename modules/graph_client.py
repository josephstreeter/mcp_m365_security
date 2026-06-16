"""
Shared Microsoft Graph client configuration with proper error handling
and environment validation.
"""

import os
import logging
from typing import Optional
from dotenv import load_dotenv
from azure.identity import InteractiveBrowserCredential, TokenCachePersistenceOptions
from msgraph.graph_service_client import GraphServiceClient

logger = logging.getLogger(__name__)

# Scopes for security operations features only.
ALL_SCOPES = [
    'User.Read',
    'User.Read.All',
    'AuditLog.Read.All',
    'ThreatHunting.Read.All',
    'Group.Read.All',
    'SecurityAlert.Read.All',
    'IdentityRiskyUser.Read.All',
    'DeviceManagementManagedDevices.Read.All',
    'Policy.Read.All',
    'UserAuthenticationMethod.Read.All',
    'Device.Read.All',
]


class ConfigurationError(Exception):
    """Raised when required configuration is missing or invalid."""
    pass


def _env_bool(name: str, default: bool = False) -> bool:
    """Read a boolean environment variable using common true/false forms."""
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "y", "on"}


def validate_environment() -> tuple[str, str]:
    """
    Validate that required environment variables are set.
    
    Returns:
        tuple[str, str]: client_id and tenant_id
        
    Raises:
        ConfigurationError: If required environment variables are missing
    """
    load_dotenv()
    
    client_id = os.getenv("client_id")
    tenant_id = os.getenv("tenant_id")
    
    if not client_id:
        raise ConfigurationError(
            "Missing required environment variable: client_id. "
            "Please set it in your .env file or environment."
        )
    
    if not tenant_id:
        raise ConfigurationError(
            "Missing required environment variable: tenant_id. "
            "Please set it in your .env file or environment."
        )
    
    logger.info("Environment validation successful")
    return client_id, tenant_id


def get_graph_client(scopes: Optional[list[str]] = None) -> GraphServiceClient:
    """
    Create and return a configured Microsoft Graph client.
    
    Args:
        scopes: Optional list of permission scopes. If None, uses ALL_SCOPES.
        
    Returns:
        GraphServiceClient: Configured Graph API client
        
    Raises:
        ConfigurationError: If environment validation fails
    """
    client_id, tenant_id = validate_environment()
    
    if scopes is None:
        scopes = ALL_SCOPES
    
    allow_unencrypted = _env_bool("ALLOW_UNENCRYPTED_TOKEN_CACHE", default=False)

    try:
        credential = InteractiveBrowserCredential(
            client_id=client_id,
            tenant_id=tenant_id,
            cache_persistence_options=TokenCachePersistenceOptions(
                name="m365-security-operations-mcp",
                allow_unencrypted_storage=allow_unencrypted,
            ),
        )

        client = GraphServiceClient(credentials=credential, scopes=scopes)
        logger.info(f"Graph client created successfully with {len(scopes)} scopes")
        return client

    except Exception as e:
        # Headless Linux sessions often cannot use libsecret-backed encrypted caches.
        if not allow_unencrypted:
            logger.warning(
                "Encrypted token cache unavailable; retrying with unencrypted cache. "
                "Set ALLOW_UNENCRYPTED_TOKEN_CACHE=true to skip this retry."
            )
            try:
                credential = InteractiveBrowserCredential(
                    client_id=client_id,
                    tenant_id=tenant_id,
                    cache_persistence_options=TokenCachePersistenceOptions(
                        name="m365-security-operations-mcp",
                        allow_unencrypted_storage=True,
                    ),
                )
                client = GraphServiceClient(credentials=credential, scopes=scopes)
                logger.info("Graph client created with unencrypted token cache fallback")
                return client
            except Exception as fallback_error:
                logger.error(f"Failed to create Graph client: {fallback_error}")
                raise ConfigurationError(
                    f"Failed to initialize Graph client: {fallback_error}"
                ) from fallback_error

        logger.error(f"Failed to create Graph client: {e}")
        raise ConfigurationError(f"Failed to initialize Graph client: {e}") from e


# Singleton client instance (created on first use)
_client: Optional[GraphServiceClient] = None


def get_singleton_client() -> GraphServiceClient:
    """
    Get or create a singleton Graph client instance.
    
    Returns:
        GraphServiceClient: Shared Graph client instance
    """
    global _client
    if _client is None:
        _client = get_graph_client()
    return _client
