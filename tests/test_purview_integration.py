import asyncio
import os
import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from modules.graph_client import get_graph_client
from modules import security_assistant


def _env_enabled(name: str) -> bool:
    value = os.getenv(name, "")
    return value.strip().lower() in {"1", "true", "yes", "on"}


RUN_PURVIEW_INTEGRATION = _env_enabled("RUN_PURVIEW_INTEGRATION")
RUN_PURVIEW_ESTIMATE = _env_enabled("RUN_PURVIEW_ESTIMATE")
PURVIEW_CASE_ID = os.getenv("PURVIEW_EDISCOVERY_CASE_ID")
PURVIEW_SEARCH_ID = os.getenv("PURVIEW_EDISCOVERY_SEARCH_ID")


pytestmark = pytest.mark.skipif(
    not RUN_PURVIEW_INTEGRATION,
    reason="Set RUN_PURVIEW_INTEGRATION=true and valid Graph auth env vars to run Purview integration tests.",
)


@pytest.fixture(scope="module")
def purview_client():
    return get_graph_client(scopes=["eDiscovery.Read.All"])


def test_list_ediscovery_cases_integration(purview_client):
    results = asyncio.run(security_assistant.list_ediscovery_cases(purview_client, top=10))

    assert isinstance(results, list)
    if results:
        assert "error" not in results[0]


@pytest.mark.skipif(
    not PURVIEW_CASE_ID,
    reason="Set PURVIEW_EDISCOVERY_CASE_ID to validate case-scoped Purview navigation.",
)
def test_case_navigation_integration(purview_client):
    case = asyncio.run(security_assistant.get_ediscovery_case(purview_client, PURVIEW_CASE_ID))
    members = asyncio.run(security_assistant.list_ediscovery_case_members(purview_client, PURVIEW_CASE_ID, top=10))
    review_sets = asyncio.run(security_assistant.list_ediscovery_review_sets(purview_client, PURVIEW_CASE_ID, top=10))
    searches = asyncio.run(security_assistant.list_ediscovery_searches(purview_client, PURVIEW_CASE_ID, top=10))
    operations = asyncio.run(security_assistant.list_ediscovery_case_operations(purview_client, PURVIEW_CASE_ID, top=10))

    assert "error" not in case
    assert isinstance(members, list)
    assert isinstance(review_sets, list)
    assert isinstance(searches, list)
    assert isinstance(operations, list)


@pytest.mark.skipif(
    not (PURVIEW_CASE_ID and PURVIEW_SEARCH_ID and RUN_PURVIEW_ESTIMATE),
    reason="Set PURVIEW_EDISCOVERY_CASE_ID, PURVIEW_EDISCOVERY_SEARCH_ID, and RUN_PURVIEW_ESTIMATE=true to run estimate submission.",
)
def test_estimate_statistics_integration(purview_client):
    result = asyncio.run(
        security_assistant.estimate_ediscovery_search_statistics(
            purview_client,
            case_id=PURVIEW_CASE_ID,
            search_id=PURVIEW_SEARCH_ID,
            wait_for_completion=False,
        )
    )

    assert "error" not in result
    assert result.get("status_code") == 202
    assert result.get("operation_location")
