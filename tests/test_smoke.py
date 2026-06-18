import asyncio
import importlib
import pathlib
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))


def test_validate_environment_missing_vars(monkeypatch):
    module = importlib.import_module("modules.graph_client")
    monkeypatch.setenv("client_id", "")
    monkeypatch.setenv("tenant_id", "")

    with pytest.raises(module.ConfigurationError):
        module.validate_environment()


def test_main_tool_wrapper_get_sign_in_logs(monkeypatch):
    monkeypatch.setenv("client_id", "test-client-id")
    monkeypatch.setenv("tenant_id", "test-tenant-id")

    module = importlib.import_module("main")

    class _FakeAssistant:
        async def get_sign_in_logs(self, _client):
            return [{"user": "smoke@example.com", "status": 0}]

    monkeypatch.setattr(module, "get_singleton_client", lambda: object())
    monkeypatch.setattr(module, "security_assistant", _FakeAssistant())

    payload = asyncio.run(module.get_sign_in_logs())
    assert "smoke@example.com" in payload


def test_main_tool_wrapper_list_ediscovery_cases(monkeypatch):
    monkeypatch.setenv("client_id", "test-client-id")
    monkeypatch.setenv("tenant_id", "test-tenant-id")

    module = importlib.import_module("main")

    class _FakeAssistant:
        async def list_ediscovery_cases(self, _client, top=50, search=None):
            return [{"id": "case-1", "display_name": "Case Alpha", "top": top, "search": search}]

    monkeypatch.setattr(module, "get_singleton_client", lambda: object())
    monkeypatch.setattr(module, "security_assistant", _FakeAssistant())

    payload = asyncio.run(module.list_ediscovery_cases(top=25, search="Alpha"))
    assert "Case Alpha" in payload
    assert '"top": 25' in payload


def test_main_tool_wrapper_list_ediscovery_review_sets(monkeypatch):
    monkeypatch.setenv("client_id", "test-client-id")
    monkeypatch.setenv("tenant_id", "test-tenant-id")

    module = importlib.import_module("main")

    class _FakeAssistant:
        async def list_ediscovery_review_sets(self, _client, case_id, top=100):
            return [{"case_id": case_id, "id": "review-1", "display_name": "Priority Review", "top": top}]

    monkeypatch.setattr(module, "get_singleton_client", lambda: object())
    monkeypatch.setattr(module, "security_assistant", _FakeAssistant())

    payload = asyncio.run(module.list_ediscovery_review_sets(case_id="case-1", top=20))
    assert "Priority Review" in payload
    assert '"top": 20' in payload


def test_main_tool_wrapper_estimate_ediscovery_search_statistics(monkeypatch):
    monkeypatch.setenv("client_id", "test-client-id")
    monkeypatch.setenv("tenant_id", "test-tenant-id")

    module = importlib.import_module("main")

    class _FakeAssistant:
        async def estimate_ediscovery_search_statistics(
            self,
            _client,
            case_id,
            search_id,
            statistics_options=None,
            wait_for_completion=False,
            max_polls=15,
            poll_interval_seconds=2.0,
        ):
            return {
                "case_id": case_id,
                "search_id": search_id,
                "statistics_options": statistics_options,
                "wait_for_completion": wait_for_completion,
                "max_polls": max_polls,
                "poll_interval_seconds": poll_interval_seconds,
                "operation_location": "https://graph.microsoft.com/v1.0/security/cases/ediscoverycases('case-1')/operations('op-1')",
            }

    monkeypatch.setattr(module, "get_singleton_client", lambda: object())
    monkeypatch.setattr(module, "security_assistant", _FakeAssistant())

    payload = asyncio.run(
        module.estimate_ediscovery_search_statistics(
            case_id="case-1",
            search_id="search-1",
            statistics_options=["includeQueryStats"],
            wait_for_completion=True,
            max_polls=3,
            poll_interval_seconds=0.5,
        )
    )
    assert "search-1" in payload
    assert "includeQueryStats" in payload
    assert '"wait_for_completion": true' in payload
    assert '"max_polls": 3' in payload


def test_estimate_ediscovery_search_statistics_waits_for_operation(monkeypatch):
    module = importlib.import_module("modules.security_assistant")

    class _FakeEstimateBuilder:
        def to_post_request_information(self):
            return object()

    class _FakeSearchItem:
        microsoft_graph_security_estimate_statistics = _FakeEstimateBuilder()

    class _FakeSearches:
        def by_ediscovery_search_id(self, _search_id):
            return _FakeSearchItem()

    class _FakeCaseItem:
        searches = _FakeSearches()

    class _FakeEdiscoveryCases:
        def by_ediscovery_case_id(self, _case_id):
            return _FakeCaseItem()

    fake_client = SimpleNamespace(
        security=SimpleNamespace(
            cases=SimpleNamespace(
                ediscovery_cases=_FakeEdiscoveryCases()
            )
        )
    )

    async def _fake_post_graph_json(_client, _request_info, _payload):
        return {
            "status_code": 202,
            "operation_location": "https://graph.microsoft.com/v1.0/security/cases/ediscoverycases('case-1')/operations('op-1')",
        }

    calls = {"count": 0}

    async def _fake_get_operation(_client, case_id, operation_id):
        calls["count"] += 1
        assert case_id == "case-1"
        assert operation_id == "op-1"
        if calls["count"] == 1:
            return {"status": "running", "id": operation_id}
        return {"status": "succeeded", "id": operation_id}

    async def _fake_sleep(_seconds):
        return None

    monkeypatch.setattr(module, "_post_graph_json", _fake_post_graph_json)
    monkeypatch.setattr(module, "get_ediscovery_operation", _fake_get_operation)
    monkeypatch.setattr(module.asyncio, "sleep", _fake_sleep)

    result = asyncio.run(
        module.estimate_ediscovery_search_statistics(
            fake_client,
            case_id="case-1",
            search_id="search-1",
            wait_for_completion=True,
            max_polls=3,
            poll_interval_seconds=0,
        )
    )

    assert result["operation"]["operation_id"] == "op-1"
    assert result["final_operation"]["status"] == "succeeded"
    assert result["poll_count"] == 2


def test_graph_client_includes_ediscovery_scope():
    module = importlib.import_module("modules.graph_client")
    assert "eDiscovery.Read.All" in module.ALL_SCOPES
