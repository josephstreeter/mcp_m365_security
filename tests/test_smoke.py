import asyncio
import importlib
import pathlib
import sys

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


def test_main_tool_wrapper_estimate_ediscovery_search_statistics(monkeypatch):
    monkeypatch.setenv("client_id", "test-client-id")
    monkeypatch.setenv("tenant_id", "test-tenant-id")

    module = importlib.import_module("main")

    class _FakeAssistant:
        async def estimate_ediscovery_search_statistics(self, _client, case_id, search_id, statistics_options=None):
            return {
                "case_id": case_id,
                "search_id": search_id,
                "statistics_options": statistics_options,
                "operation_location": "https://graph.microsoft.com/v1.0/security/cases/ediscoverycases('case-1')/operations('op-1')",
            }

    monkeypatch.setattr(module, "get_singleton_client", lambda: object())
    monkeypatch.setattr(module, "security_assistant", _FakeAssistant())

    payload = asyncio.run(
        module.estimate_ediscovery_search_statistics(
            case_id="case-1",
            search_id="search-1",
            statistics_options=["includeQueryStats"],
        )
    )
    assert "search-1" in payload
    assert "includeQueryStats" in payload


def test_graph_client_includes_ediscovery_scope():
    module = importlib.import_module("modules.graph_client")
    assert "eDiscovery.Read.All" in module.ALL_SCOPES
