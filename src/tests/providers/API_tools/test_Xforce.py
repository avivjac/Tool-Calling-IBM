
import pytest
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch, MagicMock

# Add src directory to path to handle imports correctly
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

from server.providers.API_tools import Xforce

@pytest.fixture
def mock_env(monkeypatch):
    monkeypatch.setenv("XFORCE_API_KEY", "test_key")

@pytest.fixture
def mock_httpx_client():
    with patch("httpx.AsyncClient") as mock_client:
        yield mock_client

# @pytest.mark.asyncio
# async def test_make_get_request_success(mock_httpx_client):
#     mock_response = MagicMock()
#     mock_response.status_code = 200
#     mock_response.json.return_value = {"test": "data"}
    
#     mock_client_instance = AsyncMock()
#     mock_client_instance.get.return_value = mock_response
#     mock_client_instance.__aenter__.return_value = mock_client_instance
#     mock_client_instance.__aexit__.return_value = None
    
#     mock_httpx_client.return_value = mock_client_instance
    
#     result = await Xforce.make_get_request("http://test.url")
    
#     assert result == {"data": {"test": "data"}, "error": None}
#     mock_client_instance.get.assert_called_once()

# @pytest.mark.asyncio
# async def test_make_get_request_with_params_success(mock_httpx_client):
#     mock_response = MagicMock()
#     mock_response.status_code = 200
#     mock_response.json.return_value = {"test": "data"}
    
#     mock_client_instance = AsyncMock()
#     mock_client_instance.get.return_value = mock_response
#     mock_client_instance.__aenter__.return_value = mock_client_instance
#     mock_client_instance.__aexit__.return_value = None
    
#     mock_httpx_client.return_value = mock_client_instance
    
#     params = {"key": "value"}
#     result = await Xforce.make_get_request_with_params("http://test.url", params)
    
#     assert result == {"data": {"test": "data"}, "error": None}
#     # Check if params were added to URL
#     args, kwargs = mock_client_instance.get.call_args
#     assert "key=value" in args[0]

# @pytest.mark.asyncio
# async def test_make_post_request_success(mock_httpx_client):
#     mock_response = MagicMock()
#     mock_response.status_code = 200
#     mock_response.json.return_value = {"success": True}
    
#     mock_client_instance = AsyncMock()
#     mock_client_instance.post.return_value = mock_response
#     mock_client_instance.__aenter__.return_value = mock_client_instance
#     mock_client_instance.__aexit__.return_value = None
    
#     mock_httpx_client.return_value = mock_client_instance
    
#     result = await Xforce.make_post_request("http://test.url")
    
#     assert result == {"data": {"success": True}, "error": None}
#     mock_client_instance.post.assert_called_once()


# --- Tool Tests ---

@pytest.mark.asyncio
async def test_Get_Collection_by_ID(mock_httpx_client):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"caseFileID": "123", "title": "Test Case"}
    
    mock_client_instance = AsyncMock()
    mock_client_instance.get.return_value = mock_response
    mock_client_instance.__aenter__.return_value = mock_client_instance
    mock_client_instance.__aexit__.return_value = None
    mock_httpx_client.return_value = mock_client_instance

    result = await Xforce.Get_Collection_by_ID("123")
    
    assert result == {"data": {"caseFileID": "123", "title": "Test Case"}, "error": None}
    args, _ = mock_client_instance.get.call_args
    assert "/casefiles/123" in args[0]

@pytest.mark.asyncio
async def test_Get_latest_public_Collections(mock_httpx_client):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = [{"id": "1"}, {"id": "2"}]
    
    mock_client_instance = AsyncMock()
    mock_client_instance.get.return_value = mock_response
    mock_client_instance.__aenter__.return_value = mock_client_instance
    mock_client_instance.__aexit__.return_value = None
    mock_httpx_client.return_value = mock_client_instance

    result = await Xforce.Get_latest_public_Collections()
    
    assert result == {"data": [{"id": "1"}, {"id": "2"}], "error": None}
    args, _ = mock_client_instance.get.call_args
    assert "/casefiles/public" in args[0]

@pytest.mark.asyncio
async def test_get_DNS_records(mock_httpx_client):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"A": ["1.1.1.1"]}
    
    mock_client_instance = AsyncMock()
    mock_client_instance.get.return_value = mock_response
    mock_client_instance.__aenter__.return_value = mock_client_instance
    mock_client_instance.__aexit__.return_value = None
    mock_httpx_client.return_value = mock_client_instance

    result = await Xforce.get_DNS_records("example.com")
    
    assert result == {"data": {"A": ["1.1.1.1"]}, "error": None}
    args, _ = mock_client_instance.get.call_args
    assert "/resolve/example.com" in args[0]

@pytest.mark.asyncio
async def test_Get_IP_Report(mock_httpx_client):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"ip": "8.8.8.8", "score": 1}
    
    mock_client_instance = AsyncMock()
    mock_client_instance.get.return_value = mock_response
    mock_client_instance.__aenter__.return_value = mock_client_instance
    mock_client_instance.__aexit__.return_value = None
    mock_httpx_client.return_value = mock_client_instance

    result = await Xforce.Get_IP_Report("8.8.8.8")
    
    assert result == {"data": {"ip": "8.8.8.8", "score": 1}, "error": None}
    args, _ = mock_client_instance.get.call_args
    assert "/ipr/8.8.8.8" in args[0]

@pytest.mark.asyncio
async def test_Get_Malware_for_File_Hash(mock_httpx_client):
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"family": ["test"]}
    
    mock_client_instance = AsyncMock()
    mock_client_instance.get.return_value = mock_response
    mock_client_instance.__aenter__.return_value = mock_client_instance
    mock_client_instance.__aexit__.return_value = None
    mock_httpx_client.return_value = mock_client_instance

    result = await Xforce.Get_Malware_for_File_Hash("hash123")
    
    assert result == {"data": {"family": ["test"]}, "error": None}
    args, _ = mock_client_instance.get.call_args
    assert "/malware/hash123" in args[0]
