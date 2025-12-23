
import pytest
import sys
from pathlib import Path
from unittest.mock import AsyncMock, patch, MagicMock
from typing import Any

import os
# Add src directory to path to handle imports correctly
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

# Set env var before import to pass validation
os.environ["NIST_API_KEY"] = "test_key"

from server.providers.DB_tools import NIST

@pytest.fixture
def mock_httpx_client():
    with patch("httpx.AsyncClient") as mock_client:
        yield mock_client

@pytest.mark.asyncio
async def test_CVE_filters_none_params(mock_httpx_client):
    # Setup mock return value
    mock_response = MagicMock()
    mock_response.status_code = 200
    mock_response.json.return_value = {"result": "success"}
    
    # We need to mock make_get_request_with_params because it's imported/defined in NIST.py
    # However, NIST.py defines make_get_request_with_params in the same file.
    # So we should patch it where it is used, which is inside CVE function.
    # Unlike AbuselPDB test which mocked httpx directly, here we want to verify the params *pre-filtering*.
    # Actually, the user asked to check "at this line" (where filtering happens).
    # If we mock `make_get_request_with_params`, we can check what arguments it received.
    
    # NIST.py imports utils.requests as requests.
    # So we should patch 'server.providers.DB_tools.NIST.requests.make_get_request_with_params'
    
    with patch("server.providers.DB_tools.NIST.requests.make_get_request_with_params", new_callable=AsyncMock) as mock_request:
        mock_request.return_value = {"data": {"result": "success"}, "error": None}
        
        # Call the tool with some None values and some real values
        await NIST.CVE(
            cpeName="cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*",
            cveID=None,
            resultsPerPage=20,
            isVulnerable=True
        )
        
        # Verify that make_get_request_with_params was called
        args, kwargs = mock_request.call_args
        
        # The second argument to make_get_request_with_params is the params dictionary
        # args[0] is url, args[1] is params
        called_params = args[1]
        
        # Assertions
        assert "cpeName" in called_params
        assert called_params["cpeName"] == "cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*"
        assert "cveID" not in called_params 
        assert "resultsPerPage" in called_params
        assert called_params["resultsPerPage"] == 20
        assert "isVulnerable" in called_params
        assert called_params["isVulnerable"] is True

