import sys
from pathlib import Path

# Add src directory to path so we can import utils
sys.path.insert(0, str(Path(__file__).parent.parent.parent.parent))

import requests
import httpx
from mcp.server.fastmcp import FastMCP
from typing import Any
from dotenv import load_dotenv
import os
import logging
import utils.validate as validate

load_dotenv()

# ---------- Logging ----------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    filename="URLscan_log.log",
    filemode="a"
)

logger = logging.getLogger(__name__)

mcp = FastMCP("URLscan MCP", json_response=True)

# ---------- API_KEY Loading ----------

BASE_URL = "https://urlscan.io/api/v1"
API_KEY = os.getenv("URLSCAN_API_KEY")

if not API_KEY:
    logging.error("Missing URLSCAN_API_KEY environment variable")
    raise RuntimeError("Missing URLSCAN_API_KEY")


# Helper function to make requests to VirusTotal API
async def make_get_request(url : str) -> dict[str, Any] | None :
    response, error = None, None
    headers = {
        "x-apikey": API_KEY,
    }
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, headers=headers, timeout=30.0)
            response.raise_for_status()
            response = response.json()
        # esception
        except httpx.HTTPStatusError as e:
            logging.error(f"Error response {e.response.status_code} while requesting {e.request.url!r}.")
            error = str(e)

    logging.info(f"GET {url} - Response: {response}, Error: {error}")
    return {
        "data": response,
        "error": error
        }

async def make_get_request(url : str, params : dict[str , Any]) -> dict[str, Any] | None :
    headers = {
        "x-apikey": API_KEY,
    }

    url += "?"
    for key, value in params.items():
        url += f"{key}={value}&"

    url = url[:-1]  # remove last &
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, headers=headers, timeout=30.0)
            response.raise_for_status()
            return response.json()
        # esception
        except httpx.HTTPStatusError as e:
            logging.error(f"Error response {e.response.status_code} while requesting {e.request.url!r}.")
            # raise(e)
            return None

async def make_post_request(url : str) -> dict[str, Any] | None :
    headers = {
        "x-apikey": API_KEY,
    }
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(url, headers=headers, timeout=30.0)
            response.raise_for_status()
            return response.json()
        # esception
        except httpx.HTTPStatusError as e:
            logging.error(f"Error response {e.response.status_code} while requesting {e.request.url!r}.")
            return None
        
async def make_post_request(url : str, body : dict[str, Any]) -> dict[str, Any] | None :
    headers = {
        "x-apikey": API_KEY,
    }
    async with httpx.AsyncClient() as client:
        try:
            response = await client.post(url, headers=headers, json=body, timeout=30.0)
            response.raise_for_status()
            return response.json()
        # esception
        except httpx.HTTPStatusError as e:
            logging.error(f"Error response {e.response.status_code} while requesting {e.request.url!r}.")
            return None

# tools        
@mcp.tool()
async def API_Quotas() -> dict[str, Any] | None :
    """
    API Endpoint to get available and used API quotas.
    """
    url = f"{BASE_URL}/quotas"
    data = await make_get_request(url)

    if not data:
        logging.error("No data received")
        return None
    
    logging.info(f"return: {data}")
    return data

# PRO tools
@mcp.tool()
async def User_Information(username : str) -> dict[str, Any] | None :
    """
    Get information about the current user or API key making the request.
    """
    url = f"{BASE_URL}/pro/{username}"
    data = await make_get_request(url)

    if not data:
        logging.error("No data received")
        return None
    
    logging.info(f"return: {data}")
    return data

@mcp.tool()
async def scan(url : str, visibility : str = "public", country : str | None = None, tags : list[str] | None = None, overrideSafety : bool | None = None, refer : str | None  = None, customagent : str | None = None) -> dict[str, Any] | None :
    """
    Submit a URL to be scanned and control options for how the scan should be performed.
    visibility: public / unlisted / private
    """
    api_url = f"{BASE_URL}/scan"

    # Request Body - Test - is it ok with empty parameters ?
    body = {
        "url": url,
        "visibility": visibility,
        "country": country,
        "tags": tags,
        "overrideSafety": overrideSafety,
        "refer": refer,
        "customagent": customagent
    }

    data = await make_post_request(api_url, body)

    if not data:
        logging.error("No data received")
        return None
    
    logging.info(f"return: {data}")
    return data

@mcp.tool()
async def result(scanid : str) -> dict[str, Any] | None :
    """
    Using the Scan ID received from the Submission API, you can use the Result API to poll for the scan.
    """
    url = f"{BASE_URL}/result/{scanid}"
    data = await make_get_request(url)

    if not data:
        logging.error("No data received")
        return None
    
    logging.info(f"return: {data}")
    return data

@mcp.tool()
async def screenshot(scanid : str) -> dict[str, Any] | None :
    """
    Use the scan UUID to retrieve the screenshot for a scan once the scan has finished.
    """

    if not isinstance(scanid, str):
        logging.error("Invalid scanid")
        return None
    
    data, error = None, None
    url = f"{BASE_URL}/screenshot/{scanid}.png"
    data = await make_get_request(url)

    logging.info(f"return: {data}")
    return data

@mcp.tool()
async def DOM(scanid : str) -> dict[str, Any] | None :
    """
    Use the scan UUID to retrieve the DOM snapshot for a scan once the scan has finished.
    """
    url = f"{BASE_URL}/dom/{scanid}/"
    data = await make_get_request(url)

    if not data:
        logging.error("No data received")
        return None
    
    logging.info(f"return: {data}")
    return data

@mcp.tool()
async def Available_countries() -> dict[str, Any] | None :
    """
    Retrieve countries available for scanning using the Scan API
    """
    url = f"{BASE_URL}/availableCountries"
    data = await make_get_request(url)

    if not data:
        logging.error("No data received")
        return None
    
    logging.info(f"return: {data}")
    return data

@mcp.tool()
async def Available_User_Agents() -> dict[str, Any] | None :
    """
    Get grouped user agents to use with the Scan API.
    """

    url = f"{BASE_URL}/userAgents"
    data = await make_get_request(url)

    if not data:
        logging.error("No data received")
        return None
    
    logging.info(f"return: {data}")
    return data

@mcp.tool()
async def search(query : str, size : int | None = None, search_after : int | None = None, datasource : str | None = None) -> dict[str, Any] | None :
    """
    The Search API is used to find historical scans performed on the platform.
    """
    url = f"{BASE_URL}/search/"

    params = {
        "q": query,
        "size": size,
        "search_after": search_after,
        "datasource": datasource
    }

    # Remove None values from params
    params = {k: v for k, v in params.items() if v is not None}

    data = await make_get_request(url, params)

    if not data:
        logging.error("No data received")
        return None
    
    logging.info(f"return: {data}")
    return data

@mcp.tool()
async def Live_scanners() -> dict[str, Any] | None :
    """
    API Endpoint to a list of available Live Scanning nodes along with their current metadata.
    """
    url = f"{BASE_URL}/live/scanners/"
    data = await make_get_request(url)

    if not data:
        logging.error("No data received")
        return None
    
    logging.info(f"return: {data}")
    return data

# task fields : URL, visibility.
# scanner fields : pageTimeout, captureDelay, extraHeaders, enableFeatures, disableFeatures.
@mcp.tool()
async def Non_Blocking_Trigger_Live_Scan(scannerid : str, task : dict[str, Any], scanner : dict[str, Any]) -> dict[str, Any] | None :
    """
    Task a URL to be scanned. The HTTP request will return with the scan UUID immediately and then it is your responsibility to poll the result resource type until the scan has finished.    
    """
    payload = {
        "task": task,
        "scanner": scanner
    }

    url = f"{BASE_URL}/livescan/{scannerid}/task/"
    data = await make_post_request(url, payload)

    if not data:
        logging.error("No data received")
        return None
    
    logging.info(f"return: {data}")
    return data

@mcp.tool()
async def Trigger_Live_Scan(scannerid : str, task : dict[str, Any], scanner : dict[str, Any]) -> dict[str, Any] | None :
    """
    Task a URL to be scanned. The HTTP request will block until the scan has finished.
    """
    payload = {
        "task": task,
        "scanner": scanner
    }

    url = f"{BASE_URL}/livescan/{scannerid}/"
    data = await make_post_request(url, payload)

    if not data:
        logging.error("No data received")
        return None
    
    logging.info(f"return: {data}")
    return data

def main():
    # Initialize and run the server
    mcp.run(transport='stdio')

if __name__ == "__main__":
    main()