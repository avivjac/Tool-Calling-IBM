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
import utils.requests as requests

class InvalidURLException(Exception):
    pass

load_dotenv()

# -----------------------
# Logging
# -----------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    filename="URLscan_log.log",
    filemode="a"
)

logger = logging.getLogger(__name__)

mcp = FastMCP("URLscan MCP", json_response=True)

# -----------------------
# API_KEY Loading
# -----------------------

BASE_URL = "https://urlscan.io/api/v1"
API_KEY = os.getenv("URLSCAN_API_KEY")

if not API_KEY:
    logging.error("Missing URLSCAN_API_KEY environment variable")
    raise RuntimeError("Missing URLSCAN_API_KEY")
            
# -----------------------
# Tools
# -----------------------

# Implemention of the APIs endpoints as tools

# Generic
@mcp.tool()
async def API_Quotas() -> dict[str, Any] | None :
    """
    API Endpoint to get available and used API quotas.
    """
    url = f"{BASE_URL}/quotas"
    data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")
    return data

# Scanning
@mcp.tool()
async def Scan(url : str, visibility : str = "public", country : str | None = None, tags : list[str] | None = None, overrideSafety : bool | None = None, refer : str | None  = None, customagent : str | None = None) -> dict[str, Any] | None :
    """
    Submit a URL to be scanned and control options for how the scan should be performed.
    visibility: public / unlisted / private
    """
    api_url = f"{BASE_URL}/scan"

    if not validate.is_valid_url(url):
        logging.error("Invalid URL")
        raise ValueError("Invalid URL")

    if visibility not in ["public", "unlisted", "private"]:
        logging.error("Invalid visibility")
        raise ValueError("Invalid visibility, must be public, unlisted or private")

    body = {
        "url": url,
        "visibility": visibility,
        "country": country,
        "tags": tags,
        "overrideSafety": overrideSafety,
        "refer": refer,
        "customagent": customagent
    }

    # Remove None values from body
    body = {k: v for k, v in body.items() if v}

    data = await requests.make_post_request_with_params(api_url, body, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")
    return data

@mcp.tool()
async def Result(scanid : str) -> dict[str, Any] | None :
    """
    Using the Scan ID received from the Submission API, you can use the Result API to poll for the scan.
    """
    url = f"{BASE_URL}/result/{scanid}"
    data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")
    return data

@mcp.tool()
async def Screenshot(scanid : str) -> dict[str, Any] | None :
    """
    Use the scan UUID to retrieve the screenshot for a scan once the scan has finished.
    """
    
    data, error = None, None
    url = f"{BASE_URL}/screenshot/{scanid}.png"
    data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")
    return data

@mcp.tool()
async def DOM(scanid : str) -> dict[str, Any] | None :
    """
    Use the scan UUID to retrieve the DOM snapshot for a scan once the scan has finished.
    """
    url = f"{BASE_URL}/dom/{scanid}/"
    data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")
    return data

@mcp.tool()
async def Available_Countries() -> dict[str, Any] | None :
    """
    Retrieve countries available for scanning using the Scan API
    """
    url = f"{BASE_URL}/availableCountries"
    data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")
    return data

@mcp.tool()
async def Available_User_Agents() -> dict[str, Any] | None :
    """
    Get grouped user agents to use with the Scan API.
    """

    url = f"{BASE_URL}/userAgents"
    data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")
    return data


# Search
@mcp.tool()
async def Search(query : str, size : int | None = None, search_after : str | None = None, datasource : str | None = None) -> dict[str, Any] | None :
    """
    The Search API is used to find historical scans performed on the platform.
    """
    url = f"{BASE_URL}/search/"

    if datasource and not validate.is_valid_datasource(datasource):
        logging.error("Invalid datasource")
        raise ValueError("Invalid datasource must be one of: scans, hostnames, incidents, notifications.")

    params = {
        "q": query,
        "size": size,
        "search_after": search_after,
        "datasource": datasource
    }

    # Remove None values from params
    params = {k: v for k, v in params.items() if v}

    data = await requests.make_get_request_with_params(url, params, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")
    return data

# Live Scanning
@mcp.tool()
async def Live_Scanners() -> dict[str, Any] | None :
    """
    API Endpoint to a list of available Live Scanning nodes along with their current metadata.
    """
    url = f"{BASE_URL}/live/scanners/"
    data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")
    return data

# task fields : URL, visibility.
# scanner fields : pageTimeout, captureDelay, extraHeaders, enableFeatures, disableFeatures.
@mcp.tool()
async def Non_Blocking_Trigger_Live_Scan(scannerid : str, task : dict[str, Any], scanner : dict[str, Any]) -> dict[str, Any] | None :
    """
    Task a URL to be scanned. The HTTP request will return with the scan UUID immediately and then it is your responsibility to poll the result resource type until the scan has finished.    
    """
    if not validate.is_valid_url(task["url"]):
        logging.error("Invalid URL")
        raise ValueError("Invalid URL")

    if task["visibility"] not in ["public", "unlisted", "private"]:
        logging.error("Invalid visibility")
        raise ValueError("Invalid visibility must be public, unlisted or private")

    payload = {
        "task": task,
        "scanner": scanner
    }

    url = f"{BASE_URL}/livescan/{scannerid}/task/"
    data = await requests.make_post_request(url, payload, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")
    return data

@mcp.tool()
async def Trigger_Live_Scan(scannerid : str, task : dict[str, Any], scanner : dict[str, Any]) -> dict[str, Any] | None :
    """
    Task a URL to be scanned. The HTTP request will block until the scan has finished.
    """
    if not validate.is_valid_url(task["url"]):
        logging.error("Invalid URL")
        raise ValueError("Invalid URL")
        
    if task["visibility"] not in ["public", "unlisted", "private"]:
        logging.error("Invalid visibility")
        raise ValueError("Invalid visibility must be public, unlisted or private")

    payload = {
        "task": task,
        "scanner": scanner
    }

    url = f"{BASE_URL}/livescan/{scannerid}/"
    data = await requests.make_post_request(url, payload, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")
    return data

@mcp.tool()
async def Live_Scan_Get_Resource(scannerid : str, resourceType : str, resourceId : str) -> dict[str, Any] | None :
    """
    Using the Scan ID received from the Submission API, you can use the Result API to poll for the scan.
    """

    if resourceType not in ["result", "screenshot", "dom", "response", "download"]:
        logging.error("Invalid resource type")
        raise ValueError("Invalid resource type must be one of: result, screenshot, dom, response, download")

    url = f"{BASE_URL}/livescan/{scannerid}/{resourceType}/{resourceId}"
    data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")
    return data 

# Saved Searches
@mcp.tool()
async def Saved_Searches() -> dict[str, Any] | None :
    """
    Retrieve saved searches.
    """
    url = f"{BASE_URL}/user/searches/"
    data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")
    return data 

@mcp.tool()
async def Saved_Search_Search_Results(searchId : str) -> dict[str, Any] | None :
    """
    Get the search results for a specific Saved Search.
    """
    url = f"{BASE_URL}/user/searches/{searchId}/results/"
    data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")
    return data 

# Hostnames

@mcp.tool()
async def Hostnames_History(hostname : str, limit : int = 1000, pageState : str | None = None) -> dict[str, Any] | None :
    """
    Get the historical observations for a specific hostname in the "Hostnames" data source.
    """
    url = f"{BASE_URL}/hostname/{hostname}/"

    params = {
        "limit": limit,
        "pageState": pageState,
    }

    # Remove None values from params
    params = {k: v for k, v in params.items() if v}

    data = await requests.make_get_request_with_params(url, params, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")
    return data 

# Brands - PRO
@mcp.tool()
async def Available_Brands() -> dict[str, Any] | None :
    """
    Retrieve available brands.
    """
    url = f"{BASE_URL}/brands/"
    data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")
    return data 

    
@mcp.tool()
async def Brands() -> dict[str, Any] | None :
    """
    Retrieve brands.
    """
    url = f"{BASE_URL}/brands/"
    data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")
    return data

# file
@mcp.tool()
async def Download_a_File(fileHash : str, password : str | None = "urlscan!", filename : str | None = "$fileHash.zip") -> dict[str, Any] | None :
    """
    Download a file.
    """

    if not validate.is_valid_hash(fileHash):
        logging.error("Invalid file hash")
        raise ValueError("Invalid file hash")
    
    url = f"{BASE_URL}/downloads/{fileHash}/"
    params = {
        "password": password,
        "filename": filename,
    }

    # Remove None values from params
    params = {k: v for k, v in params.items() if v}
    
    data = await requests.make_get_request_with_params(url, params, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")
    return data 

# incident

@mcp.tool()
async def Get_Incident(incidentId : str) -> dict[str, Any] | None :
    """
    Get details for a specific incident.
    """
    url = f"{BASE_URL}/user/incidents/{incidentId}/"
    data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")
    return data 

@mcp.tool()
async def Copy_Incident(incidentId : str) -> dict[str, Any] | None :
    """
    Copy an incident.
    """
    url = f"{BASE_URL}/user/incidents/{incidentId}/copy/"
    data = await requests.make_post_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")
    return data

# @mcp.tool()
# async def Fork_Incident(incidentId : str) -> dict[str, Any] | None :
#     """
#     Copy an incident along with its history (incident states).
#     """
#     url = f"{BASE_URL}/user/incidents/{incidentId}/fork/"
#     data = await requests.make_post_request(url, API_KEY)

#     if data["error"]:
#         logging.error("No data received")
    
#     logging.info(f"return: {data}")
#     return data

@mcp.tool()
async def Get_Watchable_Attributes() -> dict[str, Any] | None :
    """
    Get the list of attributes which can be supplied to the watchedAttributes property of the incident.
    """
    url = f"{BASE_URL}/user/watchableAttributes/"
    data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")
    return data

@mcp.tool()
async def Get_Incident_States(incidentId : str) -> dict[str, Any] | None :
    """
    Retrieve individual incident states of an incident.
    """
    url = f"{BASE_URL}/user/incidents/{incidentId}/"
    data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")
    return data

# Channels
@mcp.tool()
async def channels() -> dict[str, Any] | None :
    """
    Get a list of notification channels for the current user.
    """
    url = f"{BASE_URL}/user/channels/"
    data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")
    return data

@mcp.tool()
async def Channel_Search_Results(channelId : str) -> dict[str, Any] | None :
    """
    Search for results in a specific notification channel.
    """
    url = f"{BASE_URL}/user/channels/{channelId}/"
    data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")
    return data

def main():
    # Initialize and run the server
    mcp.run(transport='stdio')

if __name__ == "__main__":
    main()