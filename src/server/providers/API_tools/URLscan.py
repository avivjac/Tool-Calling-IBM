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

# ---------- Helper Request Functions ----------

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

# ---------- Tools ----------
# Implemention of the APIs endpoints as tools

# Generic
@mcp.tool()
async def API_Quotas() -> dict[str, Any] | None :
    """
    API Endpoint to get available and used API quotas.
    """
    url = f"{BASE_URL}/quotas"
    data = await make_get_request(url)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")
    return data

# PRO tools (- to delete ?)
@mcp.tool()
async def User_Information(username : str) -> dict[str, Any] | None :
    """
    Get information about the current user or API key making the request.
    """
    url = f"{BASE_URL}/pro/{username}"
    data = await make_get_request(url)

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
    data = await make_get_request(url)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")
    return data

@mcp.tool()
async def Screenshot(scanid : str) -> dict[str, Any] | None :
    """
    Use the scan UUID to retrieve the screenshot for a scan once the scan has finished.
    """

    if not isinstance(scanid, str):
        logging.error("Invalid scanid")
        return None
    
    data, error = None, None
    url = f"{BASE_URL}/screenshot/{scanid}.png"
    data = await make_get_request(url)

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
    data = await make_get_request(url)

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
    data = await make_get_request(url)

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
    data = await make_get_request(url)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")
    return data


# Search
@mcp.tool()
async def Search(query : str, size : int | None = None, search_after : int | None = None, datasource : str | None = None) -> dict[str, Any] | None :
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
    data = await make_get_request(url)

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
    payload = {
        "task": task,
        "scanner": scanner
    }

    url = f"{BASE_URL}/livescan/{scannerid}/task/"
    data = await make_post_request(url, payload)

    if data["error"]:
        logging.error("No data received")
    
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

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")
    return data

@mcp.tool()
async def Live_Scan_Get_Resource(scannerid : str, resourceType : str, resourceId : str) -> dict[str, Any] | None :
    """
    Using the Scan ID received from the Submission API, you can use the Result API to poll for the scan.
    """
    url = f"{BASE_URL}/livescan/{scannerid}/{resourceType}/{resourceId}"
    data = await make_get_request(url)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")
    return data 

# @mcp.tool()
# async def Store_Live_Scan_Result(scannerid : str, scanid : str) -> dict[str, Any] | None :
#     """
#     Store the result of a live scan.
#     """
#     url = f"{BASE_URL}/livescan/{scannerid}/{scanid}/"    

#     payload = {}

#     data = await make_put_request(url, payload)

#     if data["error"]:
#         logging.error("No data received")
    
#     logging.info(f"return: {data}")
#     return data
#     #TODO: PUT REQUEST - Need to fix params, body and helper function

# @mcp.tool()
# async def Purge_Live_Scan_Result(scannerid : str, scanid : str) -> dict[str, Any] | None :
#     """
#     Purge the result of a live scan.
#     """
#     url = f"{BASE_URL}/livescan/{scannerid}/{scanid}/"    

#     data = await make_delete_request(url)

#     if data["error"]:
#         logging.error("No data received")
    
#     logging.info(f"return: {data}")
#     return data 
#     #TODO: DELETE REQUEST - Need to fix params, body and helper function


# Saved Searches
@mcp.tool()
async def Saved_Searches() -> dict[str, Any] | None :
    """
    Retrieve saved searches.
    """
    url = f"{BASE_URL}/user/searches/"
    data = await make_get_request(url)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")
    return data 

@mcp.tool()
async def Create_Saved_Search(datasource : str, name : str, query : str, description : str | None = None, longDescription : str | None = None, permissions : list[str] | None = None, tlp : str | None = None, usertags : list[str] | None = None) -> dict[str, Any] | None :
    """
    Create a saved search.
    """

    url = f"{BASE_URL}/user/searches/"

    payload = {
        "datasource": datasource,
        "description": description,
        "longDescription": longDescription,
        "name": name,
        "permissions": permissions,
        "query": query,
        "tlp": tlp,
        "usertags": usertags
    }

    data = await make_post_request(url, payload)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")
    return data 

# @mcp.tool()
# async def Update_Saved_Search(searchId : str, datasource : str, name : str, query : str, description : str | None = None, longDescription : str | None = None,  permissions : list[str] | None = None, tlp : str | None = None, usertags : list[str] | None = None) -> dict[str, Any] | None :
#     """
#     Update a saved search.
#     """
#     url = f"{BASE_URL}/user/searches/{searchId}/"

#     payload = {
#         "datasource": datasource,
#         "description": description,
#         "longDescription": longDescription,
#         "name": name,
#         "permissions": permissions,
#         "query": query,
#         "tlp": tlp,
#         "usertags": usertags
#     }

#     data = await make_put_request(url, payload)

#     if data["error"]:
#         logging.error("No data received")
    
#     logging.info(f"return: {data}")
#     return data 

# @mcp.tool()
# async def Delete_Saved_Search(searchId : str) -> dict[str, Any] | None :
#     """
#     Delete a saved search.
#     """
#     url = f"{BASE_URL}/user/searches/{searchId}/"

#     data = await make_delete_request(url)

#     if data["error"]:
#         logging.error("No data received")
    
#     logging.info(f"return: {data}")
#     return data 

@mcp.tool()
async def Saved_Search_Search_Results(searchId : str) -> dict[str, Any] | None :
    """
    Retrieve saved search results.
    """
    url = f"{BASE_URL}/user/searches/{searchId}/results/"
    data = await make_get_request(url)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")
    return data 


# Subscriptions
# @mcp.tool()
# async def Subscriptions() -> dict[str, Any] | None :
#     """
#     Retrieve subscriptions.
#     """
#     url = f"{BASE_URL}/user/subscriptions/"
#     data = await make_get_request(url)

#     if data["error"]:
#         logging.error("No data received")
    
#     logging.info(f"return: {data}")
#     return data 

# @mcp.tool()
# async def Create_Subscription(searchIds : list[str], frequency : str, emailAddresses : list[str], name : str, isActive : bool, ignoreTime : bool, description : str | None = None, weekDays : list[str] | None = None, permissions : list[str] | None = None, channelIds : list[str] | None = None, incidentChannelIds : list[str] | None = None, incidentProfileId : str | None = None, incidentVisibility : str | None = None, incidentCreationMode : str | None = None, incidentWatchKeys : str | None = None, ) -> dict[str, Any] | None :
#     """
#     Create a subscription.
#     """
#     url = f"{BASE_URL}/user/subscriptions/"

#     payload = {
#         "searchIds": searchIds,
#         "frequency": frequency,
#         "emailAddresses": emailAddresses,
#         "name": name,
#         "description": description,
#         "isActive": isActive,
#         "ignoreTime": ignoreTime,
#         "weekDays": weekDays,
#         "permissions": permissions,
#         "channelIds": channelIds,
#         "incidentChannelIds": incidentChannelIds,
#         "incidentProfileId": incidentProfileId,
#         "incidentVisibility": incidentVisibility,
#         "incidentCreationMode": incidentCreationMode,
#         "incidentWatchKeys": incidentWatchKeys
#     }

#     data = await make_post_request(url, payload)

#     if data["error"]:
#         logging.error("No data received")
    
#     logging.info(f"return: {data}")
#     return data 

# @mcp.tool()
# async def Update_Subscription(subscriptionId : str, searchIds : list[str], frequency : str, emailAddresses : list[str], name : str, isActive : bool, ignoreTime : bool, description : str | None = None, weekDays : list[str] | None = None, permissions : list[str] | None = None, channelIds : list[str] | None = None, incidentChannelIds : list[str] | None = None, incidentProfileId : str | None = None, incidentVisibility : str | None = None, incidentCreationMode : str | None = None, incidentWatchKeys : str | None = None, ) -> dict[str, Any] | None :
#     """
#     Update a subscription.
#     """
#     url = f"{BASE_URL}/user/subscriptions/{subscriptionId}/"

#     payload = {
#         "searchIds": searchIds,
#         "frequency": frequency,
#         "emailAddresses": emailAddresses,
#         "name": name,
#         "description": description,
#         "isActive": isActive,
#         "ignoreTime": ignoreTime,
#         "weekDays": weekDays,
#         "permissions": permissions,
#         "channelIds": channelIds,
#         "incidentChannelIds": incidentChannelIds,
#         "incidentProfileId": incidentProfileId,
#         "incidentVisibility": incidentVisibility,
#         "incidentCreationMode": incidentCreationMode,
#         "incidentWatchKeys": incidentWatchKeys
#     }

#     data = await make_put_request(url, payload)

#     if data["error"]:
#         logging.error("No data received")
    
#     logging.info(f"return: {data}")
#     return data 
#     #TODO

# @mcp.tool()
# async def Delete_Subscription(subscriptionId : str) -> dict[str, Any] | None :
#     """
#     Delete a subscription.
#     """
#     url = f"{BASE_URL}/user/subscriptions/{subscriptionId}/"

#     data = await make_delete_request(url)

#     if data["error"]:
#         logging.error("No data received")
    
#     logging.info(f"return: {data}")
#     return data 
#     #TODO

# @mcp.tool()
# async def Subscription_Search_Results(subscriptionId : str, datasource : str) -> dict[str, Any] | None :
#     """
#     Retrieve subscription results.
#     """
#     url = f"{BASE_URL}/user/subscriptions/{subscriptionId}/results/{datasource}/"
#     data = await make_get_request(url)

#     if data["error"]:
#         logging.error("No data received")
    
#     logging.info(f"return: {data}")
#     return data 


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
    params = {k: v for k, v in params.items() if v is not None}

    data = await make_get_request(url, params)

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
    data = await make_get_request(url)

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
    data = await make_get_request(url)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")
    return data

# file
@mcp.tool()
async def Download_a_File(fileHash : str, password : str = "urlscan!", filename : str = "$fileHash.zip") -> dict[str, Any] | None :
    """
    Download a file.
    """
    url = f"{BASE_URL}/downloads/{fileHash}/"
    params = {
        "password": password,
        "filename": filename,
    }
    data = await make_get_request(url, params)

    if not data:
        logging.error("No data received")
        return None
    
    logging.info(f"return: {data}")
    return data 

# incident
@mcp.tool()
async def Create_Incident(channels : list[str], observable : str, visibility : str, expireAfter : int | None = None, scanInterval : int | None = None, scanIntervalMode : str | None = None, watchedAttributes : list[str] | None = None, userAgents : list[str] | None = None, userAgentsPerInterval : int | None = None, countries : list[str] | None = None, countriesPerInterval : int | None = None, stopDelaySuspended : int | None = None, stopDelayInactive : int | None = None, stopDelayMalicious : int | None = None, scanIntervalAfterSuspended : int | None = None, scanIntervalAfterMalicious : int | None = None, incidentProfile : str | None = None) -> dict[str, Any] | None :
    """
    Create an incident.
    """
    url = f"{BASE_URL}/user/incidents/"
    payload = {
        "expireAfter": expireAfter,
        "channels": channels,
        "observable": observable,
        "visibility": visibility,
        "scanInterval": scanInterval,
        "scanIntervalMode": scanIntervalMode,
        "watchedAttributes": watchedAttributes,
        "userAgents": userAgents,
        "userAgentsPerInterval": userAgentsPerInterval,
        "countries": countries,
        "countriesPerInterval": countriesPerInterval,
        "stopDelaySuspended": stopDelaySuspended,
        "stopDelayInactive": stopDelayInactive,
        "stopDelayMalicious": stopDelayMalicious,
        "scanIntervalAfterSuspended": scanIntervalAfterSuspended,
        "scanIntervalAfterMalicious": scanIntervalAfterMalicious,
        "incidentProfile": incidentProfile,
    }
    data = await make_post_request(url, payload)

    if not data:
        logging.error("No data received")
        return None
    
    logging.info(f"return: {data}")
    return data 

@mcp.tool()
async def Get_Incident(incidentId : str) -> dict[str, Any] | None :
    """
    Get details for a specific incident.
    """
    url = f"{BASE_URL}/user/incidents/{incidentId}/"
    data = await make_get_request(url)

    if not data:
        logging.error("No data received")
        return None
    
    logging.info(f"return: {data}")
    return data 

@mcp.tool()
async def Update_Incident_options(incidentId : str, channels : list[str], observable : str, visibility : str, expireAfter : int | None = None, scanInterval : int | None = None, scanIntervalMode : str | None = None, watchedAttributes : list[str] | None = None, userAgents : list[str] | None = None, userAgentsPerInterval : int | None = None, countries : list[str] | None = None, countriesPerInterval : int | None = None, stopDelaySuspended : int | None = None, stopDelayInactive : int | None = None, stopDelayMalicious : int | None = None, scanIntervalAfterSuspended : int | None = None, scanIntervalAfterMalicious : int | None = None, incidentProfile : str | None = None) -> dict[str, Any] | None :
    """
    Update specific runtime options of the incident
    """
    url = f"{BASE_URL}/user/incidents/{incidentId}/"
    payload = {
        "expireAfter": expireAfter,
        "channels": channels,
        "observable": observable,
        "visibility": visibility,
        "scanInterval": scanInterval,
        "scanIntervalMode": scanIntervalMode,
        "watchedAttributes": watchedAttributes,
        "userAgents": userAgents,
        "userAgentsPerInterval": userAgentsPerInterval,
        "countries": countries,
        "countriesPerInterval": countriesPerInterval,
        "stopDelaySuspended": stopDelaySuspended,
        "stopDelayInactive": stopDelayInactive,
        "stopDelayMalicious": stopDelayMalicious,
        "scanIntervalAfterSuspended": scanIntervalAfterSuspended,
        "scanIntervalAfterMalicious": scanIntervalAfterMalicious,
        "incidentProfile": incidentProfile,
    }
    data = await make_put_request(url, payload)

    if not data:
        logging.error("No data received")
        return None
    
    logging.info(f"return: {data}")
    return data 

@mcp.tool()
async def Close_Incident(incidentId : str) -> dict[str, Any] | None :
    """
    Close an incident.
    """
    url = f"{BASE_URL}/user/incidents/{incidentId}/close/"
    data = await make_put_request(url)

    if not data:
        logging.error("No data received")
        return None
    
    logging.info(f"return: {data}")
    return data

@mcp.tool()
async def Restart_Incident(incidentId : str) -> dict[str, Any] | None :
    """
    Restart an incident.
    """
    url = f"{BASE_URL}/user/incidents/{incidentId}/restart/"
    data = await make_put_request(url)

    if not data:
        logging.error("No data received")
        return None
    
    logging.info(f"return: {data}")
    return data

@mcp.tool()
async def Copy_Incident(incidentId : str) -> dict[str, Any] | None :
    """
    Copy an incident.
    """
    url = f"{BASE_URL}/user/incidents/{incidentId}/copy/"
    data = await make_post_request(url)

    if not data:
        logging.error("No data received")
        return None
    
    logging.info(f"return: {data}")
    return data

@mcp.tool()
async def Fork_Incident(incidentId : str) -> dict[str, Any] | None :
    """
    Copy an incident along with its history (incident states).
    """
    url = f"{BASE_URL}/user/incidents/{incidentId}/fork/"
    data = await make_post_request(url)

    if not data:
        logging.error("No data received")
        return None
    
    logging.info(f"return: {data}")
    return data

@mcp.tool()
async def Get_Watchable_Attributes() -> dict[str, Any] | None :
    """
    Get the list of attributes which can be supplied to the watchedAttributes property of the incident.


    """
    url = f"{BASE_URL}/user/watchableAttributes/"
    data = await make_get_request(url)

    if not data:
        logging.error("No data received")
        return None
    
    logging.info(f"return: {data}")
    return data

@mcp.tool()
async def Get_Incident_States(incidentId : str) -> dict[str, Any] | None :
    """
    Retrieve individual incident states of an incident.
    """
    url = f"{BASE_URL}/user/incidents/{incidentId}/"
    data = await make_get_request(url)

    if not data:
        logging.error("No data received")
        return None
    
    logging.info(f"return: {data}")
    return data

# Channels
@mcp.tool()
async def channels() -> dict[str, Any] | None :
    """
    Get a list of notification channels for the current user.
    """
    url = f"{BASE_URL}/user/channels/"
    data = await make_get_request(url)

    if not data:
        logging.error("No data received")
        return None
    
    logging.info(f"return: {data}")
    return data

@mcp.tool()
async def create_channel(type : str, name : str, id : str | None = None, webhookURL : str | None = None, frequency : str | None = None, emailAddresses : list[str] | None = None, utcTime : str | None = None, isActive : bool | None = None, isDefault : bool | None = None, ignoreTime : bool | None = None, weekDays : list[str] | None = None, permissions : list[str] | None = None) -> dict[str, Any] | None :
    """
    Create a new notification channel for the current user.
    """
    url = f"{BASE_URL}/user/channels/"
    payload = {
        "_id": id,
        "type": type,
        "webhookURL": webhookURL,
        "frequency": frequency,
        "emailAddresses": emailAddresses,
        "utcTime": utcTime,
        "name": name,
        "isActive": isActive,
        "isDefault": isDefault,
        "ignoreTime": ignoreTime,
        "weekDays": weekDays,
        "permissions": permissions,
    }
    data = await make_post_request(url, payload)

    if not data:
        logging.error("No data received")
        return None
    
    logging.info(f"return: {data}")
    return data

@mcp.tool()
async def Channel_Search_Results(channelId : str) -> dict[str, Any] | None :
    """
    Search for results in a specific notification channel.
    """
    url = f"{BASE_URL}/user/channels/{channelId}/"
    data = await make_get_request(url)

    if not data:
        logging.error("No data received")
        return None
    
    logging.info(f"return: {data}")
    return data

@mcp.tool()
async def update_channel(channelId : str, type : str, name : str, _id : str | None = None, webhookURL : str | None = None, frequency : str | None = None, emailAddresses : list[str] | None = None, utcTime : str | None = None, isActive : bool | None = None, isDefault : bool | None = None, ignoreTime : bool | None = None, weekDays : list[str] | None = None, permissions : list[str] | None = None) -> dict[str, Any] | None :
    """
    Update a notification channel for the current user.
    """
    url = f"{BASE_URL}/user/channels/{channelId}/"
    payload = {
        "_id": _id,
        "type": type,
        "webhookURL": webhookURL,
        "frequency": frequency,
        "emailAddresses": emailAddresses,
        "utcTime": utcTime,
        "name": name,
        "isActive": isActive,
        "isDefault": isDefault,
        "ignoreTime": ignoreTime,
        "weekDays": weekDays,
        "permissions": permissions,
    }
    
    data = await make_put_request(url, payload)

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