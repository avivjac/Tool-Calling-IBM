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

class InvalidURLException(Exception):
    pass

load_dotenv()

# ---------- Logging ----------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    filename="URLscan_log.log",
    filemode="a"
)

logger = logging.getLogger(__name__)

mcp = FastMCP("Xforce MCP", json_response=True)

# ---------- API_KEY Loading ----------

BASE_URL = "https://api.xforce.ibmcloud.com"
API_KEY = os.getenv("XFORCE_API_KEY")

if not API_KEY:
    logging.error("Missing XFORCE_API_KEY environment variable")
    raise RuntimeError("Missing XFORCE_API_KEY")

# ---------- Helper Request Functions ----------

# Helper function to make requests to Xforce API
async def make_get_request(url: str) -> dict[str, Any]:
    headers = {
        "x-apikey": API_KEY,
    }

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(url, headers=headers, timeout=30.0)
            resp.raise_for_status()
            data = resp.json()
            return {
                "data": data,
                "error": None,
            }
        except httpx.HTTPStatusError as e:
            logging.error(f"Error response {e.response.status_code} while requesting {e.request.url!r}.")
            return {
                "data": None,
                "error": str(e),
            }
        except httpx.RequestError as e:
            logging.error(f"Request error while requesting {url!r}: {e}")
            return {
                "data": None,
                "error": str(e),
            }


async def make_get_request_with_params(url : str, params : dict[str , Any]) -> dict[str, Any] | None :
    headers = {
        "x-apikey": API_KEY,
    }

    url += "?"
    for key, value in params.items():
        url += f"{key}={value}&"

    url = url[:-1]  
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(url, headers=headers, timeout=30.0)
            resp.raise_for_status()
            data = resp.json()
            return {
                "data": data,
                "error": None,
            }
        except httpx.HTTPStatusError as e:
            logging.error(f"Error response {e.response.status_code} while requesting {e.request.url!r}.")
            return {
                "data": None,
                "error": str(e),
            }
        except httpx.RequestError as e:
            logging.error(f"Request error while requesting {url!r}: {e}")
            return {
                "data": None,
                "error": str(e),
            }

async def make_post_request(url : str) -> dict[str, Any] | None :
    headers = {
        "x-apikey": API_KEY,
    }
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(url, headers=headers, timeout=30.0)
            resp.raise_for_status()
            data = resp.json()
            return {
                "data": data,
                "error": None,
            }
        except httpx.HTTPStatusError as e:
            logging.error(f"Error response {e.response.status_code} while requesting {e.request.url!r}.")
            return {
                "data": None,
                "error": str(e),
            }
        except httpx.RequestError as e:
            logging.error(f"Request error while requesting {url!r}: {e}")
            return {
                "data": None,
                "error": str(e),
            }
        
async def make_post_request_with_params(url : str, body : dict[str, Any]) -> dict[str, Any] | None :
    headers = {
        "x-apikey": API_KEY,
    }
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(url, headers=headers, json=body, timeout=30.0)
            resp.raise_for_status()
            data = resp.json()
            return {
                "data": data,
                "error": None,
            }
        except httpx.HTTPStatusError as e:
            logging.error(f"Error response {e.response.status_code} while requesting {e.request.url!r}.")
            return {
                "data": None,
                "error": str(e),
            }
        except httpx.RequestError as e:
            logging.error(f"Request error while requesting {url!r}: {e}")
            return {
                "data": None,
                "error": str(e),
            }

async def make_post_request_form(url: str, form: dict[str, Any]) -> dict[str, Any]:
    headers = {
        "x-apikey": API_KEY,
        "Content-Type": "application/x-www-form-urlencoded"
    }

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(url, headers=headers, data=form, timeout=30.0)
            resp.raise_for_status()
            data = resp.json()
            return {
                "data": data,
                "error": None,
            }

        except httpx.HTTPStatusError as e:
            logging.error(f"HTTP error {e.response.status_code} while requesting {e.request.url!r}.")
            return {
                "data": None,
                "error": str(e),
            }

        except httpx.RequestError as e:
            logging.error(f"Request error while requesting {url!r}: {e}")
            return {
                "data": None,
                "error": str(e),
            }
# ---------- Tools ----------
# Implemention of the APIs endpoints as tools


# Collections

@mcp.tool()
async def Get_Collection_by_ID(collectionID : str) -> dict[str, Any] | None :
    """
    Get a collection by ID
    Returns a JSON representation of a Collection
    Returns details for a given Collection.
    """
    url = f"{BASE_URL}/casefiles/{collectionID}"
    data = await make_get_request(url)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Get_Collection_as_STIX_Markup(collectionID : str) -> dict[str, Any] | None :
    """
    Get a collection as STIX markup
    Returns a STIX representation of a Collection with Attachments
    """
    url = f"{BASE_URL}/casefiles/{collectionID}/stix"
    data = await make_get_request(url)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Get_latest_public_Collections() -> dict[str, Any] | None :
    """
    Get latest public Collections
    Gets latest public Collections that you are able to see. Returns a list of publicly accessible Collections.
    """
    url = f"{BASE_URL}/casefiles/public"
    data = await make_get_request(url)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Get_public_Collections_using_pagination(limit : int | None = None, skip : int | None = 0) -> dict[str, Any] | None :
    """
    Gets all public Collections that you are able to see using pagination.
    Returns a list of all publicly accessible Collections using pagination.
    """
    url = f"{BASE_URL}/casefiles/public/paginated"
    params = {
        "limit": limit,
        "skip": skip,
    }
    data = await make_get_request_with_params(url, params)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Get_shared_Collections() -> dict[str, Any] | None :
    """
    Gets all shared Collections that you are able to see.
    Returns a list of all shared Collections.
    """
    url = f"{BASE_URL}/casefiles/shared"
    data = await make_get_request(url)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Get_Collections_by_Group_ID(groupID : str) -> dict[str, Any] | None :
    """
    Gets all Collections that you are able to see by Group ID.
    Returns a list of all Collections by Group ID.
    """
    url = f"{BASE_URL}/casefiles/group/{groupID}"
    data = await make_get_request(url)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Search_public_Collections(query : str) -> dict[str, Any] | None :
    """
    Returns a list of public Collections that were found
    This endpoint searches the title and wiki content of public Collections and returns the result.
    """
    url = f"{BASE_URL}/casefiles/public/fulltext"
    params = {
        "query": query,
    }
    data = await make_get_request_with_params(url, params)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Get_linked_Collections(collectionID : str) -> dict[str, Any] | None :
    """
    Gets all linked Collections that you are able to see for the specified Collection.
    """
    url = f"{BASE_URL}/casefiles/{collectionID}/linkedcasefiles"
    data = await make_get_request(url)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Get_Attachments(casefileid : str, limit : int | None = None, skip : int = 0) -> dict[str, Any] | None :
    """
    Get all attachments for a specified Collection.
    """
    url = f"{BASE_URL}/casefiles/{casefileid}/attachments"
    params = {
        "limit": limit,
        "skip": skip,
    }
    data = await make_get_request_with_params(url, params)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Get_Attachment_by_ID(casefileid : str, attachmentid : str) -> dict[str, Any] | None :
    """
    Get a specific attachment for a specified Collection.
    """
    url = f"{BASE_URL}/casefiles/{casefileid}/attachments/{attachmentid}"   
    data = await make_get_request(url)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Get_file_attachment(casefileid : str, attachmentid : str, filename : str) -> dict[str, Any] | None :
    """
    Get a file attachment for a specified Collection by ID.
    """
    url = f"{BASE_URL}/casefiles/{casefileid}/attachments/{attachmentid}/{filename}"   
    data = await make_get_request(url)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

# DNS

@mcp.tool()
async def get_DNS_records(input : str) -> dict[str, Any] | None :
    """
    Returns live and passive DNS records.
    """
    url = f"{BASE_URL}/resolve/{input}"   
    data = await make_get_request(url)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

# Early Warning

@mcp.tool()
async def Get_early_warning_feed(startDate : str | None = None, endDate : str | None = None, limit : int = 200, skip : int = 0) -> dict[str, Any] | None :
    """
    Returns early warning data.
    """
    url = f"{BASE_URL}/url/host/early_warning"   
    params = {
        "startDate": startDate,
        "endDate": endDate,
        "limit": limit,
        "skip": skip,
    }
    data = await make_get_request_with_params(url, params)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

# Internet Application Profile							

@mcp.tool()
async def Get_all_App_Profiles() -> dict[str, Any] | None :
    """
    Returns list of all Internet Application Profiles (IAP).
    """
    url = f"{BASE_URL}/app/"   
    data = await make_get_request(url)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data


@mcp.tool()
async def Search_App_Profiles(query : str) -> dict[str, Any] | None :
    """
    Returns list of all Internet Application Profiles (IAP) associated with the search term.
    """
    url = f"{BASE_URL}/app/fulltext"

    params = {
        "query": query,
    }

    data = await make_get_request_with_params(url, params)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Get_App_Profile_by_Name(appName : str) -> dict[str, Any] | None :
    """
    Returns a specific Internet Application Profile (IAP).
    """
    url = f"{BASE_URL}/app/{appName}"   
    data = await make_get_request(url)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

# IP Reputation							

@mcp.tool()
async def Get_IPs_by_Category(category : str) -> dict[str, Any] | None :
    """
    Return a list of IPs according to the category and date range.
    """
    url = f"{BASE_URL}/ipr"

    params = {
        "category": category,
    }

    data = await make_get_request_with_params(url, params)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Get_IP_Report(ip : str) -> dict[str, Any] | None :
    """
    Returns the IP report for the entered IP.
    """

    url = f"{BASE_URL}/ipr/{ip}"   
    data = await make_get_request(url)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Get_IP_Reputation(ip : str) -> dict[str, Any] | None :
    """
    Returns a specific IP reputation.
    """
    url = f"{BASE_URL}/ipr/history/{ip}"   
    data = await make_get_request(url)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Get_Malware_for_IP(ip : str) -> dict[str, Any] | None :
    """
    Returns the malware for a specific IP.
    """
    url = f"{BASE_URL}/ipr/history/{ip}"   
    data = await make_get_request(url)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Get_networks_for_ASN(asn : str) -> dict[str, Any] | None :
    """
    Returns the networks for a specific ASN.
    """
    url = f"{BASE_URL}/ipr/asn/{asn}"   
    data = await make_get_request(url)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Get_IP_Reputation_updates(category : str, pull_id : int | None = None) -> dict[str, Any] | None :
    """
    The Delta API provides the data as a bulk download ("base content") for each category supported, followed by periodic downloads of content updates ("deltas") for the category. 
    New base content for each category is created daily (every twenty-four hours), and a new delta pull for each category every 15 minutes.
    """
    url = f"{BASE_URL}/ipr/deltas"   

    query = {
        "category": category,
        "pull_id": pull_id,
    }

    data = await make_get_request_with_params(url, query)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Get_IPR_category_list() -> dict[str, Any] | None :
    """
    Returns a list of all IPR categories.
    """
    url = f"{BASE_URL}/ipr/categories"   
    data = await make_get_request(url)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

# Malware

@mcp.tool()
async def Get_Malware_for_File_Hash(filehash : str) -> dict[str, Any] | None :
    """
    Returns the malware for a specific file hash.
    """
    url = f"{BASE_URL}/malware/{filehash}"   
    data = await make_get_request(url)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Get_Malware_for_Family(family : str) -> dict[str, Any] | None :
    """
    Returns the malware for a specific family.
    """
    url = f"{BASE_URL}/malware/family/{family}"   
    data = await make_get_request(url)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Wildcard_search_malware_family(family : str) -> dict[str, Any] | None :
    """
    Returns the malware for a specific family.
    """
    url = f"{BASE_URL}/malware/familytext/{family}"   
    data = await make_get_request(url)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

# Signatures							

@mcp.tool()
async def Get_PAM_signature(input : str) -> dict[str, Any] | None :
    """
    Returns the PAM signature for a specific signature.
    """
    url = f"{BASE_URL}/signatures/{input}"   
    data = await make_get_request(url)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Search_Signatures(query : str) -> dict[str, Any] | None :
    """
    Returns the signature for a specific signature.
    """
    url = f"{BASE_URL}/signatures/fulltext" 
    params = {
        "query": query,
    }
    data = await make_get_request_with_params(url, params)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Get_by_XPU(xpu : str) -> dict[str, Any] | None :
    """
    Returns the signature for a specific signature.
    """
    url = f"{BASE_URL}/signatures/xpu/{xpu}"   
    data = await make_get_request(url)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Get_list_of_all_XPUs() -> dict[str, Any] | None :
    """
    Returns the signature for a specific signature.
    """
    url = f"{BASE_URL}/signatures/xpu/directory"   
    data = await make_get_request(url)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

# STIX export

@mcp.tool()
async def Get_an_object_in_STIX_format(stixversion : str, object : str, type : str, fullReport : bool) -> dict[str, Any] | None :
    """
    Returns the signature for a specific signature.
    """
    url = f"{BASE_URL}/stix/v2/export/{stixversion}/{object}/{type}/{fullReport}"   
    data = await make_get_request(url)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Get_botnets_information_in_STIX_format(fullReport : bool) -> dict[str, Any] | None :
    """
    Returns the signature for a specific signature.
    """
    url = f"{BASE_URL}/stix/v2/botnets"   

    query = {
        "fullReport": fullReport,
    }

    data = await make_get_request_with_params(url, query)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Get_a_TIS_object_in_STIX_format(stixversion : str, object : str, type : str) -> dict[str, Any] | None :
    """
    Returns the signature for a specific signature.
    """
    url = f"{BASE_URL}/stix/v2/tis-export/{stixversion}/{object}/{type}"   
    data = await make_get_request(url)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

# Tags

@mcp.tool()
async def Tag_Search(query : str) -> dict[str, Any] | None :
    """
    Returns the signature for a specific signature.
    """
    url = f"{BASE_URL}/tags/search"   
    params = {
        "query": query,
    }
    
    data = await make_get_request_with_params(url, params)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data
























