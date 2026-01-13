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

# ------------------------
# Logging
# ------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    filename="Xforce_log.log",
    filemode="a"
)

logger = logging.getLogger(__name__)

mcp = FastMCP("Xforce MCP", json_response=True)

# ------------------------
# API_KEY Loading
# ------------------------

BASE_URL = "https://api.xforce.ibmcloud.com"
API_KEY = os.getenv("XFORCE_API_KEY")
API_PASSWORD = os.getenv("XFORCE_API_PASSWORD")

if not API_KEY:
    logging.error("Missing XFORCE_API_KEY environment variable")
    raise RuntimeError("Missing XFORCE_API_KEY")

# ------------------------
# Tools
# ------------------------

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
    data = await requests.make_get_request(url, API_KEY)

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
    data = await requests.make_get_request(url, API_KEY)

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
    data = await requests.make_get_request(url, API_KEY)

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

    # Remove None values from params
    params = {k: v for k, v in params.items() if v}
    
    data = await requests.make_get_request_with_params(url, params, API_KEY)

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
    data = await requests.make_get_request(url, API_KEY)

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
    data = await requests.make_get_request(url, API_KEY)

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
        "q": query,
    }
    data = await requests.make_get_request_with_params(url, params, API_KEY)

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
    data = await requests.make_get_request(url, API_KEY)

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
    
    # Remove None values from params
    params = {k: v for k, v in params.items() if v}
    
    data = await requests.make_get_request_with_params(url, params, API_KEY)

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
    data = await requests.make_get_request(url, API_KEY)

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
    data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

# DNS

@mcp.tool()
async def get_DNS_records(input : str) -> dict[str, Any] | None :
    """
    Returns live and passive DNS records.
    input - ip/domain/url
    """
    url = f"{BASE_URL}/resolve/{input}"   

    if not validate.is_valid_ip(input) and not validate.is_valid_domain(input) and not validate.is_valid_url(input):
        logging.error("Invalid input")
        raise ValueError("Invalid input - must be a valid IP, domain or URL")

    data = await requests.make_get_request(url, API_KEY)

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

    if startDate and not validate.is_valid_date(startDate):
        logging.error("Invalid startDate")
        raise ValueError("Invalid startDate")
    
    if endDate and not validate.is_valid_date(endDate):
        logging.error("Invalid endDate")
        raise ValueError("Invalid endDate")
    
    url = f"{BASE_URL}/url/host/early_warning"   

    params = {
        "startDate": startDate,
        "endDate": endDate,
        "limit": limit,
        "skip": skip,
    }

    # Remove None values from params
    params = {k: v for k, v in params.items() if v}

    data = await requests.make_get_request_with_params(url, params, API_KEY)

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
    data = await requests.make_get_request(url, API_KEY)

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
        "q": query,
    }

    data = await requests.make_get_request_with_params(url, params, API_KEY)

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
    data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

# IP Reputation							

@mcp.tool()
async def Get_IPs_by_Category(category : str, startDate : str, endDate : str, descanding : str, limit : int, skip : int) -> dict[str, Any] | None :
    """
    Return a list of IPs according to the category and date range.
    """
    url = f"{BASE_URL}/ipr"

    if not validate.is_valid_date(startDate) and not validate.is_valid_date(endDate):
        logging.error("Invalid date")
        raise ValueError("Invalid date")

    if not descanding in ["true", "false"]:
        logging.error("Invalid descanding")
        raise ValueError("Invalid descanding - must be true or false")
    
    params = {
        "category": category,
        "startDate": startDate,
        "endDate": endDate,
        "descanding": descanding,
        "limit": limit,
        "skip": skip,
    }

    # Remove None values from params
    params = {k: v for k, v in params.items() if v}

    data = await requests.make_get_request_with_params(url, params, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Get_IP_Report(ip : str) -> dict[str, Any] | None :
    """
    Returns the IP report for the entered IP.
    """
    if not validate.is_valid_ip(ip):
        logging.error("Invalid IP")
        raise ValueError("Invalid IP")

    url = f"{BASE_URL}/ipr/{ip}"   
    data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Get_IP_Reputation(ip : str) -> dict[str, Any] | None :
    """
    Returns a specific IP reputation.
    """
    if not validate.is_valid_ip(ip):
        logging.error("Invalid IP")
        raise ValueError("Invalid IP")
    
    url = f"{BASE_URL}/ipr/history/{ip}"   
    data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Get_Malware_for_IP(ip : str) -> dict[str, Any] | None :
    """
    Returns the malware for a specific IP.
    """
    if not validate.is_valid_ip(ip):
        logging.error("Invalid IP")
        raise ValueError("Invalid IP")
    
    url = f"{BASE_URL}/ipr/history/{ip}"   
    data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Get_networks_for_ASN(asn : str) -> dict[str, Any] | None :
    """
    Returns the networks for a specific ASN.
    """
    if not validate.is_valid_asn(asn):
        logging.error("Invalid ASN")
        raise ValueError("Invalid ASN")
    
    url = f"{BASE_URL}/ipr/asn/{asn}"   
    data = await requests.make_get_request(url, API_KEY)

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

    # Remove None values from params
    query = {k: v for k, v in query.items() if v}

    data = await requests.make_get_request_with_params(url, query, API_KEY)

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
    data = await requests.make_get_request(url, API_KEY)

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
    data = await requests.make_get_request(url, API_KEY)

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
    data = await requests.make_get_request(url, API_KEY)

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
    data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

# Signatures							

@mcp.tool()
async def Get_PAM_signature(input : str) -> dict[str, Any] | None :
    """
    Returns the PAM signature for a specific signature.
    input - pamid \ pam name
    """
    url = f"{BASE_URL}/signatures/{input}"   
    data = await requests.make_get_request(url, API_KEY)

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
        "q": query,
    }

    # Remove None values from params
    params = {k: v for k, v in params.items() if v}
    
    data = await requests.make_get_request_with_params(url, params, API_KEY)

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
    data = await requests.make_get_request(url, API_KEY)

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
    data = await requests.make_get_request(url, API_KEY)

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
    data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Get_botnets_information_in_STIX_format(fullReport : bool | None = None) -> dict[str, Any] | None :
    """
    Returns the signature for a specific signature.
    """
    url = f"{BASE_URL}/stix/v2/botnets"   

    query = {
        "fullReport": fullReport,
    }

    # Remove None values from params
    query = {k: v for k, v in query.items() if v}

    data = await requests.make_get_request_with_params(url, query, API_KEY)

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
    data = await requests.make_get_request(url, API_KEY)

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
        "q": query,
    }

    data = await requests.make_get_request_with_params(url, params, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

# TAXII2

@mcp.tool()
async def Get_API_Root_information(UserAgent : str | None = None) -> dict[str, Any] | None :
    """ 
    Returns the signature for a specific signature.
    """
    url = f"{BASE_URL}/taxii2"   
    
    if UserAgent :
        headers = {
            "User-Agent": UserAgent,
        }
        data = await requests.make_get_request_with_headers(url, headers, API_KEY)
    else :
        data = await make_get_request(url)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Get_Server_Discovery_Resource(UserAgent : str | None = None) -> dict[str, Any] | None :
    """
    Returns the signature for a specific signature.
    """
    url = f"{BASE_URL}/taxii2/discovery" 

    if UserAgent :
        headers = {
            "User-Agent": UserAgent,
        }
        data = await requests.make_get_request_with_headers(url, headers, API_KEY)
    else :
        data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Get_Collections(UserAgent : str | None = None) -> dict[str, Any] | None :
    """
    Returns the signature for a specific signature.
    """
    url = f"{BASE_URL}/taxii2/collections"   

    if UserAgent :
        headers = {
            "User-Agent": UserAgent,
        }
        data = await requests.make_get_request_with_headers(url, headers, API_KEY)
    else :
        data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Get_Collections_by_ID(collection_id : str, UserAgent : str | None = None) -> dict[str, Any] | None :
    """
    Returns the signature for a specific signature.
    """
    url = f"{BASE_URL}/taxii2/collections/{collection_id}" 

    if UserAgent :
        headers = {
            "User-Agent": UserAgent,
        }
        data = await requests.make_get_request_with_headers(url, headers, API_KEY)
    else :
        data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Get_Objects_by_Collection_ID(collection_id : str, added_after : str | None = None, added_before : str | None = None, UserAgent : str | None = None) -> dict[str, Any] | None :
    """
    Returns the signature for a specific signature.
    """
    if added_after and not validate.is_valid_date(added_after):
        logging.error("Invalid added_after date")
        raise ValueError("Invalid added_after date")
        
    if added_before and not validate.is_valid_date(added_before):
        logging.error("Invalid added_before date")
        raise ValueError("Invalid added_before date")
    
    url = f"{BASE_URL}/taxii2/collections/{collection_id}/objects" 

    query = {
        "added_after": added_after,
        "added_before": added_before,
    }

    # Remove None values from params
    query = {k: v for k, v in query.items() if v}

    if UserAgent :
        headers = {
            "User-Agent": UserAgent,
        }
        data = await requests.make_get_request_with_headers_and_params(url, headers, query, API_KEY)
    else :
        data = await requests.make_get_request_with_params(url, query, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Get_Object_by_Object_ID(collectionID : str, object_id : str, UserAgent : str | None = None) -> dict[str, Any] | None :
    """
    Returns the object for a specific object.
    """
    url = f"{BASE_URL}/taxii2/collections/{collectionID}/objects/{object_id}"   

    if UserAgent :
        headers = {
            "User-Agent": UserAgent,
        }
        data = await requests.make_get_request_with_headers(url, headers, API_KEY)
    else :
        data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Get_object_version_by_object_ID(collectionID : str, object_id : str, UserAgent : str | None = None) -> dict[str, Any] | None :
    """
    Returns the object version for a specific object.
    """
    url = f"{BASE_URL}/taxii2/collections/{collectionID}/objects/{object_id}/versions"   

    if UserAgent :
        headers = {
            "User-Agent": UserAgent,
        }
        data = await requests.make_get_request_with_headers(url, headers, API_KEY)
    else :
        data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Get_manifest_by_collectionID(collectionID : str, added_after : str | None = None, added_before : str | None = None, UserAgent : str | None = None) -> dict[str, Any] | None :
    """
    Returns the manifest for a specific collection.
    """
    url = f"{BASE_URL}/taxii2/collections/{collectionID}/manifest"   

    if not validate.is_valid_date(added_after) or not validate.is_valid_date(added_before) :
        logging.error("Invalid date format")
        raise ValueError("Invalid date format")

    query = {
        "added_after": added_after,
        "added_before": added_before,
    }

    # Remove None values from params
    query = {k: v for k, v in query.items() if v}

    if UserAgent :
        headers = {
            "User-Agent": UserAgent,
        }
        data = await requests.make_get_request_with_headers_and_params(url, headers, query, API_KEY)
    else :
        data = await requests.make_get_request_with_params(url, query, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

# URL

@mcp.tool()
async def Get_URLs_by_Category(category : str, startDate : str | None = None, endDate : str | None = None, descending : str | None = None, limit : int | None = None, skip : int | None = None) -> dict[str, Any] | None :
    """
    Return a list of URLs according to the category and date range.
    """
    url = f"{BASE_URL}/url"

    if not validate.is_valid_date(startDate) or not validate.is_valid_date(endDate) :
        logging.error("Invalid date format")
        raise ValueError("Invalid date format")

    query = {
        "category": category,
        "startDate": startDate,
        "endDate": endDate,
        "descending": descending,
        "limit": limit,
        "skip": skip,
    }
    
    # Remove None values from params
    query = {k: v for k, v in query.items() if v}

    data = await requests.make_get_request_with_params(url, query, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Get_URL_Report(url : str) -> dict[str, Any] | None :
    """
    Returns the report for a specific URL.
    """
    if not validate.is_valid_url(url) :
        logging.error("Invalid URL format")
        raise ValueError("Invalid URL format")

    url = f"{BASE_URL}/url/{url}"

    data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Get_URL_History(url : str) -> dict[str, Any] | None :
    """
    Returns the history for a specific URL.
    """
    if not validate.is_valid_url(url) :
        logging.error("Invalid URL format")
        raise ValueError("Invalid URL format")

    url = f"{BASE_URL}/url/history/{url}"

    data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Get_Malware_for_URL(url : str) -> dict[str, Any] | None :
    """
    Returns the malware for a specific URL.
    """
    if not validate.is_valid_url(url) :
        logging.error("Invalid URL format")
        raise ValueError("Invalid URL format")

    url = f"{BASE_URL}/url/malware/{url}"

    data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Get_URL_Updates(category : str, pull_id : int | None = None) -> dict[str, Any] | None :
    """
    Returns the updates for a specific URL.
    """

    url = f"{BASE_URL}/url/updates"

    query = {
        "category": category,
        "pull_id": pull_id,
    }

    # Remove None values from params
    query = {k: v for k, v in query.items() if v}

    data = await requests.make_get_request_with_params(url, query, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Get_URL_category_list() -> dict[str, Any] | None :
    """
    Returns the list of URL categories.
    """
    url = f"{BASE_URL}/url/categories"

    data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

# Vulnerabilities

@mcp.tool()
async def Get_Recent_Vulnerabilities(startDate : str | None = None, endDate : str | None = None, descending : str | None = None, limit : int | None = None, skip : int | None = None) -> dict[str, Any] | None :
    """
    Returns the recent vulnerabilities.
    """

    url = f"{BASE_URL}/vulnerabilities/"

    if startDate and not validate.is_valid_date(startDate):
        logging.error("Invalid startDate")
        raise ValueError("Invalid startDate")
        
    if endDate and not validate.is_valid_date(endDate):
        logging.error("Invalid endDate")
        raise ValueError("Invalid endDate")

    if limit is not None and not isinstance(limit, int) :
        logging.error("Invalid limit format")
        raise ValueError("Invalid type - required int , received {type(limit)}")

    if skip is not None and not isinstance(skip, int) :
        logging.error("Invalid skip format")
        raise ValueError("Invalid type - required int , received {type(skip)}")

    if descending and descending != "true" and descending != "false":
        logging.error("Invalid descending format")
        raise ValueError("Invalid descending value, must be 'true' or 'false'")

    query = {
        "startDate": startDate,
        "endDate": endDate,
        "descending": descending,
        "limit": limit,
        "skip": skip,
    }

    # Remove None values from params
    query = {k: v for k, v in query.items() if v}

    data = await requests.make_get_request_with_params(url, query, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Get_updated_Vulnerabilities(startDate : str | None = None, endDate : str | None = None, descending : str | None = None, limit : int | None = None, skip : int | None = None) -> dict[str, Any] | None :
    """
    Returns a list of vulnerabilities that were updated
    """
    url = f"{BASE_URL}/vulnerabilities/change"

    if startDate and not validate.is_valid_date(startDate):
        logging.error("Invalid startDate")
        raise ValueError("Invalid startDate")

    if endDate and not validate.is_valid_date(endDate):
        logging.error("Invalid endDate")
        raise ValueError("Invalid endDate")

    if limit is not None and not isinstance(limit, int) :
        logging.error("Invalid limit format")
        raise ValueError(f"Invalid type - required int , received {type(limit)}")

    if skip is not None and not isinstance(skip, int) :
        logging.error("Invalid skip format")
        raise ValueError(f"Invalid type - required int , received {type(skip)}")

    if descending and descending != "true" and descending != "false":
        logging.error("Invalid descending format")
        raise ValueError("Invalid descending value, must be 'true' or 'false'")

    query = {
        "startDate": startDate,
        "endDate": endDate,
        "descending": descending,
        "limit": limit,
        "skip": skip,
    }

    # Remove None values from params
    query = {k: v for k, v in query.items() if v}

    data = await requests.make_get_request_with_params(url, query, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Search_Vulnerabilities(q : str, startDate : str | None = None, endDate : str | None = None, bookmark : str | None = None) -> dict[str, Any] | None :
    """
    Returns a list of vulnerabilities that match the query
    """
    url = f"{BASE_URL}/vulnerabilities/fulltext"

    if startDate and not validate.is_valid_date(startDate):
        logging.error("Invalid startDate")
        raise ValueError("Invalid startDate")

    if endDate and not validate.is_valid_date(endDate):
        logging.error("Invalid endDate")
        raise ValueError("Invalid endDate")

    query = {
        "q": q,
        "startDate": startDate,
        "endDate": endDate,
        "bookmark": bookmark,
    }

    # Remove None values from params
    query = {k: v for k, v in query.items() if v}

    data = await requests.make_get_request_with_params(url, query, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Get_by_XFID(xfid : str) -> dict[str, Any] | None :
    """
    Returns the vulnerability associated with the entered xfdbid.
    """
    url = f"{BASE_URL}/vulnerabilities/{xfid}"

    data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Get_by_STDCODE(stdcode : str) -> dict[str, Any] | None :
    """
    Returns the vulnerability associated with the entered stdcode.
    """
    url = f"{BASE_URL}/vulnerabilities/{stdcode}"

    data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Get_by_Microsoft_Security_Bulletein_ID(msid : str) -> dict[str, Any] | None :
    """
    Returns the vulnerability associated with the entered msbid.
    """
    url = f"{BASE_URL}/vulnerabilities/{msid}"

    data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

# WHOIS

@mcp.tool()
async def Get_WHOIS_Information(host : str) -> dict[str, Any] | None :
    """
    Returns the WHOIS information for the entered domain.
    """
    url = f"{BASE_URL}/whois/{host}"

    data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data


# Protection Feed

@mcp.tool()
async def Anonymization_Services_IPv4() -> dict[str, Any] | None :
    """
    Returns a list of IPv4 addresses that are categorized as anonymization services.
    """
    url = f"{BASE_URL}/xfti/anonsvcs/ipv4"

    data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Anonymization_Services_IPv6() -> dict[str, Any] | None :
    """
    Returns a list of IPv6 addresses that are categorized as anonymization services.
    """
    url = f"{BASE_URL}/xfti/anonsvcs/ipv6"

    data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Anonymization_Services_URL() -> dict[str, Any] | None :
    """
    Returns a list of URLs that are categorized as anonymization services.
    """
    url = f"{BASE_URL}/xfti/anonsvcs/url"

    data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Botnet_CnC_Servers_IPv4() -> dict[str, Any] | None :
    """
    Returns a list of IPv4 addresses that are categorized as botnet CnC servers.
    """
    url = f"{BASE_URL}/xfti/c2server/ipv4"

    data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Botnet_CnC_Servers_IPv6() -> dict[str, Any] | None :
    """
    Returns a list of IPv6 addresses that are categorized as botnet CnC servers.
    """
    url = f"{BASE_URL}/xfti/c2server/ipv6"

    data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Botnet_CnC_Servers_URL() -> dict[str, Any] | None :
    """
    Returns a list of URLs that are categorized as botnet CnC servers.
    """
    url = f"{BASE_URL}/xfti/c2server/url"

    data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Bots_IPv4() -> dict[str, Any] | None :
    """
    Returns a list of IPv4 addresses that are categorized as bots.
    """
    url = f"{BASE_URL}/xfti/bots/ipv4"

    data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Bots_IPv6() -> dict[str, Any] | None :
    """
    Returns a list of IPv6 addresses that are categorized as bots.
    """
    url = f"{BASE_URL}/xfti/bots/ipv6"

    data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Cryptocurrency_mining_IPv4() -> dict[str, Any] | None :
    """
    Returns a list of IPv4 addresses that are categorized as cryptocurrency mining.
    """
    url = f"{BASE_URL}/xfti/cryptomining/ipv4"

    data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data 

@mcp.tool()
async def Cryptocurrency_mining_IPv6() -> dict[str, Any] | None :
    """
    Returns a list of IPv6 addresses that are categorized as cryptocurrency mining.
    """
    url = f"{BASE_URL}/xfti/cryptomining/ipv6"

    data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data 

@mcp.tool()
async def Cryptocurrency_mining_URL() -> dict[str, Any] | None :
    """
    Returns a list of URLs that are categorized as cryptocurrency mining.
    """
    url = f"{BASE_URL}/xfti/cryptomining/url"

    data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data 

@mcp.tool()
async def Early_Warning_URL() -> dict[str, Any] | None :
    """
    Returns a list of URLs that are categorized as early warning.
    """
    url = f"{BASE_URL}/xfti/ew/url"

    data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data 

@mcp.tool()
async def Malware_IPv4() -> dict[str, Any] | None :
    """
    Returns a list of IPv4 addresses that are categorized as malware.
    """
    url = f"{BASE_URL}/xfti/mw/ipv4"

    data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data 

@mcp.tool()
async def Malware_IPv6() -> dict[str, Any] | None :
    """
    Returns a list of IPv6 addresses that are categorized as malware.
    """
    url = f"{BASE_URL}/xfti/mw/ipv6"

    data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data 

@mcp.tool()
async def Malware_URL() -> dict[str, Any] | None :
    """
    Returns a list of URLs that are categorized as malware.
    """
    url = f"{BASE_URL}/xfti/mw/url"

    data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data 

@mcp.tool()
async def Phishing_URL() -> dict[str, Any] | None :
    """
    Returns a list of URLs that are categorized as phishing.
    """
    url = f"{BASE_URL}/xfti/phishing/url"

    data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data 

@mcp.tool()
async def Scanning_IPs_IPv4() -> dict[str, Any] | None :
    """
    Returns a list of IPv4 addresses that are categorized as scanning IPs.
    """
    url = f"{BASE_URL}/xfti/scanning/ipv4"

    data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data 

@mcp.tool()
async def Scanning_IPs_IPv6() -> dict[str, Any] | None :
    """
    Returns a list of IPv6 addresses that are categorized as scanning IPs.
    """
    url = f"{BASE_URL}/xfti/scanning/ipv6"

    data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data 

@mcp.tool()
async def Top_Activity_URL() -> dict[str, Any] | None :
    """
    Returns the top ten thousand URLs rated by activity as known by X-Force Exchange.
    """
    url = f"{BASE_URL}/xfti/topact/url/10k"

    data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Benign_IPv4() -> dict[str, Any] | None :
    """
    Returns a list of IPv4 addresses that are categorized as benign.
    """
    url = f"{BASE_URL}/xfti/benign/ipv4"

    data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Benign_IPv6() -> dict[str, Any] | None :
    """
    Returns a list of IPv6 addresses that are categorized as benign.
    """
    url = f"{BASE_URL}/xfti/benign/ipv6"

    data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Benign_URL() -> dict[str, Any] | None :
    """
    Returns a list of URLs that are categorized as benign.
    """
    url = f"{BASE_URL}/xfti/benign/url"

    data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

# Protection Feed TAXII2						

@mcp.tool()
async def Get_API_Root_information(UserAgent : str | None = None) -> dict[str, Any] | None :
    """
    This is the TAXII 2 root information endpoint.
    """
    url = f"{BASE_URL}/xfti/taxii2"

    if UserAgent :
        headers = {
            "User-Agent": UserAgent,
        }
        data = await requests.make_get_request_with_headers(url, headers, API_KEY)
    else :
        data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Get_Collections(UserAgent : str | None = None) -> dict[str, Any] | None :
    """
    This is the TAXII 2 collections endpoint.
    """
    url = f"{BASE_URL}/xfti/taxii2/collections"

    if UserAgent :
        headers = {
            "User-Agent": UserAgent,
        }
        data = await requests.make_get_request_with_headers(url, headers, API_KEY)
    else :
        data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Collection_metadata(CollectionID : str, UserAgent : str | None = None) -> dict[str, Any] | None :
    """
    This is the TAXII 2 collection metadata endpoint.
    """
    url = f"{BASE_URL}/xfti/taxii2/collections/{CollectionID}"    

    if UserAgent :
        headers = {
            "User-Agent": UserAgent,
        }
        data = await requests.make_get_request_with_headers(url, headers, API_KEY)
    else :
        data = await requests.make_get_request(url, API_KEY)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Collection_objects(CollectionID : str, UserAgent : str | None = None) -> dict[str, Any] | None :
    """
    This is the TAXII 2 collection objects endpoint.
    """
    url = f"{BASE_URL}/xfti/taxii2/collections/{CollectionID}/objects"    

    if UserAgent :
        headers = {
            "User-Agent": UserAgent,
        }
        data = await requests.make_get_request_with_headers(url, headers, API_KEY)
    else :
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
