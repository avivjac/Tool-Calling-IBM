import requests
import httpx
from mcp.server.fastmcp import FastMCP
from typing import Any
import logging
import base64

# ---------- Logging ----------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    filename="VitusTotal.log",
    filemode="a"
)

logger = logging.getLogger(__name__)

mcp = FastMCP("VirusTotal MCP", json_response=True)

BASE_URL = "https://www.virustotal.com/api/v3"
API_KEY = ""

# Helper function to make requests to VirusTotal API
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
            resp = await client.post(url, json = body,headers=headers, timeout=30.0)
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
            resp = await client.post(url, json = form, headers=headers, timeout=30.0)
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


# tools    

#IP adresses
class InvalidIPAddressError(Exception):
    pass


@mcp.tool()
async def Get_an_IP_address_report(IP : str) -> dict[str, Any] | None :
    """
    Get an IP address report from VirusTotal.
    """

    if not is_valid_ip(IP):
        raise InvalidIPAddressError(f"The IP address '{IP}' is not a valid address.")

    url = f"{BASE_URL}/ip_addresses/{IP}"
    data = await make_get_request(url)

    if data["error"]:
        logging.error(f"Error in VT IP report: {data['error']}")

    logging.info("return: {data}")
    return data



@mcp.tool()
async def Request_an_IP_address_rescan(IP : str) -> dict[str, Any] | None :
    """
    Request an IP address rescan from VirusTotal.
    example: IP=' """

    if not is_valid_ip(IP):
        raise InvalidIPAddressError(f"The IP address '{IP}' is not a valid address.")

    url = f"{BASE_URL}/ip_addresses/{IP}/analyse"
    data = await make_post_request(url)

    if data["error"]:
        logging.error(f"Error in VT IP report: {data['error']}")
    
    logging.info("return: {data}")
    return data


@mcp.tool()
async def Get_comments_on_an_IP_address(IP : str, limit : int | None = 10, cursor : str | None = None) -> dict[str, Any] | None :
    """
    Get comments on an IP address from VirusTotal.
    example: IP=' """

    if not is_valid_ip(IP):
        raise InvalidIPAddressError(f"The IP address '{IP}' is not a valid address.")

    params = {"limit": limit}

    if cursor:
        params["cursor"] = cursor

    url = f"{BASE_URL}/ip_addresses/{IP}/comments"
    data = await make_get_request_with_params(url, params)

    if data["error"]:
        logging.error(f"Error in VT IP report: {data['error']}")
    logging.info("return: {data}")
    return data


# @mcp.tool()
# async def Add_a_comment_to_an_IP_address(IP: str, comment: str) -> dict[str, Any] | None :
#     """
#     Add a comment to an IP address on VirusTotal.
#     example: IP=' ', comment='This is a test comment.'
#     """

#     if not is_valid_ip(IP):
#         raise InvalidIPAddressError(f"The IP address '{IP}' is not a valid address.")

#     url = f"{BASE_URL}/ip_addresses/{IP}/comments"
    
#     payload = {
#         "data": {
#             "type": "comment",
#             "attributes": {
#                 "text": comment
#             }
#         }
#     }

    data = await make_post_request_with_params(url, payload)

    if data["error"]:
        logging.error(f"Error in VT IP report: {data['error']}")
    logging.info("return: {data}")
    return data


@mcp.tool()
async def Get_objects_related_to_an_IP_address(IP : str, relationship : str, limit : int | None = 10, cursor : str | None = None) -> dict[str, Any] | None :
    """
    Get objects related to an IP address from VirusTotal.
    example: IP=' '
    """

    if not is_valid_ip(IP):
        raise InvalidIPAddressError(f"The IP address '{IP}' is not a valid address.")

    params = {"limit": limit}

    if cursor:
        params["cursor"] = cursor


    url = f"{BASE_URL}/ip_addresses/{IP}/{relationship}"
    data = await make_get_request_with_params(url, params)

    if data["error"]:
        logging.error(f"Error in VT IP report: {data['error']}")
    logging.info("return: {data}")
    return data

@mcp.tool()
async def Get_object_descriptors_related_to_an_IP_address(IP : str, relationship : str) -> dict[str, Any] | None :
    """
    Get object descriptors related to an IP address from VirusTotal.
    example: IP=' '
    """
    if not is_valid_ip(IP):
        raise InvalidIPAddressError(f"The IP address '{IP}' is not a valid address.")

    url = f"{BASE_URL}/ip_addresses/{IP}/relationships/{relationship}"
    data = await make_get_request(url)

    if data["error"]:
        logging.error(f"Error in VT IP report: {data['error']}")
    logging.info("return: {data}")
    return data


@mcp.tool()
async def Get_votes_on_an_IP_address(IP : str) -> dict[str, Any] | None :
    """
    Get votes on an IP address from VirusTotal.
    example: IP=' '
    """
    if not is_valid_ip(IP):
        raise InvalidIPAddressError(f"The IP address '{IP}' is not a valid address.")

    url = f"{BASE_URL}/ip_addresses/{IP}/votes"
    data = await make_get_request(url)

    if data["error"]:
        logging.error(f"Error in VT IP report: {data['error']}")
    logging.info("return: {data}")
    return data


# @mcp.tool()
# async def Add_a_vote_to_an_IP_address(IP: str, vote: dict[str, Any]) -> dict[str, Any] | None :
#     """
#     Add a vote to an IP address on VirusTotal.
#     example: IP=' ', vote={'verdict': 'malicious'}
#     """
#     if not is_valid_ip(IP):
#         raise InvalidIPAddressError(f"The IP address '{IP}' is not a valid address.")

#     url = f"{BASE_URL}/ip_addresses/{IP}/votes"
    
#     payload = {
#         "data": {
#             "type": "vote",
#             "attributes": {
#     	        "verdict": vote
#             }
#         }
#     }

#     data = await make_post_request_with_params(url, payload)

#     if data["error"]:
#         logging.error(f"Error in VT IP report: {data['error']}")
#     logging.info("return: {data}")
#     return data



#Domains & Resolutions
class InvalidDomainError(Exception):
    pass

@mcp.tool()
async def Get_a_domain_report(domain: str) -> dict[str, Any] | None:
    """
    Get a domain report from VirusTotal.
    example: domain='example.com'
    """
    if not is_valid_domain(domain):
        raise InvalidDomainError(f"The domain '{domain}' is not a valid domain.")

    url = f"{BASE_URL}/domains/{domain}"
    data = await make_get_request(url)

    if data["error"]:
        logging.error(f"Error in Domain report: {data['error']}")
    logging.info("return: {data}")
    return data


@mcp.tool()
async def Request_an_domain_rescan(domain: str) -> dict[str, Any] | None:
    """
    Request a domain rescan from VirusTotal.
    example: domain='example.com'
    """
    if not is_valid_domain(domain):
        raise InvalidDomainError(f"The domain '{domain}' is not a valid domain.")
    
    url = f"{BASE_URL}/domains/{domain}/analyse"
    data = await make_post_request(url)

    if data["error"]:
        logging.error(f"Error in Domain report: {data['error']}")
    logging.info("return: {data}")
    return data


@mcp.tool()
async def Get_comments_on_a_domain(domain: str, limit: int | None = 10, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get comments on a domain from VirusTotal.
    example: domain='example.com'
    """
    if not is_valid_domain(domain):
        raise InvalidDomainError(f"The domain '{domain}' is not a valid domain.")
    
    params = {"limit": limit}

    if cursor:
        params["cursor"] = cursor

    url = f"{BASE_URL}/domains/{domain}/comments"
    data = await make_get_request(url, params)

    if data["error"]:
        logging.error(f"Error in Domain report: {data['error']}")
    logging.info("return: {data}")
    return data


# @mcp.tool()
# async def Add_a_comment_to_a_domain(domain: str, comment: str) -> dict[str, Any] | None:
#     """
#     Add a comment to a domain on VirusTotal.
#     example: domain='example.com', comment='This is a test comment.'
#     """
#     if not is_valid_domain(domain):
#         raise InvalidDomainError(f"The domain '{domain}' is not a valid domain.")
#     url = f"{BASE_URL}/domains/{domain}/comments"
    
#     payload = {
#         "data": {
#             "type": "comment",
#             "attributes": {
#                 "text": comment
#             }
#         }
#     }

#     data = await make_post_request(url, payload)

#     if data["error"]:
#         logging.error(f"Error in Domain report: {data['error']}")
#     logging.info("return: {data}")
#     return data


@mcp.tool()
async def Get_objects_related_to_a_domain(domain: str, relationship: str, limit: int | None = 10, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get objects related to a domain from VirusTotal.
    example: domain='example.com'
    """
    if not is_valid_domain(domain):
        raise InvalidDomainError(f"The domain '{domain}' is not a valid domain.")
    
    params = {"limit": limit}

    if cursor:
        params["cursor"] = cursor
    
    url = f"{BASE_URL}/domains/{domain}/{relationship}"
    data = await make_get_request(url, params)

    if data["error"]:
        logging.error(f"Error in Domain report: {data['error']}")
    logging.info("return: {data}")
    return data


@mcp.tool()
async def Get_object_descriptors_related_to_a_domain(domain: str, relationship: str, limit: int | None = 10, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get object descriptors related to a domain from VirusTotal.
    example: domain='example.com'
    """
    if not is_valid_domain(domain):
        raise InvalidDomainError(f"The domain '{domain}' is not a valid domain.")
    
    params = {"limit": limit}

    if cursor:
        params["cursor"] = cursor

    url = f"{BASE_URL}/domains/{domain}/relationships/{relationship}"
    data = await make_get_request(url, params)

    if data["error"]:
        logging.error(f"Error in Domain report: {data['error']}")
    logging.info("return: {data}")
    return data


@mcp.tool()
async def Get_a_DNS_resolution_object(domain: str) -> dict[str, Any] | None:
    """
    Get a DNS resolution object from VirusTotal.
    example: domain='example.com'
    """
    if not is_valid_domain(domain):
        raise InvalidDomainError(f"The domain '{domain}' is not a valid domain.")
    
    url = f"{BASE_URL}/resolutions/{domain}"
    data = await make_get_request(url)

    if data["error"]:
        logging.error(f"Error in Domain report: {data['error']}")
    logging.info("return: {data}")
    return data


@mcp.tool()
async def Get_votes_on_a_domain(domain: str) -> dict[str, Any] | None:
    """
    Get votes on a domain from VirusTotal.
    example: domain='example.com'
    """
    if not is_valid_domain(domain):
        raise InvalidDomainError(f"The domain '{domain}' is not a valid domain.")
    
    url = f"{BASE_URL}/domains/{domain}/votes"
    data = await make_get_request(url)

    if data["error"]:
        logging.error(f"Error in Domain report: {data['error']}")
    logging.info("return: {data}")
    return data


# @mcp.tool()
# async def Add_a_vote_to_a_domain(domain: str, verdict : str) -> dict[str, Any] | None:
#     """
#     Add a vote to a domain on VirusTotal.
#     example: domain='example.com', verdict='malicious'
#     """
#     if not is_valid_domain(domain):
#         raise InvalidDomainError(f"The domain '{domain}' is not a valid domain.")
    
#     url = f"{BASE_URL}/domains/{domain}/votes"
    
#     payload = {
#         "data": {
#             "type": "vote",
#             "attributes": {
#                 "verdict": verdict
#             }
#         }
#     }

#     data = await make_post_request(url, payload)

#     if data["error"]:
#         logging.error(f"Error in Domain report: {data['error']}")
#     logging.info("return: {data}")
#     return data



#Files

@mcp.tool()
async def Upload_a_file(file_path: str, password: str | None = None) -> dict[str, Any] | None:
    """
    Upload and scan a file using VirusTotal.
    """
    url = f"{BASE_URL}/files"

    body = {
        "data": {
            "type": "file_upload",
            "attributes": {
                "file_path": file_path
            }
        }
    }

    if password:
        body["data"]["attributes"]["password"] = password

    data = await make_post_request_with_params(url, body)
    if data["error"]:
        logging.error(f"Error in VT File report: {data['error']}")
    logging.info("return: {data}")
    return data



@mcp.tool()
async def Get_a_URL_for_uploading_large_files() -> dict[str, Any] | None:
    """
    Get a temporary upload URL for large files (>32MB).
    """
    url = f"{BASE_URL}/files/upload_url"
    data = await make_get_request(url)

    if data["error"]:
        logging.error(f"Error in VT File report: {data['error']}")
    logging.info("return: {data}")
    return data



@mcp.tool()
async def Get_a_file_report(file_id: str) -> dict[str, Any] | None:
    """
    Get a file report from VirusTotal.
    example: file_id='44d88612fea8a8f36de82e1278abb02f'
    """
    url = f"{BASE_URL}/files/{file_id}"
    data = await make_get_request(url)

    if data["error"]:
        logging.error(f"Error in VT File report: {data['error']}")
    logging.info("return: {data}")
    return data




@mcp.tool()
async def Request_a_file_rescan(file_id: str) -> dict[str, Any] | None:
    """
    Request a rescan (analysis) of a file on VirusTotal.
    """
    url = f"{BASE_URL}/files/{file_id}/analyse"
    data = await make_post_request(url)

    if data["error"]:
        logging.error(f"Error in VT File report: {data['error']}")
    logging.info("return: {data}")
    return data



@mcp.tool()
async def Get_comments_on_a_file(file_id: str, limit: int | None = 10, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get comments on a file.
    """
    params = {"limit": limit}

    if cursor:
        params["cursor"] = cursor

    url = f"{BASE_URL}/files/{file_id}/comments"
    data = await make_get_request_with_params(url, params)

    if data["error"]:
        logging.error(f"Error in VT File report: {data['error']}")
    logging.info("return: {data}")
    return data



# @mcp.tool()
# async def Add_a_comment_to_a_file(file_id: str, comment: str) -> dict[str, Any] | None:
#     """
#     Add a comment to a file.
#     """
#     url = f"{BASE_URL}/files/{file_id}/comments"

#     payload = {
#         "data": {
#             "type": "comment",
#             "attributes": {
#                 "text": comment
#             }
#         }
#     }

#     data = await make_post_request_with_params(url, payload)

#     if data["error"]:
#         logging.error(f"Error in VT File report: {data['error']}")
#     logging.info("return: {data}")
#     return data



@mcp.tool()
async def Get_objects_related_to_a_file(file_id: str, relationship: str, limit: int | None = 10, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get objects related to a file.
    """
    params = {"limit": limit}

    if cursor:
        params["cursor"] = cursor

    url = f"{BASE_URL}/files/{file_id}/{relationship}"
    data = await make_get_request_with_params(url, params)

    if data["error"]:
        logging.error(f"Error in VT File report: {data['error']}")
    logging.info("return: {data}")
    return data



@mcp.tool()
async def Get_object_descriptors_related_to_a_file(file_id: str, relationship: str) -> dict[str, Any] | None:
    """
    Get object descriptors related to a file.
    """
    url = f"{BASE_URL}/files/{file_id}/relationships/{relationship}"
    data = await make_get_request(url)

    if data["error"]:
        logging.error(f"Error in VT File report: {data['error']}")
    logging.info("return: {data}")
    return data



@mcp.tool()
async def Get_a_crowdsourced_Sigma_rule_object(rule_id: str) -> dict[str, Any] | None:
    """
    Get a crowdsourced Sigma rule object.
    """
    url = f"{BASE_URL}/sigma_rules/{rule_id}"
    data = await make_get_request(url)

    if data["error"]:
        logging.error(f"Error in VT File report: {data['error']}")
    logging.info("return: {data}")
    return data


@mcp.tool()
async def Get_a_crowdsourced_YARA_ruleset(ruleset_id: str) -> dict[str, Any] | None:
    """
    Get a crowdsourced YARA ruleset.
    """
    url = f"{BASE_URL}/yara_rulesets/{ruleset_id}"
    data = await make_get_request(url)

    if data["error"]:
        logging.error(f"Error in VT File report: {data['error']}")
    logging.info("return: {data}")
    return data



@mcp.tool()
async def Get_votes_on_a_file(file_id: str, limit: int | None = 10, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get votes on a file.
    """
    params = {"limit": limit}

    if cursor:
        params["cursor"] = cursor

    url = f"{BASE_URL}/files/{file_id}/votes"
    data = await make_get_request_with_params(url, params)

    if data["error"]:
        logging.error(f"Error in VT File report: {data['error']}")
    logging.info("return: {data}")
    return data



# @mcp.tool()
# async def Add_a_vote_to_a_file(file_id: str, vote: str) -> dict[str, Any] | None:
#     """
#     Add a vote to a file.
#     example: vote='malicious' or 'harmless'
#     """
#     url = f"{BASE_URL}/files/{file_id}/votes"

#     payload = {
#         "data": {
#             "type": "vote",
#             "attributes": {
#                 "verdict": vote
#             }
#         }
#     }

#     data = await make_post_request_with_params(url, payload)

#     if data["error"]:
#         logging.error(f"Error in VT File report: {data['error']}")
#     logging.info("return: {data}")
#     return data


#File Behaviours
@mcp.tool()
async def Get_a_summary_of_all_behavior_reports_for_a_file(file_id: str) -> dict[str, Any] | None:
    """
    Get a summary of all behavior reports for a file.
    """
    url = f"{BASE_URL}/files/{file_id}/behaviour_summary"
    data = await make_get_request(url)

    if data["error"]:
        logging.error(f"Error in VT File Behaviours report: {data['error']}")
    logging.info("return: {data}")
    return data



@mcp.tool()
async def Get_a_summary_of_all_MITRE_ATTACK_techniques_observed_in_a_file(file_id: str) -> dict[str, Any] | None:
    """
    Get MITRE ATT&CK techniques summary observed in a file.
    """
    url = f"{BASE_URL}/files/{file_id}/behaviour_mitre_trees"
    data = await make_get_request(url)

    if data["error"]:
        logging.error(f"Error in VT File Behaviours report: {data['error']}")
    logging.info("return: {data}")
    return data


@mcp.tool()
async def Get_all_behavior_reports_for_a_file(file_id: str) -> dict[str, Any] | None:
    """
    Get all behaviour reports for a file.
    """
    url = f"{BASE_URL}/files/{file_id}/behaviours"
    data = await make_get_request(url)

    if data["error"]:
        logging.error(f"Error in VT File Behaviours report: {data['error']}")
    logging.info("return: {data}")
    return data


@mcp.tool()
async def Get_a_file_behaviour_report_from_a_sandbox(sandbox_id: str) -> dict[str, Any] | None:
    """
    Get a file behaviour report from a specific sandbox.
    """
    url = f"{BASE_URL}/file_behaviours/{sandbox_id}"
    data = await make_get_request(url)

    if data["error"]:
        logging.error(f"Error in VT File Behaviours report: {data['error']}")
    logging.info("return: {data}")
    return data


@mcp.tool()
async def Get_objects_related_to_a_behaviour_report(sandbox_id: str, relationship: str, limit: int | None = 10, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get objects related to a behaviour report.
    """
    params = {"limit": limit}
    if cursor:
        params["cursor"] = cursor

    url = f"{BASE_URL}/file_behaviours/{sandbox_id}/{relationship}"
    data = await make_get_request_with_params(url, params)

    if data["error"]:
        logging.error(f"Error in VT File Behaviours report: {data['error']}")
    logging.info("return: {data}")
    return data



@mcp.tool()
async def Get_object_descriptors_related_to_a_behaviour_report(sandbox_id: str, relationship: str, limit: int | None = 10, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get object descriptors related to a behaviour report.
    """
    params = {"limit": limit}
    if cursor:
        params["cursor"] = cursor

    url = f"{BASE_URL}/file_behaviours/{sandbox_id}/relationships/{relationship}"
    data = await make_get_request_with_params(url, params)

    if data["error"]:
        logging.error(f"Error in VT File Behaviours report: {data['error']}")
    logging.info("return: {data}")
    return data


@mcp.tool()
async def Get_a_detailed_HTML_behaviour_report(sandbox_id: str) -> dict[str, Any] | None:
    """
    Get a detailed HTML behaviour report for a sandbox behaviour ID.
    """
    url = f"{BASE_URL}/file_behaviours/{sandbox_id}/html"
    data = await make_get_request(url)

    if data["error"]:
        logging.error(f"Error in VT File Behaviours report: {data['error']}")
    logging.info("return: {data}")
    return data



#URLs
class InvalidURLError(Exception):
    pass


@mcp.tool()
async def Scan_URL(url: str) -> dict[str, Any] | None:
    """
    Scan / analyze a URL using VirusTotal.
    """
    if not is_valid_url(url):
        raise InvalidURLError(f"The URL '{url}' is not valid.")

    endpoint = f"{BASE_URL}/urls"
    form_data = {"url": url}

    data = await make_post_request_form(endpoint, form_data)

    if data["error"]:
        logging.error(f"Error in VT URL scan: {data['error']}")
    logging.info("return: {data}")
    return data


@mcp.tool()
async def Get_a_URL_report(url_id: str) -> dict[str, Any] | None:
    """
    Get a URL analysis report.
    Example url_id: a hash returned from Scan_URL
    """
    url = f"{BASE_URL}/urls/{url_id}"
    data = await make_get_request(url)

    if data["error"]:
        logging.error(f"Error in VT URL report: {data['error']}")
    logging.info("return: {data}")
    return data


@mcp.tool()
async def Request_a_URL_rescan(url_id: str) -> dict[str, Any] | None:
    """
    Request a rescan (re-analysis) for a URL.
    """
    endpoint = f"{BASE_URL}/urls/{url_id}/analyse"
    data = await make_post_request(endpoint)

    if data["error"]:
        logging.error(f"Error in VT URL rescan: {data['error']}")
    logging.info("return: {data}")
    return data


@mcp.tool()
async def Get_comments_on_a_URL(url_id: str, limit: int | None = 10, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get comments for a URL.
    """
    params = {"limit": limit}
    if cursor:
        params["cursor"] = cursor

    url = f"{BASE_URL}/urls/{url_id}/comments"
    data = await make_get_request_with_params(url, params)

    if data["error"]:
        logging.error(f"Error fetching VT URL comments: {data['error']}")
    logging.info("return: {data}")
    return data


# @mcp.tool()
# async def Add_a_comment_on_a_URL(url_id: str, comment: str) -> dict[str, Any] | None:
#     """
#     Add a comment to a URL.
#     """
#     url = f"{BASE_URL}/urls/{url_id}/comments"

#     payload = {
#         "data": {
#             "type": "comment",
#             "attributes": {
#                 "text": comment
#             }
#         }
#     }

#     data = await make_post_request_with_params(url, payload)

#     if data["error"]:
#         logging.error(f"Error adding VT URL comment: {data['error']}")
#     logging.info("return: {data}")
#     return data



@mcp.tool()
async def Get_objects_related_to_a_URL(url_id: str, relationship: str, limit: int | None = 10, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get objects related to a URL.
    """
    params = {"limit": limit}
    if cursor:
        params["cursor"] = cursor

    url = f"{BASE_URL}/urls/{url_id}/{relationship}"
    data = await make_get_request_with_params(url, params)

    if data["error"]:
        logging.error(f"Error fetching related VT URL objects: {data['error']}")
    logging.info("return: {data}")
    return data


@mcp.tool()
async def Get_object_descriptors_related_to_a_URL(url_id: str, relationship: str, limit: int | None = 10, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get object descriptors related to a URL.
    """
    params = {"limit": limit}
    if cursor:
        params["cursor"] = cursor

    url = f"{BASE_URL}/urls/{url_id}/relationships/{relationship}"
    data = await make_get_request_with_params(url, params)

    if data["error"]:
        logging.error(f"Error fetching VT URL relationship descriptors: {data['error']}")
    logging.info("return: {data}")
    return data


@mcp.tool()
async def Get_votes_on_a_URL(url_id: str, limit: int | None = 10, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get votes for a URL.
    """
    params = {"limit": limit}
    if cursor:
        params["cursor"] = cursor

    url = f"{BASE_URL}/urls/{url_id}/votes"
    data = await make_get_request_with_params(url, params)

    if data["error"]:
        logging.error(f"Error fetching VT URL votes: {data['error']}")
    logging.info("return: {data}")
    return data


# @mcp.tool()
# async def Add_a_vote_on_a_URL(url_id: str, verdict: str) -> dict[str, Any] | None:
#     """
#     Add a vote on a URL.
#     verdict must be either 'harmless' or 'malicious'.
#     """
#     url = f"{BASE_URL}/urls/{url_id}/votes"

#     payload = {
#         "type": "vote",
#         "attributes": {
#             "verdict": verdict
#         }
#     }

#     data = await make_post_request_with_params(url, payload)

#     if data["error"]:
#         logging.error(f"Error adding VT URL vote: {data['error']}")
#     logging.info("return: {data}")
#     return data


#comments

@mcp.tool()
async def Get_latest_comments(limit: int | None = 10, filter: str | None = None, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get information about the latest comments added to VirusTotal.
    """
    params = {"limit": limit}
    if filter:
        params["filter"] = filter
    if cursor:
        params["cursor"] = cursor
    url = f"{BASE_URL}/comments"
    data = await make_get_request_with_params(url, params)
    if data["error"]:
        logging.error(f"Error in VT Comments report: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_a_comment_object(commentID: str, relationships: str | None = None) -> dict[str, Any] | None:
    """
    Get a comment object.
    """
    url = f"{BASE_URL}/comments/{commentID}"
    
    if relationships:
        params = {"relationships": relationships}
        data = await make_get_request_with_params(url, params)
    else:
        data = await make_get_request(url)
    if data["error"]:
        logging.error(f"Error in VT Comments report: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_objects_related_to_a_comment(commentID: str, relationship: str) -> dict[str, Any] | None:
    """
    Get objects related to a comment.
    """
    url = f"{BASE_URL}/comments/{commentID}/{relationship}"
    data = await make_get_request(url)

    if data["error"]:
        logging.error(f"Error in VT Comments report: {data['error']}")
    logging.info(f"return: {data}")
    return data



@mcp.tool()
async def Get_object_descriptors_related_to_a_comment(commentID: str, relationship: str, limit: int | None = 10, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get object descriptors related to a comment.
    """
    params = {"limit": limit}

    if cursor:
        params["cursor"] = cursor

    url = f"{BASE_URL}/comments/{commentID}/relationships/{relationship}"
    data = await make_get_request_with_params(url, params)

    if data["error"]:
        logging.error(f"Error in VT Comments report: {data['error']}")
    logging.info(f"return: {data}")
    return data


#Analyses, Submissions & Operations

@mcp.tool()
async def Get_a_URL_file_analysis(ID: str) -> dict[str, Any] | None:
    """
    Get a URL / file analysis.
    """
    url = f"{BASE_URL}/analyses/{ID}"
    data = await make_get_request(url)
    if data["error"]:
        logging.error(f"Error in VT Analyses report: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_objects_related_to_an_analysis(ID: str, relationship: str) -> dict[str, Any] | None:
    """
    Get objects related to an analysis.
    """
    url = f"{BASE_URL}/analyses/{ID}/{relationship}"
    data = await make_get_request(url)
    if data["error"]:
        logging.error(f"Error in VT Analyses report: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_object_descriptors_related_to_an_analysis(ID: str, relationship: str) -> dict[str, Any] | None:
    """
    Get object descriptors related to an analysis.
    """
    url = f"{BASE_URL}/analyses/{ID}/relationships/{relationship}"
    data = await make_get_request(url)
    if data["error"]:
        logging.error(f"Error in VT Analyses report: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_a_submission_object(ID: str) -> dict[str, Any] | None:
    """
    Get a submission object.
    """
    url = f"{BASE_URL}/submission/{ID}"
    data = await make_get_request(url)
    if data["error"]:
        logging.error(f"Error in VT Submission report: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_an_operation_object(ID: str) -> dict[str, Any] | None:
    """
    Get an operation object.
    """
    url = f"{BASE_URL}/operations/{ID}"
    data = await make_get_request(url)
    if data["error"]:
        logging.error(f"Error in VT Operation report: {data['error']}")
    logging.info(f"return: {data}")
    return data


#Attack Tactics

@mcp.tool()
async def Get_an_attack_tactic_object(ID: str) -> dict[str, Any] | None:
    """
    Get an attack tactic object.
    """
    url = f"{BASE_URL}/attack_tactics/{ID}"
    data = await make_get_request(url)
    if data["error"]:
        logging.error(f"Error in VT Attack Tactic report: {data['error']}")
    logging.info(f"return: {data}")
    return data 


@mcp.tool()
async def Get_objects_related_to_an_attack_tactic(ID: str, relationship: str, limit: int | None = 10, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get objects related to an attack tactic.
    """
    params = {"limit": limit}
    if cursor:
        params["cursor"] = cursor
    url = f"{BASE_URL}/attack_tactics/{ID}/{relationship}"
    data = await make_get_request_with_params(url, params)
    if data["error"]:
        logging.error(f"Error in VT Attack Tactic report: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_object_descriptors_related_to_an_attack_tactic(ID: str, relationship: str, limit: int | None = 10, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get object descriptors related to an attack tactic.
    """
    params = {"limit": limit}
    if cursor:
        params["cursor"] = cursor
    url = f"{BASE_URL}/attack_tactics/{ID}/relationships/{relationship}"
    data = await make_get_request_with_params(url, params)
    if data["error"]:
        logging.error(f"Error in VT Attack Tactic report: {data['error']}")
    logging.info(f"return: {data}")
    return data


#Attack Techniques
@mcp.tool()
async def Get_an_attack_technique_object(ID: str) -> dict[str, Any] | None:
    """
    Get an attack technique object.
    """
    url = f"{BASE_URL}/attack_techniques/{ID}"
    data = await make_get_request(url)
    if data["error"]:
        logging.error(f"Error in VT Attack Technique report: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_objects_related_to_an_attack_technique(ID: str, relationship: str, limit: int | None = 10, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get objects related to an attack technique.
    """
    params = {"limit": limit}
    if cursor:
        params["cursor"] = cursor
    url = f"{BASE_URL}/attack_techniques/{ID}/{relationship}"
    data = await make_get_request_with_params(url, params)
    if data["error"]:
        logging.error(f"Error in VT Attack Technique report: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_object_descriptors_related_to_an_attack_technique(ID: str, relationship: str, limit: int | None = 10, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get object descriptors related to an attack technique.
    """
    params = {"limit": limit}
    if cursor:
        params["cursor"] = cursor
    url = f"{BASE_URL}/attack_techniques/{ID}/relationships/{relationship}"
    data = await make_get_request_with_params(url, params)
    if data["error"]:
        logging.error(f"Error in VT Attack Technique report: {data['error']}")
    logging.info(f"return: {data}")
    return data


#Popular Threat Categories

@mcp.tool()
async def Get_a_list_of_popular_threat_categories() -> dict[str, Any] | None:
    """
    Get a list of popular threat categories.
    """
    url = f"{BASE_URL}/popular_threat_categories"
    data = await make_get_request(url)
    if data["error"]:
        logging.error(f"Error in VT Popular Threat Categories report: {data['error']}")
    logging.info(f"return: {data}")
    return data


#Code Insights

@mcp.tool()
async def Analyse_code_blocks_with_Code_Insights(code: str, code_type: str = "decompiled") -> dict[str, Any] | None:
    """
    Analyse code blocks with Code Insights.
    """
    url = f"{BASE_URL}/codeinsights/analyse-binary"
    
    # We need to import base64 at the top of the file
    code_b64 = base64.b64encode(code.encode('utf-8')).decode('utf-8')
    
    payload = {
        "data": {
            "code": code_b64,
            "code_type": code_type
        }
    }
    
    data = await make_post_request_with_params(url, payload)
    
    if data["error"]:
        logging.error(f"Error in VT Code Insights: {data['error']}")
    logging.info(f"return: {data}")
    return data


#Search & Metadata
@mcp.tool()
async def Search_for_files_URLs_domains_IPs_and_comments(query: str) -> dict[str, Any] | None:
    """
    Search for files, URLs, domains, IPs and comments.
    """
    url = f"{BASE_URL}/search"
    params = {"query": query}
    data = await make_get_request_with_params(url, params)
    if data["error"]:
        logging.error(f"Error in VT Search: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_file_content_search_snippets(snippet: str) -> dict[str, Any] | None:
    """
    Get file content search snippets.
    """
    url = f"{BASE_URL}/intelligence/search/snippets/{snippet}"
    data = await make_get_request(url)
    if data["error"]:
        logging.error(f"Error in VT Intelligence Search Snippets: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_VirusTotal_metadata() -> dict[str, Any] | None:
    """
    Get VirusTotal metadata.
    """
    url = f"{BASE_URL}/metadata"
    data = await make_get_request(url)
    if data["error"]:
        logging.error(f"Error in VT Metadata: {data['error']}")
    logging.info(f"return: {data}")
    return data


#Collections

@mcp.tool()
async def Create_a_new_collection(data: dict[str, Any]) -> dict[str, Any] | None:
    """
    Create a new collection.
    """
    url = f"{BASE_URL}/collections"
    
    # The API expects the body to be {"data": <collection object>}
    payload = {"data": data}
    
    data = await make_post_request_with_params(url, payload)
    if data["error"]:
        logging.error(f"Error in VT Create Collection: {data['error']}")
    logging.info(f"return: {data}")
    return data
 

 @mcp.tool()
async def Get_a_collection(ID: str) -> dict[str, Any] | None:
    """
    Get a collection.
    """
    url = f"{BASE_URL}/collections/{ID}"
    data = await make_get_request(url)
    if data["error"]:
        logging.error(f"Error in VT Collection report: {data['error']}")
    logging.info(f"return: {data}")
    return data

  
  @mcp.tool()
async def Get_comments_on_a_collection(ID: str, limit: int | None = 10, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get comments on a collection.
    """
    params = {"limit": limit}
    if cursor:
        params["cursor"] = cursor
    url = f"{BASE_URL}/collections/{ID}/comments"
    data = await make_get_request_with_params(url, params)
    if data["error"]:
        logging.error(f"Error in VT Collection Comments: {data['error']}")
    logging.info(f"return: {data}")
    return data


 @mcp.tool()
async def Get_objects_related_to_a_collection(ID: str, relationship: str, limit: int | None = 10, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get objects related to a collection.
    """
    params = {"limit": limit}
    if cursor:
        params["cursor"] = cursor
    url = f"{BASE_URL}/collections/{ID}/{relationship}"
    data = await make_get_request_with_params(url, params)
    if data["error"]:
        logging.error(f"Error in VT Collection Objects: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_object_descriptors_related_to_a_collection(ID: str, relationship: str, limit: int | None = 10, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get object descriptors related to a collection.
    """
    params = {"limit": limit}
    if cursor:
        params["cursor"] = cursor
    url = f"{BASE_URL}/collections/{ID}/relationships/{relationship}"
    data = await make_get_request_with_params(url, params)
    if data["error"]:
        logging.error(f"Error in VT Collection Object Descriptors: {data['error']}")
    logging.info(f"return: {data}")
    return data


#Zipping files

@mcp.tool()
async def Create_a_password_protected_ZIP_with_VirusTotal_files(hashes: list[str], password: str | None = None) -> dict[str, Any] | None:
    """
    Create a password-protected ZIP with VirusTotal files.
    """
    url = f"{BASE_URL}/intelligence/zip_files"
    
    data_content = {"hashes": hashes}
    if password:
        data_content["password"] = password
        
    payload = {"data": data_content}
    
    data = await make_post_request_with_params(url, payload)
    
    if data["error"]:
        logging.error(f"Error in VT Create ZIP: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Check_a_ZIP_file_s_status(ID: str) -> dict[str, Any] | None:
    """
    Check a ZIP file's status.
    """
    url = f"{BASE_URL}/intelligence/zip_files/{ID}"
    data = await make_get_request(url)
    
    if data["error"]:
        logging.error(f"Error in VT ZIP Status: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_a_ZIP_file_s_download_url(ID: str) -> dict[str, Any] | None:
    """
    Get a ZIP file's download URL.
    """
    url = f"{BASE_URL}/intelligence/zip_files/{ID}/download_url"
    data = await make_get_request(url)
    
    if data["error"]:
        logging.error(f"Error in VT ZIP Download URL: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Download_a_ZIP_file(ID: str) -> dict[str, Any] | None:
    """
    Download a ZIP file.
    """
    url = f"{BASE_URL}/intelligence/zip_files/{ID}/download"
    data = await make_get_request(url)
    
    if data["error"]:
        logging.error(f"Error in VT ZIP Download: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Delete_a_ZIP_file(ID: str) -> dict[str, Any] | None:
    """
    Delete a ZIP file.
    """
    url = f"{BASE_URL}/intelligence/zip_files/{ID}"
    data = await make_delete_request(url)
    
    if data["error"]:
        logging.error(f"Error in VT ZIP Delete: {data['error']}")
    logging.info(f"return: {data}")
    return data


#YARA Rules
@mcp.tool()
async def List_Crowdsourced_YARA_Rules(limit: int | None = 10, filter: str | None = None, order: str | None = None, cursor: str | None = None) -> dict[str, Any] | None:
    """
    List Crowdsourced YARA Rules.
    ACCEPTED FILTERS: author, creation_date, enabled, included_date, last_modification_date, name, tag, threat_category.
    ACCEPTED ORDERS: matches, creation_date, included_date, modification_date (append + or - for asc/desc).
    """
    url = f"{BASE_URL}/yara_rules"

    params = {"limit": limit}
    if filter:
        params["filter"] = filter
    if order:
        params["order"] = order
    if cursor:
        params["cursor"] = cursor
        
    data = await make_get_request_with_params(url, params)
    
    if data["error"]:
        logging.error(f"Error in VT YARA Rules List: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_a_Crowdsourced_YARA_rule(ID: str) -> dict[str, Any] | None:
    """
    Get a Crowdsourced YARA rule.
    """
    url = f"{BASE_URL}/yara_rules/{ID}"
    data = await make_get_request(url)
    
    if data["error"]:
        logging.error(f"Error in VT YARA Rule: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_objects_related_to_a_Crowdsourced_YARA_rule(ID: str, relationship: str) -> dict[str, Any] | None:
    """
    Get objects related to a Crowdsourced YARA rule.
    """
    url = f"{BASE_URL}/yara_rules/{ID}/{relationship}"
    data = await make_get_request(url)
    
    if data["error"]:
        logging.error(f"Error in VT YARA Rule Objects: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_object_descriptors_related_to_a_Crowdsourced_YARA_rule(ID: str, relationship: str) -> dict[str, Any] | None:
    """
    Get object descriptors related to a Crowdsourced YARA rule.
    """
    url = f"{BASE_URL}/yara_rules/{ID}/relationships/{relationship}"
    data = await make_get_request(url)
    
    if data["error"]:
        logging.error(f"Error in VT YARA Rule Descriptors: {data['error']}")
    logging.info(f"return: {data}")
    return data


#IoC Stream

@mcp.tool()
async def Get_objects_from_the_IoC_Stream(limit: int | None = 10, descriptors_only: bool = False, filter: str | None = None, cursor: str | None = None, order: str | None = None) -> dict[str, Any] | None:
    """
    Get objects from the IoC Stream.
    The IoC stream endpoint returns different types of objects (files, URLs, domains, IP addresses).
    
    ALLOWED FILTERS:
    - date:2023-02-07T10:00:00+ (after)
    - date:2023-02-07- (before)
    - origin:hunting or origin:subscriptions
    - entity_id:objectId
    - entity_type:file (file, domain, url, ip_address)
    - source_type:hunting_ruleset (hunting_ruleset, retrohunt_job, collection, threat_actor)
    - source_id:objectId
    - notification_tag:ruleName
    
    ALLOWED ORDERS:
    - date- (default, most recent first)
    - date+ (oldest first)
    """
    url = f"{BASE_URL}/ioc_stream"
    
    params = {"limit": limit}
    if descriptors_only:
        params["descriptors_only"] = "true"
    if filter:
        params["filter"] = filter
    if cursor:
        params["cursor"] = cursor
    if order:
        params["order"] = order
        
    data = await make_get_request_with_params(url, params)
    
    if data["error"]:
        logging.error(f"Error in VT IoC Stream: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_an_IoC_Stream_notification(ID: str) -> dict[str, Any] | None:
    """
    Get an IoC Stream notification.
    """
    url = f"{BASE_URL}/ioc_stream_notifications/{ID}"
    data = await make_get_request(url)
    
    if data["error"]:
        logging.error(f"Error in VT IoC Stream Notification: {data['error']}")
    logging.info(f"return: {data}")
    return data


#VT Graph

@mcp.tool()
async def Search_graphs(limit: int | None = None, filter: str | None = None, cursor: str | None = None, order: str | None = None, attributes: str | None = None) -> dict[str, Any] | None:
    """
    Search graphs.
    
    SUPPORTED ORDER FIELDS: name, owner, creation_date, last_modification_date, views_count, comments_count.
    """
    url = f"{BASE_URL}/graphs"
    
    params = {}
    if limit:
        params["limit"] = limit
    if filter:
        params["filter"] = filter
    if cursor:
        params["cursor"] = cursor
    if order:
        params["order"] = order
    if attributes:
        params["attributes"] = attributes
        
    data = await make_get_request_with_params(url, params)
    
    if data["error"]:
        logging.error(f"Error in VT Search Graphs: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Create_a_graph(graph_content: dict[str, Any]) -> dict[str, Any] | None:
    """
    Create a graph.
    The graph_content should be the valid JSON structure for a VirusTotal graph.
    """
    url = f"{BASE_URL}/graphs"
    
    data = await make_post_request_with_params(url, graph_content)
    
    if data["error"]:
        logging.error(f"Error in VT Create Graph: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_a_graph_object(ID: str) -> dict[str, Any] | None:
    """
    Get a graph object.
    """
    url = f"{BASE_URL}/graphs/{ID}"
    data = await make_get_request(url)
    
    if data["error"]:
        logging.error(f"Error in VT Graph Object: {data['error']}")
    logging.info(f"return: {data}")
    return data

@mcp.tool()
async def Get_comments_on_a_graph(ID: str, limit: int | None = None, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get comments on a graph.
    """
    params = {}
    if limit:
        params["limit"] = limit
    if cursor:
        params["cursor"] = cursor
        
    url = f"{BASE_URL}/graphs/{ID}/comments"
    data = await make_get_request_with_params(url, params)
    
    if data["error"]:
        logging.error(f"Error in VT Graph Comments: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_objects_related_to_a_graph(ID: str, relationship: str, limit: int | None = None, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get objects related to a graph.
    """
    params = {}
    if limit:
        params["limit"] = limit
    if cursor:
        params["cursor"] = cursor
        
    url = f"{BASE_URL}/graphs/{ID}/{relationship}"
    data = await make_get_request_with_params(url, params)
    
    if data["error"]:
        logging.error(f"Error in VT Graph Related Objects: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_object_descriptors_related_to_a_graph(ID: str, relationship: str, limit: int | None = None, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get object descriptors related to a graph.
    """
    params = {}
    if limit:
        params["limit"] = limit
    if cursor:
        params["cursor"] = cursor
        
    url = f"{BASE_URL}/graphs/{ID}/relationships/{relationship}"
    data = await make_get_request_with_params(url, params)
    
    if data["error"]:
        logging.error(f"Error in VT Graph Related Descriptors: {data['error']}")
    logging.info(f"return: {data}")
    return data


#VT Graph Permissions & ACL

@mcp.tool()
async def Get_users_and_groups_that_can_view_a_graph(ID: str, limit: int | None = None, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get users and groups that can view a graph.
    """
    params = {}
    if limit:
        params["limit"] = limit
    if cursor:
        params["cursor"] = cursor
        
    url = f"{BASE_URL}/graphs/{ID}/relationships/viewers"
    data = await make_get_request_with_params(url, params)
    
    if data["error"]:
        logging.error(f"Error in VT Graph Viewers: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Check_if_a_user_or_group_can_view_a_graph(ID: str, user_or_group_id: str) -> dict[str, Any] | None:
    """
    Check if a user or group can view a graph.
    """
    url = f"{BASE_URL}/graphs/{ID}/relationships/viewers/{user_or_group_id}"
    data = await make_get_request(url)
    
    if data["error"]:
        logging.error(f"Error in VT Check Graph Viewer: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_users_and_groups_that_can_edit_a_graph(ID: str, limit: int | None = None, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get users and groups that can edit a graph.
    """
    params = {}
    if limit:
        params["limit"] = limit
    if cursor:
        params["cursor"] = cursor
        
    url = f"{BASE_URL}/graphs/{ID}/relationships/editors"
    data = await make_get_request_with_params(url, params)
    
    if data["error"]:
        logging.error(f"Error in VT Graph Editors: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Check_if_a_user_or_group_can_edit_a_graph(ID: str, user_or_group_id: str) -> dict[str, Any] | None:
    """
    Check if a user or group can edit a graph.
    """
    url = f"{BASE_URL}/graphs/{ID}/relationships/editors/{user_or_group_id}"
    data = await make_get_request(url)
    
    if data["error"]:
        logging.error(f"Error in VT Check Graph Editor: {data['error']}")
    logging.info(f"return: {data}")
    return data


#Zipping private files	
# 							
@mcp.tool()
async def Create_a_password_protected_ZIP_with_VirusTotal_private_files(hashes: list[str], password: str | None = None) -> dict[str, Any] | None:
    """
    Create a password-protected ZIP with VirusTotal private files.
    """
    url = f"{BASE_URL}/private/zip_files"
    
    body = {
        "data": {
            "hashes": hashes
        }
    }
    if password:
        body["data"]["password"] = password
        
    data = await make_post_request_with_params(url, body)
    
    if data["error"]:
        logging.error(f"Error in VT Create Private ZIP: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Check_a_ZIP_file_s_status(ID: str) -> dict[str, Any] | None:
    """
    Check a ZIP file's status.
    The status attribute contains one of: starting, creating, finished, timeout, error-starting, error-creating.
    """
    url = f"{BASE_URL}/private/zip_files/{ID}"
    data = await make_get_request(url)
    
    if data["error"]:
        logging.error(f"Error in VT ZIP Status: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_a_ZIP_file_s_download_url(ID: str) -> dict[str, Any] | None:
    """
    Get a ZIP file's download URL.
    Returns a signed URL. The URL expires after 1 hour.
    """
    url = f"{BASE_URL}/private/zip_files/{ID}/download_url"
    data = await make_get_request(url)
    
    if data["error"]:
        logging.error(f"Error in VT ZIP Download URL: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Download_a_ZIP_file(ID: str) -> dict[str, Any] | None:
    """
    Download a ZIP file.
    This endpoint redirects to the download URL.
    """
    url = f"{BASE_URL}/private/zip_files/{ID}/download"
    data = await make_get_request(url)
    
    if data["error"]:
        logging.error(f"Error in VT Download ZIP: {data['error']}")
    logging.info(f"return: {data}")
    return data


#User Management

@mcp.tool()
async def Get_a_user_object(ID: str) -> dict[str, Any] | None:
    """
    Get a user object.
    ID can be User ID or API key.
    """
    url = f"{BASE_URL}/users/{ID}"
    data = await make_get_request(url)
    
    if data["error"]:
        logging.error(f"Error in VT Get User: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_objects_related_to_a_user(ID: str, relationship: str, limit: int | None = 10, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get objects related to a user.
    """
    params = {"limit": limit}
    if cursor:
        params["cursor"] = cursor
        
    url = f"{BASE_URL}/users/{ID}/{relationship}"
    data = await make_get_request_with_params(url, params)
    
    if data["error"]:
        logging.error(f"Error in VT User Related Objects: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_object_descriptors_related_to_a_user(ID: str, relationship: str, limit: int | None = 10, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get object descriptors related to a user.
    """
    params = {"limit": limit}
    if cursor:
        params["cursor"] = cursor
        
    url = f"{BASE_URL}/users/{ID}/relationships/{relationship}"
    data = await make_get_request_with_params(url, params)
    
    if data["error"]:
        logging.error(f"Error in VT User Related Descriptors: {data['error']}")
    logging.info(f"return: {data}")
    return data


#Graph Management

@mcp.tool()
async def Get_a_group_object(ID: str) -> dict[str, Any] | None:
    """
    Get a group object.
    """
    url = f"{BASE_URL}/groups/{ID}"
    data = await make_get_request(url)
    
    if data["error"]:
        logging.error(f"Error in VT Get Group: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_administrators_for_a_group(ID: str) -> dict[str, Any] | None:
    """
    Get administrators for a group.
    """
    url = f"{BASE_URL}/groups/{ID}/relationships/administrators"
    data = await make_get_request(url)
    
    if data["error"]:
        logging.error(f"Error in VT Group Administrators: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Check_if_a_user_is_a_group_admin(group_id: str, user_id: str) -> dict[str, Any] | None:
    """
    Check if a user is a group admin.
    """
    url = f"{BASE_URL}/groups/{group_id}/relationships/administrators/{user_id}"
    data = await make_get_request(url)
    
    if data["error"]:
        logging.error(f"Error in VT Check Group Admin: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_group_users(ID: str) -> dict[str, Any] | None:
    """
    Get group users.
    """
    url = f"{BASE_URL}/groups/{ID}/relationships/users"
    data = await make_get_request(url)
    
    if data["error"]:
        logging.error(f"Error in VT Group Users: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Check_if_a_user_is_a_group_member(group_id: str, user_id: str) -> dict[str, Any] | None:
    """
    Check if a user is a group member.
    """
    url = f"{BASE_URL}/groups/{group_id}/relationships/users/{user_id}"
    data = await make_get_request(url)
    
    if data["error"]:
        logging.error(f"Error in VT Check Group Member: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_objects_related_to_a_group(ID: str, relationship: str, limit: int | None = None, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get objects related to a group.
    """
    params = {}
    if limit:
        params["limit"] = limit
    if cursor:
        params["cursor"] = cursor
        
    url = f"{BASE_URL}/groups/{ID}/{relationship}"
    data = await make_get_request_with_params(url, params)
    
    if data["error"]:
        logging.error(f"Error in VT Group Related Objects: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_object_descriptors_related_to_a_group(ID: str, relationship: str, limit: int | None = None, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get object descriptors related to a group.
    """
    params = {}
    if limit:
        params["limit"] = limit
    if cursor:
        params["cursor"] = cursor
        
    url = f"{BASE_URL}/groups/{ID}/relationships/{relationship}"
    data = await make_get_request_with_params(url, params)
    
    if data["error"]:
        logging.error(f"Error in VT Group Related Descriptors: {data['error']}")
    logging.info(f"return: {data}")
    return data

#Pupular Threat Categories
@mcp.tool()
async def Get_a_list_of_popular_threat_categories() -> dict[str, Any] | None:
    """
    Get a list of popular threat categories.
    """
    url = f"{BASE_URL}/popular_threat_categories"
    data = await make_get_request(url)
    if data["error"]:
        logging.error(f"Error in VT Popular Threat Categories report: {data['error']}")
    logging.info(f"return: {data}")
    return data

#Quota Management

@mcp.tool()
async def Get_a_user_s_API_usage(id: str, start_date: str | None = None, end_date: str | None = None) -> dict[str, Any] | None:
    """
    Get a user's API usage.
    id: User ID or API key.
    start_date: A string in format YYYYMMDD.
    end_date: A string in format YYYYMMDD.
    """
    url = f"{BASE_URL}/users/{id}/api_usage"
    params = {}
    if start_date:
        params["start_date"] = start_date
    if end_date:
        params["end_date"] = end_date
        
    data = await make_get_request_with_params(url, params)
    
    if data["error"]:
        logging.error(f"Error in VT API Usage: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_a_group_s_API_usage(id: str, start_date: str | None = None, end_date: str | None = None) -> dict[str, Any] | None:
    """
    Get a group's API usage.
    id: Group ID.
    start_date: A string in format YYYYMMDD.
    end_date: A string in format YYYYMMDD.
    """
    url = f"{BASE_URL}/groups/{id}/api_usage"
    params = {}
    if start_date:
        params["start_date"] = start_date
    if end_date:
        params["end_date"] = end_date
        
    data = await make_get_request_with_params(url, params)
    
    if data["error"]:
        logging.error(f"Error in VT Group API Usage: {data['error']}")
    logging.info(f"return: {data}")
    return data


#Service Account Management
@mcp.tool()
async def Create_a_new_Service_Account(id: str, service_account_id: str) -> dict[str, Any] | None:
    """
    Create a new Service Account inside your VT Enterprise group.
    id: Group ID.
    service_account_id: A descriptive identifier which must be unique inside your group.
    """
    url = f"{BASE_URL}/groups/{id}/relationships/service_accounts"
    
    payload = {
        "data": [
            {
                "type": "service_account",
                "id": service_account_id
            }
        ]
    }
    
    data = await make_post_request_with_params(url, payload)
    
    if data["error"]:
        logging.error(f"Error in VT Create Service Account: {data['error']}")
    logging.info(f"return: {data}")
    return data
 

@mcp.tool()
async def Get_Service_Accounts_of_a_group(id: str) -> dict[str, Any] | None:
    """
    Get Service Accounts of a group.
    id: Group ID.
    """
    url = f"{BASE_URL}/groups/{id}/relationships/service_accounts"
    data = await make_get_request(url)
    
    if data["error"]:
        logging.error(f"Error in VT Group Service Accounts: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_a_Service_Account_object(id: str) -> dict[str, Any] | None:
    """
    Get the information about a Service Account object.
    id: Format: groupId_serviceAccountId.
    """
    url = f"{BASE_URL}/service_accounts/{id}"
    data = await make_get_request(url)
    
    if data["error"]:
        logging.error(f"Error in VT Get Service Account: {data['error']}")
    logging.info(f"return: {data}")
    return data



#Audit Log

@mcp.tool()
async def Get_Activity_Logs(group: str, limit: int | None = 10, filter: str | None = None, cursor: str | None = None, relationships: str | None = None) -> dict[str, Any] | None:
    """
    Get Activity Logs.
    group: Group ID.
    filter: Filter logs by different properties.
    relationships: Provides additional information about the logs. Supported values: user, group, target.
    limit: Maximum number of logs to retrieve. The maximum value is 40 logs.
    """
    url = f"{BASE_URL}/groups/{group}/activity_log_entries"
    
    params = {"limit": limit}
    if filter:
        params["filter"] = filter
    if cursor:
        params["cursor"] = cursor
    if relationships:
        params["relationships"] = relationships
        
    data = await make_get_request_with_params(url, params)
    
    if data["error"]:
        logging.error(f"Error in VT Activity Logs: {data['error']}")
    logging.info(f"return: {data}")
    return data


#Rendering

@mcp.tool()
async def Get_a_widget_rendering_URL(query: str, fg1: str | None = None, bg1: str | None = None, bg2: str | None = None, bd1: str | None = None) -> dict[str, Any] | None:
    """
    Get a widget rendering URL.
    query: A file hash, domain, URL or IP address.
    fg1: Theme primary foreground color in hex notation.
    bg1: Theme primary background color in hex notation.
    bg2: Theme secondary background color in hex notation.
    bd1: Theme border color in hex notation.
    """
    url = f"{BASE_URL}/widget/url"

    params = {"query": query}
    if fg1:
        params["fg1"] = fg1
    if bg1:
        params["bg1"] = bg1
    if bg2:
        params["bg2"] = bg2
    if bd1:
        params["bd1"] = bd1
        
    data = await make_get_request_with_params(url, params)

    if data["error"]:
        logging.error(f"Error in VT Widget URL: {data['error']}")
    logging.info(f"return: {data}")
    return data

# Helper function specifically for fetching raw HTML/text content
async def make_html_get_request(url: str) -> str | None:
    # Note: The documentation suggests this specific UI endpoint does not require the x-apikey header.
    # If it does turn out to need it, uncomment the headers line below.
    # headers = {"x-apikey": API_KEY}
    
    async with httpx.AsyncClient() as client:
        try:
            # resp = await client.get(url, headers=headers, timeout=30.0) # Use this if API key is needed later
            resp = await client.get(url, timeout=30.0)
            resp.raise_for_status()
            # Return the raw text content (HTML) instead of parsing JSON
            return resp.text
        except httpx.HTTPStatusError as e:
            logging.error(f"Error response {e.response.status_code} while requesting HTML {e.request.url!r}.")
            return None
        except httpx.RequestError as e:
            logging.error(f"Request error while requesting HTML {url!r}: {e}")
            return None

@mcp.tool()
async def Retrieve_the_widget_s_HTML_content(token: str) -> str | None:
    """
    Retrieve the actual HTML content of the widget report for a given observable.
    token: The token provided by the previous endpoint: /widget/url
    Returns raw HTML string.
    """
    # Warning: This endpoint uses a different base URL than the main API.
    url = f"https://www.virustotal.com/ui/widget/html/{token}"

    html_content = await make_html_get_request(url)

    if html_content:
        logging.info(f"Successfully retrieved HTML widget for token beginning with: {token[:15]}...")
    else:
        logging.error(f"Failed to retrieve HTML widget for token: {token}")
        
    return html_content


#VT Augment
#Augment

@mcp.tool()
async def Get_a_widget_rendering_URL(
    query: str,
    fg1: str | None = None,
    bg1: str | None = None,
    bg2: str | None = None,
    bd1: str | None = None
) -> dict[str, Any] | None:
    """
    Get a URL for rendering a VirusTotal widget for a given query.
    query: The query for which the widget will be rendered (e.g., domain, URL, hash).
    fg1: Foreground color 1 (optional hex code, e.g., '000000').
    bg1: Background color 1 (optional hex code).
    bg2: Background color 2 (optional hex code).
    bd1: Border color 1 (optional hex code).
    """
    url = f"{BASE_URL}/widget/url"

    params = {"query": query}
    if fg1:
        params["fg1"] = fg1
    if bg1:
        params["bg1"] = bg1
    if bg2:
        params["bg2"] = bg2
    if bd1:
        params["bd1"] = bd1
        
    data = await make_get_request_with_params(url, params)

    if data["error"]:
        logging.error(f"Error in VT Get Widget URL: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Retrieve_the_widgets_HTML_content(token: str) -> str | None:
    """
    Retrieve the widget's HTML content.
    token: The widget token.
    """
    url = f"https://www.virustotal.com/ui/widget/html/{token}"
    
    data = await make_html_get_request(url)

    if data:
        logging.info(f"Successfully retrieved widget HTML for token: {token}.")
    else:
        logging.error(f"Failed to retrieve widget HTML for token: {token}.")
        
    return data



#Monitor Items
@mcp.tool()
async def Get_a_list_of_MonitorItem_objects_by_path_or_tag(filter: str, limit: int | None = None, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get a list of MonitorItem objects by path or tag.
    filter: The filter query. Examples: 'tag:detected', 'path:/myfolder/', 'item:monitor_item_id'.
            Possible tags include: 'detected', 'new-detections', 'decreasing-detections', 'increasing-detections', 'solved-detections', 'swapped-detections', '[engine_name]'.
    """
    url = f"{BASE_URL}/monitor/items"

    params = {"filter": filter}
    
    if limit:
        params["limit"] = limit
    if cursor:
        params["cursor"] = cursor
        
    data = await make_get_request_with_params(url, params)

    if data["error"]:
        logging.error(f"Error in VT Get Monitor Items: {data['error']}")
    logging.info(f"return: {data}")
    return data


# Helper function specifically for multipart/form-data POST requests (for file uploads with other parameters)
async def make_multipart_post_request(url: str, data: dict[str, Any] = {}, files: dict[str, Any] = {}) -> dict[str, Any]:
    headers = {
        "x-apikey": API_KEY,
    }
    async with httpx.AsyncClient() as client:
        try:
            file_handles = {}
            if files:
                for key, file_path in files.items():
                    try:
                        file_handles[key] = open(file_path, "rb")
                    except FileNotFoundError:
                        return {"data": None, "error": f"File not found at path: {file_path}"}
                
            resp = await client.post(url, data=data, files=file_handles, headers=headers, timeout=60.0) # Increased timeout for uploads
            
            for fh in file_handles.values():
                fh.close()
                
            resp.raise_for_status()
            
            try:
                response_data = resp.json()
            except ValueError:
                response_data = resp.text

            return {
                "data": response_data,
                "error": None,
            }

        except httpx.HTTPStatusError as e:
            logging.error(f"Error response {e.response.status_code} while requesting {e.request.url!r}: {e.response.text}")
            return {
                "data": None,
                "error": f"HTTP error {e.response.status_code}: {e.response.text}",
            }
        except httpx.RequestError as e:
            logging.error(f"Request error while requesting {url!r}: {e}")
            return {
                "data": None,
                "error": str(e),
            }
        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}")
            return {
                "data": None,
                "error": f"Unexpected error: {str(e)}",
            }


@mcp.tool()
async def Upload_a_file_or_create_a_new_folder(
    file_path: str | None = None,
    path: str | None = None,
    item: str | None = None
) -> dict[str, Any] | None:
    """
    Upload a file or create a new folder in VirusTotal Monitor.
    
    :param file_path: The local path to the file you want to upload. Omit this to create a folder.
    :param path: A path relative to the current monitor user root folder. 
                 Must include the filename at the end for file uploads (e.g., '/folder/myfile.exe').
                 Must end with a slash (/) to create a folder (e.g., '/my_new_folder/').
    :param item: A Monitor ID describing a group and path. Can be used instead of 'path'.
    """
    url = f"{BASE_URL}/monitor/items"

    if not path and not item:
        return {"data": None, "error": "You must provide either a 'path' or an 'item' identifier."}

    form_data = {}
    if path:
        form_data["path"] = path
    if item:
        form_data["item"] = item
        
    files_data = {}
    if file_path:
        files_data["file"] = file_path

    data = await make_multipart_post_request(url, data=form_data, files=files_data)

    if data["error"]:
        logging.error(f"Error in VT Monitor Upload/Create: {data['error']}")
    logging.info(f"return: {data}")
    return data



@mcp.tool()
async def Get_a_URL_for_uploading_large_files_to_Monitor() -> dict[str, Any] | None:
    """
    Get a special upload URL for uploading files larger than 32MB to VirusTotal Monitor.
    For smaller files, you can use the Upload_a_file_or_create_a_new_folder tool.
    The returned URL can be used as a drop-in replacement for the /items endpoint.
    A new upload URL should be generated for each big file upload.
    """
    url = f"{BASE_URL}/monitor/items/upload_url"
    
    data = await make_get_request(url)

    if data["error"]:
        logging.error(f"Error in VT Get Monitor Upload URL: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_attributes_and_metadata_for_a_specific_MonitorItem(id: str) -> dict[str, Any] | None:
    """
    Get attributes and metadata for a specific MonitorItem.
    id: The MonitorItem ID (e.g., a file hash or folder ID).
    """
    url = f"{BASE_URL}/monitor/items/{id}"
    
    data = await make_get_request(url)

    if data["error"]:
        logging.error(f"Error in VT Get Monitor Item: {data['error']}")
    logging.info(f"return: {data}")
    return data


# Helper function specifically for fetching raw binary content (e.g., for file downloads)
async def make_binary_get_request(url: str, params: dict[str, Any] | None = None) -> bytes | None:
    headers = {
        "x-apikey": API_KEY,
    }
    if params:
        url += "?"
        for key, value in params.items():
            url += f"{key}={str(value)}&"
        url = url[:-1]

    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(url, headers=headers, timeout=60.0)
            resp.raise_for_status()
            return resp.content
        except httpx.HTTPStatusError as e:
            logging.error(f"Error response {e.response.status_code} while requesting binary {e.request.url!r}.")
            return None
        except httpx.RequestError as e:
            logging.error(f"Request error while requesting binary {url!r}: {e}")
            return None



@mcp.tool()
async def Download_a_file_in_VirusTotal_Monitor(id: str) -> bytes | None:
    """
    Download a file from VirusTotal Monitor.
    id: The MonitorItem ID of the file you want to download.
    Returns the raw binary data of the file.
    """
    url = f"{BASE_URL}/monitor/items/{id}/download"

    file_content = await make_binary_get_request(url)

    if file_content:
        logging.info(f"Successfully downloaded file with ID: {id}. Size: {len(file_content)} bytes.")
    else:
        logging.error(f"Failed to download file with ID: {id}.")
        
    return file_content


@mcp.tool()
async def Get_a_URL_for_downloading_a_file_in_VirusTotal_Monitor(id: str) -> dict[str, Any] | None:
    """
    Get a signed URL for downloading a specific file from VirusTotal Monitor.
    The URL expires after 1 hour.
    id: The MonitorItem ID (e.g., a file hash) of the file to download.
    """
    url = f"{BASE_URL}/monitor/items/{id}/download_url"
    
    data = await make_get_request(url)

    if data["error"]:
        logging.error(f"Error in VT Get Monitor Download URL: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_the_latest_file_analyses(id: str, limit: int | None = None, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get the latest analyses for a specific Monitor item.
    id: The Monitor item identifier.
    limit: Maximum number of analyses to retrieve.
    cursor: Continue listing after this offset.
    """
    url = f"{BASE_URL}/monitor/items/{id}/analyses"
    
    params = {}
    if limit:
        params["limit"] = limit
    if cursor:
        params["cursor"] = cursor
        
    data = await make_get_request_with_params(url, params)

    if data["error"]:
        logging.error(f"Error in VT Get Monitor Item Analyses: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_user_owning_the_MonitorItem_object(id: str) -> dict[str, Any] | None:
    """
    Get the user owning the MonitorItem object.
    id: The Monitor item identifier.
    """
    url = f"{BASE_URL}/monitor/items/{id}/owner"
    
    data = await make_get_request(url)

    if data["error"]:
        logging.error(f"Error in VT Get Monitor Item Owner: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Retrieve_partners_comments_on_a_file(id: str, limit: int | None = None, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Retrieve partner's comments on a file (monitor item).
    id: The Monitor item identifier.
    limit: Maximum number of comments to retrieve.
    cursor: Continue listing after this offset.
    """
    url = f"{BASE_URL}/monitor/items/{id}/comments"

    params = {}
    if limit:
        params["limit"] = limit
    if cursor:
        params["cursor"] = cursor
        
    data = await make_get_request_with_params(url, params)

    if data["error"]:
        logging.error(f"Error in VT Monitor Item Comments: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Retrieve_statistics_about_analyses_performed_on_your_software_collection(limit: int | None = None, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Retrieve statistics about analyses performed on your software collection in VirusTotal Monitor.
    limit: Maximum number of statistics entries to retrieve.
    cursor: Continue listing after this offset.
    """
    url = f"{BASE_URL}/monitor/statistics"

    params = {}
    if limit:
        params["limit"] = limit
    if cursor:
        params["cursor"] = cursor
        
    data = await make_get_request_with_params(url, params)

    if data["error"]:
        logging.error(f"Error in VT Monitor Statistics: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_historical_events_about_your_software_collection(
    cursor: str | None = None,
    job_id: str | None = None,
    filter: str | None = None
) -> dict[str, Any] | None:
    """
    Retrieve historical events about your software collection in VirusTotal Monitor.
    cursor: Continue listing after this offset.
    job_id: Filter events by a specific job ID.
    filter: Filter query to select specific events.
    """
    url = f"{BASE_URL}/monitor/events"

    params = {}
    if cursor:
        params["cursor"] = cursor
    if job_id:
        params["job_id"] = job_id
    if filter:
        params["filter"] = filter
        
    data = await make_get_request_with_params(url, params)

    if data["error"]:
        logging.error(f"Error in VT Monitor Events: {data['error']}")
    logging.info(f"return: {data}")
    return data


#Antivirus Partners

@mcp.tool()
async def Get_a_list_of_MonitorHashes_detected_by_an_engine(filter: str, limit: int | None = None, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get a list of MonitorHashes detected by an antivirus engine.
    filter: The filter query, typically in the format 'engine:engine_name' (e.g., 'engine:Symantec').
    limit: Maximum number of hashes to retrieve.
    cursor: Continue listing after this offset.
    """
    url = f"{BASE_URL}/monitor_partner/hashes"

    params = {"filter": filter}
    if limit:
        params["limit"] = limit
    if cursor:
        params["cursor"] = cursor
        
    data = await make_get_request_with_params(url, params)

    if data["error"]:
        logging.error(f"Error in VT Monitor Partner Hashes: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_a_list_of_analyses_for_a_file(sha256: str, limit: int | None = None, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get a list of analyses for a file.
    sha256: The SHA256 hash of the file.
    limit: Maximum number of analyses to retrieve.
    cursor: Continue listing after this offset.
    """
    url = f"{BASE_URL}/monitor_partner/hashes/{sha256}/analyses"

    params = {}
    if limit:
        params["limit"] = limit
    if cursor:
        params["cursor"] = cursor
        
    data = await make_get_request_with_params(url, params)

    if data["error"]:
        logging.error(f"Error in VT Monitor Partner File Analyses: {data['error']}")
    logging.info(f"return: {data}")
    return data

@mcp.tool()
async def Get_a_list_of_items_with_a_given_sha256_hash(sha256: str, limit: int | None = None, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Get a list of items with a given sha256 hash.
    sha256: The SHA256 hash of the file.
    limit: Maximum number of items to retrieve.
    cursor: Continue listing after this offset.
    """
    url = f"{BASE_URL}/monitor_partner/hashes/{sha256}/items"

    params = {}
    if limit:
        params["limit"] = limit
    if cursor:
        params["cursor"] = cursor
        
    data = await make_get_request_with_params(url, params)

    if data["error"]:
        logging.error(f"Error in VT Monitor Partner Hash Items: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Create_a_comment_over_a_hash(sha256: str, comment: str, engine: str) -> dict[str, Any] | None:
    """
    Create a comment over a hash (Antivirus Partners endpoint).
    sha256: The SHA256 hash to comment on.
    comment: The text of the comment.
    engine: The Engine ID associated with the comment.
    """
    url = f"{BASE_URL}/monitor_partner/hashes/{sha256}/comments"
    payload = {
        "data": [
            {
                "attributes": {
                    "comment": comment,
                    "detection": "confirmed",
                    "engine": engine,
                    "sha256": sha256
                },
                "type": "monitor_hash_comment"
            }
        ]
    }
    data = await make_post_request_with_params(url, payload)

    if data["error"]:
        logging.error(f"Error in VT Monitor Partner Create Comment: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_comments_on_a_sha256_hash(id: str) -> dict[str, Any] | None:
    """
    Get comments on a sha256 hash (Antivirus Partners endpoint).
    id: The comment ID.
    """
    url = f"{BASE_URL}/monitor_partner/comments/{id}"
    
    data = await make_get_request(url)

    if data["error"]:
        logging.error(f"Error in VT Get Monitor Partner Comment: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Download_a_file_with_a_given_sha256_hash(sha256: str, limit: int | None = None, cursor: str | None = None) -> bytes | None:
    """
    Download a file with a given sha256 hash (Antivirus Partners endpoint).
    sha256: The SHA256 hash of the file to download.
    limit: (Optional parameter based on documentation)
    cursor: (Optional parameter based on documentation)
    Returns the raw binary data of the file.
    """
    url = f"{BASE_URL}/monitor_partner/files/{sha256}/download"

    params = {}
    if limit:
        params["limit"] = limit
    if cursor:
        params["cursor"] = cursor

    # Pass params only if they are not empty
    file_content = await make_binary_get_request(url, params=params if params else None)

    if file_content:
        logging.info(f"Successfully downloaded file (Partner) with hash: {sha256}. Size: {len(file_content)} bytes.")
    else:
        logging.error(f"Failed to download file (Partner) with hash: {sha256}.")
        
    return file_content


@mcp.tool()
async def Retrieve_a_download_url_for_a_file_with_a_given_sha256_hash(sha256: str, limit: int | None = None, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Retrieve a download url for a file with a given sha256 hash (Antivirus Partners endpoint).
    sha256: The SHA256 hash of the file.
    limit: (Optional parameter based on documentation)
    cursor: (Optional parameter based on documentation)
    """
    url = f"{BASE_URL}/monitor_partner/files/{sha256}/download_url"

    params = {}
    if limit:
        params["limit"] = limit
    if cursor:
        params["cursor"] = cursor
        
    data = await make_get_request_with_params(url, params)

    if data["error"]:
        logging.error(f"Error in VT Monitor Partner Get Download URL: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Download_a_daily_detection_bundle_directly(engine_name: str) -> bytes | None:
    """
    Download a daily detection bundle directly for a specific engine (Antivirus Partners endpoint).
    engine_name: The name of the antivirus engine.
    Returns the raw binary data of the bundle.
    """
    url = f"{BASE_URL}/monitor_partner/detections_bundle/{engine_name}/download"

    # No query parameters needed for this endpoint, just the base URL
    bundle_content = await make_binary_get_request(url)

    if bundle_content:
        logging.info(f"Successfully downloaded detection bundle for engine: {engine_name}. Size: {len(bundle_content)} bytes.")
    else:
        logging.error(f"Failed to download detection bundle for engine: {engine_name}.")
        
    return bundle_content


@mcp.tool()
async def Get_a_daily_detection_bundle_download_URL(engine_name: str) -> dict[str, Any] | None:
    """
    Get a daily detection bundle download URL for a specific engine (Antivirus Partners endpoint).
    engine_name: The name of the antivirus engine.
    """
    url = f"{BASE_URL}/monitor_partner/detections_bundle/{engine_name}/download_url"
    
    data = await make_get_request(url)

    if data["error"]:
        logging.error(f"Error in VT Get Detection Bundle Download URL: {data['error']}")
    logging.info(f"return: {data}")
    return data


@mcp.tool()
async def Get_a_list_of_MonitorHashes_detected_by_an_engine(filter: str, limit: int | None = None, cursor: str | None = None) -> dict[str, Any] | None:
    """
    Retrieve statistics about analyses performed by your engine (Antivirus Partners endpoint).
    filter: The filter query, typically to select your engine.
    limit: Maximum number of statistics entries to retrieve.
    cursor: Continue listing after this offset.
    """
    url = f"{BASE_URL}/monitor_partner/statistics"

    params = {"filter": filter}
    if limit:
        params["limit"] = limit
    if cursor:
        params["cursor"] = cursor
        
    data = await make_get_request_with_params(url, params)

    if data["error"]:
        logging.error(f"Error in VT Monitor Partner Statistics: {data['error']}")
    logging.info(f"return: {data}")
    return data


def main():
    # Initialize and run the server
    mcp.run(transport='stdio')

if __name__ == "__main__":
    main()