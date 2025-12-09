import requests
import httpx
from mcp.server.fastmcp import FastMCP
from typing import Any
import logging

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


# tools    

#IP adresses
class InvalidIPAddressError(Exception):
    pass


@mcp.tool()
async def Get_an_IP_address_report(IP : str) -> dict[str, Any] | None :
    """
    Get an IP address report from VirusTotal.
    example: IP=')"""

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

@mcp.tool()
async def Add_a_comment_to_an_IP_address(IP: str, comment: str) -> dict[str, Any] | None :
    """
    Add a comment to an IP address on VirusTotal.
    example: IP=' ', comment='This is a test comment.'
    """

    if not is_valid_ip(IP):
        raise InvalidIPAddressError(f"The IP address '{IP}' is not a valid address.")

    url = f"{BASE_URL}/ip_addresses/{IP}/comments"
    
    payload = {
        "data": {
            "type": "comment",
            "attributes": {
                "text": comment
            }
        }
    }

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


@mcp.tool()
async def Add_a_vote_to_an_IP_address(IP: str, vote: dict[str, Any]) -> dict[str, Any] | None :
    """
    Add a vote to an IP address on VirusTotal.
    example: IP=' ', vote={'verdict': 'malicious'}
    """
    if not is_valid_ip(IP):
        raise InvalidIPAddressError(f"The IP address '{IP}' is not a valid address.")

    url = f"{BASE_URL}/ip_addresses/{IP}/votes"
    
    payload = {
        "data": {
            "type": "vote",
            "attributes": {
    	        "verdict": vote
            }
        }
    }

    data = await make_post_request_with_params(url, payload)

    if data["error"]:
        logging.error(f"Error in VT IP report: {data['error']}")
    logging.info("return: {data}")
    return data


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


@mcp.tool()
async def Add_a_comment_to_a_domain(domain: str, comment: str) -> dict[str, Any] | None:
    """
    Add a comment to a domain on VirusTotal.
    example: domain='example.com', comment='This is a test comment.'
    """
    if not is_valid_domain(domain):
        raise InvalidDomainError(f"The domain '{domain}' is not a valid domain.")
    url = f"{BASE_URL}/domains/{domain}/comments"
    
    payload = {
        "data": {
            "type": "comment",
            "attributes": {
                "text": comment
            }
        }
    }

    data = await make_post_request(url, payload)

    if data["error"]:
        logging.error(f"Error in Domain report: {data['error']}")
    logging.info("return: {data}")
    return data


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


@mcp.tool()
async def Add_a_vote_to_a_domain(domain: str, verdict : str) -> dict[str, Any] | None:
    """
    Add a vote to a domain on VirusTotal.
    example: domain='example.com', verdict='malicious'
    """
    if not is_valid_domain(domain):
        raise InvalidDomainError(f"The domain '{domain}' is not a valid domain.")
    
    url = f"{BASE_URL}/domains/{domain}/votes"
    
    payload = {
        "data": {
            "type": "vote",
            "attributes": {
                "verdict": verdict
            }
        }
    }

    data = await make_post_request(url, payload)

    if data["error"]:
        logging.error(f"Error in Domain report: {data['error']}")
    logging.info("return: {data}")
    return data



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



@mcp.tool()
async def Add_a_comment_to_a_file(file_id: str, comment: str) -> dict[str, Any] | None:
    """
    Add a comment to a file.
    """
    url = f"{BASE_URL}/files/{file_id}/comments"

    payload = {
        "data": {
            "type": "comment",
            "attributes": {
                "text": comment
            }
        }
    }

    data = await make_post_request_with_params(url, payload)

    if data["error"]:
        logging.error(f"Error in VT File report: {data['error']}")
    logging.info("return: {data}")
    return data



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



@mcp.tool()
async def Add_a_vote_to_a_file(file_id: str, vote: str) -> dict[str, Any] | None:
    """
    Add a vote to a file.
    example: vote='malicious' or 'harmless'
    """
    url = f"{BASE_URL}/files/{file_id}/votes"

    payload = {
        "data": {
            "type": "vote",
            "attributes": {
                "verdict": vote
            }
        }
    }

    data = await make_post_request_with_params(url, payload)

    if data["error"]:
        logging.error(f"Error in VT File report: {data['error']}")
    logging.info("return: {data}")
    return data


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


@mcp.tool()
async def Add_a_comment_on_a_URL(url_id: str, comment: str) -> dict[str, Any] | None:
    """
    Add a comment to a URL.
    """
    url = f"{BASE_URL}/urls/{url_id}/comments"

    payload = {
        "data": {
            "type": "comment",
            "attributes": {
                "text": comment
            }
        }
    }

    data = await make_post_request_with_params(url, payload)

    if data["error"]:
        logging.error(f"Error adding VT URL comment: {data['error']}")
    logging.info("return: {data}")
    return data



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


@mcp.tool()
async def Add_a_vote_on_a_URL(url_id: str, verdict: str) -> dict[str, Any] | None:
    """
    Add a vote on a URL.
    verdict must be either 'harmless' or 'malicious'.
    """
    url = f"{BASE_URL}/urls/{url_id}/votes"

    payload = {
        "type": "vote",
        "attributes": {
            "verdict": verdict
        }
    }

    data = await make_post_request_with_params(url, payload)

    if data["error"]:
        logging.error(f"Error adding VT URL vote: {data['error']}")
    logging.info("return: {data}")
    return data




def main():
    # Initialize and run the server
    mcp.run(transport='stdio')

if __name__ == "__main__":
    main()