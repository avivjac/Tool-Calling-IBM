import requests
import httpx
from mcp.server.fastmcp import FastMCP
from typing import Any

mcp = FastMCP("VirusTotal MCP", json_response=True)

BASE_URL = "https://www.virustotal.com/api/v3"
API_KEY = ""

# Helper function to make requests to VirusTotal API
async def make_get_request(url : str) -> dict[str, Any] | None :
    headers = {
        "x-apikey": API_KEY,
    }
    async with httpx.AsyncClient() as client:
        try:
            response = await client.get(url, headers=headers, timeout=30.0)
            response.raise_for_status()
            return response.json()
        # esception
        except httpx.HTTPStatusError as e:
            print(f"Error response {e.response.status_code} while requesting {e.request.url!r}.")
            return None

async def make_get_request2(url : str, params : dict[str , Any]) -> dict[str, Any] | None :
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
            print(f"Error response {e.response.status_code} while requesting {e.request.url!r}.")
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
            print(f"Error response {e.response.status_code} while requesting {e.request.url!r}.")
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
            print(f"Error response {e.response.status_code} while requesting {e.request.url!r}.")
            return None

# tools        
@mcp.tool()
async def Get_an_IP_address_report(IP : str) -> dict[str, Any] | None :
    """
    Get an IP address report from VirusTotal.
    example: IP=')"""
    url = f"{BASE_URL}/ip_addresses/{IP}"
    data = await make_get_request(url)

    if not data:
        print("not data")
        return None
    
    return data

@mcp.tool()
async def Request_an_IP_address_rescan(IP : str) -> dict[str, Any] | None :
    """
    Request an IP address rescan from VirusTotal.
    example: IP=' """
    url = f"{BASE_URL}/ip_addresses/{IP}/analyse"
    data = await make_post_request(url)

    if not data:
        print("not data")
        return None
    
    return data

# 
@mcp.tool()
async def Get_comments_on_an_IP_address(IP : str, limit : int | None = 10, cursor : str | None = None) -> dict[str, Any] | None :
    """
    Get comments on an IP address from VirusTotal.
    example: IP=' """
    params = {"limit": limit}

    if cursor:
        params["cursor"] = cursor

    url = f"{BASE_URL}/ip_addresses/{IP}/comments"
    data = await make_get_request(url, params)

    if not data:
        print("not data")
        return None
    
    return data

@mcp.tool()
async def Add_a_comment_to_an_IP_address(IP: str, comment: str) -> dict[str, Any] | None :
    """
    Add a comment to an IP address on VirusTotal.
    example: IP=' ', comment='This is a test comment.'
    """
    url = f"{BASE_URL}/ip_addresses/{IP}/comments"
    
    payload = {
        "data": {
            "type": "comment",
            "attributes": {
                "text": comment
            }
        }
    }

    data = await make_post_request(url, payload)

    if not data:
        print("not data")
        return None
    return data

@mcp.tool()
async def Get_objects_related_to_an_IP_address(IP : str, relationship : str, limit : int | None = 10, cursor : str | None = None) -> dict[str, Any] | None :
    """
    Get objects related to an IP address from VirusTotal.
    example: IP=' '
    """
    params = {"limit": limit}

    if cursor:
        params["cursor"] = cursor


    url = f"{BASE_URL}/ip_addresses/{IP}/{relationship}"
    data = await make_get_request(url, params)

    if not data:
        print("not data")
        return None
    
    return data

@mcp.tool()
async def Get_object_descriptors_related_to_an_IP_address(IP : str, relationship : str) -> dict[str, Any] | None :
    """
    Get object descriptors related to an IP address from VirusTotal.
    example: IP=' '
    """
    url = f"{BASE_URL}/ip_addresses/{IP}/relationships/{relationship}"
    data = await make_get_request(url)

    if not data:
        print("not data")
        return None
    
    return data

@mcp.tool()
async def Get_votes_on_an_IP_address(IP : str) -> dict[str, Any] | None :
    """
    Get votes on an IP address from VirusTotal.
    example: IP=' '
    """
    url = f"{BASE_URL}/ip_addresses/{IP}/votes"
    data = await make_get_request(url)

    if not data:
        print("not data")
        return None
    
    return data

@mcp.tool()
async def Add_a_vote_to_an_IP_address(IP: str, vote: dict[str, Any]) -> dict[str, Any] | None :
    """
    Add a vote to an IP address on VirusTotal.
    example: IP=' ', vote={'verdict': 'malicious'}
    """
    url = f"{BASE_URL}/ip_addresses/{IP}/votes"
    
    payload = {
        "data": {
            "type": "vote",
            "attributes": {
    	        "verdict": vote
            }
        }
    }

    data = await make_post_request(url, payload)

    if not data:
        print("not data")
        return None
    
    return data



def main():
    # Initialize and run the server
    mcp.run(transport='stdio')

if __name__ == "__main__":
    main()