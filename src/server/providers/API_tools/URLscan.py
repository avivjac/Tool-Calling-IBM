import requests
import httpx
from mcp.server.fastmcp import FastMCP
from typing import Any

mcp = FastMCP("URLscan.io MCP", json_response=True)

BASE_URL = "https://urlscan.io/api/v1"
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
async def API_Quotas() -> dict[str, Any] | None :
    """
    מחזיר את המידע על המגבלות של המפתח API.
    """
    url = f"{BASE_URL}/quotas"
    data = await make_get_request(url)

    if not data:
        print("No data received")
        return None
    
    return data

# PRO tools
@mcp.tool()
async def User_Information(username : str) -> dict[str, Any] | None :
    """
    מחזיר את המידע על המשתמש לפי שם המשתמש.
    """
    url = f"{BASE_URL}/pro/{username}"
    data = await make_get_request(url)

    if not data:
        print("No data received")
        return None
    
    return data

@mcp.tool()
async def scan(url : str, visibility : str = "public", country : str | None = None, tags : list[str] | None = None, overrideSafety : bool | None = None, refer : str | None  = None, customagent : str | None = None) -> dict[str, Any] | None :
    """
    סורק URL חדש ב-URLscan.io.
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
        print("No data received")
        return None
    
    return data

@mcp.tool()
async def result(scanid : str) -> dict[str, Any] | None :
    """
    מחזיר את תוצאות הסריקה לפי scanid.
    """
    url = f"{BASE_URL}/result/{scanid}"
    data = await make_get_request(url)

    if not data:
        print("No data received")
        return None
    
    return data

@mcp.tool()
async def screenshot(scanid : str) -> dict[str, Any] | None :
    """
    מחזיר את צילום המסך של הסריקה לפי scanid.
    """
    url = f"{BASE_URL}/screenshot/{scanid}.png"
    data = await make_get_request(url)

    if not data:
        print("No data received")
        return None
    
    return data

@mcp.tool()
async def DOM(scanid : str) -> dict[str, Any] | None :
    """
    מחזיר את ה-DOM של הסריקה לפי scanid.
    """
    url = f"{BASE_URL}/dom/{scanid}/"
    data = await make_get_request(url)

    if not data:
        print("No data received")
        return None
    
    return data

@mcp.tool()
async def Available_countries() -> dict[str, Any] | None :
    """
    מחזיר את רשימת המדינות הזמינות לסריקה.
    """
    url = f"{BASE_URL}/availableCountries"
    data = await make_get_request(url)

    if not data:
        print("No data received")
        return None
    
    return data

@mcp.tool()
async def Available_User_Agents() -> dict[str, Any] | None :
    """
    מחזיר את רשימת סוכני המשתמש הזמינים לסריקה.
    """
    url = f"{BASE_URL}/userAgents"
    data = await make_get_request(url)

    if not data:
        print("No data received")
        return None
    
    return data

def main():
    # Initialize and run the server
    mcp.run(transport='stdio')

if __name__ == "__main__":
    main()