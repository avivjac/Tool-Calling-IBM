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

# ------------------------
# Logging
# ------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    filename="AbuselPDB_log.log",
    filemode="a"
)

logger = logging.getLogger(__name__)

mcp = FastMCP("AbuselPDB MCP", json_response=True)

# ------------------------
# API_KEY Loading
# ------------------------

BASE_URL = "https://www.abuseipdb.com"
API_KEY = os.getenv("ABUSELPDB_API_KEY")

if not API_KEY:
    logging.error("Missing ABUSELPDB_API_KEY environment variable")
    raise RuntimeError("Missing ABUSELPDB_API_KEY")

# ------------------------
# Helper Request Functions
# ------------------------

async def make_get_request(url: str) -> dict[str, Any]:
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(url, timeout=30.0)
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
    url += "?"
    for key, value in params.items():
        url += f"{key}={value}&"

    url = url[:-1]  
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.get(url, timeout=30.0)
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
    async with httpx.AsyncClient() as client:
        try:
            resp = await client.post(url, timeout=30.0)
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

# ------------------------
# Tools
# ------------------------

# Implemention of the APIs endpoints as tools

@mcp.tool()
async def Check_IP(ip : str, days : int = 30) -> dict[str, Any] | None :
    """
    Check an IP address for abusel
    """
    if not validate.is_valid_ip(ip):
        logging.error("Invalid IP address")
        raise ValueError("Invalid IP address")
    
    url = f"{BASE_URL}/check/{ip}/json?key={API_KEY}&days={days}"
    data = await make_get_request(url)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Check_CIDR(cidr : str, days : int = 30) -> dict[str, Any] | None :
    """
    Check a CIDR for abusel
    """
    if not validate.is_valid_ip(cidr):
        logging.error("Invalid CIDR")
        raise ValueError("Invalid CIDR")
    
    url = f"{BASE_URL}/check-block/json?network={cidr}&key={API_KEY}&days={days}"
    data = await make_get_request(url)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def Report_IP(ip : str, category : str, comment : str | None = None) -> dict[str, Any] | None :
    """
    Report an IP address for abusel
    """
    if not validate.is_valid_ip(ip):
        logging.error("Invalid IP address")
        raise ValueError("Invalid IP address")
    
    url = f"{BASE_URL}/report/json"
    url += "?"
    params = {
        "key": API_KEY,
        "category": category,
        "comment": comment,
        "ip": ip
    }
    
    for key, value in params.items():
        url += f"{key}={value}&"

    url = url[:-1]
    
    
    data = await make_post_request(url)

    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

def main():
    # Initialize and run the server
    mcp.run(transport='stdio')

if __name__ == "__main__":
    main()