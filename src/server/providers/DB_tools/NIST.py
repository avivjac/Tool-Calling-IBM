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
    filename="NIST_log.log",
    filemode="a"
)

logger = logging.getLogger(__name__)

mcp = FastMCP("NIST MCP", json_response=True)

# ------------------------
# API_KEY Loading
# ------------------------

BASE_URL = "https://services.nvd.nist.gov/rest/json"
API_KEY = os.getenv("NIST_API_KEY")

if not API_KEY:
    logging.error("Missing NIST_API_KEY environment variable")
    raise RuntimeError("Missing NIST_API_KEY")

# ------------------------
# Helper Request Functions
# ------------------------

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
    
# ------------------------
# Tools
# ------------------------

# Implemention of the APIs endpoints as tools

@mcp.tool()
async def CVE(cpeName : str | None = None, cveID : str | None = None, cveTag : str | None = None, cvssV2Metrics : str | None = None, cvssV2Severity :str | None = None, cvssV3Metrics : str | None = None, cvssV3Severity :str | None = None, cvssV4Metrics :str | None = None, cvssV4Severity :str | None = None, cweId : str | None = None, hasCertAlerts : bool | None = None, hasCertNotes : bool | None = None, hasKev : bool | None = None, hasOval : bool | None = None, isVulnerable : bool | None = None, kevStartDate : str | None = None, kevEndDate : str | None = None, keywordExactMatch : str | None  = None, keywordSearch : str | None = None, lastModStartDare : str | None = None, lastModEndDate : str | None = None, noReject : bool | None = None, pubStartDate : str | None = None, pubEndDate : str | None = None, resultsPerPage : int | None = None, startIndex : int  | None = None, sourceIdentifier : str | None = None, versionEnd : str | None = None, versionEndType : str | None = None, versionStart : str | None = None, versionStartType : str | None = None, virtualMatchString : str | None = None) -> dict[str, Any] | None :
    """
    API Endpoint to get CVE information.
    """
    url = f"{BASE_URL}/cves/2.0"

    # valdiation 



    
    params = {
        "cpeName": cpeName,
        "cveID": cveID,
        "cveTag": cveTag,
        "cvssV2Metrics": cvssV2Metrics,
        "cvssV2Severity": cvssV2Severity,
        "cvssV3Metrics": cvssV3Metrics,
        "cvssV3Severity": cvssV3Severity,
        "cvssV4Metrics": cvssV4Metrics,
        "cvssV4Severity": cvssV4Severity,
        "cweId": cweId,
        "hasCertAlerts": hasCertAlerts,
        "hasCertNotes": hasCertNotes,
        "hasKev": hasKev,
        "hasOval": hasOval,
        "isVulnerable": isVulnerable,
        "kevStartDate": kevStartDate,
        "kevEndDate": kevEndDate,
        "keywordExactMatch": keywordExactMatch,
        "keywordSearch": keywordSearch,
        "lastModStartDare": lastModStartDare,
        "lastModEndDate": lastModEndDate,
        "noReject": noReject,
        "pubStartDate": pubStartDate,
        "pubEndDate": pubEndDate,
        "resultsPerPage": resultsPerPage,
        "startIndex": startIndex,
        "sourceIdentifier": sourceIdentifier,
        "versionEnd": versionEnd,
        "versionEndType": versionEndType,
        "versionStart": versionStart,
        "versionStartType": versionStartType,
        "virtualMatchString": virtualMatchString,
    }

    data = await make_get_request_with_params(url, params)
    
    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data