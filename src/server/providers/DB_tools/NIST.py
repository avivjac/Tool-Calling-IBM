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
# Tools
# ------------------------

# Implemention of the APIs endpoints as tools

@mcp.tool()
async def CVE(cpeName : str | None = None, cveID : str | None = None, cveTag : str | None = None, cvssV2Metrics : str | None = None, cvssV2Severity :str | None = None, cvssV3Metrics : str | None = None, cvssV3Severity :str | None = None, cvssV4Metrics :str | None = None, cvssV4Severity :str | None = None, cweId : str | None = None, hasCertAlerts : bool | None = None, hasCertNotes : bool | None = None, hasKev : bool | None = None, hasOval : bool | None = None, isVulnerable : bool | None = None, kevStartDate : str | None = None, kevEndDate : str | None = None, keywordExactMatch : bool | None  = None, keywordSearch : str | None = None, lastModStartDate : str | None = None, lastModEndDate : str | None = None, noReject : bool | None = None, pubStartDate : str | None = None, pubEndDate : str | None = None, resultsPerPage : int | None = None, startIndex : int  | None = None, sourceIdentifier : str | None = None, versionEnd : str | None = None, versionEndType : str | None = None, versionStart : str | None = None, versionStartType : str | None = None, virtualMatchString : str | None = None) -> dict[str, Any] | None :
    """
    API Endpoint to get CVE information.
    """
    url = f"{BASE_URL}/cves/2.0"

    # valdiation 
    if cpeName is not None and not validate.is_valid_cpe(cpeName):
        logging.error("Invalid CPE name")
        raise ValueError("Invalid CPE name")

    if cveID is not None and not validate.is_valid_cve(cveID):
        logging.error("Invalid CVE ID")
        raise ValueError("Invalid CVE ID")

    if cveTag is not None and cveTag not in ["disputed", "unsupported-when-assigned", "exclusively-hosted-service"]:
        logging.error("Invalid CVE Tag")
        raise ValueError("Invalid CVE Tag, need to be one of: disputed, unsupported-when-assigned, exclusively-hosted-service")

    cvss_metrics_count = sum(1 for m in [cvssV2Metrics, cvssV3Metrics, cvssV4Metrics] if m is not None)
    if cvss_metrics_count > 1:
        logging.error("Invalid CVSS metrics")
        raise ValueError("Invalid CVSS metrics, need to be a list of strings, and only one of cvssV2Metrics, cvssV3Metrics, cvssV4Metrics can be provided")

    if cvssV2Metrics is not None and not isinstance(cvssV2Metrics, list):
         logging.error("Invalid CVSS metrics")
         raise ValueError("Invalid CVSS metrics, need to be a list of strings")

    if cvssV3Metrics is not None and not isinstance(cvssV3Metrics, list):
         logging.error("Invalid CVSS metrics")
         raise ValueError("Invalid CVSS metrics, need to be a list of strings")

    if cvssV4Metrics is not None and not isinstance(cvssV4Metrics, list):
         logging.error("Invalid CVSS metrics")
         raise ValueError("Invalid CVSS metrics, need to be a list of strings")

    if cvssV2Severity is not None and cvssV3Severity is not None:
        logging.error("Invalid CVSS severity")
        raise ValueError("Invalid CVSS severity, only one of cvssV2Severity, cvssV3Severity can be provided")

    if cvssV2Severity is not None and cvssV4Severity is not None:
        logging.error("Invalid CVSS severity")
        raise ValueError("Invalid CVSS severity, only one of cvssV2Severity, cvssV4Severity can be provided")

    if cvssV3Severity is not None and cvssV4Severity is not None:
        logging.error("Invalid CVSS severity")
        raise ValueError("Invalid CVSS severity, only one of cvssV3Severity, cvssV4Severity can be provided")

    if cvssV2Severity is not None and cvssV2Severity not in ["HIGH", "MEDIUM", "LOW"]:
        logging.error("Invalid CVSS severity")
        raise ValueError("Invalid CVSS severity, need to be one of: HIGH, MEDIUM, LOW")

    if cvssV3Severity is not None and cvssV3Severity not in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        logging.error("Invalid CVSS severity")
        raise ValueError("Invalid CVSS severity, need to be one of: CRITICAL, HIGH, MEDIUM, LOW")

    if cvssV4Severity is not None and cvssV4Severity not in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        logging.error("Invalid CVSS severity")
        raise ValueError("Invalid CVSS severity, need to be one of: CRITICAL, HIGH, MEDIUM, LOW")
    
    if cweId is not None and not validate.is_valid_cwe(cweId):
        logging.error("Invalid CWE ID")
        raise ValueError("Invalid CWE ID")


    if (kevStartDate is not None) ^ (kevEndDate is not None):
        logging.error("Both kevStartDate and kevEndDate are required when filtering by KEV inclusion dates.")
        raise ValueError("Both kevStartDate and kevEndDate are required when filtering by KEV inclusion dates.")

    if kevStartDate is not None and not validate.is_valid_date(kevStartDate):
        logging.error("Invalid kevStartDate format. Expected ISO-8601.")
        raise ValueError("Invalid kevStartDate format. Expected ISO-8601.")

    if kevEndDate is not None and not validate.is_valid_date(kevEndDate):
        logging.error("Invalid kevEndDate format. Expected ISO-8601.")
        raise ValueError("Invalid kevEndDate format. Expected ISO-8601.")

    if lastModStartDate is not None and not validate.is_valid_date(lastModStartDate):
        logging.error("Invalid lastModStartDate format. Expected ISO-8601.")
        raise ValueError("Invalid lastModStartDate format. Expected ISO-8601.")

    if lastModEndDate is not None and not validate.is_valid_date(lastModEndDate):
        logging.error("Invalid lastModEndDate format. Expected ISO-8601.")
        raise ValueError("Invalid lastModEndDate format. Expected ISO-8601.")

    if pubStartDate is not None and not validate.is_valid_date(pubStartDate):
        logging.error("Invalid pubStartDate format. Expected ISO-8601.")
        raise ValueError("Invalid pubStartDate format. Expected ISO-8601.")

    if pubEndDate is not None and not validate.is_valid_date(pubEndDate):
        logging.error("Invalid pubEndDate format. Expected ISO-8601.")
        raise ValueError("Invalid pubEndDate format. Expected ISO-8601.")

    if versionEndType is not None and versionEndType not in ["including", "excluding"]:
        logging.error("Invalid versionEndType")
        raise ValueError("Invalid versionEndType, need to be one of: including, excluding")

    if versionStartType is not None and versionStartType not in ["including", "excluding"]:
        logging.error("Invalid versionStartType")
        raise ValueError("Invalid versionStartType, need to be one of: including, excluding")

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
        "lastModStartDate": lastModStartDate,
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

    # remove None values
    params = {k: v for k, v in params.items() if v}

    data = await requests.make_get_request_with_params_for_nist(url, params, API_KEY)
    
    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

# Functions to get CVE using the same endpoint as above but for specific parametrs.

@mcp.tool()
async def get_CVE_by_CPE(cpeName : str) -> dict[str, Any] | None :
    """
    The CVE by CPE API is used to retrieve information on a single CVE or a collection of CVE from the NVD based on the CPE name.
    """
    url = f"{BASE_URL}/cves/2.0"

    # valdiation 
    if cpeName is not None and not validate.is_valid_cpe(cpeName):
        logging.error("Invalid CPE name")
        raise ValueError("Invalid CPE name")

    params = {
        "cpeName": cpeName,
    }

    data = await requests.make_get_request_with_params_for_nist(url, params, API_KEY)
    
    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def get_CVE_by_CVEID(cveID : str) -> dict[str, Any] | None :
    """
    The CVE by CVE ID API is used to retrieve information on a single CVE or a collection of CVE from the NVD based on the CVE ID.
    """
    url = f"{BASE_URL}/cves/2.0"

    # valdiation 
    if cveID is not None and not validate.is_valid_cve(cveID):
        logging.error("Invalid CVE ID")
        raise ValueError("Invalid CVE ID")

    params = {
        "cveID": cveID,
    }

    data = await requests.make_get_request_with_params_for_nist(url, params, API_KEY)
    
    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def get_CVE_by_CWEID(cweId : str) -> dict[str, Any] | None :
    """
    The CVE by CWE ID API is used to retrieve information on a single CVE or a collection of CVE from the NVD based on the CWE ID.
    """
    url = f"{BASE_URL}/cves/2.0"

    # valdiation 
    if cweId is not None and not validate.is_valid_cwe(cweId):
        logging.error("Invalid CWE ID")
        raise ValueError("Invalid CWE ID")

    params = {
        "cweId": cweId,
    }

    data = await requests.make_get_request_with_params_for_nist(url, params, API_KEY)
    
    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def get_CVE_by_hasKEV(hasKev : bool) -> dict[str, Any] | None :
    """
    The CVE by hasKEV API is used to retrieve information on a single CVE or a collection of CVE from the NVD based on the hasKEV.
    """
    url = f"{BASE_URL}/cves/2.0"

    params = {
        "hasKev": hasKev,
    }

    data = await requests.make_get_request_with_params_for_nist(url, params, API_KEY)
    
    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data
    
@mcp.tool()
async def get_CVE_by_isVulnerable(isVulnerable : bool) -> dict[str, Any] | None :
    """
    The CVE by isVulnerable API is used to retrieve information on a single CVE or a collection of CVE from the NVD based on the isVulnerable.
    """
    url = f"{BASE_URL}/cves/2.0"

    params = {
        "isVulnerable": isVulnerable,
    }

    data = await requests.make_get_request_with_params_for_nist(url, params, API_KEY)
    
    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def get_CVE_by_keywordExactMatch(keywordExactMatch : bool, keywordSearch : str) -> dict[str, Any] | None :
    """
    The CVE by keywordExactMatch API is used to retrieve information on a single CVE or a collection of CVE from the NVD based on the keywordExactMatch.
    """
    url = f"{BASE_URL}/cves/2.0"

    params = {
        "keywordExactMatch": keywordExactMatch,
        "keywordSearch": keywordSearch,
    }

    data = await requests.make_get_request_with_params_for_nist(url, params, API_KEY)
    
    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def get_CVE_by_keywordSearch(keywordSearch : str) -> dict[str, Any] | None :
    """
    The CVE by keywordSearch API is used to retrieve information on a single CVE or a collection of CVE from the NVD based on the keywordSearch.
    """
    url = f"{BASE_URL}/cves/2.0"

    params = {
        "keywordSearch": keywordSearch,
    }

    data = await requests.make_get_request_with_params_for_nist(url, params, API_KEY)
    
    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data 

@mcp.tool()
async def get_CVE_by_date(kevStartDate : str, kevEndDate : str) -> dict[str, Any] | None :
    """
    The CVE by date API is used to retrieve information on a single CVE or a collection of CVE from the NVD based on the date.
    """
    url = f"{BASE_URL}/cves/2.0"

    # validate
    if kevStartDate is None and kevEndDate is None:
        logging.error("Both kevStartDate and kevEndDate are required when filtering by date.")
        raise ValueError("Both kevStartDate and kevEndDate are required when filtering by date.")

    if kevStartDate is not None and not validate.is_valid_date(kevStartDate):
        logging.error("Invalid kevStartDate format. Expected ISO-8601.")
        raise ValueError("Invalid kevStartDate format. Expected ISO-8601.")

    if kevEndDate is not None and not validate.is_valid_date(kevEndDate):
        logging.error("Invalid kevEndDate format. Expected ISO-8601.")
        raise ValueError("Invalid kevEndDate format. Expected ISO-8601.")

    params = {
        "kevStartDate": kevStartDate,
        "kevEndDate": kevEndDate,
    }

    data = await requests.make_get_request_with_params_for_nist(url, params, API_KEY)
    
    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

@mcp.tool()
async def CVE_Change_History(changeStartDate : str | None = None, changeEndDate : str | None = None, cveId : str | None = None, eventName : str | None = None, resultsPerPage : int | None = None, startIndex : int | None = None) -> dict[str, Any]:
    """
    he CVE Change History API is used to easily retrieve information on changes made to a single CVE or a collection of CVE from the NVD. This API provides additional transparency to the work of the NVD, allowing users to easily monitor when and why vulnerabilities change.

    The NVD has existed in some form since 1999 and the fidelity of this information has changed several times over the decades. Earlier records may not contain the level of detail available with more recent CVE records. This is most apparent on CVE records prior to 2015.

    The URL stem for retrieving CVE information is shown below.
    """

    # validate
    if changeStartDate is not None and changeEndDate is not None:
        logging.error("Both changeStartDate and changeEndDate are required when filtering by change dates.")
        raise ValueError("Both changeStartDate and changeEndDate are required when filtering by change dates.")

    if changeStartDate is not None and not validate.is_valid_date(changeStartDate):
        logging.error("Invalid changeStartDate format. Expected ISO-8601.")
        raise ValueError("Invalid changeStartDate format. Expected ISO-8601.")

    if changeEndDate is not None and not validate.is_valid_date(changeEndDate):
        logging.error("Invalid changeEndDate format. Expected ISO-8601.")
        raise ValueError("Invalid changeEndDate format. Expected ISO-8601.")

    if cveId is not None and not validate.is_valid_cve(cveId):
        logging.error("Invalid cveId format. Expected CVE-YYYY-NNNN.")
        raise ValueError("Invalid cveId format. Expected CVE-YYYY-NNNN.")

    if eventName is not None and eventName not in ["CVE Received", "Initial Analysis", "Reanalysis", "CVE Modified", "Modified Analysis", "CVE Translated", "Vendor Comment", "CVE Source Update", "CPE Deprecation Remap", "CWE Remap", "Reference Tag Update", "CVE Rejected", "CVE Unrejected", "CVE CISA KEV Update"]:
        logging.error("Invalid eventName format.")
        raise ValueError("Invalid eventName format.")

    url = "{BASE_URL}/cvehistory/2.0"

    params = {
        "changeStartDate": changeStartDate,
        "changeEndDate": changeEndDate,
        "cveId": cveId,
        "eventName": eventName,
        "resultsPerPage": resultsPerPage,
        "startIndex": startIndex,
    }

    # remove None values
    params = {k: v for k, v in params.items() if v}

    data = await requests.make_get_request_with_params(url, params, API_KEY)
    
    if data["error"]:
        logging.error("No data received")
    
    logging.info(f"return: {data}")

    return data

def main():
    # Initialize and run the server
    mcp.run(transport='stdio')

if __name__ == "__main__":
    main()