import ipaddress
import re
from urllib.parse import urlparse
from typing import Any
import logging
import base64
import binascii
import datetime

# ---------- Logging ----------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s - %(message)s",
    filename="validate.log",
    filemode="a"
)

logger = logging.getLogger(__name__)

# Validate IP address
def is_valid_ip(ip: str) -> bool:
    logger.info(f"Validating IP address: {ip}")
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        logger.error(f"Invalid IP address: {ip}")
        return False
    
# Validate domain name
def is_valid_domain(domain: str) -> bool:
    logger.info(f"Validating domain name: {domain}")
    if len(domain) > 253:
        logger.error(f"Invalid domain name (too long): {domain}")    
        return False   
    
    regex = r"^(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$"
    result = re.match(regex, domain) is not None
    logger.info(f"Domain validation result for {domain}: {result}")
    return result

# Validate URL
def is_valid_url(url: str) -> bool:
    logger.info(f"Validating URL: {url}")
    try:
        result = urlparse(url)
        return all([result.scheme in ("http", "https"), result.netloc != ""])
    except Exception:
        logger.error(f"Invalid URL: {url}")
        return False

# Validate email address
def is_valid_email(email: str) -> bool:
    logger.info(f"Validating email address: {email}")
    regex = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return re.match(regex, email) is not None

# Validate hash (MD5, SHA1, SHA256)
def is_valid_hash(hash_str: str) -> bool:
    md5_regex = r"^[a-fA-F0-9]{32}$"
    sha1_regex = r"^[a-fA-F0-9]{40}$"
    sha256_regex = r"^[a-fA-F0-9]{64}$"

    logger.info(f"Validating hash: {hash_str}")

    return (re.match(md5_regex, hash_str) is not None or
            re.match(sha1_regex, hash_str) is not None or
            re.match(sha256_regex, hash_str) is not None)

# General indicator validation
def is_valid_indicator(indicator: str, indicator_type: str) -> bool:
    logger.info(f"Validating indicator: {indicator} of type {indicator_type}")
    if indicator_type == "ip":
        return is_valid_ip(indicator)
    elif indicator_type == "domain":
        return is_valid_domain(indicator)
    elif indicator_type == "url":
        return is_valid_url(indicator)
    elif indicator_type == "email":
        return is_valid_email(indicator)
    elif indicator_type == "hash":
        return is_valid_hash(indicator)
    else:
        logger.error(f"Unknown indicator type: {indicator_type}")
        return False
    
# Validate ipv4 address
def is_valid_ipv4(ip: str) -> bool:
    logger.info(f"Validating IPv4 address: {ip}")
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ipaddress.AddressValueError:
        logger.error(f"Invalid IPv4 address: {ip}")
        return False
    
# Validate ipv6 address
def is_valid_ipv6(ip: str) -> bool:
    logger.info(f"Validating IPv6 address: {ip}")
    try:
        ipaddress.IPv6Address(ip)
        return True
    except ipaddress.AddressValueError:
        logger.error(f"Invalid IPv6 address: {ip}")
        return False
    
# Validate MAC address
def is_valid_mac(mac: str) -> bool:
    logger.info(f"Validating MAC address: {mac}")
    regex = r"^(?:[0-9a-fA-F]{2}[:-]){5}(?:[0-9a-fA-F]{2})$"
    return re.match(regex, mac) is not None

# Validate CVE identifier
def is_valid_cve(cve: str) -> bool:
    logger.info(f"Validating CVE identifier: {cve}")
    regex = r"^CVE-\d{4}-\d{4,}$"
    return re.match(regex, cve) is not None

# Validate CPE identifier
def is_valid_cpe(cpe: str) -> bool:
    logger.info(f"Validating CPE identifier: {cpe}")
    regex = r"^cpe:2\.3:[aho](?::[^:]+){10}$"
    return re.match(regex, cpe) is not None

# Validate CWE identifier
def is_valid_cwe(cwe: str) -> bool:
    logger.info(f"Validating CWE identifier: {cwe}")
    regex = r"^CWE-\d{1,5}$"
    return re.match(regex, cwe) is not None
    
# Validate CIDR notation
def is_valid_cidr(cidr: str) -> bool:
    logger.info(f"Validating CIDR notation: {cidr}")
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        logger.error(f"Invalid CIDR notation: {cidr}")
        return False
    
# Validate datasource
# using for search endpoint at URLscan.py
def is_valid_datasource(datasource: str) -> bool:
    logger.info(f"Validating datasource: {datasource}")
    return datasource in ["scans", "hostnames", "incidents", "notifications"]

# Validate date
def is_valid_date(date_str: str) -> bool:
    logger.info(f"Validating date: {date_str}")
    # List of formats to check
    formats = [
        "%Y-%m-%d",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ"
    ]
    
    for fmt in formats:
        try:
            datetime.datetime.strptime(date_str, fmt)
            return True
        except ValueError:
            continue
            
    logger.error(f"Invalid date format: {date_str}")
    return False

# validate ASN
def is_valid_asn(asn: str) -> bool:
    logger.info(f"Validating ASN: {asn}")
    try:
        ipaddress.ip_network(asn, strict=False)
        return True
    except ValueError:
        logger.error(f"Invalid ASN: {asn}")
        return False

def is_valid_url_identifier(identifier: str) -> bool:
    """
    Validates if a string is a valid VirusTotal URL identifier.
    A valid identifier is EITHER:
    1. A 64-character hex string (SHA-256 hash).
    2. An unpadded base64url encoded string (RFC 4648 sec 3.2).
    """
    if identifier is None or not isinstance(identifier, str):
        return False

    # --- Check 1: SHA-256 Hex String ---
    # Check length is exactly 64 and contains only hex characters.
    if len(identifier) == 64 and re.fullmatch(r'[a-fA-F0-9]{64}', identifier):
        return True

    # --- Check 2: Unpadded base64url string ---
    # 1. Check for forbidden characters (padding '=' is not allowed in unpadded input)
    if '=' in identifier:
        logging.warning(f"URL identifier validation failed: Found padding '=' in identifier: {identifier}")
        return False
       
    # 2. Check allowed characters for base64url (A-Z, a-z, 0-9, -, _)
    if not re.fullmatch(r'[a-zA-Z0-9_-]+', identifier):
         # If it failed SHA256 check AND has invalid base64 chars, it's invalid.
        logging.warning(f"URL identifier validation failed: Invalid characters in identifier: {identifier}")
        return False

    # 3. Try to decode.
    # Standard base64 decoders require padding. We must re-add padding temporarily to test decoding.
    try:
        padding_needed = len(identifier) % 4
        if padding_needed > 0:
            padded_identifier = identifier + '=' * (4 - padding_needed)
        else:
            padded_identifier = identifier
           
        # Try decoding using the urlsafe alphabet
        base64.urlsafe_b64decode(padded_identifier)
       
        # If decoding succeeded, it's a valid base64url string ready for VT
        return True
       
    except (binascii.Error, ValueError):
        logging.warning(f"URL identifier validation failed: Could not decode base64 string: {identifier}")
        return False