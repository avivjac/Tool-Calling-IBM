import ipaddress
import re
from urllib.parse import urlparse
from typing import Any
import logging

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