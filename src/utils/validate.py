import ipaddress
import re
from urllib.parse import urlparse
from typing import Any

# Validate IP address
def is_valid_ip(ip: str) -> bool:
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False
    
# Validate domain name
def is_valid_domain(domain: str) -> bool:
    if len(domain) > 253:
        return False   
    
    regex = r"^(?!-)[A-Za-z0-9-]{1,63}(?<!-)\.(?:[A-Za-z]{2,})$"
    return re.match(regex, domain) is not None

# Validate URL
def is_valid_url(url: str) -> bool:
    try:
        result = urlparse(url)
        return all([result.scheme in ("http", "https"), result.netloc != ""])
    except Exception:
        return False

# Validate email address
def is_valid_email(email: str) -> bool:
    regex = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    return re.match(regex, email) is not None

# Validate hash (MD5, SHA1, SHA256)
def is_valid_hash(hash_str: str) -> bool:
    md5_regex = r"^[a-fA-F0-9]{32}$"
    sha1_regex = r"^[a-fA-F0-9]{40}$"
    sha256_regex = r"^[a-fA-F0-9]{64}$"
    
    return (re.match(md5_regex, hash_str) is not None or
            re.match(sha1_regex, hash_str) is not None or
            re.match(sha256_regex, hash_str) is not None)

# General indicator validation
def is_valid_indicator(indicator: str, indicator_type: str) -> bool:
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
        return False
    
# Validate ipv4 address
def is_valid_ipv4(ip: str) -> bool:
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False
    
# Validate ipv6 address
def is_valid_ipv6(ip: str) -> bool:
    try:
        ipaddress.IPv6Address(ip)
        return True
    except ipaddress.AddressValueError:
        return False
    
# Validate MAC address
def is_valid_mac(mac: str) -> bool:
    regex = r"^(?:[0-9a-fA-F]{2}[:-]){5}(?:[0-9a-fA-F]{2})$"
    return re.match(regex, mac) is not None

# Validate CVE identifier
def is_valid_cve(cve: str) -> bool:
    regex = r"^CVE-\d{4}-\d{4,}$"
    return re.match(regex, cve) is not None

# Validate CPE identifier
def is_valid_cpe(cpe: str) -> bool:
    regex = r"^cpe:2\.3:[aho]:[^:]+:[^:]+:[^:]+:[^:]+:[^:]+:[^:]+:[^:]+$"
    return re.match(regex, cpe) is not None

# Validate CWE identifier
def is_valid_cwe(cwe: str) -> bool:
    regex = r"^CWE-\d{1,5}$"
    return re.match(regex, cwe) is not None
    
# Validate CIDR notation
def is_valid_cidr(cidr: str) -> bool:
    try:
        ipaddress.ip_network(cidr, strict=False)
        return True
    except ValueError:
        return False
    
