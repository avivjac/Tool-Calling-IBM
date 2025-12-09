import pytest
import sys
import os

# Ensure src is in python path to import utils
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '../../..')))

from src.utils import validate

class TestValidate:
    
    # IP Address Tests
    def test_is_valid_ip(self):
        assert validate.is_valid_ip("192.168.1.1") is True
        assert validate.is_valid_ip("::1") is True
        assert validate.is_valid_ip("256.256.256.256") is False
        assert validate.is_valid_ip("invalid-ip") is False

    def test_is_valid_ipv4(self):
        assert validate.is_valid_ipv4("192.168.1.1") is True
        assert validate.is_valid_ipv4("::1") is False
        assert validate.is_valid_ipv4("invalid") is False

    def test_is_valid_ipv6(self):
        assert validate.is_valid_ipv6("::1") is True
        assert validate.is_valid_ipv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334") is True
        assert validate.is_valid_ipv6("192.168.1.1") is False
        assert validate.is_valid_ipv6("invalid") is False

    # Domain Tests
    def test_is_valid_domain(self):
        assert validate.is_valid_domain("google.com") is True
        assert validate.is_valid_domain("sub.example.co.uk") is True
        assert validate.is_valid_domain("-start.com") is False
        assert validate.is_valid_domain("end-.com") is False
        assert validate.is_valid_domain("a" * 255 + ".com") is False  # Too long

    # URL Tests
    def test_is_valid_url(self):
        assert validate.is_valid_url("https://www.google.com") is True
        assert validate.is_valid_url("http://example.com/path?query=1") is True
        assert validate.is_valid_url("ftp://example.com") is False # Code checks only http/https
        assert validate.is_valid_url("not-a-url") is False

    # Email Tests
    def test_is_valid_email(self):
        assert validate.is_valid_email("test@example.com") is True
        assert validate.is_valid_email("user.name+tag@example.co.uk") is True
        assert validate.is_valid_email("invalid-email") is False
        assert validate.is_valid_email("test@.com") is False

    # Hash Tests
    def test_is_valid_hash(self):
        # MD5
        assert validate.is_valid_hash("d41d8cd98f00b204e9800998ecf8427e") is True
        # SHA1
        assert validate.is_valid_hash("da39a3ee5e6b4b0d3255bfef95601890afd80709") is True
        # SHA256
        assert validate.is_valid_hash("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855") is True
        
        assert validate.is_valid_hash("short") is False
        assert validate.is_valid_hash("invalidcharacters!!") is False

    # MAC Address Tests
    def test_is_valid_mac(self):
        assert validate.is_valid_mac("00:11:22:33:44:55") is True
        assert validate.is_valid_mac("aa:bb:cc:dd:ee:ff") is True
        assert validate.is_valid_mac("00-11-22-33-44-55") is True # Regex allows hyphens
        assert validate.is_valid_mac("invalid") is False

    # CVE Tests
    def test_is_valid_cve(self):
        assert validate.is_valid_cve("CVE-2023-12345") is True
        assert validate.is_valid_cve("CVE-1999-0001") is True
        assert validate.is_valid_cve("CVE-2023-1") is False # Expects 4 digits
        assert validate.is_valid_cve("invalid") is False

    # CPE Tests
    def test_is_valid_cpe(self):
        assert validate.is_valid_cpe("cpe:2.3:a:microsoft:internet_explorer:8.0.6001:beta:*:*:*:*:*:*") is True
        assert validate.is_valid_cpe("invalid") is False

    # CWE Tests
    def test_is_valid_cwe(self):
        assert validate.is_valid_cwe("CWE-89") is True
        assert validate.is_valid_cwe("CWE-12345") is True
        assert validate.is_valid_cwe("CWE-") is False
        assert validate.is_valid_cwe("invalid") is False

    # CIDR Tests
    def test_is_valid_cidr(self):
        assert validate.is_valid_cidr("192.168.1.0/24") is True
        assert validate.is_valid_cidr("10.0.0.0/8") is True
        assert validate.is_valid_cidr("::1/128") is True
        assert validate.is_valid_cidr("192.168.1.1") is True # technically valid IP is a single hose CIDR often parsed ok, checking implementation
        # implementation uses ip_network(strict=False). 192.168.1.1 is valid as /32 implicitly or if no mask provided? 
        # ipaddress.ip_network('192.168.1.1') works.
        assert validate.is_valid_cidr("invalid") is False
        assert validate.is_valid_cidr("192.168.1.1/555") is False

    # General Indicator Tests
    def test_is_valid_indicator(self):
        assert validate.is_valid_indicator("1.1.1.1", "ip") is True
        assert validate.is_valid_indicator("google.com", "domain") is True
        assert validate.is_valid_indicator("https://google.com", "url") is True
        assert validate.is_valid_indicator("test@test.com", "email") is True
        assert validate.is_valid_indicator("d41d8cd98f00b204e9800998ecf8427e", "hash") is True
        
        assert validate.is_valid_indicator("invalid", "ip") is False
        assert validate.is_valid_indicator("invalid", "unknown_type") is False
