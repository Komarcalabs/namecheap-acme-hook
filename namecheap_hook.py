#!/usr/bin/env python3
"""
Namecheap ACME Hook for Certbot
==============================

A Certbot DNS-01 manual auth/cleanup hook script designed to work with the
official Namecheap API.

Features:
- Pure Python 3.10+ implementation with zero external dependencies (except 'requests').
- Complete REST/XML client for Namecheap domains.dns.getHosts and domains.dns.setHosts.
- Automatic detection of registered domain (SLD/TLD) for subdomains and complex TLDs.
- Custom pure-Python UDP DNS client for verifying TXT record propagation.
- Auto-detection of server public IP (required by Namecheap API whitelisting).
- Configurable via namecheap.ini file.
- Comprehensive log timing and error reporting.

Author: Komarcalabs
License: MIT
"""

import argparse
import configparser
import logging
import os
import random
import socket
import struct
import sys
import time
import xml.etree.ElementTree as ET
from typing import TypedDict, Optional

# --- Logger Setup ---

class ColorFormatter(logging.Formatter):
    """Logging Formatter to add colors and info styling for TTY outputs."""
    
    GREY = "\x1b[38;20m"
    YELLOW = "\x1b[33;20m"
    RED = "\x1b[31;20m"
    BOLD_RED = "\x1b[31;1m"
    GREEN = "\x1b[32;20m"
    CYAN = "\x1b[36;20m"
    RESET = "\x1b[0m"
    
    FORMATS = {
        logging.DEBUG: GREY + "[DEBUG] %(message)s" + RESET,
        logging.INFO: CYAN + "[INFO] %(message)s" + RESET,
        logging.WARNING: YELLOW + "[WARNING] %(message)s" + RESET,
        logging.ERROR: RED + "[ERROR] %(message)s" + RESET,
        logging.CRITICAL: BOLD_RED + "[CRITICAL] %(message)s" + RESET
    }
    
    def format(self, record):
        if not sys.stderr.isatty():
            clean_fmt = "[%(levelname)s] %(message)s"
            formatter = logging.Formatter(clean_fmt)
            return formatter.format(record)
            
        log_fmt = self.FORMATS.get(record.levelno, "[%(levelname)s] %(message)s")
        formatter = logging.Formatter(log_fmt)
        return formatter.format(record)


logger = logging.getLogger("namecheap_hook")
handler = logging.StreamHandler(sys.stderr)
handler.setFormatter(ColorFormatter())
logger.addHandler(handler)
logger.setLevel(logging.INFO)

# Import requests (only external library dependency allowed)
try:
    import requests
except ImportError:
    logger.critical("The 'requests' library is required. Please install it using 'pip install requests'.")
    sys.exit(1)


# --- Types and Custom Exceptions ---

class HostRecord(TypedDict):
    Name: str
    Type: str
    Address: str
    MXPref: str
    TTL: str


class NamecheapAPIError(Exception):
    """Raised when Namecheap API returns an error status in XML."""
    def __init__(self, errors: list[tuple[str, str]]):
        self.errors = errors
        super().__init__("; ".join([f"Error {num}: {text}" for num, text in errors]))


# --- Config Loader & IP Auto-detection ---

def load_config(config_path: str) -> dict:
    """Loads configuration settings from an INI file."""
    if not os.path.exists(config_path):
        raise FileNotFoundError(f"Configuration file not found at: {config_path}")
        
    config = configparser.ConfigParser()
    config.read(config_path)
    
    section = 'namecheap' if 'namecheap' in config else 'DEFAULT'
    
    # Required authentication fields
    required = ['api_user', 'user_name', 'api_key']
    missing = [key for key in required if key not in config[section]]
    if missing:
        raise ValueError(f"Missing required configuration options in [{section}]: {', '.join(missing)}")
        
    # Optional parameters with safe defaults
    ttl = config[section].getint('ttl', fallback=60)
    propagation_timeout = config[section].getint('propagation_timeout', fallback=300)
    propagation_interval = config[section].getint('propagation_interval', fallback=15)
    sandbox = config[section].getboolean('sandbox', fallback=False)
    client_ip = config[section].get('client_ip', fallback='').strip()
    
    config_dict = {
        'api_user': config[section]['api_user'].strip(),
        'user_name': config[section]['user_name'].strip(),
        'api_key': config[section]['api_key'].strip(),
        'client_ip': client_ip,
        'ttl': ttl,
        'propagation_timeout': propagation_timeout,
        'propagation_interval': propagation_interval,
        'sandbox': sandbox
    }
    
    # If client_ip is empty, attempt to auto-detect it
    if not config_dict['client_ip']:
        logger.info("client_ip is blank. Auto-detecting public IP address...")
        config_dict['client_ip'] = auto_detect_public_ip()
        
    return config_dict


def auto_detect_public_ip() -> str:
    """Fetches public IP address using public APIs (ipify with fallback to ifconfig.me)."""
    providers = [
        ('https://api.ipify.org', 5.0),
        ('https://ifconfig.me/ip', 5.0)
    ]
    
    for url, timeout in providers:
        try:
            logger.debug(f"Attempting to query public IP from: {url}")
            response = requests.get(url, timeout=timeout)
            if response.status_code == 200:
                ip = response.text.strip()
                # Verify that it is a valid IP address
                socket.inet_aton(ip)
                logger.info(f"Auto-detected public IP: {ip}")
                return ip
        except Exception as e:
            logger.warning(f"Could not fetch public IP from {url}: {e}")
            
    raise RuntimeError("Failed to auto-detect public IP address. Please specify 'client_ip' in namecheap.ini.")


def find_config_file(custom_path: Optional[str] = None) -> str:
    """Locates the namecheap.ini config file based on several standard search paths."""
    if custom_path:
        if os.path.exists(custom_path):
            return custom_path
        raise FileNotFoundError(f"Specified config file not found: {custom_path}")
        
    # 1. Environment Variable
    env_path = os.environ.get('NAMECHEAP_INI')
    if env_path and os.path.exists(env_path):
        return env_path
        
    # 2. Directory of the script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    script_path = os.path.join(script_dir, 'namecheap.ini')
    if os.path.exists(script_path):
        return script_path
        
    # 3. Current Working Directory
    cwd_path = os.path.join(os.getcwd(), 'namecheap.ini')
    if os.path.exists(cwd_path):
        return cwd_path
        
    # 4. Standard system /etc path
    etc_path = '/etc/namecheap.ini'
    if os.path.exists(etc_path):
        return etc_path
        
    raise FileNotFoundError("Could not find namecheap.ini configuration file.")


# --- Namecheap API REST Client ---

def make_api_request(command: str, params: dict, config: dict) -> str:
    """Helper method to construct and POST a request to Namecheap XML-RPC API with retries."""
    base_url = (
        "https://api.sandbox.namecheap.com/xml.response"
        if config['sandbox']
        else "https://api.namecheap.com/xml.response"
    )
    
    query_params = {
        'ApiUser': config['api_user'],
        'ApiKey': config['api_key'],
        'UserName': config['user_name'],
        'ClientIP': config['client_ip'],
        'Command': command,
    }
    query_params.update(params)
    
    max_retries = 3
    retry_delay = 2.0
    
    for attempt in range(max_retries):
        try:
            logger.debug(f"Calling Namecheap API '{command}' (Attempt {attempt+1}/{max_retries})...")
            # Always POST to support larger lists of records safely
            response = requests.post(base_url, data=query_params, timeout=30.0)
            response.raise_for_status()
            return response.text
        except requests.exceptions.RequestException as e:
            logger.warning(f"HTTP request error: {e}")
            if attempt == max_retries - 1:
                raise
            time.sleep(retry_delay)
            
    raise RuntimeError("Max retries exceeded for API request.")


def parse_xml_response(response_text: str) -> ET.Element:
    """Parses Namecheap's XML response, strips namespaces, and handles API errors."""
    try:
        root = ET.fromstring(response_text)
    except ET.ParseError as e:
        logger.error(f"Failed to parse XML response: {e}")
        logger.debug(f"Raw response: {response_text}")
        raise ValueError(f"Invalid XML format in Namecheap API response: {e}")
        
    # Strip namespaces from XML tags for easier querying
    for elem in root.iter():
        if '}' in elem.tag:
            elem.tag = elem.tag.split('}', 1)[1]
            
    status = root.attrib.get('Status', 'ERROR')
    if status == 'ERROR':
        errors = []
        for err_node in root.findall('.//Errors/Error'):
            num = err_node.attrib.get('Number', 'Unknown')
            text = err_node.text or 'No details'
            errors.append((num, text))
            
        if not errors:
            errors.append(('Unknown', 'Unknown Namecheap API error occurred.'))
            
        raise NamecheapAPIError(errors)
        
    return root


def get_dns_hosts(sld: str, tld: str, config: dict) -> tuple[list[HostRecord], str]:
    """Retrieves all DNS host records and the active EmailType for a domain."""
    params = {
        'SLD': sld,
        'TLD': tld,
    }
    response_text = make_api_request('namecheap.domains.dns.getHosts', params, config)
    root = parse_xml_response(response_text)
    
    result_node = root.find('.//DomainDNSGetHostsResult')
    if result_node is None:
        raise ValueError("DomainDNSGetHostsResult element was missing from API response.")
        
    email_type = result_node.attrib.get('EmailType', 'NONE')
    
    hosts: list[HostRecord] = []
    for host_node in result_node.findall('host'):
        hosts.append({
            'Name': host_node.attrib.get('Name', ''),
            'Type': host_node.attrib.get('Type', ''),
            'Address': host_node.attrib.get('Address', ''),
            'MXPref': host_node.attrib.get('MXPref', '10'),
            'TTL': host_node.attrib.get('TTL', '1799'),
        })
        
    return hosts, email_type


def set_dns_hosts(sld: str, tld: str, hosts: list[HostRecord], email_type: str, config: dict) -> None:
    """Replaces all current DNS host records for a domain with the provided list."""
    params = {
        'SLD': sld,
        'TLD': tld,
        'EmailType': email_type,
    }
    
    for idx, host in enumerate(hosts, start=1):
        params[f'HostName{idx}'] = host['Name']
        params[f'RecordType{idx}'] = host['Type']
        params[f'Address{idx}'] = host['Address']
        params[f'TTL{idx}'] = host['TTL']
        if host['Type'].upper() == 'MX':
            params[f'MXPref{idx}'] = host['MXPref']
            
    response_text = make_api_request('namecheap.domains.dns.setHosts', params, config)
    parse_xml_response(response_text)
    logger.debug(f"Successfully set {len(hosts)} DNS host records for {sld}.{tld}.")


# --- Domain Suffix Matching Algorithm ---

def detect_registered_domain(domain: str, config: dict) -> tuple[str, str, str]:
    """
    Iterates right-to-left through the domain parts to determine the registered
    second-level domain (SLD) and top-level domain (TLD) by testing getHosts API.
    
    Returns a tuple of (sld, tld, subdomain_prefix).
    """
    domain = domain.lower().strip()
    if domain.startswith('*.'):
        domain = domain[2:]
        
    parts = domain.split('.')
    n = len(parts)
    if n < 2:
        raise ValueError(f"Invalid domain syntax: {domain}")
        
    last_error = ""
    # Test candidate splits from shortest registered domain suffix (e.g. sld=parts[-2], tld=parts[-1])
    # to longest registered domain suffix (e.g. sld=parts[0], tld=parts[1...n])
    for i in range(2, n + 1):
        sld = parts[-i]
        tld = '.'.join(parts[-(i - 1):])
        subdomain_prefix = '.'.join(parts[:-i])
        
        logger.debug(f"Checking if registered domain is '{sld}.{tld}'...")
        try:
            get_dns_hosts(sld, tld, config)
            # If get_dns_hosts returns without error, we own this domain suffix
            return sld, tld, subdomain_prefix
        except NamecheapAPIError as e:
            is_unowned_error = False
            for num, text in e.errors:
                # 2016166: Domain is not associated with your account
                # Check messages for safety in case error codes vary
                if num == '2016166' or 'not associated' in text.lower() or 'not found' in text.lower():
                    is_unowned_error = True
                    break
            if is_unowned_error:
                last_error = str(e)
                continue
            # Raise other API errors (auth failure, IP whitelist blocks) immediately
            raise
        except Exception:
            raise
            
    raise ValueError(f"No registered domain found in your Namecheap account matching '{domain}'. Last API error: {last_error}")


# --- Custom Pure-Python UDP DNS Client ---

def _parse_name(data: bytes, offset: int, depth: int = 0) -> tuple[list[str], int]:
    """Helper to parse a DNS label sequence, supporting RFC-1035 compression pointers."""
    if depth > 10:
        raise ValueError("Excessive DNS pointer redirection/loop detected.")
        
    labels = []
    while True:
        if offset >= len(data):
            raise IndexError("Truncated DNS packet label sequence.")
            
        byte = data[offset]
        if byte == 0:
            offset += 1
            break
        elif (byte & 0xC0) == 0xC0:
            # Compression pointer: 14-bit offset
            if offset + 1 >= len(data):
                raise IndexError("Truncated compression pointer offset.")
            pointer = struct.unpack('!H', data[offset:offset+2])[0] & 0x3FFF
            offset += 2
            
            ref_labels, _ = _parse_name(data, pointer, depth + 1)
            labels.extend(ref_labels)
            break
        else:
            offset += 1
            if offset + byte > len(data):
                raise IndexError("Truncated DNS label string data.")
            label_str = data[offset:offset+byte].decode('utf-8', errors='ignore')
            labels.append(label_str)
            offset += byte
            
    return labels, offset


def query_dns_txt(domain: str, dns_server: str, timeout: float = 4.0) -> list[str]:
    """
    Sends a raw UDP DNS query for TXT records to a specific server.
    Returns parsed TXT record strings. Safe, fast, and dependency-free.
    """
    tx_id = random.randint(0, 65535)
    # Header: Standard Query, Recursion Desired (0x0100)
    header = struct.pack('!HHHHHH', tx_id, 0x0100, 1, 0, 0, 0)
    
    # Question: Encode name
    qname = b''
    for part in domain.split('.'):
        part_bytes = part.encode('utf-8')
        if len(part_bytes) > 63:
            raise ValueError(f"DNS label too long: {part}")
        qname += struct.pack('B', len(part_bytes)) + part_bytes
    qname += b'\x00'
    
    # QTYPE = 16 (TXT), QCLASS = 1 (IN)
    question = qname + struct.pack('!HH', 16, 1)
    query_packet = header + question
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    
    try:
        sock.sendto(query_packet, (dns_server, 53))
        response_data, _ = sock.recvfrom(512)
    except Exception as e:
        logger.debug(f"DNS query to {dns_server} failed or timed out: {e}")
        return []
    finally:
        sock.close()
        
    if len(response_data) < 12:
        return []
        
    resp_id, resp_flags, resp_qd, resp_an, resp_ns, resp_ar = struct.unpack('!HHHHHH', response_data[:12])
    if resp_id != tx_id:
        return []
        
    # Check Response Code (RCODE is lower 4 bits of flags)
    rcode = resp_flags & 0x000F
    if rcode != 0:
        return []
        
    try:
        offset = 12
        # Skip questions
        for _ in range(resp_qd):
            _, offset = _parse_name(response_data, offset)
            offset += 4  # type and class
            
        # Parse answers
        txt_values = []
        for _ in range(resp_an):
            _, offset = _parse_name(response_data, offset)
            if offset + 10 > len(response_data):
                break
            atype, aclass, attl, rdlength = struct.unpack('!HHIH', response_data[offset:offset+10])
            offset += 10
            
            if offset + rdlength > len(response_data):
                break
            rdata = response_data[offset:offset+rdlength]
            offset += rdlength
            
            if atype == 16:  # TXT record type
                # Read multiple length-prefixed chunks in rdata
                seg_offset = 0
                txt_parts = []
                while seg_offset < len(rdata):
                    seg_len = rdata[seg_offset]
                    seg_offset += 1
                    if seg_offset + seg_len > len(rdata):
                        break
                    txt_parts.append(rdata[seg_offset:seg_offset+seg_len].decode('utf-8', errors='ignore'))
                    seg_offset += seg_len
                txt_values.append("".join(txt_parts))
                
        return txt_values
    except Exception as e:
        logger.debug(f"Failed parsing DNS response payload: {e}")
        return []


def get_system_dns_servers() -> list[str]:
    """Reads system resolvers on Linux/macOS from /etc/resolv.conf."""
    servers = []
    try:
        with open('/etc/resolv.conf', 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('nameserver'):
                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[1]
                        # Verify valid IPv4 format
                        socket.inet_aton(ip)
                        servers.append(ip)
    except Exception:
        pass
    return servers


# --- Hook Actions ---

def do_auth(config: dict, certbot_domain: str, certbot_validation: str) -> None:
    """Executes the --manual-auth-hook challenge creation and DNS checking."""
    start_time = time.time()
    
    # Strip any wildcard marker
    clean_domain = certbot_domain.lower().strip()
    if clean_domain.startswith('*.'):
        clean_domain = clean_domain[2:]
        
    logger.info(f"Starting DNS-01 authentication challenge for domain: {clean_domain}")
    
    # 1. Detect registered SLD/TLD and subdomain prefix
    sld, tld, subdomain_prefix = detect_registered_domain(clean_domain, config)
    
    # 2. Determine target record hostname
    # For domains.dns.setHosts:
    # - If we want to add _acme-challenge to example.com, host is "_acme-challenge"
    # - If we want to add _acme-challenge to sub.example.com, host is "_acme-challenge.sub"
    target_host = f"_acme-challenge.{subdomain_prefix}" if subdomain_prefix else "_acme-challenge"
    
    # 3. Retrieve existing host records
    hosts, email_type = get_dns_hosts(sld, tld, config)
    
    # 4. Check if validation token already exists to prevent duplicate entries
    duplicate = False
    for host in hosts:
        if (host['Name'].lower() == target_host.lower() and 
            host['Type'].upper() == 'TXT' and 
            host['Address'] == certbot_validation):
            duplicate = True
            break
            
    if duplicate:
        logger.info(f"TXT record for {target_host}.{sld}.{tld} with value already exists. Skipping write.")
    else:
        # Create and append new TXT record
        new_record: HostRecord = {
            'Name': target_host,
            'Type': 'TXT',
            'Address': certbot_validation,
            'MXPref': '10',
            'TTL': str(config['ttl'])
        }
        hosts.append(new_record)
        
        logger.info(f"Adding TXT record: {target_host}.{sld}.{tld} -> '{certbot_validation}' (TTL: {config['ttl']})")
        set_dns_hosts(sld, tld, hosts, email_type, config)
        
    # 5. Wait for DNS propagation
    query_name = f"_acme-challenge.{clean_domain}"
    logger.info(f"Checking for DNS propagation of TXT record at '{query_name}'...")
    
    resolvers = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]
    for sys_dns in get_system_dns_servers():
        if sys_dns not in resolvers:
            resolvers.append(sys_dns)
            
    logger.debug(f"Target DNS servers for validation: {', '.join(resolvers)}")
    
    timeout_limit = config['propagation_timeout']
    interval = config['propagation_interval']
    elapsed = 0
    propagated = False
    
    while elapsed < timeout_limit:
        logger.info(f"Waiting for propagation... (Elapsed: {elapsed}s / Timeout: {timeout_limit}s)")
        
        for resolver in resolvers:
            logger.debug(f"Querying resolver {resolver} for '{query_name}'...")
            txt_records = query_dns_txt(query_name, resolver)
            if certbot_validation in txt_records:
                logger.info(f"Success! TXT validation value found on resolver {resolver} ({elapsed}s elapsed).")
                propagated = True
                break
                
        if propagated:
            break
            
        time.sleep(interval)
        elapsed += interval
        
    if not propagated:
        logger.error(f"DNS propagation timed out after {timeout_limit} seconds.")
        # We fail and exit with error to avoid a guaranteed Let's Encrypt validation error
        sys.exit(1)
        
    total_time = time.time() - start_time
    logger.info(f"DNS-01 auth challenge successfully completed in {total_time:.2f}s total.")


def do_cleanup(config: dict, certbot_domain: str, certbot_validation: str) -> None:
    """Executes the --manual-cleanup-hook challenge destruction."""
    start_time = time.time()
    
    clean_domain = certbot_domain.lower().strip()
    if clean_domain.startswith('*.'):
        clean_domain = clean_domain[2:]
        
    logger.info(f"Starting DNS-01 cleanup challenge for domain: {clean_domain}")
    
    # 1. Detect registered SLD/TLD and subdomain prefix
    sld, tld, subdomain_prefix = detect_registered_domain(clean_domain, config)
    
    # 2. Determine target record hostname
    target_host = f"_acme-challenge.{subdomain_prefix}" if subdomain_prefix else "_acme-challenge"
    
    # 3. Retrieve existing host records
    hosts, email_type = get_dns_hosts(sld, tld, config)
    
    # 4. Filter out ONLY the TXT record that matches our verification token
    original_count = len(hosts)
    filtered_hosts: list[HostRecord] = []
    
    removed_count = 0
    for host in hosts:
        if (host['Name'].lower() == target_host.lower() and 
            host['Type'].upper() == 'TXT' and 
            host['Address'] == certbot_validation):
            removed_count += 1
            continue
        filtered_hosts.append(host)
        
    if removed_count == 0:
        logger.info(f"No matching TXT record found for cleanup of {target_host}.{sld}.{tld}.")
        return
        
    logger.info(f"Removing {removed_count} matching TXT records for {target_host}.{sld}.{tld}.")
    set_dns_hosts(sld, tld, filtered_hosts, email_type, config)
    
    total_time = time.time() - start_time
    logger.info(f"DNS-01 cleanup challenge successfully completed in {total_time:.2f}s total.")


# --- CLI Interface Entrypoint ---

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Namecheap DNS-01 Certbot Hook client",
        epilog="Expects CERTBOT_DOMAIN and CERTBOT_VALIDATION environment variables to be set by Certbot."
    )
    parser.add_argument(
        'action',
        choices=['auth', 'cleanup'],
        help="The hook action (auth to create record and verify; cleanup to remove record)."
    )
    parser.add_argument(
        '--config',
        default=None,
        help="Path to the namecheap.ini configuration file. If omitted, search default paths."
    )
    parser.add_argument(
        '--verbose',
        action='store_true',
        help="Enable detailed debug-level logging output."
    )
    
    args = parser.parse_args()
    
    # Set verbose log levels
    if args.verbose:
        logger.setLevel(logging.DEBUG)
        logger.debug("Debug verbose logging is enabled.")
        
    # Read environment variables injected by Certbot
    certbot_domain = os.environ.get('CERTBOT_DOMAIN')
    certbot_validation = os.environ.get('CERTBOT_VALIDATION')
    
    if not certbot_domain:
        logger.critical("Missing required environment variable: CERTBOT_DOMAIN")
        sys.exit(1)
    if not certbot_validation:
        logger.critical("Missing required environment variable: CERTBOT_VALIDATION")
        sys.exit(1)
        
    try:
        config_path = find_config_file(args.config)
        logger.debug(f"Using configuration file: {config_path}")
        config = load_config(config_path)
    except Exception as e:
        logger.critical(f"Configuration error: {e}")
        sys.exit(1)
        
    try:
        if args.action == 'auth':
            do_auth(config, certbot_domain, certbot_validation)
        elif args.action == 'cleanup':
            do_cleanup(config, certbot_domain, certbot_validation)
    except Exception as e:
        logger.critical(f"Hook failed with error: {e}")
        if logger.isEnabledFor(logging.DEBUG):
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()
