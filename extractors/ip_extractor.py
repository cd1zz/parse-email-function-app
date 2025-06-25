import logging
import re

logger = logging.getLogger(__name__)

def extract_ip_addresses(text):
    """
    Extract IPv4 and IPv6 addresses from text content.
    
    Args:
        text (str): Text content to extract IP addresses from
        
    Returns:
        list: List of unique IP addresses found
    """
    if not text:
        return []
    
    logger.debug("Extracting IP addresses from text content")
    
    try:
        # Extract IPv4 addresses
        ipv4_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
        ipv4_matches = re.findall(ipv4_pattern, text)
        
        # Filter valid IPv4 addresses
        valid_ipv4 = [ip for ip in ipv4_matches if is_valid_ipv4(ip)]
        
        # Extract IPv6 addresses
        ipv6_pattern = r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,5}(?::[0-9a-fA-F]{1,4}){1,2}\b|\b(?:[0-9a-fA-F]{1,4}:){1,4}(?::[0-9a-fA-F]{1,4}){1,3}\b|\b(?:[0-9a-fA-F]{1,4}:){1,3}(?::[0-9a-fA-F]{1,4}){1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,2}(?::[0-9a-fA-F]{1,4}){1,5}\b|\b[0-9a-fA-F]{1,4}:(?::[0-9a-fA-F]{1,4}){1,6}\b|\b:(?::[0-9a-fA-F]{1,4}){1,7}\b|\b::(?:[0-9a-fA-F]{1,4}:){0,6}[0-9a-fA-F]{1,4}\b|\b(?:[0-9a-fA-F]{1,4}:){1,7}:\b'
        ipv6_matches = re.findall(ipv6_pattern, text)
        
        # Combine unique IP addresses
        ip_addresses = list(set(valid_ipv4 + ipv6_matches))
        
        logger.debug(f"Extracted {len(ip_addresses)} unique IP addresses")
        return ip_addresses
        
    except Exception as e:
        logger.error(f"Error extracting IP addresses: {str(e)}")
        return []

def is_valid_ipv4(ip):
    """
    Validate if a string is a valid IPv4 address.
    
    Args:
        ip (str): IP address to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    octets = ip.split('.')
    
    # Check if IP has 4 octets
    if len(octets) != 4:
        return False
    
    # Check each octet
    for octet in octets:
        try:
            # Validate numeric range
            value = int(octet)
            if value < 0 or value > 255:
                return False
            
            # Check for leading zeros (avoiding confusion with octal notation)
            if len(octet) > 1 and octet.startswith('0'):
                return False
                
        except ValueError:
            return False
    
    # Skip local/private IP addresses if needed
    if (
        ip.startswith("127.")
        or ip.startswith("10.")
        or ip.startswith("192.168.")
    ):
        return False

    # Cover the entire 172.16.0.0/12 private range (172.16.0.0 - 172.31.255.255)
    if ip.startswith("172."):
        second_octet = int(octets[1])
        if 16 <= second_octet <= 31:
            return False
    
    return True