# extractors/header_extractor.py
import logging
import re
from email.utils import parseaddr, parsedate_to_datetime
from typing import Dict, List, Any, Optional

logger = logging.getLogger(__name__)

def extract_headers(msg):
    """
    Extract and validate headers from an email message.
    
    Args:
        msg (email.message.Message): Email message object
        
    Returns:
        dict: Dictionary containing validated header information
    """
    logger.debug("Starting header extraction")
    
    headers = {
        "message_id": "",
        "sender": "",
        "return_path": "",
        "receiver": "",
        "reply_to": "",
        "subject": "",
        "date": "",
        "authentication": {
            "dkim": "",
            "spf": "",
            "dmarc": ""
        },
        "smtp": {
            "delivered_to": "",
            "received": []
        }
    }
    
    try:
        # Common header extraction logic
        headers["message_id"] = sanitize_header(msg.get("Message-ID", ""))
        logger.debug(f"Extracted Message-ID: {headers['message_id']}")
        
        headers["sender"] = sanitize_header(msg.get("From", ""))
        logger.debug(f"Extracted sender: {headers['sender']}")
        
        headers["return_path"] = sanitize_header(msg.get("Return-Path", ""), remove_brackets=True)
        logger.debug(f"Extracted Return-Path: {headers['return_path']}")
        
        headers["receiver"] = sanitize_header(msg.get("To", ""))
        logger.debug(f"Extracted receiver: {headers['receiver']}")
        
        headers["reply_to"] = sanitize_header(msg.get("Reply-To", ""))
        logger.debug(f"Extracted Reply-To: {headers['reply_to']}")
        
        headers["subject"] = sanitize_header(msg.get("Subject", ""))
        logger.debug(f"Extracted subject: {headers['subject']}")
        
        # Date parsing with error handling
        date_header = sanitize_header(msg.get("Date", ""))
        headers["date"] = parse_date_safely(date_header)
        logger.debug(f"Extracted date: {headers['date']}")
        
        # Extract authentication results
        auth_results = sanitize_header(msg.get("Authentication-Results", ""))
        logger.debug(f"Raw Authentication-Results: {auth_results}")
        
        if auth_results:
            # Extract DKIM result
            dkim_match = re.search(r'dkim=(\w+)', auth_results, re.IGNORECASE)
            if dkim_match:
                headers["authentication"]["dkim"] = dkim_match.group(1)
                logger.debug(f"Extracted DKIM result: {headers['authentication']['dkim']}")
            
            # Extract SPF result
            spf_match = re.search(r'spf=(\w+)', auth_results, re.IGNORECASE)
            if spf_match:
                headers["authentication"]["spf"] = spf_match.group(1)
                logger.debug(f"Extracted SPF result: {headers['authentication']['spf']}")
            
            # Extract DMARC result
            dmarc_match = re.search(r'dmarc=(\w+)', auth_results, re.IGNORECASE)
            if dmarc_match:
                headers["authentication"]["dmarc"] = dmarc_match.group(1)
                logger.debug(f"Extracted DMARC result: {headers['authentication']['dmarc']}")
        else:
            logger.debug("No Authentication-Results header found")
            
            # Set default values for authentication fields when not present
            # This ensures the structure matches what email_parser.py expects
            headers["authentication"]["dkim"] = ""
            headers["authentication"]["spf"] = ""
            headers["authentication"]["dmarc"] = ""
        
        # Extract SMTP headers
        headers["smtp"]["delivered_to"] = sanitize_header(msg.get("Delivered-To", ""))
        logger.debug(f"Extracted Delivered-To: {headers['smtp']['delivered_to']}")
        
        received_headers = msg.get_all("Received", [])
        headers["smtp"]["received"] = [sanitize_header(r) for r in received_headers]
        logger.debug(f"Extracted {len(headers['smtp']['received'])} Received headers")
        
        # Validate headers
        validate_headers(headers)
        
        logger.debug("Header extraction completed successfully")
        
    except Exception as e:
        logger.error(f"Error extracting headers: {str(e)}")
        import traceback
        logger.debug(traceback.format_exc())
        
        # Ensure authentication fields exist even in case of error
        if "authentication" not in headers:
            headers["authentication"] = {"dkim": "", "spf": "", "dmarc": ""}
        
    return headers

def sanitize_header(header_value, remove_brackets=False):
    """
    Sanitize a header value to prevent injection attacks.
    
    Args:
        header_value (str): The header value to sanitize
        remove_brackets (bool): Whether to remove angle brackets
        
    Returns:
        str: Sanitized header value
    """
    if not header_value:
        return ""
        
    # Remove newlines and control characters
    sanitized = re.sub(r'[\r\n\t]', '', str(header_value))
    
    # Remove angle brackets if specified
    if remove_brackets:
        sanitized = re.sub(r'[<>]', '', sanitized)
        
    return sanitized.strip()

def parse_date_safely(date_string):
    """
    Parse date with error handling.
    
    Args:
        date_string (str): Date string to parse
        
    Returns:
        str: ISO formatted date string or original string if parsing fails
    """
    if not date_string:
        return ""
        
    try:
        dt = parsedate_to_datetime(date_string)
        return dt.isoformat()
    except Exception as e:
        logger.warning(f"Failed to parse date header: {date_string}, error: {str(e)}")
        return date_string

def validate_headers(headers):
    """
    Validate header values and structure.
    
    Args:
        headers (dict): Headers dictionary to validate
    """
    # Validate email addresses
    for field in ["sender", "return_path", "receiver", "reply_to"]:
        if headers[field] and not is_valid_email_address(headers[field]):
            logger.warning(f"Invalid email address in {field}: {headers[field]}")
    
    # Check for required headers
    if not headers["sender"]:
        logger.warning("Missing sender header")
    
    # Validate date format if present
    if headers["date"] and not (
        re.match(r'^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}', headers["date"]) or 
        re.match(r'^[A-Z][a-z]{2}, \d{1,2} [A-Z][a-z]{2} \d{4}', headers["date"])
    ):
        logger.warning(f"Date format may be invalid: {headers['date']}")
    
    # Validate Message-ID format
    if headers["message_id"] and not (
        headers["message_id"].startswith("<") and 
        headers["message_id"].endswith(">") and
        "@" in headers["message_id"]
    ):
        logger.warning(f"Message-ID format may be invalid: {headers['message_id']}")
    
def is_valid_email_address(email):
    """
    Basic validation for email addresses.
    
    Args:
        email (str): Email address to validate
        
    Returns:
        bool: True if email format is valid, False otherwise
    """
    # Check for empty or non-string input
    if not email or not isinstance(email, str):
        return False
    
    # Check for angle brackets and strip if present
    if email.startswith("<") and email.endswith(">"):
        email = email[1:-1]
    
    # Check for display name and extract just the email
    if " " in email:
        _, email = parseaddr(email)
    
    # Basic pattern matching
    return bool(re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email))