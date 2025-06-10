import logging
import traceback
import re
from extractors.body_extractor import extract_body
from extractors.ip_extractor import extract_ip_addresses
from utils.url_processing import UrlExtractor, UrlProcessor


logger = logging.getLogger(__name__)

def parse_forwarded_email(msg, depth, max_depth, container_path):
    """
    Parse forwarded email content, identifying the original email from various
    email client forwarding formats.
    
    Args:
        msg (email.message.Message): Email message object
        depth (int): Current recursion depth
        max_depth (int): Maximum recursion depth
        container_path (list): Path of containers
        
    Returns:
        dict: Parsed forwarded email data
    """
    logger.debug(f"Parsing forwarded email at depth {depth}")
    
    # Extract body content
    body_data = extract_body(msg)

    # Get the text string from the body dictionary
    if isinstance(body_data, dict) and "body" in body_data:
        body_text = body_data["body"]
    else:
        body_text = str(body_data)
        
    # Initialize result
    forwarded_data = {
        "client_type": "unknown",
        "original_sender": "",
        "original_recipient": "",
        "original_subject": "",
        "original_date": "",
        "original_body": "",
        "is_original_phishing_email": False,
        "urls": [],
        "ip_addresses": [],
        "domains": []  # Add domains key to ensure it exists
    }
    
    # Try different email client forwarding patterns
    
    # Gmail forwarding pattern
    if "---------- Forwarded message ---------" in body_text:
        logger.debug("Detected Gmail forwarding pattern")
        forwarded_data["client_type"] = "gmail"
        forwarded_data = parse_gmail_forwarded(body_text, forwarded_data)
    
    # Apple Mail forwarding pattern
    elif "Begin forwarded message:" in body_text:
        logger.debug("Detected Apple Mail forwarding pattern")
        forwarded_data["client_type"] = "apple_mail"
        forwarded_data = parse_apple_mail_forwarded(body_text, forwarded_data)
    
    # Outlook forwarding pattern - more precise pattern to avoid false positives
    elif re.search(r"^From:.+?\r?\nSent:.+?\r?\nTo:.+?\r?\nSubject:", body_text, re.MULTILINE | re.DOTALL | re.IGNORECASE):
        logger.debug("Detected Outlook forwarding pattern")
        forwarded_data["client_type"] = "outlook"
        forwarded_data = parse_outlook_forwarded(body_text, forwarded_data)
    
    # Generic forwarding pattern
    elif "-----Original Message-----" in body_text:
        logger.debug("Detected generic forwarding pattern")
        forwarded_data["client_type"] = "generic"
        forwarded_data = parse_generic_forwarded(body_text, forwarded_data)
    
    if forwarded_data["original_body"]:
        # Create a simple body_data dictionary
        body_data = {"body": forwarded_data["original_body"]}
        extracted_urls = UrlExtractor.extract_all_urls_from_email(body_data)
        forwarded_data["urls"] = UrlProcessor.process_urls(extracted_urls)
        forwarded_data["ip_addresses"] = extract_ip_addresses(forwarded_data["original_body"])
        
        # Add domain extraction
        from extractors.domain_extractor import extract_domains
        forwarded_data["domains"] = extract_domains(forwarded_data["urls"])
    
    return forwarded_data

def parse_gmail_forwarded(body_text, forwarded_data):
    """
    Parse Gmail-style forwarded email content.
    
    Args:
        body_text (str): The email body text
        forwarded_data (dict): Dictionary to populate with forwarded email data
        
    Returns:
        dict: Updated forwarded email data
    """
    logger.debug("Parsing Gmail forwarded email")
    
    try:
        # Extract header section after the forwarded message marker
        gmail_pattern = r"---------- Forwarded message ---------\s*\n(.*?)(?:\n\n|\Z)"
        header_match = re.search(gmail_pattern, body_text, re.DOTALL)
        
        if header_match:
            header_section = header_match.group(1)
            
            # Extract From
            from_match = re.search(r"From:\s*(.*?)(?:\n|$)", header_section)
            if from_match:
                forwarded_data["original_sender"] = from_match.group(1).strip()
            
            # Extract Date
            date_match = re.search(r"Date:\s*(.*?)(?:\n|$)", header_section)
            if date_match:
                forwarded_data["original_date"] = date_match.group(1).strip()
            
            # Extract Subject
            subject_match = re.search(r"Subject:\s*(.*?)(?:\n|$)", header_section)
            if subject_match:
                forwarded_data["original_subject"] = subject_match.group(1).strip()
            
            # Extract To
            to_match = re.search(r"To:\s*(.*?)(?:\n|$)", header_section)
            if to_match:
                forwarded_data["original_recipient"] = to_match.group(1).strip()
        
        # Extract the body content after the header section
        body_pattern = r"---------- Forwarded message ---------\s*\n.*?\n\n(.*)"
        body_match = re.search(body_pattern, body_text, re.DOTALL)
        if body_match:
            forwarded_data["original_body"] = body_match.group(1).strip()
        
    except Exception as e:
        logger.error(f"Error parsing Gmail forwarded email: {str(e)}")
    
    return forwarded_data

def parse_apple_mail_forwarded(body_text, forwarded_data):
    """
    Parse Apple Mail-style forwarded email content.
    
    Args:
        body_text (str): The email body text
        forwarded_data (dict): Dictionary to populate with forwarded email data
        
    Returns:
        dict: Updated forwarded email data
    """
    logger.debug("Parsing Apple Mail forwarded email")
    
    try:
        # Extract header section after the forwarded message marker
        apple_pattern = r"Begin forwarded message:(.*?)(?:\n\n|\Z)"
        header_match = re.search(apple_pattern, body_text, re.DOTALL)
        
        if header_match:
            header_section = header_match.group(1)
            
            # Extract From
            from_match = re.search(r"From:\s*(.*?)(?:\n|$)", header_section)
            if from_match:
                forwarded_data["original_sender"] = from_match.group(1).strip()
            
            # Extract Date
            date_match = re.search(r"Date:\s*(.*?)(?:\n|$)", header_section)
            if date_match:
                forwarded_data["original_date"] = date_match.group(1).strip()
            
            # Extract Subject
            subject_match = re.search(r"Subject:\s*(.*?)(?:\n|$)", header_section)
            if subject_match:
                forwarded_data["original_subject"] = subject_match.group(1).strip()
            
            # Extract To
            to_match = re.search(r"To:\s*(.*?)(?:\n|$)", header_section)
            if to_match:
                forwarded_data["original_recipient"] = to_match.group(1).strip()
        
        # Extract the body content after the header section
        body_pattern = r"Begin forwarded message:.*?\n\n(.*)"
        body_match = re.search(body_pattern, body_text, re.DOTALL)
        if body_match:
            forwarded_data["original_body"] = body_match.group(1).strip()
        
    except Exception as e:
        logger.error(f"Error parsing Apple Mail forwarded email: {str(e)}")
    
    return forwarded_data

def parse_outlook_forwarded(body_text, forwarded_data):
    """
    Parse Outlook-style forwarded email content.
    
    Args:
        body_text (str): The email body text
        forwarded_data (dict): Dictionary to populate with forwarded email data
        
    Returns:
        dict: Updated forwarded email data
    """
    logger.debug("Parsing Outlook forwarded email")
    logger.debug(f"Body text length: {len(body_text)}")
    if len(body_text) > 0:
        logger.debug(f"First 200 chars of body text: {body_text[:200]}")
    
    try:
        # Extract the entire header block - more permissive pattern
        outlook_pattern = r"(From:\s*.+?(?:Sent|Date):\s*.+?To:\s*.+?Subject:\s*.+?)(?:\r?\n\r?\n|\Z)"
        header_match = re.search(outlook_pattern, body_text, re.DOTALL | re.IGNORECASE)
        
        if header_match:
            header_section = header_match.group(1)
            logger.debug(f"Found header section: {header_section}")
            
            # Extract From
            from_match = re.search(r"From:\s*(.*?)(?:\r?\n|$)", header_section, re.IGNORECASE)
            if from_match:
                forwarded_data["original_sender"] = from_match.group(1).strip()
                logger.debug(f"Extracted sender: {forwarded_data['original_sender']}")
            
            # Extract Sent (Date) - look for both Sent: and Date:
            date_match = re.search(r"(?:Sent|Date):\s*(.*?)(?:\r?\n|$)", header_section, re.IGNORECASE)
            if date_match:
                forwarded_data["original_date"] = date_match.group(1).strip()
                logger.debug(f"Extracted date: {forwarded_data['original_date']}")
            
            # Extract Subject
            subject_match = re.search(r"Subject:\s*(.*?)(?:\r?\n|$)", header_section, re.IGNORECASE)
            if subject_match:
                forwarded_data["original_subject"] = subject_match.group(1).strip()
                logger.debug(f"Extracted subject: {forwarded_data['original_subject']}")
            
            # Extract To
            to_match = re.search(r"To:\s*(.*?)(?:\r?\n|$)", header_section, re.IGNORECASE)
            if to_match:
                forwarded_data["original_recipient"] = to_match.group(1).strip()
                logger.debug(f"Extracted recipient: {forwarded_data['original_recipient']}")
            
            # Extract the body content
            # Find where the header ends in the original text
            full_match = header_match.group(0)
            header_start = body_text.find(full_match)
            if header_start >= 0:
                header_end = header_start + len(full_match)
                # The body is everything after the header
                if header_end < len(body_text):
                    forwarded_data["original_body"] = body_text[header_end:].strip()
                    logger.debug(f"Extracted body of length: {len(forwarded_data['original_body'])}")
                    if len(forwarded_data["original_body"]) > 0:
                        logger.debug(f"First 200 chars of body: {forwarded_data['original_body'][:200]}")
                else:
                    logger.warning("Header ends at end of text, no body content found")
            else:
                logger.warning("Could not locate header in original text")
        else:
            logger.warning("No matching Outlook header pattern found")
            # Fallback: treat the entire body as the forwarded content
            if len(body_text) > 0:
                forwarded_data["original_body"] = body_text
                logger.debug("Using entire text as body (fallback)")
    except Exception as e:
        logger.error(f"Error parsing Outlook forwarded email: {str(e)}")
        logger.error(traceback.format_exc())
    
    return forwarded_data

def parse_generic_forwarded(body_text, forwarded_data):
    """
    Parse generic forwarded email content.
    
    Args:
        body_text (str): The email body text
        forwarded_data (dict): Dictionary to populate with forwarded email data
        
    Returns:
        dict: Updated forwarded email data
    """
    logger.debug("Parsing generic forwarded email")
    
    try:
        # Extract header section
        generic_pattern = r"-----Original Message-----(.*?)(?:\n\n|\Z)"
        header_match = re.search(generic_pattern, body_text, re.DOTALL)
        
        if header_match:
            header_section = header_match.group(1)
            
            # Extract From
            from_match = re.search(r"From:\s*(.*?)(?:\n|$)", header_section)
            if from_match:
                forwarded_data["original_sender"] = from_match.group(1).strip()
            
            # Extract Date
            date_match = re.search(r"Date:\s*(.*?)(?:\n|$)", header_section) or \
                         re.search(r"Sent:\s*(.*?)(?:\n|$)", header_section)
            if date_match:
                forwarded_data["original_date"] = date_match.group(1).strip()
            
            # Extract Subject
            subject_match = re.search(r"Subject:\s*(.*?)(?:\n|$)", header_section)
            if subject_match:
                forwarded_data["original_subject"] = subject_match.group(1).strip()
            
            # Extract To
            to_match = re.search(r"To:\s*(.*?)(?:\n|$)", header_section)
            if to_match:
                forwarded_data["original_recipient"] = to_match.group(1).strip()
        
        # Extract the body content after the header section
        body_pattern = r"-----Original Message-----.*?\n\n(.*)"
        body_match = re.search(body_pattern, body_text, re.DOTALL)
        if body_match:
            forwarded_data["original_body"] = body_match.group(1).strip()
        
    except Exception as e:
        logger.error(f"Error parsing generic forwarded email: {str(e)}")
    
    return forwarded_data