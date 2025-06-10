# parsers/email_parser.py
import logging
import re
import traceback
from typing import Dict, List, Union, Optional, Any, Set
from email.parser import BytesParser

from extractors.header_extractor import extract_headers
from extractors.body_extractor import extract_body
from extractors.attachment_extractor import extract_attachments
from extractors.ip_extractor import extract_ip_addresses
from extractors.domain_extractor import extract_domains

# New imports for URL processing
from utils.url_processing import UrlExtractor, UrlProcessor

from utils.email_policy import CustomEmailPolicy
from utils.text_cleaner import truncate_urls_in_text, clean_excessive_newlines, strip_urls_and_html

from parsers.proofpoint_parser import is_proofpoint_email, parse_proofpoint_email
from parsers.forwarded_parser import parse_forwarded_email

logger = logging.getLogger(__name__)

def parse_email(
    email_content: Union[str, bytes], 
    depth: int = 0, 
    max_depth: int = 10, 
    container_path: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Main function to parse an email with recursive unwrapping to find original email.
    Following strict hierarchy: message/RFC822 > TNEF > .eml/.msg > forwarded content.
    
    Args:
        email_content: Raw email content as string or bytes
        depth: Current recursion depth
        max_depth: Maximum recursion depth to prevent infinite loops
        container_path: Path of containers (how this email was contained)
        
    Returns:
        dict: Original email data only, without debug/progress information
    """
    if depth > max_depth:
        return {"error": f"Maximum recursion depth ({max_depth}) exceeded"}
    
    if container_path is None:
        container_path = []
    
    logger.debug(f"Parsing email at depth {depth} with container path {container_path}")
    
    try:
        # Convert to bytes if string is provided
        if isinstance(email_content, str):
            email_content = email_content.encode('utf-8', errors='replace')
            
        # Create custom policy for header parsing    
        custom_policy = CustomEmailPolicy(raise_on_defect=False)
        
        # Parse the email content with our custom policy
        msg = BytesParser(policy=custom_policy).parsebytes(email_content)
        
        # Initialize extraction status to track if we found an embedded email
        extracted_email_found = False
        extracted_email_data = None
        
        # PRIORITY 1: Check if this is a Proofpoint-reported email (special case)
        if is_proofpoint_email(msg):
            logger.info("Detected Proofpoint-reported email format")
            proofpoint_data = parse_proofpoint_email(email_content)
            return proofpoint_data
        
        # PRIORITY 2: Process any message/RFC822 parts (highest priority)
        if msg.is_multipart():
            for part in msg.walk():
                if part.get_content_type() == 'message/rfc822':
                    logger.info("Found message/rfc822 attachment")
                    try:
                        # Extract the embedded message
                        rfc822_content = part.get_payload(decode=True)
                        if not rfc822_content and isinstance(part.get_payload(), list) and len(part.get_payload()) > 0:
                            embedded_msg = part.get_payload()[0]
                            if hasattr(embedded_msg, 'as_bytes'):
                                rfc822_content = embedded_msg.as_bytes()
                            elif isinstance(embedded_msg, str):
                                rfc822_content = embedded_msg.encode('utf-8')
                        
                        if rfc822_content:
                            # Recursively parse the embedded email
                            embedded_email = parse_email(
                                rfc822_content, 
                                depth + 1, 
                                max_depth, 
                                container_path + ["message/rfc822"]
                            )
                            
                            if embedded_email and "error" not in embedded_email:
                                extracted_email_found = True
                                extracted_email_data = embedded_email
                                break
                    except Exception as e:
                        logger.error(f"Error extracting message/rfc822 content: {str(e)}")
        
        # PRIORITY 3: Check for TNEF attachments
        if not extracted_email_found:
            for part in msg.walk():
                if part.get_content_type() == 'application/ms-tnef':
                    logger.info("Found TNEF attachment")
                    try:
                        # Try to import tnefparse if available
                        from tnefparse import TNEF
                        tnef_data = part.get_payload(decode=True)
                        if tnef_data:
                            tnef = TNEF(tnef_data)
                            for attachment in tnef.attachments:
                                if attachment.name.lower() == "message.rfc822" or attachment.mime_type == "message/rfc822":
                                    embedded_email = parse_email(
                                        attachment.data,
                                        depth + 1,
                                        max_depth,
                                        container_path + ["tnef_attachment"]
                                    )
                                    
                                    if embedded_email and "error" not in embedded_email:
                                        extracted_email_found = True
                                        extracted_email_data = embedded_email
                                        break
                    except ImportError:
                        logger.warning("tnefparse module not available, cannot process TNEF attachment")
                    except Exception as e:
                        logger.error(f"Error processing TNEF attachment: {str(e)}")
        
        # PRIORITY 4: Check for .eml or .msg attachments
        if not extracted_email_found:
            for part in msg.walk():
                if part.get_content_maintype() == 'multipart':
                    continue
                
                filename = part.get_filename() or ""
                if filename.lower().endswith(('.eml', '.msg')):
                    logger.info(f"Found email file attachment: {filename}")
                    attachment_data = part.get_payload(decode=True)
                    if attachment_data:
                        embedded_email = None
                        
                        if filename.lower().endswith('.eml'):
                            # Import here to avoid circular dependency
                            from parsers.eml_parser import parse_eml
                            embedded_email = parse_eml(attachment_data, max_depth)
                        elif filename.lower().endswith('.msg'):
                            # Import here to avoid circular dependency
                            from parsers.msg_parser import parse_msg
                            embedded_email = parse_msg(
                                attachment_data,
                                max_depth=max_depth,
                                depth=depth + 1,
                                container_path=container_path,
                            )
                        
                        if embedded_email and "error" not in embedded_email:
                            extracted_email_found = True
                            extracted_email_data = embedded_email
                            break
        
        # PRIORITY 5: Check for regular email attachments that might contain emails
        if not extracted_email_found:
            # Extract and process attachments
            attachments = extract_attachments(msg, depth, max_depth, container_path)
            # Filter out None values (image attachments will be None)
            attachments = [attachment for attachment in attachments if attachment is not None]
            
            # Process any email attachments recursively
            for i, attachment in enumerate(attachments):
                if attachment.get("is_email", False) and "parsed_email" in attachment:
                    logger.debug(f"Found embedded email in attachment {i}")
                    
                    attachment_parsed_email = attachment["parsed_email"]
                    
                    # If the attachment already has an "original_email" field, use it
                    if isinstance(attachment_parsed_email, dict) and "original_email" in attachment_parsed_email:
                        original_email = attachment_parsed_email["original_email"]
                        
                        # Update container path
                        original_email["container_path"] = container_path + [f"attachment[{i}]"]
                        original_email["reconstruction_method"] = "attachment"
                        
                        extracted_email_found = True
                        extracted_email_data = {"email_content": original_email}
                        break
        
        # PRIORITY 6: Check if this is a forwarded email
        if not extracted_email_found:
            # Extract body content for forwarded email check
            body_data = extract_body(msg)
            
            if is_forwarded_email(msg, body_data):
                logger.debug("Email is forwarded, parsing forwarded content")
                forwarded_data = parse_forwarded_email(
                    msg, 
                    depth + 1, 
                    max_depth, 
                    container_path + ["forwarded"]
                )
                
                # If we successfully parsed the forwarded email, use it
                if forwarded_data and not is_empty_email_data(forwarded_data):
                    forwarded_email = {
                        "message_id": "",
                        "sender": forwarded_data.get("original_sender", ""),
                        "return_path": "",
                        "receiver": forwarded_data.get("original_recipient", ""),
                        "reply_to": "",
                        "subject": forwarded_data.get("original_subject", ""),
                        "date": forwarded_data.get("original_date", ""),
                        "body": strip_urls_and_html(truncate_urls_in_text(clean_excessive_newlines(forwarded_data.get("original_body", "")))),
                        "attachments": [],
                        "container_path": container_path + ["forwarded"],
                        "reconstruction_method": "forwarded",
                        "urls": forwarded_data.get("urls", []),
                        "ip_addresses": forwarded_data.get("ip_addresses", []),
                        "domains": forwarded_data.get("domains", [])
                    }
                    
                    extracted_email_found = True
                    extracted_email_data = {"email_content": forwarded_email}
        
        # If we found an extracted email through any method, return it
        if extracted_email_found and extracted_email_data:
            return extracted_email_data
        
        # If no embedded email was found, treat this as the original email
        # Extract all necessary metadata
        headers = extract_headers(msg)
        body_data = extract_body(msg) if "body_data" not in locals() else body_data
        
        # Extract attachments if not already done
        if 'attachments' not in locals():
            attachments = extract_attachments(msg, depth, max_depth, container_path)
            attachments = [attachment for attachment in attachments if attachment is not None]

        # ----- COLLECT ALL URLS FROM ALL SOURCES -----
        all_urls = []

        # Extract URLs from email content (HTML and plain text)
        body_text = body_data.get("body", "")
        content_urls = UrlExtractor.extract_all_urls_from_email(body_data, body_text)
        all_urls.extend(content_urls)

        # Extract URLs from attachments
        attachment_urls = UrlProcessor.extract_urls_from_attachments(attachments)
        all_urls.extend(attachment_urls)

        logger.debug(f"Total URLs before processing: {len(all_urls)}")

        # ----- UNIFIED URL PROCESSING -----
        processed_urls = UrlProcessor.process_urls(all_urls)
        logger.debug(f"Total unique URLs after processing: {len(processed_urls)}")

        # Extract IP addresses and domains
        headers_text = " ".join([f"{k}: {v}" for k, v in msg.items()])
        ip_addresses = extract_ip_addresses(body_text + " " + headers_text)

        # Add IP addresses from attachments
        for attachment in attachments:
            if "ip_addresses" in attachment:
                ip_addresses.extend(attachment.get("ip_addresses", []))

        # Remove duplicates
        ip_addresses = list(set(ip_addresses))

        # Extract domains from processed URLs
        domains = extract_domains(processed_urls)

        # Add domains from attachments
        for attachment in attachments:
            if "domains" in attachment:
                domains.extend(attachment.get("domains", []))
        # Remove duplicates
        domains = list(set(domains))

        logger.debug(f"Extracted {len(domains)} domains and {len(ip_addresses)} IP addresses")
        
        # Create original email from our parsed data
        parsed_email = {
            "message_id": headers["message_id"],
            "sender": headers["sender"],
            "return_path": headers["return_path"],
            "receiver": headers["receiver"],
            "reply_to": headers["reply_to"],
            "subject": headers["subject"],
            "date": headers["date"],
            "authentication": {
                "dkim": headers["authentication"]["dkim"],
                "spf": headers["authentication"]["spf"],
                "dmarc": headers["authentication"]["dmarc"]
            },
            "body": strip_urls_and_html(truncate_urls_in_text(clean_excessive_newlines(body_data.get("body", "")))),
            "attachments": attachments,
            "container_path": container_path,
            "reconstruction_method": "direct",
            "urls": processed_urls,
            "ip_addresses": ip_addresses,
            "domains": domains
        }
        
        return {"email_content": parsed_email}
        
    except Exception as e:
        logger.error(f"Error parsing email: {str(e)}")
        logger.debug(traceback.format_exc())
        return {"error": f"Failed to parse email: {str(e)}"}

def is_forwarded_email(msg, body_data=None) -> bool:
    """
    Check if the email is a forwarded email based on various indicators.
    More precise to avoid false positives from email signatures.
    
    Args:
        msg: Email message object
        body_data: Body data if already extracted
        
    Returns:
        bool: True if it's a forwarded email, False otherwise
    """
    # Check subject for forwarding indicators
    subject = msg.get('Subject', '')
    if subject and (subject.lower().startswith(('fw:', 'fwd:')) or 'forwarded' in subject.lower()):
        logger.debug("Email subject indicates forwarded message")
        
    # Check content for forwarding patterns
    if body_data is None:
        # If body_data wasn't provided, extract it now
        body_data = extract_body(msg)
    
    # Use both plain and HTML for checking patterns
    body_text = ""
    if isinstance(body_data, dict):
        if "body" in body_data:
            body_text = body_data["body"]
    else:
        # Fallback if body_data is not a dict
        body_text = str(body_data)
    
    # Common forwarding patterns from different email clients
    forwarding_patterns = [
        "---------- Forwarded message ---------",  # Gmail
        "Begin forwarded message:",              # Apple Mail
        # More specific Outlook pattern to avoid false positives from signatures
        r"^From:.*?\r?\nSent:.*?\r?\nTo:.*?\r?\nSubject:",  # Outlook with line breaks
        "-----Original Message-----",           # Various clients
        "Forwarded Message",                    # Various clients
    ]
    
    for pattern in forwarding_patterns:
        if pattern.startswith('^'):
            # This is a regex pattern
            if re.search(pattern, body_text, re.MULTILINE | re.DOTALL | re.IGNORECASE):
                logger.debug(f"Found forwarded email pattern: {pattern}")
                return True
        elif pattern.lower() in body_text.lower():
            # This is a simple string pattern
            logger.debug(f"Found forwarded email pattern: {pattern}")
            return True
    
    return False

def is_empty_email_data(email_data: Dict[str, Any]) -> bool:
    """
    Check if email data dictionary has empty values for all important fields.
    
    Args:
        email_data: Email data dictionary
        
    Returns:
        bool: True if all important fields are empty, False otherwise
    """
    if not isinstance(email_data, dict):
        return True
        
    # Check for empty original sender/recipient fields
    has_sender = bool(email_data.get("original_sender", ""))
    has_recipient = bool(email_data.get("original_recipient", ""))
    has_subject = bool(email_data.get("original_subject", ""))
    has_body = bool(email_data.get("original_body", ""))
    
    # If all are empty, consider it empty
    return not (has_sender or has_recipient or has_subject or has_body)