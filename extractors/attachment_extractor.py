# extractors/attachment_extractor.py
import logging
import hashlib
import re
import traceback
from utils.url_processing import UrlExtractor

logger = logging.getLogger(__name__)

def extract_attachments(msg, depth=0, max_depth=10, container_path=None):
    """
    Extract attachments from an email message.
    Enhanced to handle TNEF and message/rfc822 formats better.
    
    Args:
        msg (email.message.Message): Email message object
        depth (int): Current recursion depth
        max_depth (int): Maximum recursion depth
        container_path (list): Path of containers
        
    Returns:
        list: List of attachment information dictionaries
    """
    if container_path is None:
        container_path = []
    
    logger.debug(f"Extracting attachments at depth {depth}")
    attachments = []
    
    try:
        # Handle multipart messages
        if msg.is_multipart():
            logger.debug("Message is multipart, processing parts")
            for part in msg.walk():
                # Skip the container multipart parts
                if part.get_content_maintype() == 'multipart':
                    continue
                    
                # Check if it's an attachment
                if is_attachment(part):
                    attachment = process_attachment(part, depth, max_depth, container_path)
                    if attachment:
                        attachments.append(attachment)
        
        # Handle single part message with attachment
        elif is_attachment(msg):
            attachment = process_attachment(msg, depth, max_depth, container_path)
            if attachment:
                attachments.append(attachment)
        
        # Check for possible application/ms-tnef content
        for part in msg.walk():
            if part.get_content_type() == 'application/ms-tnef':
                logger.info("Found TNEF attachment, processing")
                try:
                    # Try to import tnefparse if available
                    try:
                        from tnefparse import TNEF
                        tnef_data = part.get_payload(decode=True)
                        if tnef_data:
                            tnef_attachments = process_tnef_attachment(tnef_data, depth, max_depth, container_path)
                            if tnef_attachments:
                                attachments.extend(tnef_attachments)
                    except ImportError:
                        logger.warning("tnefparse module not available, cannot process TNEF attachment")
                        # Still add the TNEF attachment itself for reference
                        tnef_attachment = {
                            "attachment_name": part.get_filename() or "winmail.dat",
                            "attachment_sha256": hashlib.sha256(part.get_payload(decode=True) or b"").hexdigest(),
                            "content_type": "application/ms-tnef",
                            "size": len(part.get_payload(decode=True) or b""),
                            "content_id": part.get("Content-ID", ""),
                            "is_email": False,
                            "attachment_text": "TNEF attachment (requires tnefparse module)"
                        }
                        attachments.append(tnef_attachment)
                except Exception as e:
                    logger.error(f"Error processing TNEF attachment: {str(e)}")
                    logger.debug(traceback.format_exc())
        
        logger.debug(f"Found {len(attachments)} attachments")
        return attachments
    
    except Exception as e:
        logger.error(f"Error in extract_attachments: {str(e)}")
        logger.debug(traceback.format_exc())
        return attachments

def process_tnef_attachment(tnef_data, depth, max_depth, container_path):
    """
    Process TNEF attachment data.
    
    Args:
        tnef_data (bytes): TNEF attachment binary data
        depth (int): Current recursion depth
        max_depth (int): Maximum recursion depth
        container_path (list): Path of containers
        
    Returns:
        list: List of attachment information dictionaries
    """
    attachments = []
    
    try:
        from tnefparse import TNEF
        tnef = TNEF(tnef_data)
        
        # Process each attachment in the TNEF file
        for attachment in tnef.attachments:
            try:
                # Extract the attachment
                attachment_name = attachment.name or "unknown"
                attachment_data = attachment.data
                
                # Calculate SHA256 hash
                attachment_sha256 = hashlib.sha256(attachment_data).hexdigest()
                
                # Check for RFC822 message
                is_email = False
                parsed_email = None
                
                if attachment_name.lower() == "message.rfc822" or attachment.mime_type == "message/rfc822":
                    is_email = True
                    if depth < max_depth:
                        logger.debug(f"Found embedded email in TNEF attachment, recursively parsing at depth {depth+1}")
                        # Import here to avoid circular import
                        from parsers.email_parser import parse_email
                        
                        parsed_email = parse_email(
                            attachment_data,
                            depth + 1,
                            max_depth,
                            container_path + ["tnef_attachment"]
                        )
                
                # Create attachment info
                attachment_info = {
                    "attachment_name": attachment_name,
                    "attachment_sha256": attachment_sha256,
                    "content_type": attachment.mime_type or "application/octet-stream",
                    "size": len(attachment_data),
                    "content_id": "",
                    "is_email": is_email,
                    "attachment_text": ""
                }
                
                # If it's an email, add the parsed data
                if parsed_email:
                    attachment_info["parsed_email"] = parsed_email
                
                attachments.append(attachment_info)
                
            except Exception as e:
                logger.error(f"Error processing TNEF attachment {attachment.name}: {str(e)}")
                logger.debug(traceback.format_exc())
    
    except Exception as e:
        logger.error(f"Error processing TNEF data: {str(e)}")
        logger.debug(traceback.format_exc())
    
    return attachments

def is_attachment(part):
    """
    Determine if a message part is an attachment.
    
    Args:
        part (email.message.Message): Email message part
        
    Returns:
        bool: True if it's an attachment, False otherwise
    """
    # Check Content-Disposition header
    content_disposition = part.get("Content-Disposition", "")
    if "attachment" in content_disposition.lower():
        return True
    
    # Check if part has a filename
    filename = get_filename(part)
    if filename:
        return True
    
    # Check if it's an embedded message
    content_type = part.get_content_type().lower()
    if content_type == "message/rfc822":
        return True
    
    # Check for TNEF
    if content_type == "application/ms-tnef":
        return True
    
    # Check Content-ID for inline attachments
    if part.get("Content-ID"):
        return True
    
    return False

def get_filename(part):
    """
    Extract filename from message part.
    
    Args:
        part (email.message.Message): Email message part
        
    Returns:
        str: Filename or empty string if not found
    """
    # Try Content-Disposition header
    content_disposition = part.get("Content-Disposition", "")
    filename_match = re.search(r'filename="([^"]+)"', content_disposition)
    if filename_match:
        return filename_match.group(1)
    
    # Try Content-Type header
    content_type = part.get("Content-Type", "")
    filename_match = re.search(r'name="([^"]+)"', content_type)
    if filename_match:
        return filename_match.group(1)
    
    # Try get_filename() method if available
    if hasattr(part, 'get_filename') and callable(getattr(part, 'get_filename')):
        filename = part.get_filename()
        if filename:
            return filename
    
    return ""

def process_attachment(part, depth, max_depth, container_path):
    """
    Process an attachment part and extract relevant information.
    
    Args:
        part (email.message.Message): Email message part
        depth (int): Current recursion depth
        max_depth (int): Maximum recursion depth
        container_path (list): Path of containers
        
    Returns:
        dict: Attachment information dictionary or None if it's an image
    """
    try:
        filename = get_filename(part)
        content_type = part.get_content_type()
        
        # Skip image attachments if requested
        if content_type.startswith('image/'):
            logger.debug(f"Skipping image attachment: {filename}, type: {content_type}")
            return None
            
        content_id = part.get("Content-ID", "")
        
        # Clean up Content-ID if it's in angle brackets
        if content_id and content_id.startswith("<") and content_id.endswith(">"):
            content_id = content_id[1:-1]
        
        logger.debug(f"Processing attachment: {filename}, type: {content_type}")
        
        # Get the attachment content
        content = part.get_payload(decode=True)
        if content is None:
            logger.warning(f"Empty attachment content for {filename}")
            content = b""
        
        # Calculate SHA256 hash
        sha256 = hashlib.sha256(content).hexdigest()
        
        # Check if it's an embedded email
        is_email = False
        parsed_email = None
        
        if content_type.lower() == "message/rfc822":
            is_email = True
            if depth < max_depth:
                logger.debug(f"Found embedded email, recursively parsing at depth {depth+1}")
                # Import here to avoid circular import
                from parsers.email_parser import parse_email
                
                # For embedded emails, get the payload (which should be a list with the message)
                # Need to handle different ways message/rfc822 can be structured
                if isinstance(part.get_payload(), list) and len(part.get_payload()) > 0:
                    embedded_msg = part.get_payload()[0]
                    # Convert to string if it's an EmailMessage
                    if hasattr(embedded_msg, 'as_string'):
                        email_content = embedded_msg.as_string()
                    else:
                        # Otherwise use the raw content
                        email_content = content
                        
                    parsed_email = parse_email(
                        email_content,
                        depth + 1,
                        max_depth,
                        container_path + ["attachment"]
                    )
                else:
                    # Use the raw content if not a list
                    parsed_email = parse_email(
                        content,
                        depth + 1,
                        max_depth,
                        container_path + ["attachment"]
                    )
            else:
                logger.warning(f"Maximum recursion depth ({max_depth}) reached, not parsing embedded email")
        
        # Extract text from attachment for indexing
        attachment_text = ""
        
        # PDF handling with extended content type recognition
        if content_type in {"application/pdf", "application/x-pdf", "application/octet-stream"} and (
            content_type != "application/octet-stream" or (filename and filename.lower().endswith('.pdf'))
        ):
            try:
                # Try to extract text from PDF
                from extractors.pdf_extractor import extract_text_from_pdf
                attachment_text = extract_text_from_pdf(content)
                logger.debug(f"Extracted {len(attachment_text)} characters of text from PDF")
            except Exception as e:
                logger.warning(f"Failed to extract PDF text: {str(e)}")
                attachment_text = f"[PDF Text Extraction Failed: {str(e)}]"
                
        # Excel file handling
        elif content_type in {
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            "application/vnd.ms-excel",
            "application/msexcel",
            "application/x-msexcel",
            "application/x-ms-excel",
            "application/x-excel",
            "application/x-dos_ms_excel",
            "application/xls",
            "application/x-xls"
        } or (filename and filename.lower().endswith(('.xls', '.xlsx'))):
            try:
                # Import Excel extractor
                from extractors.excel_extractor import extract_text_from_excel
                attachment_text = extract_text_from_excel(content)
                logger.debug(f"Extracted {len(attachment_text)} characters of text from Excel")
            except Exception as e:
                logger.warning(f"Failed to extract Excel text: {str(e)}")
                attachment_text = f"[Excel Text Extraction Failed: {str(e)}]"

        # Word document handling
        elif content_type in {
            "application/msword",
            "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
            "application/vnd.ms-word",
            "application/vnd.ms-word.document.macroEnabled.12",
            "application/vnd.ms-word.template.macroEnabled.12"
        } or (filename and filename.lower().endswith(('.doc', '.docx', '.docm'))):
            try:
                # Import Word extractor
                from extractors.word_extractor import extract_text_from_word
                attachment_text = extract_text_from_word(content)
                logger.debug(f"Extracted {len(attachment_text)} characters of text from Word document")
            except Exception as e:
                logger.warning(f"Failed to extract Word document text: {str(e)}")
                attachment_text = f"[Word Document Text Extraction Failed: {str(e)}]"

        # Plain text and HTML handling
        elif content_type.startswith("text/"):
            try:
                charset = part.get_content_charset() or 'utf-8'
                decoded_content = content.decode(charset, errors='replace')
                
                # Process HTML attachments using the same approach as body extraction
                if content_type == "text/html":
                    from utils.html_processor import process_html_content
                    processed_result = process_html_content(decoded_content)
                    attachment_text = processed_result["text"]  # Clean, stripped HTML
                else:
                    # For plain text, just use the content directly
                    attachment_text = decoded_content
                
            except Exception as e:
                logger.warning(f"Failed to decode attachment text: {str(e)}")
                attachment_text = content.decode('utf-8', errors='replace')
        
        # Extract URLs using the centralized function from url_processor
        attachment_urls = UrlExtractor.extract_urls_by_content_type(
            content=content,
            content_type=content_type,
            filename=filename
        )
        
        # Extract IP addresses if we have attachment text
        ip_addresses = []
        if attachment_text:
            from extractors.ip_extractor import extract_ip_addresses
            ip_addresses = extract_ip_addresses(attachment_text)
            logger.debug(f"Extracted {len(ip_addresses)} IP addresses from attachment text")
        
        # Extract domains if we have URLs
        domains = []
        if attachment_urls:
            from extractors.domain_extractor import extract_domains
            domains = extract_domains(attachment_urls)
            logger.debug(f"Extracted {len(domains)} domains from attachment URLs")
        
        attachment = {
            "attachment_name": filename,
            "attachment_sha256": sha256,
            "content_type": content_type,
            "size": len(content),
            "content_id": content_id,
            "is_email": is_email,
            "attachment_text": attachment_text
        }
        
        # Add extracted data to attachment
        if attachment_urls:
            attachment["urls"] = attachment_urls
        
        if ip_addresses:
            attachment["ip_addresses"] = ip_addresses
            
        if domains:
            attachment["domains"] = domains
        
        if parsed_email:
            attachment["parsed_email"] = parsed_email
        
        return attachment
        
    except Exception as e:
        logger.error(f"Error processing attachment: {str(e)}")
        logger.debug(traceback.format_exc())
        return None