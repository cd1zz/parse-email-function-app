# extractors/body_extractor.py
import logging
from utils.html_processor import process_html_content
from utils.url_processing import UrlExtractor


logger = logging.getLogger(__name__)

def extract_body(msg):
    """
    Extract and process the body content of an email message.
    
    Args:
        msg (email.message.Message): Email message object
        
    Returns:
        dict: Dictionary with body text content and original HTML content if available
    """
    logger.debug("Extracting body content from email message")
    
    # Initialize plain and html content
    plain_content = ""
    html_content = ""
    
    # Handle multipart messages
    if msg.is_multipart():
        logger.debug("Message is multipart, processing parts")
        logger.debug(f"Number of parts: {len(msg.get_payload())}")
        
        for i, part in enumerate(msg.get_payload()):
            content_type = part.get_content_type().lower()
            logger.debug(f"Part {i}: Content-Type: {content_type}")
            
            # Collect text content
            if content_type == "text/plain":
                decoded_content = decode_content(part)
                logger.debug(f"Found text/plain part of length {len(decoded_content)}")
                if len(decoded_content) > 0:
                    logger.debug(f"First 100 chars: {decoded_content[:100]}")
                plain_content += decoded_content
            
            # Collect HTML content
            elif content_type == "text/html":
                decoded_content = decode_content(part)
                logger.debug(f"Found text/html part of length {len(decoded_content)}")
                if len(decoded_content) > 0:
                    logger.debug(f"First 100 chars: {decoded_content[:100]}")
                html_content += decoded_content
            
            # Recursively process nested multipart messages
            elif part.is_multipart():
                logger.debug(f"Found nested multipart in part {i}, recursively extracting")
                nested_body = extract_body(part)
                if isinstance(nested_body, dict):
                    if "body" in nested_body:
                        nested_body_content = nested_body["body"]
                        logger.debug(f"Found nested body of length {len(nested_body_content)}")
                        # If no plain content yet, use the nested body
                        if not plain_content:
                            plain_content = nested_body_content
                    if "html" in nested_body and not html_content:
                        html_content = nested_body["html"]
    
    # Handle single part messages
    else:
        content_type = msg.get_content_type().lower()
        logger.debug(f"Message is single part with content-type: {content_type}")

        if content_type in ("text/plain", "text/html"):
            content = decode_content(msg)
            logger.debug(f"Decoded content length: {len(content)}")
            if len(content) > 0:
                logger.debug(f"First 100 chars: {content[:100]}")

            if content_type == "text/plain":
                plain_content = content
            else:
                html_content = content
        else:
            logger.debug("Skipping non-text single part content")
    
    # Create result dictionary with both plain text and HTML content
    result = {}
    
    # Prioritize plain text content for the body field
    if plain_content:
        logger.debug(f"Using plain text content of length {len(plain_content)}")
        result["body"] = plain_content
    # If no plain text, extract text from HTML
    elif html_content:
        logger.debug("Processing HTML content")
        processed_html = process_html_content(html_content)
        result["body"] = processed_html["text"]
        result["extracted_urls"] = processed_html["urls"]
    else:
        # No content found
        logger.warning("No content found in message")
        result["body"] = ""
    
    # Always include the original HTML content if available
    if html_content:
        logger.debug("Processing HTML content")
        # Use the UrlExtractor to extract URLs from the HTML content
        urls = UrlExtractor.extract_urls_from_html(html_content)
        result["extracted_urls"] = urls
        # Preserve the raw HTML so other functions can parse it
        result["html"] = html_content
    
    return result

def decode_content(part):
    """
    Decode the content of an email part based on its encoding.
    
    Args:
        part (email.message.Message): Email message part
        
    Returns:
        str: Decoded content as string
    """
    # Get content and encoding
    content = part.get_payload(decode=True)
    encoding = part.get_content_charset()
    
    if content is None:
        logger.warning("Content is None, returning empty string")
        return ""
    
    # Handle different content transfer encodings
    transfer_encoding = part.get('Content-Transfer-Encoding', '').lower()
    logger.debug(f"Decoding content with transfer encoding: {transfer_encoding}")
    
    try:
        # Convert bytes to string if needed
        if isinstance(content, bytes):
            if encoding:
                try:
                    logger.debug(f"Decoding with charset: {encoding}")
                    content = content.decode(encoding, errors='replace')
                except (LookupError, UnicodeDecodeError) as e:
                    logger.warning(f"Error decoding with {encoding}: {str(e)}. Falling back to utf-8")
                    content = content.decode('utf-8', errors='replace')
            else:
                logger.debug("No charset specified, using utf-8 with replace error handling")
                content = content.decode('utf-8', errors='replace')
        
        return content
        
    except Exception as e:
        logger.error(f"Error decoding content: {str(e)}")
        if isinstance(content, bytes):
            return content.decode('utf-8', errors='replace')
        return str(content)