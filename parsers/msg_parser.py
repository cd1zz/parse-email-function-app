import logging
import io
import olefile
from parsers.email_parser import parse_email
from utils.rtf_converter import rtf_to_text


def _read_ole_string(ole, candidates):
    """Return the first available stream decoded with the provided encoding."""
    for name, encoding in candidates:
        if ole.exists(name):
            try:
                data = ole.openstream(name).read()
                return data.decode(encoding, errors="replace")
            except Exception:  # pragma: no cover - unexpected decode issues
                return ole.openstream(name).read().decode("utf-8", errors="replace")
    return None

logger = logging.getLogger(__name__)

def parse_msg(msg_content, max_depth=10, depth=0, container_path=None, stop_recursion=False):
    """
    Parse an Outlook .msg file and extract email information.
    
    Args:
        msg_content (bytes): Content of the .msg file
        max_depth (int): Maximum recursion depth for nested emails
        depth (int): Current recursion depth
        container_path (list): Path of containers leading to this .msg
        
    Returns:
        dict: Parsed email data
    """
    if container_path is None:
        container_path = []

    logger.debug("Parsing .msg file")
    
    try:
        # Write MSG content to a temporary BytesIO object to use with olefile
        msg_file = io.BytesIO(msg_content)
        
        # Open the MSG file using olefile
        ole = olefile.OleFileIO(msg_file)     
           
        # Convert MSG to EML format
        eml_content = convert_msg_to_eml(ole)
        
        # Use the main email parser to parse the converted EML content
        parsed_data = parse_email(
            eml_content,
            depth=depth,
            max_depth=max_depth,
            container_path=container_path,
            stop_recursion=stop_recursion,
        )
        
        # Close the OLE file
        ole.close()
        
        return parsed_data
        
    except ImportError:
        logger.error("olefile module not installed. Required for .msg parsing.")
        return {"error": "olefile module not installed. Required for .msg parsing."}
    except Exception as e:
        logger.error(f"Error parsing .msg file: {str(e)}")
        return {"error": f"Failed to parse .msg file: {str(e)}"}

def convert_msg_to_eml(ole):
    """
    Convert an Outlook MSG file to EML format.
    
    Args:
        ole (olefile.OleFile): OLE file object of the MSG file
        
    Returns:
        bytes: Email content in EML format
    """
    logger.debug("Converting MSG to EML format")
    
    # Initialize an email message
    eml_parts = []
    
    # Extract headers with UTF-8/UTF-16 fallbacks
    subject = _read_ole_string(
        ole,
        [
            ('__substg1.0_007D001F', 'utf-16-le'),
            ('__substg1.0_007D001E', 'utf-8'),
            ('__substg1.0_0037001F', 'utf-16-le'),
            ('__substg1.0_0037001E', 'utf-8'),
        ],
    )
    if subject:
        eml_parts.append(f"Subject: {subject}")

    sender = _read_ole_string(
        ole,
        [
            ('__substg1.0_0C1A001F', 'utf-16-le'),
            ('__substg1.0_0C1A001E', 'utf-8'),
        ],
    )
    if sender:
        eml_parts.append(f"From: {sender}")

    recipient = _read_ole_string(
        ole,
        [
            ('__substg1.0_0E04001F', 'utf-16-le'),
            ('__substg1.0_0E04001E', 'utf-8'),
        ],
    )
    if recipient:
        eml_parts.append(f"To: {recipient}")

    # Message-ID
    message_id = _read_ole_string(
        ole,
        [
            ('__substg1.0_1035001F', 'utf-16-le'),
            ('__substg1.0_1035001E', 'utf-8'),
        ],
    )
    if message_id:
        eml_parts.append(f"Message-ID: {message_id}")

    in_reply_to = _read_ole_string(
        ole,
        [
            ('__substg1.0_0042001F', 'utf-16-le'),
            ('__substg1.0_0042001E', 'utf-8'),
        ],
    )
    if in_reply_to:
        eml_parts.append(f"In-Reply-To: {in_reply_to}")
    
    # Extract date
    if ole.exists('__substg1.0_00390040'):  # Sent time (64-bit)
        sent_time = ole.openstream('__substg1.0_00390040').read()
        # Convert FileTime to readable date
        if len(sent_time) == 8:
            filetime = int.from_bytes(sent_time, byteorder='little')
            # Convert from FileTime (100-nanosecond intervals since January 1, 1601) to Unix timestamp
            unix_time = (filetime - 116444736000000000) // 10000000
            from datetime import datetime, timezone
            date_str = datetime.fromtimestamp(unix_time, tz=timezone.utc).strftime('%a, %d %b %Y %H:%M:%S %z')
            eml_parts.append(f"Date: {date_str}")
    
    # Extract body
    body = ""
    content_type = "text/plain; charset=utf-8"
    body = _read_ole_string(
        ole,
        [
            ('__substg1.0_1000001F', 'utf-16-le'),
            ('__substg1.0_1000001E', 'utf-8'),
        ],
    ) or ""

    html_body = _read_ole_string(
        ole,
        [
            ('__substg1.0_1013001F', 'utf-16-le'),
            ('__substg1.0_1013001E', 'utf-8'),
        ],
    )

    if html_body:
        body = html_body
        content_type = "text/html; charset=utf-8"
    elif ole.exists('__substg1.0_10130102'):  # Compressed HTML body
        try:
            compressed = ole.openstream('__substg1.0_10130102').read()
            try:
                from utils.rtf_converter import _decompress_lzfu
                decompressed = _decompress_lzfu(compressed)
            except Exception as decomp_err:  # pragma: no cover - fallback path
                logger.warning(f"Failed to decompress HTML body: {decomp_err}")
                decompressed = compressed

            body = decompressed.decode('utf-8', errors='replace')
            content_type = "text/html; charset=utf-8"
        except Exception as e:
            logger.warning(f"Failed to decode compressed HTML body: {e}")
    elif ole.exists('__substg1.0_10090102'):  # RTF body
        rtf_data = ole.openstream('__substg1.0_10090102').read()
        body = rtf_to_text(rtf_data)

    if 'html' in content_type:
        eml_parts.append(f"Content-Type: {content_type}")
    
    # Add body
    eml_parts.append("")  # Empty line separates headers from body
    eml_parts.append(body)
    
    # Extract attachments (simplified - would need more complex processing for real attachments)
    # This is a basic implementation and would need to be expanded for full attachment support
    if ole.exists('__attach_version1.0_#00000000'):
        logger.debug("MSG file contains attachments - extracting")
        # Implement attachment extraction here
    
    # Combine all parts into an EML string
    eml_content = "\n".join(eml_parts).encode('utf-8')
    
    return eml_content
