import logging
import base64
import re

logger = logging.getLogger(__name__)

def analyze_mime_structure(msg):
    """
    Analyze the MIME structure of an email message, identifying all parts and boundaries.
    
    Args:
        msg (email.message.Message): Email message object
        
    Returns:
        dict: Analysis of the MIME structure
    """
    mime_analysis = {
        "parts_count": 0,
        "boundaries": [],
        "content_types": [],
        "reconstructed_parts": []
    }
    
    # Extract boundaries
    content_type = msg.get_content_type()
    mime_analysis["content_types"].append(content_type)
    
    # Get boundary parameter if present
    content_type_header = msg.get('Content-Type', '')
    boundary_match = re.search(r'boundary="([^"]+)"', content_type_header)
    if boundary_match:
        mime_analysis["boundaries"].append(boundary_match.group(1))
    
    # Process all parts
    if msg.is_multipart():
        for part in msg.get_payload():
            mime_analysis["parts_count"] += 1
            part_content_type = part.get_content_type()
            mime_analysis["content_types"].append(part_content_type)
            
            # Get the raw content of this part
            try:
                # Try to get the raw part content including headers
                raw_part = part.as_string()
            except Exception as e:
                # Fallback to just the payload
                raw_part = part.get_payload(decode=True)
                if isinstance(raw_part, bytes):
                    try:
                        raw_part = raw_part.decode('utf-8', errors='replace')
                    except Exception as e:
                        raw_part = str(raw_part)
            
            # Add to reconstructed parts
            mime_analysis["reconstructed_parts"].append({
                "content_type": part_content_type,
                "content_transfer_encoding": part.get('Content-Transfer-Encoding', ''),
                "content": raw_part
            })
            
            # Check for nested multipart
            if part.is_multipart():
                nested_analysis = analyze_mime_structure(part)
                mime_analysis["parts_count"] += nested_analysis["parts_count"]
                mime_analysis["boundaries"].extend(nested_analysis["boundaries"])
                mime_analysis["content_types"].extend(nested_analysis["content_types"])
                # We don't add nested reconstructed parts to avoid duplication
    else:
        mime_analysis["parts_count"] = 1
        
        # Get the payload
        payload = msg.get_payload(decode=True)
        if payload is not None:  # Check if payload is not None
            if isinstance(payload, bytes):
                try:
                    payload = payload.decode('utf-8', errors='replace')
                except Exception as e:
                    payload = str(payload)
        else:
            payload = ""
        
        mime_analysis["reconstructed_parts"].append({
            "content_type": content_type,
            "content_transfer_encoding": msg.get('Content-Transfer-Encoding', ''),
            "content": payload
        })
    
    return mime_analysis

def reconstruct_email_from_parts(parts):
    """
    Reconstruct an email from its MIME parts.
    
    Args:
        parts (list): List of MIME parts with content
        
    Returns:
        str: Reconstructed email content
    """
    # This is a placeholder implementation
    # In a real implementation, this would properly reassemble the email
    # based on the MIME structure and boundaries
    
    reconstructed = ""
    for part in parts:
        reconstructed += f"Content-Type: {part['content_type']}\n"
        if part['content_transfer_encoding']:
            reconstructed += f"Content-Transfer-Encoding: {part['content_transfer_encoding']}\n"
        reconstructed += "\n"
        reconstructed += part['content']
        reconstructed += "\n--\n"
    
    return reconstructed

def extract_base64_chunks(content):
    """
    Extract and decode base64 chunks from content.
    
    Args:
        content (str): Email content that may contain base64 chunks
        
    Returns:
        list: List of decoded base64 chunks
    """
    # Regular expression to find base64 encoded chunks
    # This is a simplified pattern and might need refinement
    base64_pattern = r'(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=|[A-Za-z0-9+/]{4})'
    
    # Find all potential base64 chunks
    chunks = re.findall(base64_pattern, content)
    
    # Filter to chunks that are likely base64 encoded (reasonable length and valid charset)
    valid_chunks = []
    for chunk in chunks:
        # Skip short chunks as they're likely not meaningful base64 data
        if len(chunk) < 20:
            continue
        
        # Try to decode
        try:
            decoded = base64.b64decode(chunk)
            # Check if decoded content looks like text or binary data
            try:
                text = decoded.decode('utf-8', errors='strict')
                # If it decodes as valid UTF-8, it might be text
                valid_chunks.append({"original": chunk, "decoded": text, "is_binary": False})
            except UnicodeDecodeError:
                # If it doesn't decode as UTF-8, it might be binary data
                valid_chunks.append({"original": chunk, "decoded": decoded, "is_binary": True})
        except:
            # Not valid base64
            pass
    
    return valid_chunks

def detect_encoding_type(headers, content):
    """
    Detect the encoding type of email content based on headers and content analysis.
    
    Args:
        headers (dict): Email headers
        content (str or bytes): Email content
        
    Returns:
        str: Detected encoding type (base64, quoted-printable, 7bit, 8bit, etc.)
    """
    # Check Content-Transfer-Encoding header first
    content_transfer_encoding = headers.get('Content-Transfer-Encoding', '').lower()
    if content_transfer_encoding in ['base64', 'quoted-printable', '7bit', '8bit', 'binary']:
        return content_transfer_encoding
    
    # If header not present or not standard, try to detect from content
    if isinstance(content, str):
        # Check for base64 characteristics
        if re.match(r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$', content.strip()):
            return 'base64'
        
        # Check for quoted-printable characteristics
        if '=' in content and re.search(r'=[0-9A-F]{2}', content):
            return 'quoted-printable'
        
        # Check for 7bit (ASCII)
        if all(ord(c) < 128 for c in content):
            return '7bit'
        
        # Default to 8bit
        return '8bit'
    
    # For bytes content
    else:
        # Check for base64 characteristics in decoded bytes
        try:
            decoded = content.decode('ascii', errors='strict')
            if re.match(r'^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$', decoded.strip()):
                return 'base64'
        except UnicodeDecodeError:
            pass
        
        # Check for 7bit (ASCII)
        if all(b < 128 for b in content):
            return '7bit'
        
        # Default to binary
        return 'binary'