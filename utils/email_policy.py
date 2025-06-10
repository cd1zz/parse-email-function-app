# utils/email_policy.py
import logging
import re
from email.policy import EmailPolicy

logger = logging.getLogger(__name__)

class CustomEmailPolicy(EmailPolicy):
    """
    Custom email policy to handle common email parsing issues.
    """
    def header_fetch_parse(self, name, value):
        # Handle Message-ID headers with square brackets
        if name.lower() == 'message-id':
            if isinstance(value, str) and ('[' in value or ']' in value):
                clean_value = value.replace('[', '').replace(']', '')
                logger.debug(f"Cleaned Message-ID: {clean_value}")
                return clean_value
                
        # Handle potentially encoded subject lines
        elif name.lower() == 'subject':
            try:
                if '=?' in value and '?=' in value:
                    # This might be RFC 2047 encoded
                    import email.header
                    decoded_header = email.header.decode_header(value)
                    decoded_parts = []
                    for part, encoding in decoded_header:
                        if isinstance(part, bytes) and encoding:
                            try:
                                decoded_parts.append(part.decode(encoding, errors='replace'))
                            except LookupError:
                                decoded_parts.append(part.decode('utf-8', errors='replace'))
                        elif isinstance(part, bytes):
                            decoded_parts.append(part.decode('utf-8', errors='replace'))
                        else:
                            decoded_parts.append(str(part))
                    return ' '.join(decoded_parts)
            except Exception as e:
                logger.warning(f"Error decoding subject header: {str(e)}")
                
        # Handle date headers with invalid formats
        elif name.lower() == 'date':
            if isinstance(value, str):
                # Try to fix common date format issues
                # This is a simplified example - robust handling would be more complex
                if value.endswith(')'):
                    # Some clients add comments to date headers
                    clean_value = re.sub(r'\s*\([^)]*\)\s*$', '', value)
                    logger.debug(f"Cleaned Date header: {clean_value}")
                    return clean_value
                    
        return super().header_fetch_parse(name=name, value=value)