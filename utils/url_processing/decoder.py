"""
URL decoder module for decoding various types of encoded URLs.
"""

import logging
import re
import urllib.parse
import quopri
from io import BytesIO

logger = logging.getLogger(__name__)

class UrlDecoder:
    """
    Class for decoding different types of encoded URLs including
    SafeLinks, Proofpoint URLDefense, and quoted-printable encoding.
    """
    
    @staticmethod
    def decode_safelinks(safelink):
        """
        Decode Microsoft SafeLinks URLs.
        
        Args:
            safelink (str): Microsoft SafeLink URL
            
        Returns:
            str: Decoded URL or original if decoding fails
        """
        if not safelink or "safelinks.protection.outlook.com" not in safelink:
            return safelink
            
        logger.debug(f"Attempting to decode SafeLink")
        
        try:
            # Parse the URL
            parsed_url = urllib.parse.urlparse(safelink)
            
            # Extract the URL parameter
            query_params = urllib.parse.parse_qs(parsed_url.query)
            original_url = query_params.get('url', [None])[0]
            
            if original_url:
                # URL decode the original URL
                decoded_url = urllib.parse.unquote(original_url)
                logger.debug(f"Successfully decoded SafeLink to: {decoded_url}")
                return decoded_url
            
            return safelink
        except Exception as e:
            logger.error(f"Error decoding SafeLink: {str(e)}")
            return safelink
    
    @staticmethod
    def decode_proofpoint_urls(urldefense):
        """
        Decodes a Proofpoint URLDefense URL to extract the original URL.
        
        Args:
            urldefense (str): Proofpoint URLDefense URL
            
        Returns:
            str: The original URL or the input URL if decoding fails
        """
        if not urldefense or "urldefense.com" not in urldefense:
            return urldefense
            
        logger.debug(f"Attempting to decode Proofpoint URL")
        
        try:
            # URL decode first
            decoded_url = urllib.parse.unquote(urldefense)
            
            # Try to extract the original URL using different patterns
            
            # Pattern 1: u parameter
            if "u=" in decoded_url:
                parts = decoded_url.split("u=")
                if len(parts) > 1:
                    u_value = parts[1].split("&")[0]
                    return urllib.parse.unquote(u_value)
            
            # Pattern 2: __
            if "__" in decoded_url:
                parts = decoded_url.split("__")
                if len(parts) > 1:
                    # Handle both http and https
                    url_part = parts[1]
                    if url_part.startswith("https:/"):
                        url_part = url_part.replace("https:/", "https://")
                    elif url_part.startswith("http:/"):
                        url_part = url_part.replace("http:/", "http://")
                    
                    # Cut off at semicolon if present
                    if ";" in url_part:
                        url_part = url_part.split(";")[0]
                        
                    return url_part
                    
            # If no pattern matched, return the original
            return urldefense
        except Exception as e:
            logger.error(f"Error decoding Proofpoint URL: {str(e)}")
            return urldefense
    
    @staticmethod
    def decode_quoted_printable(text):
        """
        Decode quoted-printable encoding in text, especially focused on URLs.
        
        Args:
            text (str): Text that may contain quoted-printable encoded content
            
        Returns:
            str: Decoded text
        """
        if not text:
            return text
            
        try:
            # Look for patterns like href=3D"http
            if "=3D" in text:
                # Use regex to find and replace quoted-printable sequences
                text = re.sub(r'=3D(["\'])(https?://[^"\']+)(\1)', r'=\1\2\3', text)
                
                # Try to use quopri for more comprehensive decoding
                # Only decode if it looks like quoted-printable
                if re.search(r'=[0-9A-F]{2}', text):
                    encoded_text = text.encode('utf-8', errors='replace')
                    decoded_bytes = quopri.decodestring(encoded_text)
                    text = decoded_bytes.decode('utf-8', errors='replace')
            
            return text
        except Exception as e:
            logger.error(f"Error decoding quoted-printable content: {str(e)}")
            return text