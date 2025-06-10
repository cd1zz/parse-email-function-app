"""
URL validator module for validating, cleaning, and normalizing URLs.
"""

import logging
import re
import urllib.parse

logger = logging.getLogger(__name__)

class UrlValidator:
    """
    Class for URL validation operations including cleaning, checking if a URL
    is shortened, and identifying image URLs.
    """
    
    # List of known URL shortener domains
    URL_SHORTENER_PROVIDERS = [
        "bit.ly", "t.co", "goo.gl", "ow.ly", "tinyurl.com", "is.gd", "buff.ly", 
        "rebrandly.com", "cutt.ly", "bl.ink", "snip.ly", "su.pr", "lnkd.in", 
        "fb.me", "cli.gs", "sh.st", "mcaf.ee", "yourls.org", "v.gd", "s.id", 
        "t.ly", "tiny.cc", "qlink.me", "po.st", "short.io", "shorturl.at", 
        "aka.ms", "tr.im", "bit.do", "git.io", "adf.ly", "qr.ae", "tny.im", 
        "x.co", "d.pr", "rb.gy", "vk.cc", "t1p.de", "chilp.it", "ouo.io", 
        "zi.ma", "pd.am", "hyperurl.co", "tiny.ie", "qps.ru", "l.ead.me", 
        "shorte.st"
    ]
    
    # Image file extensions
    IMAGE_EXTENSIONS = ['.jpg', '.jpeg', '.png', '.gif', '.bmp', '.svg', '.webp', '.tiff']
    
    @staticmethod
    def clean_url(url):
        """
        Clean a URL by removing trailing punctuation and normalizing.
        
        Args:
            url (str): URL to clean
            
        Returns:
            str: Cleaned URL
        """
        if not url:
            return url
            
        # Remove trailing punctuation
        while url and url[-1] in '.,;:!?)]}\'\"':
            url = url[:-1]
        
        # Try to normalize the URL
        try:
            # Parse the URL
            parsed = urllib.parse.urlparse(url)
            
            # Rebuild it to ensure proper formatting
            if parsed.scheme and parsed.netloc:
                return urllib.parse.urlunparse(parsed)
        except Exception as e:
            logger.warning(f"Error normalizing URL {url}: {str(e)}")
        
        return url
    
    @staticmethod
    def is_url_shortened(url):
        """
        Check if a URL is likely to be shortened.
        
        Args:
            url (str): URL to check
            
        Returns:
            bool: True if it's likely a shortened URL, False otherwise
        """
        if not url:
            return False
            
        try:
            parsed = urllib.parse.urlparse(url)
            domain = parsed.netloc.lower()
            
            # Check if domain matches a known shortener
            if any(domain == shortener or domain.endswith('.' + shortener) 
                   for shortener in UrlValidator.URL_SHORTENER_PROVIDERS):
                return True
            
            # Check for suspiciously short path (like 5-8 character hash)
            if parsed.path and len(parsed.path) <= 10 and re.match(r'^/[a-zA-Z0-9]+$', parsed.path):
                return True
        
        except Exception as e:
            logger.warning(f"Error checking if URL is shortened: {str(e)}")
        
        return False
    
    @staticmethod
    def is_image_url(url):
        """
        Determines if a URL points to an image based on its extension.

        Args:
            url (str): URL to check
            
        Returns:
            bool: True if URL points to an image, False otherwise
        """
        if not url:
            return False
            
        try:
            parsed = urllib.parse.urlparse(url)
            path = parsed.path.lower()
            return any(path.endswith(ext) for ext in UrlValidator.IMAGE_EXTENSIONS)
        except Exception as e:
            logger.warning(f"Error checking if URL is an image: {str(e)}")
            return False