import logging
import urllib.parse
import re

logger = logging.getLogger(__name__)

def extract_domains(urls):
    """
    Extract unique domains from a list of URLs.
    
    Args:
        urls (list): List of URL dictionaries or strings
        
    Returns:
        list: List of unique domain strings
    """
    if not urls:
        return []
    
    logger.debug("Extracting domains from URLs")
    domains = set()
    
    try:
        for url in urls:
            # Handle URL object or string
            if isinstance(url, dict) and "original_url" in url:
                url_str = url["original_url"]
            else:
                url_str = str(url)
            
            # Extract domain from URL
            domain = get_domain_from_url(url_str)
            if domain:
                domains.add(domain)
        
        result = list(domains)
        logger.debug(f"Extracted {len(result)} unique domains")
        return result
        
    except Exception as e:
        logger.error(f"Error extracting domains: {str(e)}")
        return []

def get_domain_from_url(url):
    """
    Extract domain from a URL.
    
    Args:
        url (str): URL to extract domain from
        
    Returns:
        str: Domain or empty string if extraction fails
    """
    # Handle mailto: links
    if url.startswith('mailto:'):
        try:
            email = url[7:]  # Remove 'mailto:'
            domain = email.split('@')[1].split()[0]  # Get domain part and remove any trailing spaces
            return domain
        except IndexError:
            return ""
    
    try:
        # Parse URL and extract netloc
        parsed = urllib.parse.urlparse(url)
        domain = parsed.netloc.lower()
        
        # Remove port number if present
        domain = re.sub(r':\d+$', '', domain)
        
        # Handle cases with no netloc but path that might be a domain
        if not domain and parsed.path:
            # Check if path starts with a domain-like pattern
            match = re.match(r'^(?:https?:\/\/)?([^\/]+)', parsed.path)
            if match:
                domain = match.group(1).lower()
        
        # Verify it looks like a domain
        if domain and '.' in domain:
            return domain
            
    except Exception as e:
        logger.warning(f"Error extracting domain from URL {url}: {str(e)}")
    
    return ""