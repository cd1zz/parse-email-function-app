"""
URL processor module for high-level URL processing operations.
"""

import logging
import requests
import time
import urllib.parse
from .validator import UrlValidator
from .decoder import UrlDecoder

logger = logging.getLogger(__name__)

class UrlProcessor:
    """
    Class for high-level URL processing operations including expansion,
    deduplication, and unified processing.
    """
    
    @staticmethod
    def expand_url(url, timeout=5, max_redirects=10):
        """
        Expands a shortened URL by following redirects.
        If the final connection cannot be made, returns the last known location.
        
        Args:
            url (str): URL to expand
            timeout (int): Request timeout in seconds
            max_redirects (int): Maximum number of redirects to follow
            
        Returns:
            str: The expanded URL or the original URL if expansion fails
        """
        if not url or not UrlValidator.is_url_shortened(url):
            return url
            
        logger.debug(f"Expanding shortened URL: {url}")
        
        try:
            # Ensure URL has a scheme
            if not (url.startswith('http://') or url.startswith('https://')):
                url = 'http://' + url
            
            # Follow redirects with a HEAD request
            session = requests.Session()
            response = session.head(
                url,
                allow_redirects=True,
                timeout=timeout,
                headers={
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                }
            )
            
            # Get the final URL after redirects
            expanded_url = response.url
            
            logger.debug(f"URL expanded to: {expanded_url}")
            return expanded_url
            
        except requests.exceptions.RequestException as e:
            logger.warning(f"Error expanding URL {url}: {str(e)}")
            
            # Try to get the last redirect URL if available
            if hasattr(e, 'response') and e.response is not None:
                return e.response.url
                
            if hasattr(e, 'request'):
                return e.request.url
                
            # Attempt HTTP if HTTPS failed
            if url.startswith("https://"):
                fallback_url = url.replace("https://", "http://", 1)
                logger.debug(f"Retrying with HTTP: {fallback_url}")
                try:
                    response = session.head(fallback_url, allow_redirects=True, timeout=timeout)
                    return response.url
                except requests.RequestException:
                    pass
        
        # Return the original URL if expansion fails
        return url
    
    @staticmethod
    def batch_expand_urls(urls, delay=0.5):
        """
        Expand a batch of shortened URLs to their final destinations.
        
        Args:
            urls (list): List of URL dictionaries
            delay (float): Delay between requests in seconds
            
        Returns:
            list: List of URL dictionaries with expanded URLs
        """
        if not urls:
            return urls
        
        logger.debug(f"Batch expanding {len(urls)} URLs")
        
        expanded_urls = []
        for url_obj in urls:
            if isinstance(url_obj, dict) and "original_url" in url_obj:
                # Clone the URL object
                expanded_url_obj = url_obj.copy()
                
                # Only expand if it's a shortened URL
                if expanded_url_obj.get("is_shortened", False):
                    # Expand the URL
                    expanded_url = UrlProcessor.expand_url(expanded_url_obj["original_url"])
                    
                    # Only set expanded_url if it's actually different from the original
                    if expanded_url and expanded_url != expanded_url_obj["original_url"]:
                        expanded_url_obj["expanded_url"] = expanded_url
                    else:
                        expanded_url_obj["expanded_url"] = "Not Applicable"
                else:
                    expanded_url_obj["expanded_url"] = "Not Applicable"
                
                expanded_urls.append(expanded_url_obj)
                
                # Add delay to avoid rate limiting
                if delay > 0 and expanded_url_obj.get("is_shortened", False):
                    time.sleep(delay)
            else:
                # If not in expected format, keep as is
                expanded_urls.append(url_obj)
        
        return expanded_urls
    
    @staticmethod
    def process_urls(urls):
        """
        Process a list of URLs consistently to deduplicate, decode SafeLinks/Proofpoint,
        and identify shortened URLs.
        
        Args:
            urls (list): List of URL strings or dictionaries
            
        Returns:
            list: Processed URL dictionaries
        """
        if not urls:
            return []
            
        logger.debug(f"Processing {len(urls)} URLs")
        processed_urls = []
        seen_urls = set()
        
        for url in urls:
            url_str = url if isinstance(url, str) else url.get("original_url", "")
            
            if not url_str:
                continue
                
            # Skip if we've seen this URL already
            if url_str in seen_urls:
                continue

            # Skip image URLs
            if UrlValidator.is_image_url(url_str):
                logger.debug(f"Skipping image URL: {url_str}")
                continue
            
            # Handle Microsoft SafeLinks
            if "safelinks.protection.outlook.com" in url_str:
                decoded_url = UrlDecoder.decode_safelinks(url_str)
                logger.debug(f"Decoded SafeLink: {url_str} -> {decoded_url}")
                # Skip if we've already seen this decoded URL
                if decoded_url in seen_urls:
                    continue
                url_str = decoded_url
            
            # Handle Proofpoint URL Defense
            elif "urldefense.com" in url_str:
                decoded_url = UrlDecoder.decode_proofpoint_urls(url_str)
                logger.debug(f"Decoded Proofpoint URL: {url_str} -> {decoded_url}")
                # Skip if we've already seen this decoded URL
                if decoded_url in seen_urls:
                    continue
                url_str = decoded_url
            
            seen_urls.add(url_str)
            
            # Standardize URL format
            url_obj = {"original_url": url_str}
            if isinstance(url, dict):
                # Only update with relevant fields
                if "is_shortened" in url:
                    url_obj["is_shortened"] = url["is_shortened"]
                if "expanded_url" in url and url["expanded_url"] != url_str:
                    url_obj["expanded_url"] = url["expanded_url"]
            
            # Check if it's a shortened URL if not already determined
            if "is_shortened" not in url_obj:
                url_obj["is_shortened"] = UrlValidator.is_url_shortened(url_str)
            
            # Set expanded_url based on shortened status
            if not url_obj["is_shortened"]:
                url_obj["expanded_url"] = "Not Applicable"
            elif "expanded_url" not in url_obj:
                url_obj["expanded_url"] = url_str
            
            processed_urls.append(url_obj)
        
        return processed_urls
    
    @staticmethod
    def dedupe_to_base_urls(url_list):
        """
        Deduplicate only non-shortened URLs by their base domain,
        preserving all fields including expanded_url.
        Shortened URLs are left intact.
        """
        logger.debug(f"Deduplicating {len(url_list)} URLs")

        seen_bases = set()
        deduped = []

        for url_obj in url_list:
            if not isinstance(url_obj, dict) or "original_url" not in url_obj:
                continue

            if url_obj.get("is_shortened", False):
                deduped.append(url_obj)
                continue

            try:
                parsed = urllib.parse.urlparse(url_obj["original_url"])
                base_url = f"{parsed.scheme}://{parsed.netloc}"

                if base_url not in seen_bases:
                    seen_bases.add(base_url)
                    deduped.append({
                        "original_url": base_url,
                        "is_shortened": False,
                        "expanded_url": url_obj.get("expanded_url", "Not Applicable")
                    })
            except Exception as e:
                logger.warning(f"Error deduplicating URL {url_obj['original_url']}: {str(e)}")
                deduped.append(url_obj)

        logger.debug(f"Final deduplicated URL count: {len(deduped)}")
        return deduped
    
    @staticmethod
    def fix_url_expansions(urls):
        """
        Fix URL expansion fields to ensure expanded_url is only set for shortened URLs.
        
        Args:
            urls (list): List of URL dictionaries
            
        Returns:
            list: List of fixed URL dictionaries
        """
        fixed_urls = []
        for url in urls:
            if isinstance(url, dict):
                # Make a copy to avoid modifying the original
                fixed_url = url.copy()
                
                # If not a shortened URL, set expanded_url to "Not Applicable"
                if not fixed_url.get("is_shortened", False):
                    fixed_url["expanded_url"] = "Not Applicable"
                # If it is shortened but expanded_url is the same as original_url, set to "Not Applicable"
                elif fixed_url.get("expanded_url") == fixed_url.get("original_url"):
                    fixed_url["expanded_url"] = "Not Applicable"
                    
                fixed_urls.append(fixed_url)
            else:
                fixed_urls.append(url)
        
        return fixed_urls
    
    @staticmethod
    def extract_urls_from_attachments(attachments):
        """
        Extract URLs from email attachments.
        
        Args:
            attachments (list): List of attachment dictionaries
            
        Returns:
            list: List of URLs found in attachments
        """
        attachment_urls = []
        
        for attachment in attachments:
            if "urls" in attachment:
                attachment_urls.extend(attachment["urls"])
                # Remove the URLs from the attachment to prevent duplication
                # Note: We're making a copy to avoid modifying the original attachment
                # in case it's needed elsewhere
                attachment_copy = attachment.copy()
                del attachment_copy["urls"]
        
        logger.debug(f"Extracted {len(attachment_urls)} URLs from attachments")
        return attachment_urls