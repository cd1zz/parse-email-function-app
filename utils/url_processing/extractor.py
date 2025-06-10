"""
URL extractor module for extracting URLs from various content types.
"""

import logging
import re
from bs4 import BeautifulSoup
from .validator import UrlValidator

logger = logging.getLogger(__name__)

class UrlExtractor:
    """
    Class for extracting URLs from different types of content including
    plain text, HTML, and various file formats.
    """
    
    # Define URL pattern for extraction
    URL_PATTERN = r'\bhttps?://[a-zA-Z0-9\-._~:/?#[\]@!$&\'()*+,;=%]+'
    
    @staticmethod
    def extract_urls(text):
        """
        Extract URLs from text content.
        
        Args:
            text (str): Text content to extract URLs from
            
        Returns:
            list: List of dictionaries with URL information
        """
        if not text:
            return []
        
        # Extract URLs using regex
        regex_urls = re.findall(UrlExtractor.URL_PATTERN, text)
        
        # Process each URL
        urls = []
        for url in regex_urls:
            # Clean the URL
            url = UrlValidator.clean_url(url)
            
            # Check if it's a shortened URL
            is_shortened = UrlValidator.is_url_shortened(url)
            if is_shortened:
                logger.debug(f"URL is using a shortning service: {url}")
            
            url_info = {
                "original_url": url,
                "is_shortened": is_shortened,
                "expanded_url": ""
            }
            
            urls.append(url_info)
        
        logger.debug(f"Extracted {len(urls)} URLs")
        return urls
    
    @staticmethod
    def extract_urls_from_html(html_content):
        """
        Extracts URLs from HTML content using BeautifulSoup.
        
        Args:
            html_content (str): HTML content
            
        Returns:
            list: List of URLs found in HTML elements
        """
        if not html_content:
            return []
            
        try:
            urls = []
            soup = BeautifulSoup(html_content, "html.parser")
            
            # Extract from anchor tags
            for a in soup.find_all('a', href=True):
                href = a['href'].strip()
                if href and not href.startswith(('#', 'javascript:', 'mailto:')):
                    urls.append(href)
            
            # Extract from image sources
            for img in soup.find_all('img', src=True):
                src = img['src'].strip()
                if src and not src.startswith(('data:', 'cid:')):
                    urls.append(src)
            
            # Extract from link tags
            for link in soup.find_all('link', href=True):
                href = link['href'].strip()
                if href:
                    urls.append(href)
            
            # Extract from script sources
            for script in soup.find_all('script', src=True):
                src = script['src'].strip()
                if src:
                    urls.append(src)
            
            # Extract from form actions
            for form in soup.find_all('form', action=True):
                action = form['action'].strip()
                if action and not action.startswith('#'):
                    urls.append(action)
            
            # Extract URLs from inline styles
            for tag in soup.find_all(style=True):
                style_urls = re.findall(r'url\([\'"]?(https?://[^\'"\)]+)[\'"]?\)', tag['style'])
                urls.extend(style_urls)
            
            # Extract URLs from style tags
            for style in soup.find_all('style'):
                if style.string:
                    style_urls = re.findall(r'url\([\'"]?(https?://[^\'"\)]+)[\'"]?\)', style.string)
                    urls.extend(style_urls)
            
            return urls
        except Exception as e:
            logger.error(f"Error extracting URLs from HTML: {str(e)}")
            return []
    
    @staticmethod
    def extract_urls_by_content_type(content, content_type, filename=None):
        """
        Extract URLs from content based on its content type.
        
        Args:
            content: Content to extract URLs from (string or bytes)
            content_type: MIME type of the content
            filename: Optional filename for additional type detection
            
        Returns:
            list: List of extracted URLs
        """
        if not content:
            return []
        
        try:
            # If content is bytes, try to decode it
            if isinstance(content, bytes):
                try:
                    # Try to detect charset from content_type
                    charset = None
                    if content_type and 'charset=' in content_type:
                        charset_match = re.search(r'charset=([^\s;]+)', content_type)
                        if charset_match:
                            charset = charset_match.group(1)
                    
                    # Fallback to utf-8
                    charset = charset or 'utf-8'
                    content = content.decode(charset, errors='replace')
                except Exception as e:
                    logger.warning(f"Failed to decode content: {str(e)}")
                    content = content.decode('utf-8', errors='replace')
            
            # Determine content type-specific extraction method
            if content_type and ('html' in content_type.lower() or 
                               (filename and filename.lower().endswith('.html'))):
                urls = UrlExtractor.extract_urls_from_html(content)
                logger.debug(f"Extracted {len(urls)} URLs from HTML content")
                
            # For other content types, use the general extraction method
            else:
                urls = UrlExtractor.extract_urls(content)
                logger.debug(f"Extracted {len(urls)} URLs from content")
            
            return urls
            
        except Exception as e:
            logger.error(f"Error extracting URLs from content: {str(e)}")
            return []
    
    @staticmethod
    def extract_all_urls_from_email(body_data, body_text=""):
        """
        Extract all URLs from different parts of an email.
        
        Args:
            body_data (dict): The body data dictionary from extract_body()
            body_text (str, optional): Plain text body if already extracted
            
        Returns:
            list: List of all extracted URLs
        """
        from .decoder import UrlDecoder
        
        all_urls = []
        
        # Extract URLs from HTML content if available
        if "html" in body_data and body_data["html"]:
            html_content = body_data["html"]
            # First decode any quoted-printable encoding in HTML
            decoded_html = UrlDecoder.decode_quoted_printable(html_content)
            
            # Extract URLs directly from HTML elements
            html_urls_extracted = UrlExtractor.extract_urls_from_html(decoded_html)
            logger.debug(f"Extracted {len(html_urls_extracted)} URLs directly from HTML")
            all_urls.extend(html_urls_extracted)
            
            # Also use the regular URL extractor on HTML content
            html_urls = UrlExtractor.extract_urls(decoded_html)
            logger.debug(f"Extracted {len(html_urls)} URLs from HTML with regex")
            all_urls.extend(html_urls)
        
        # Extract from plain text body
        if not body_text and "body" in body_data:
            body_text = body_data.get("body", "")
        
        if body_text:
            decoded_body = UrlDecoder.decode_quoted_printable(body_text)
            body_urls = UrlExtractor.extract_urls(decoded_body)
            logger.debug(f"Extracted {len(body_urls)} URLs from plain text body")
            all_urls.extend(body_urls)
        
        return all_urls