# utils/html_processor.py

import logging
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

def process_html_content(html_content):
    """
    Process HTML content to extract clean text and URLs.
    
    Args:
        html_content (str): HTML content to process
        
    Returns:
        dict: Dictionary with processed text and metadata
            - text: Plain text without HTML tags
            - urls: List of URLs found in the HTML
    """
    result = {
        "text": "",
        "urls": []
    }
    
    if not html_content:
        return result
    
    try:
        # Strip HTML tags to get clean text
        soup = BeautifulSoup(html_content, "html.parser")
        
        # Extract text
        text = soup.get_text()
        # Remove excessive whitespace
        import re
        text = re.sub(r'\s+', ' ', text).strip()
        result["text"] = text
        
        # Extract URLs from various HTML elements
        from utils.url_processor import extract_urls_from_html, decode_quoted_printable
        
        # First decode any quoted-printable encoding in HTML
        decoded_html = decode_quoted_printable(html_content)
        urls = extract_urls_from_html(decoded_html)
        
        # Filter out image URLs
        from utils.url_processor import is_image_url
        filtered_urls = []
        for url in urls:
            url_str = url if isinstance(url, str) else url.get("original_url", "")
            if not is_image_url(url_str):
                filtered_urls.append(url)
        
        result["urls"] = filtered_urls
        
        logger.debug(f"Processed HTML content: {len(text)} chars of text, {len(filtered_urls)} URLs")
        
    except Exception as e:
        logger.error(f"Error processing HTML content: {str(e)}")
        # Fallback method using regex
        import re
        text = re.sub(r'<[^>]+>', ' ', html_content)
        text = re.sub(r'\s+', ' ', text).strip()
        result["text"] = text
        
        # Basic URL extraction fallback
        from utils.url_processor import extract_urls
        result["urls"] = extract_urls(text)
    
    return result