# utils/text_cleaner.py
import re
import logging
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

def strip_urls_and_html(text):
    if not text:
        return text

    #logger.debug(f"strip_urls_and_html text before html stripping: {text}")
    # Remove HTML tags with robust error handling for malformed content
    try:
        soup = BeautifulSoup(text, "html.parser")
        text = soup.get_text(separator=" ", strip=True)
    except Exception as e:
        logger.warning(f"BeautifulSoup failed to parse body text: {e}")
        # Replace non-printable characters and fall back to raw text
        text = re.sub(r"[^\x09\x0A\x0D\x20-\x7E]", " ", text)

    # Remove raw URLs
    text = re.sub(r"\bhttps?://[\w\-._~:/?#@!$&'()*+,;=%]+", "", text)
    text = re.sub(r"\bwww\.[\w\-._~:/?#@!$&'()*+,;=%]+", "", text)

    # Remove angle-bracketed URLs (e.g., <http://...>)
    text = re.sub(r"<https?://[\w\-._~:/?#@!$&'()*+,;=%]+>", "", text)

    # Remove markdown-style image or link lines
    text = re.sub(r"\[[^\]]+\]\s*<https?://[\w\-._~:/?#@!$&'()*+,;=%]+>", "", text)

    # Remove banner or tracking garbage (optional list can grow)
    noisy_markers = ["ZjQcmQRYFpfptBannerStart", "ZjQcmQRYFpfptBannerEnd"]
    for marker in noisy_markers:
        text = text.replace(marker, "")

    # Normalize whitespace
    text = re.sub(r"\s+", " ", text).strip()
    #logger.debug(f"strip_urls_and_html text after stripping: {text}")
    return text

def truncate_urls_in_text(text):
    """
    Replace URLs in text with domain placeholders to reduce token size
    while preserving the context of which sites were linked.
    
    Args:
        text (str): Text containing URLs to truncate
        
    Returns:
        str: Text with URLs replaced by domain placeholders
    """
    if not text:
        return text
    
    # Use regex to replace URLs with domain placeholders
    url_pattern = r'\bhttps?://([a-zA-Z0-9\-._~:/?#@!$&\'()*+,;=%]+)'
    
    def replace_with_domain(match):
        full_url = match.group(0)
        url_part = match.group(1)
        
        # Extract domain from URL
        domain_match = re.match(r'([a-zA-Z0-9\-._~]+\.[a-zA-Z0-9\-._~]+)', url_part)
        if domain_match:
            domain = domain_match.group(1)
            return f"[URL_truncated:{domain}]"
        return "[URL]"
    
    # Replace URLs with domain placeholders
    processed_text = re.sub(url_pattern, replace_with_domain, text)
    
    # Also handle "www." URLs that might not have http/https prefix
    www_pattern = r'\bwww\.([a-zA-Z0-9\-._~:/?#@!$&\'()*+,;=%]+)'
    processed_text = re.sub(www_pattern, lambda m: f"[URL_truncated:{m.group(1)}]", processed_text)
    
    return processed_text

def clean_excessive_newlines(text: str) -> str:
    """
    Replace multiple consecutive newlines (2 or more) with a single newline.
    
    Args:
        text: Text to clean
        
    Returns:
        str: Cleaned text
    """
    # Replace multiple consecutive newlines (2 or more) with a single newline
    cleaned_text = re.sub(r'\n{2,}', '\n', text)
    return cleaned_text
