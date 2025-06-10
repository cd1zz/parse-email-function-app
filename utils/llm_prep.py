# In utils/llm_prep.py

import re
import urllib.parse
from utils.url_processing import UrlValidator

def prepare_email_for_llm(email_data: dict) -> dict:
    """
    Prepare email data for sending to an LLM by reducing token size.
    
    - Truncates URLs in the body
    - (Other future optimizations can be added here)
    
    Args:
        email_data (dict): The parsed email data
        
    Returns:
        dict: Email data optimized for LLM processing
    """
    # Make a copy to avoid modifying the original
    import copy
    optimized_data = copy.deepcopy(email_data)
    
    # Truncate URLs in the body
    if "email_content" in optimized_data and "body" in optimized_data["email_content"]:
        body = optimized_data["email_content"]["body"]
        
        # Use regex to replace URLs with domain placeholders
        url_pattern = r'\bhttps?://[a-zA-Z0-9\-._~:/?#[\]@!$&\'()*+,;=%]+'
        
        def replace_with_domain(match):
            url = match.group(0)
            clean_url = UrlValidator.clean_url(url)
            
            try:
                parsed = urllib.parse.urlparse(clean_url)
                domain = parsed.netloc
                return f"[URL_truncated:{domain}]"
            except:
                return "[URL]"
        
        # Replace URLs with domain placeholders
        body = re.sub(url_pattern, replace_with_domain, body)
        
        optimized_data["email_content"]["body"] = body
    
    return optimized_data