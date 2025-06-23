import logging
from parsers.email_parser import parse_email

logger = logging.getLogger(__name__)

def parse_eml(eml_content, max_depth=10, stop_recursion=False):
    """
    Parse an .eml file and extract email information.
    
    Args:
        eml_content (bytes or str): Content of the .eml file
        max_depth (int): Maximum recursion depth for nested emails
        
    Returns:
        dict: Parsed email data
    """
    logger.debug("Parsing .eml file")
    
    try:
        # Convert to bytes if string is provided
        if isinstance(eml_content, str):
            eml_content = eml_content.encode('utf-8', errors='replace')
        
        # Use the main email parser to parse the EML content
        parsed_data = parse_email(
            eml_content,
            max_depth=max_depth,
            stop_recursion=stop_recursion,
        )
        
        return parsed_data
        
    except Exception as e:
        logger.error(f"Error parsing .eml file: {str(e)}")
        return {"error": f"Failed to parse .eml file: {str(e)}"}