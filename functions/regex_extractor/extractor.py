import logging
import re
import json
from typing import Optional, Tuple
import azure.functions as func

# Set up logging configuration
logger = logging.getLogger(__name__)

def extract_with_regex(subject: str, pattern: str) -> Tuple[Optional[str], Optional[str]]:
    """
    Extracts a match from a subject string using a provided regex pattern.
    
    Args:
        subject (str): The string to search in
        pattern (str): The regex pattern to use for matching
        
    Returns:
        Tuple[Optional[str], Optional[str]]: 
            - First element is the matched string if found, None otherwise
            - Second element is an error message if an error occurred, None otherwise
        
    Note:
        Does not raise exceptions but returns error messages as part of the tuple
    """
    if not isinstance(subject, str):
        return None, "Subject must be a string"
    
    if not isinstance(pattern, str):
        return None, "Pattern must be a string"
    
    try:
        match = re.search(pattern, subject)
        if match and match.groups():
            return match.group(1), None  # Return first captured group
        elif match:
            return match.group(0), None  # Return entire match if no groups
        return None, None  # No match found
    except re.error as e:
        return None, f"Invalid regex pattern: {str(e)}"
    except Exception as e:
        return None, f"Unexpected error: {str(e)}"

def extract_regex(req: func.HttpRequest) -> func.HttpResponse:
    """
    Azure Function endpoint that processes regex matching requests.
    
    Expected request body format:
    {
        "pattern": "regex_pattern_here",
        "subject": "string_to_search_in"
    }
    """
    try:
        logger.debug("Received HTTP request.")
        
        # Get request body
        try:
            req_body = req.get_json()
        except ValueError:
            return func.HttpResponse(
                "Invalid JSON in request body",
                status_code=400
            )
        
        # Extract required fields
        pattern = req_body.get('pattern')
        subject = req_body.get('subject')
        
        if not pattern or not subject:
            return func.HttpResponse(
                "Missing required fields: 'pattern' and 'subject' are required",
                status_code=400
            )
            
        logger.debug(f"Processing regex pattern: {pattern}")
        logger.debug(f"Testing against subject: {subject}")
        
        # Attempt to extract match
        match_result, error_message = extract_with_regex(subject, pattern)
        
        if error_message:
            return func.HttpResponse(
                error_message,
                status_code=400
            )
            
        response_data = {
            "input": {
                "pattern": pattern,
                "subject": subject
            },
            "match_found": match_result is not None,
            "matched_value": match_result
        }
        
        return func.HttpResponse(
            json.dumps(response_data, indent=2),
            mimetype="application/json"
        )
        
    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)
        return func.HttpResponse(
            f"An error occurred while processing the request: {str(e)}",
            status_code=500
        )