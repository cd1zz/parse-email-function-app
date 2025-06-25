import json
import logging
import re
import azure.functions as func

logger = logging.getLogger(__name__)

# In the Azure Functions environment the host configures logging. Avoid
# overriding it here so we simply obtain a module level logger.

def remove_markdown_notation(input_string):
    logger.debug("Starting markdown notation removal.")
    # Remove markdown notation, handle both triple backticks and variations like ~~~json
    cleaned_string = re.sub(r'```json\n|\n```', '', input_string)  # Remove both starting and trailing markdown notation for triple backticks
    cleaned_string = re.sub(r'~~~json\n|\n~~~', '', cleaned_string)  # Also remove any ~~~json annotations
    cleaned_string = re.sub(r'###.*?\n', '', cleaned_string)  # Remove '###' annotations along with anything until the next newline
    logger.debug("Completed markdown notation removal.")
    return cleaned_string.strip()  # Strip leading/trailing whitespace

def sanitize_problematic_characters(input_string):
    """
    Replace or properly escape problematic characters that might cause JSON parsing issues.
    """
    logger.debug("Starting character sanitization.")
    
    # Replace backtick characters (commonly used for code in markdown or for currency)
    sanitized = re.sub(r'`', "'", input_string)  # Replace backticks with single quotes
    
    # Handle form feed characters
    sanitized = sanitized.replace('\f', '\\f')
    
    # Handle other potentially problematic control characters
    sanitized = re.sub(r'[\x00-\x08\x0b-\x0c\x0e-\x1f]', '', sanitized)
    
    logger.debug("Completed character sanitization.")
    return sanitized

def replace_nulls_with_none(d):
    logger.debug("Starting replacement of null values with 'None'.")
    if isinstance(d, dict):
        replaced_dict = {k: replace_nulls_with_none(v) for k, v in d.items()}
        logger.debug(f"Replaced dictionary: {replaced_dict}")
        return replaced_dict
    elif isinstance(d, list):
        replaced_list = [replace_nulls_with_none(i) for i in d]
        logger.debug(f"Replaced list: {replaced_list}")
        return replaced_list
    elif d is None:
        return "None"  # Replace null with the string "None"
    else:
        return d

def clean_json_input(req: func.HttpRequest) -> func.HttpResponse:
    try:
        logger.debug("Received HTTP request.")
        
        # Get the raw input body as a byte string and decode it
        req_body = req.get_body().decode('utf-8')
        logger.debug(f"Original request body: {req_body}")

        # Remove markdown notation
        clean_json = remove_markdown_notation(req_body)
        logger.debug(f"Request body after removing markdown notation: {clean_json}")
        
        # Sanitize problematic characters
        clean_json = sanitize_problematic_characters(clean_json)
        logger.debug(f"Request body after sanitizing characters: {clean_json}")

        # First try: If the input is already valid JSON
        try:
            parsed_json = json.loads(clean_json)
            logger.debug("Successfully parsed JSON on first attempt.")
        except json.JSONDecodeError as e:
            logger.warning(f"First JSON parsing attempt failed: {e}")
            
            # Second try: Check if the input has extra opening or closing braces
            # Sometimes LLMs add extra context before or after the JSON
            match = re.search(r'\{.*\}', clean_json, re.DOTALL)
            if match:
                clean_json = match.group(0)
                logger.debug(f"Extracted JSON-like content: {clean_json}")
                
                try:
                    parsed_json = json.loads(clean_json)
                    logger.debug("Successfully parsed JSON on second attempt.")
                except json.JSONDecodeError as inner_e:
                    logger.error(f"Second JSON parsing attempt failed: {inner_e}")
                    raise inner_e
            else:
                logger.error("Could not find JSON-like content in the input.")
                raise e

        # Replace null values with the string "None"
        parsed_json = replace_nulls_with_none(parsed_json)
        logger.debug(f"JSON after replacing null values with 'None': {parsed_json}")

        # Convert it back to a string for the response
        validated_json = json.dumps(parsed_json, indent=4)
        logger.debug(f"Final validated JSON string: {validated_json}")

        return func.HttpResponse(
            validated_json,
            status_code=200,
            mimetype="application/json"
        )

    except json.JSONDecodeError as e:
        logger.error(f"JSON decoding error: {e}")
        return func.HttpResponse(
            f"Unable to clean and parse the provided input. Please ensure the input is structured as JSON. Error: {e}",
            status_code=400
        )

    except Exception as e:
        logger.error(f"An unexpected error occurred: {e}", exc_info=True)
        return func.HttpResponse(
            f"An error occurred while processing the request: {e}",
            status_code=500
        )