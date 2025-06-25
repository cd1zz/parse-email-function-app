import logging
import azure.functions as func
import json
import base64
from parsers.email_parser import parse_email
from functions.json_cleaner.cleaner import clean_json_input
from functions.html_report.generator import generate_html_report
from functions.regex_extractor.extractor import extract_regex

logging.getLogger().setLevel(logging.DEBUG)
logger = logging.getLogger("AzureFunction")
logger.setLevel(logging.DEBUG)

# Initialize the function app
app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

@app.function_name("parse_email_functionapp")
@app.route(methods=["POST"], route="")
def parse_email_functionapp(req: func.HttpRequest) -> func.HttpResponse:
    """
    Azure Function endpoint to parse emails and extract the original email.
    
    Args:
        req (func.HttpRequest): HTTP request object

    Query Parameters:
        max_depth (int): Maximum recursion depth. Defaults to 10.
        stop_recursion (bool): If "true", disable recursive parsing. Defaults to False.
        first_email_only (bool): If "true", only return the first parsed email. Defaults to True.

    Returns:
        func.HttpResponse: HTTP response with original email data in JSON format
    """
    logger.info("Email Parser function processing a request.")
    
    try:
        # Get email content from the request
        email_content = req.get_body()
        
        if not email_content:
            # Check if email content is provided as a base64 string in JSON
            try:
                req_body = req.get_json()
                if "email_content_base64" in req_body:
                    email_content = base64.b64decode(req_body["email_content_base64"])
                elif "email_content" in req_body:
                    email_content = req_body["email_content"].encode('utf-8')
            except ValueError:
                pass
        
        if not email_content:
            return func.HttpResponse(
                json.dumps({"error": "No email content provided"}),
                mimetype="application/json",
                status_code=400
            )
        
        # Get max depth parameter (default to 10)
        max_depth = 10
        params = {}
        try:
            params = req.params
            if "max_depth" in params:
                max_depth = int(params["max_depth"])
        except (ValueError, TypeError, AttributeError):
            pass
        
        # Determine whether to stop recursion (default False)
        stop_recursion = False
        try:
            if params and "stop_recursion" in params:
                stop_recursion = str(params["stop_recursion"]).lower() == "true"
        except Exception:
            pass

        first_email_only = False
        try:
            if params and "first_email_only" in params:
                first_email_only = str(params["first_email_only"]).lower() == "true"
        except Exception:
            pass

        # Parse the email - returns the original email data
        parsed_data = parse_email(
            email_content,
            max_depth=max_depth,
            stop_recursion=stop_recursion,
            first_email_only=first_email_only,
        )
        
        # Return the parsed data as JSON
        return func.HttpResponse(
            json.dumps(parsed_data, indent=2, default=str),
            mimetype="application/json"
        )
        
    except Exception as e:
        logger.error(f"Error processing request: {str(e)}")
        return func.HttpResponse(
            json.dumps({"error": f"Failed to process email: {str(e)}"}),
            mimetype="application/json",
            status_code=500
        )

@app.function_name("clean_json_functionapp")
@app.route(methods=["POST"], route="")
def clean_json_functionapp(req: func.HttpRequest) -> func.HttpResponse:
    """
    Azure Function endpoint to clean and validate JSON input by removing markdown notation
    and replacing null values with "None" strings.
    
    Args:
        req (func.HttpRequest): HTTP request object
        
    Returns:
        func.HttpResponse: HTTP response with cleaned JSON
    """
    logger.info("JSON Cleaner function processing a request.")
    return clean_json_input(req)

@app.function_name("generate_html_report_functionapp")
@app.route(methods=["POST"], route="")
def generate_html_report_functionapp(req: func.HttpRequest) -> func.HttpResponse:
    """
    Azure Function endpoint to generate an HTML report from phishing analysis results.
    
    Args:
        req (func.HttpRequest): HTTP request object containing phishing analysis JSON
        
    Returns:
        func.HttpResponse: HTTP response with HTML report
    """
    logger.info("HTML Report Generator function processing a request.")
    return generate_html_report(req)

@app.function_name("extract_regex_functionapp")
@app.route(methods=["POST"], route="")
def extract_regex_functionapp(req: func.HttpRequest) -> func.HttpResponse:
    """
    Azure Function endpoint to extract content from a string using regex pattern matching.
    
    Args:
        req (func.HttpRequest): HTTP request object containing pattern and subject
        
    Returns:
        func.HttpResponse: HTTP response with regex match results
    """
    logger.info("Regex Extractor function processing a request.")
    return extract_regex(req)