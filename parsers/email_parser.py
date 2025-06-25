# parsers/email_parser.py
import logging
import re
import traceback
from typing import Dict, List, Union, Optional, Any, Set
from email.parser import BytesParser

from extractors.header_extractor import extract_headers
from extractors.body_extractor import extract_body
from extractors.attachment_extractor import extract_attachments
from extractors.ip_extractor import extract_ip_addresses
from extractors.domain_extractor import extract_domains

# New imports for URL processing
from utils.url_processing import UrlExtractor, UrlProcessor

from utils.email_policy import CustomEmailPolicy
from utils.text_cleaner import (
    truncate_urls_in_text,
    clean_excessive_newlines,
    strip_urls_and_html,
)

from parsers.proofpoint_parser import is_proofpoint_email, parse_proofpoint_email
from parsers.forwarded_parser import parse_forwarded_email

logger = logging.getLogger(__name__)

def extract_basic_email_data(
    email_content: Union[str, bytes],
    depth: int = 0,
    max_depth: int = 10,
    container_path: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Extract core email fields without recursion or forwarding logic."""

    if container_path is None:
        container_path = []

    try:
        if isinstance(email_content, str):
            email_content = email_content.encode("utf-8", errors="replace")

        custom_policy = CustomEmailPolicy(raise_on_defect=False)
        msg = BytesParser(policy=custom_policy).parsebytes(email_content)

        headers = extract_headers(msg)
        body_data = extract_body(msg)

        attachments = extract_attachments(
            msg, depth, max_depth, container_path, stop_recursion=True
        )
        attachments = [a for a in attachments if a is not None]

        # Append text from attachments (e.g., parsed .msg) to body text for
        # downstream processing
        body_text = body_data.get("body", "")
        for att in attachments:
            if att.get("attachment_text"):
                body_text += "\n" + att["attachment_text"]

        all_urls: List[str] = []
        all_urls.extend(UrlExtractor.extract_all_urls_from_email(body_data, body_text))
        all_urls.extend(UrlProcessor.extract_urls_from_attachments(attachments))
        processed_urls = UrlProcessor.process_urls(all_urls)

        headers_text = " ".join([f"{k}: {v}" for k, v in msg.items()])
        ip_addresses = extract_ip_addresses(body_text + " " + headers_text)
        for att in attachments:
            ip_addresses.extend(att.get("ip_addresses", []))
        ip_addresses = list(set(ip_addresses))

        domains = extract_domains(processed_urls)
        for att in attachments:
            domains.extend(att.get("domains", []))
        domains = list(set(domains))

        parsed_email = {
            "message_id": headers["message_id"],
            "sender": headers["sender"],
            "return_path": headers["return_path"],
            "receiver": headers["receiver"],
            "reply_to": headers["reply_to"],
            "subject": headers["subject"],
            "date": headers["date"],
            "authentication": {
                "dkim": headers["authentication"]["dkim"],
                "spf": headers["authentication"]["spf"],
                "dmarc": headers["authentication"]["dmarc"],
            },
            "body": strip_urls_and_html(
                truncate_urls_in_text(
                    clean_excessive_newlines(body_text)
                )
            ),
            "attachments": attachments,
            "container_path": container_path,
            "reconstruction_method": "direct",
            "urls": processed_urls,
            "ip_addresses": ip_addresses,
            "domains": domains,
        }

        return {"email_content": parsed_email}

    except Exception as exc:
        logger.error(f"Error extracting basic email data: {exc}")
        logger.debug(traceback.format_exc())
        return {"error": f"Failed to extract basic email data: {exc}"}


def parse_email(
    email_content: Union[str, bytes],
    depth: int = 0,
    max_depth: int = 10,
    container_path: Optional[List[str]] = None,
    stop_recursion: bool = False,
    first_email_only: bool = False,
) -> Dict[str, Any]:
    """Parse an email. When called at depth 0 this returns a structure
    containing the carrier email and the first target email found."""

    if depth > max_depth:
        return {"error": f"Maximum recursion depth ({max_depth}) exceeded"}

    if stop_recursion:
        return extract_basic_email_data(
            email_content,
            depth=depth,
            max_depth=max_depth,
            container_path=container_path,
        )

    if container_path is None:
        container_path = []

    logger.debug(
        f"Parsing email at depth {depth} with container path {container_path}"
    )

    try:
        if isinstance(email_content, str):
            email_content = email_content.encode("utf-8", errors="replace")

        custom_policy = CustomEmailPolicy(raise_on_defect=False)
        msg = BytesParser(policy=custom_policy).parsebytes(email_content)

        # -- FIRST EMAIL ONLY MODE --
        if first_email_only and depth == 0:
            attachments = extract_attachments(
                msg, depth, max_depth, container_path, stop_recursion=stop_recursion
            )
            attachments = [a for a in attachments if a is not None]
            for att in attachments:
                if att.get("is_email") and "parsed_email" in att:
                    inner = att["parsed_email"]
                    if isinstance(inner, dict) and "email_content" in inner:
                        email_data = inner["email_content"]
                    else:
                        email_data = inner
                    extra_atts = [a for a in attachments if a is not att]
                    email_data.setdefault("attachments", []).extend(extra_atts)
                    if "email_content" in inner:
                        inner["email_content"] = email_data
                        return inner
                    return {"email_content": email_data}

            if is_forwarded_email(msg):
                forwarded_data = parse_forwarded_email(
                    msg, depth + 1, max_depth, container_path + ["forwarded"]
                )
                if forwarded_data and not is_empty_email_data(forwarded_data):
                    forwarded_email = {
                        "message_id": "",
                        "sender": forwarded_data.get("original_sender", ""),
                        "return_path": "",
                        "receiver": forwarded_data.get("original_recipient", ""),
                        "reply_to": "",
                        "subject": forwarded_data.get("original_subject", ""),
                        "date": forwarded_data.get("original_date", ""),
                        "body": strip_urls_and_html(
                            truncate_urls_in_text(
                                clean_excessive_newlines(
                                    forwarded_data.get("original_body", "")
                                )
                            )
                        ),
                        "attachments": attachments,
                        "container_path": container_path + ["forwarded"],
                        "reconstruction_method": "forwarded",
                        "urls": forwarded_data.get("urls", []),
                        "ip_addresses": forwarded_data.get("ip_addresses", []),
                        "domains": forwarded_data.get("domains", []),
                    }
                    return {"email_content": forwarded_email}

        headers = extract_headers(msg)
        body_data = extract_body(msg)

        attachments = extract_attachments(
            msg, depth, max_depth, container_path, stop_recursion=stop_recursion
        )
        attachments = [a for a in attachments if a is not None]

        body_text = body_data.get("body", "")
        for att in attachments:
            if att.get("attachment_text"):
                body_text += "\n" + att["attachment_text"]

        all_urls: List[str] = []
        all_urls.extend(UrlExtractor.extract_all_urls_from_email(body_data, body_text))
        all_urls.extend(UrlProcessor.extract_urls_from_attachments(attachments))
        processed_urls = UrlProcessor.process_urls(all_urls)

        headers_text = " ".join([f"{k}: {v}" for k, v in msg.items()])
        ip_addresses = extract_ip_addresses(body_text + " " + headers_text)
        for att in attachments:
            ip_addresses.extend(att.get("ip_addresses", []))
        ip_addresses = list(set(ip_addresses))

        domains = extract_domains(processed_urls)
        for att in attachments:
            domains.extend(att.get("domains", []))
        domains = list(set(domains))

        parsed_email = {
            "message_id": headers["message_id"],
            "sender": headers["sender"],
            "return_path": headers["return_path"],
            "receiver": headers["receiver"],
            "reply_to": headers["reply_to"],
            "subject": headers["subject"],
            "date": headers["date"],
            "authentication": {
                "dkim": headers["authentication"]["dkim"],
                "spf": headers["authentication"]["spf"],
                "dmarc": headers["authentication"]["dmarc"],
            },
            "body": strip_urls_and_html(
                truncate_urls_in_text(clean_excessive_newlines(body_text))
            ),
            "attachments": attachments,
            "container_path": container_path,
            "reconstruction_method": "direct",
            "urls": processed_urls,
            "ip_addresses": ip_addresses,
            "domains": domains,
        }

        result = {"email_content": parsed_email}

        if depth == 0 and not first_email_only:
            target_email = None
            for att in attachments:
                if att.get("is_email") and att.get("parsed_email"):
                    target_email = att["parsed_email"]
                    break

            if not target_email and is_forwarded_email(msg, body_data):
                forwarded_data = parse_forwarded_email(
                    msg, depth + 1, max_depth, container_path + ["forwarded"]
                )
                if forwarded_data and not is_empty_email_data(forwarded_data):
                    forwarded_email = {
                        "message_id": "",
                        "sender": forwarded_data.get("original_sender", ""),
                        "return_path": "",
                        "receiver": forwarded_data.get("original_recipient", ""),
                        "reply_to": "",
                        "subject": forwarded_data.get("original_subject", ""),
                        "date": forwarded_data.get("original_date", ""),
                        "body": strip_urls_and_html(
                            truncate_urls_in_text(
                                clean_excessive_newlines(
                                    forwarded_data.get("original_body", "")
                                )
                            )
                        ),
                        "attachments": [],
                        "container_path": container_path + ["forwarded"],
                        "reconstruction_method": "forwarded",
                        "urls": forwarded_data.get("urls", []),
                        "ip_addresses": forwarded_data.get("ip_addresses", []),
                        "domains": forwarded_data.get("domains", []),
                    }
                    target_email = {"email_content": forwarded_email}

            return {
                "carrier_email": parsed_email,
                "target_email": target_email,
            }

        return result

    except Exception as e:  # pragma: no cover - unexpected failure path
        logger.error(f"Error parsing email: {str(e)}")
        logger.debug(traceback.format_exc())
        return {"error": f"Failed to parse email: {str(e)}"}

def is_forwarded_email(msg, body_data=None) -> bool:
    """Check whether the message looks like a forwarded email.

    The detection heuristics look at subject/body patterns but ignore
    emails that clearly carry another email as an attachment. This helps
    avoid misclassifying "carrier" emails (where the original email is
    attached rather than inline) as forwarded messages.

    Args:
        msg: Email message object.
        body_data: Optional body data already extracted.

    Returns:
        bool: ``True`` if heuristics indicate a forwarded email, ``False``
        otherwise.
    """
    # If the message includes an attached email, treat it as a carrier
    # message rather than an inline forward.
    for part in msg.walk():
        if part.get_content_maintype() == "multipart":
            continue

        filename = part.get_filename() or ""
        content_type = part.get_content_type().lower()

        if (
            filename.lower().endswith((".eml", ".msg"))
            or content_type == "message/rfc822"
        ):
            logger.debug(
                "Email contains attached email; skipping forwarded detection"
            )
            return False
    # Check subject for forwarding indicators
    subject = msg.get('Subject', '')
    if subject and (subject.lower().startswith(('fw:', 'fwd:')) or 'forwarded' in subject.lower()):
        logger.debug("Email subject indicates forwarded message")
        
    # Check content for forwarding patterns
    if body_data is None:
        # If body_data wasn't provided, extract it now
        body_data = extract_body(msg)
    
    # Use both plain and HTML for checking patterns
    body_text = ""
    if isinstance(body_data, dict):
        if "body" in body_data:
            body_text = body_data["body"]
    else:
        # Fallback if body_data is not a dict
        body_text = str(body_data)
    
    # Common forwarding patterns from different email clients
    forwarding_patterns = [
        "---------- Forwarded message ---------",  # Gmail
        "Begin forwarded message:",              # Apple Mail
        # More specific Outlook pattern to avoid false positives from signatures
        r"^From:.*?\r?\nSent:.*?\r?\nTo:.*?\r?\nSubject:",  # Outlook with line breaks
        "-----Original Message-----",           # Various clients
        "Forwarded Message",                    # Various clients
    ]
    
    for pattern in forwarding_patterns:
        if pattern.startswith('^'):
            # This is a regex pattern
            if re.search(pattern, body_text, re.MULTILINE | re.DOTALL | re.IGNORECASE):
                logger.debug(f"Found forwarded email pattern: {pattern}")
                return True
        elif pattern.lower() in body_text.lower():
            # This is a simple string pattern
            logger.debug(f"Found forwarded email pattern: {pattern}")
            return True
    
    return False

def is_empty_email_data(email_data: Dict[str, Any]) -> bool:
    """
    Check if email data dictionary has empty values for all important fields.
    
    Args:
        email_data: Email data dictionary
        
    Returns:
        bool: True if all important fields are empty, False otherwise
    """
    if not isinstance(email_data, dict):
        return True
        
    # Check for empty original sender/recipient fields
    has_sender = bool(email_data.get("original_sender", ""))
    has_recipient = bool(email_data.get("original_recipient", ""))
    has_subject = bool(email_data.get("original_subject", ""))
    has_body = bool(email_data.get("original_body", ""))
    
    # If all are empty, consider it empty
    return not (has_sender or has_recipient or has_subject or has_body)