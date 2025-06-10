# parsers/proofpoint_parser.py
import logging
import re

logger = logging.getLogger(__name__)

# Define Proofpoint markers
PROOFPOINT_HEADER_MARKER_BEGIN = "---------- Begin Email Headers ----------"
PROOFPOINT_HEADER_MARKER_END = "---------- End Email Headers ----------"
PROOFPOINT_BODY_MARKER_BEGIN = "---------- Begin Reported Email ----------"
PROOFPOINT_BODY_MARKER_END = "---------- End Reported Email ----------"

def is_proofpoint_email(msg):
    subject = msg.get('Subject', '')
    subject_match = subject and "Potential Phish:" in subject

    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() in ['text/plain', 'text/html']:
                try:
                    content = part.get_payload(decode=True)
                    if content:
                        body += content.decode('utf-8', errors='ignore')
                except Exception as e:
                    logger.error(f"Error decoding content in is_proofpoint_email: {str(e)}")
    else:
        try:
            content = msg.get_payload(decode=True)
            if content:
                body += content.decode('utf-8', errors='ignore')
        except Exception as e:
            logger.error(f"Error decoding content in is_proofpoint_email: {str(e)}")

    body_match = any(marker in body for marker in [
        PROOFPOINT_HEADER_MARKER_BEGIN,
        PROOFPOINT_HEADER_MARKER_END,
        PROOFPOINT_BODY_MARKER_BEGIN
    ])

    return subject_match and body_match

def extract_proofpoint_sections(text):
    headers_text = ""
    reported_content = ""

    header_patterns = [
        rf"{re.escape(PROOFPOINT_HEADER_MARKER_BEGIN)}\r?\n(.*?)\r?\n{re.escape(PROOFPOINT_HEADER_MARKER_END)}",
        r"[-]{2,15} Begin Email Headers [-]{0,15}\r?\n(.*?)\r?\n[-]{2,15} End Email Headers [-]{0,15}",
        r"Begin Email Headers\s*[-]*\s*\r?\n(.*?)\r?\nEnd Email Headers",
        r"Email Headers:\r?\n[-]{0,15}\r?\n(.*?)\r?\n[-]{0,15}"
    ]
    for pattern in header_patterns:
        headers_match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
        if headers_match:
            headers_text = headers_match.group(1).strip()
            break

    content_patterns = [
        rf"{re.escape(PROOFPOINT_BODY_MARKER_BEGIN)}\r?\n(.*?)(?:\r?\n{re.escape(PROOFPOINT_BODY_MARKER_END)}|$)",
        r"[-]{2,15} Begin Reported Email [-]{0,15}\r?\n(.*?)(?:\r?\n[-]{2,15} End Reported Email [-]{0,15}|$)",
        r"Begin Reported Email\s*[-]*\s*\r?\n(.*?)(?:\r?\nEnd Reported Email|$)",
        r"Reported Email:\r?\n[-]{0,15}\r?\n(.*?)(?:\r?\n[-]{0,15}|$)"
    ]
    for pattern in content_patterns:
        content_match = re.search(pattern, text, re.DOTALL | re.IGNORECASE)
        if content_match:
            reported_content = content_match.group(1).strip()
            break

    return headers_text, reported_content

def parse_proofpoint_email(email_content, depth=0, max_depth=10, container_path=None):
    if container_path is None:
        container_path = []

    logger.debug("Parsing Proofpoint-formatted email")

    if isinstance(email_content, bytes):
        try:
            email_content_str = email_content.decode('utf-8', errors='replace')
        except Exception as e:
            logger.error(f"Error decoding Proofpoint email content: {str(e)}")
            return {"error": f"Failed to decode Proofpoint email content: {str(e)}"}
    else:
        email_content_str = email_content

    from email import message_from_string, message_from_bytes
    msg = message_from_bytes(email_content) if isinstance(email_content, bytes) else message_from_string(email_content)

    headers_text = ""
    reported_content = ""

    if msg.is_multipart():
        logger.debug("Proofpoint email is multipart, processing all parts")
        for part in msg.walk():
            if part.get_content_maintype() == 'multipart':
                continue
            part_content = part.get_payload(decode=True)
            if part_content is None:
                continue
            try:
                charset = part.get_content_charset() or 'utf-8'
                part_text = part_content.decode(charset, errors='replace')
            except Exception as e:
                logger.warning(f"Error decoding part: {str(e)}, trying utf-8")
                part_text = part_content.decode('utf-8', errors='replace')
            found_headers, found_content = extract_proofpoint_sections(part_text)
            if found_headers:
                headers_text = found_headers
            if found_content:
                reported_content = found_content
            if headers_text and reported_content:
                break
    else:
        payload = msg.get_payload(decode=True)
        if payload:
            try:
                charset = msg.get_content_charset() or 'utf-8'
                payload_text = payload.decode(charset, errors='replace')
            except Exception as e:
                logger.warning(f"Error decoding payload: {str(e)}, trying utf-8")
                payload_text = payload.decode('utf-8', errors='replace')
            headers_text, reported_content = extract_proofpoint_sections(payload_text)

    if not headers_text or not reported_content:
        headers_text_alt, reported_content_alt = extract_proofpoint_sections(email_content_str)
        if not headers_text:
            headers_text = headers_text_alt
        if not reported_content:
            reported_content = reported_content_alt

    logger.debug(f"Extracted headers length: {len(headers_text)}")
    logger.debug(f"Extracted content length: {len(reported_content)}")

    from parsers.email_parser import parse_email
    flattened_email = f"{headers_text}\n\n{reported_content}"
    try:
        result = parse_email(flattened_email.encode('utf-8'), depth=depth, max_depth=max_depth, container_path=container_path + ["proofpoint"])
        if not result or 'error' in result:
            logger.warning("parse_email returned empty or error from Proofpoint input")
        return result
    except Exception as e:
        logger.exception("Exception in parse_email from Proofpoint flow")
        return {"error": f"Proofpoint parse_email failure: {str(e)}"}
