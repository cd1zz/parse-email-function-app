import pytest

bs4_available = True
try:
    from bs4 import BeautifulSoup  # noqa: F401
except Exception:
    bs4_available = False

if bs4_available:
    from email.message import EmailMessage
    from parsers.email_parser import parse_email
else:
    EmailMessage = None  # type: ignore
    parse_email = None  # type: ignore

pytestmark = pytest.mark.skipif(not bs4_available, reason="requires bs4")


def build_simple_email(subject, body):
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = 'a@example.com'
    msg['To'] = 'b@example.com'
    msg.set_content(body)
    return msg


def test_rfc822_attachment_stops_recursion():
    inner = build_simple_email('Inner', 'inner body')

    middle = build_simple_email('Middle', 'middle body')
    middle.add_attachment(inner.as_bytes(), maintype='message', subtype='rfc822')

    outer = build_simple_email('Outer', 'outer body')
    outer.add_attachment(middle.as_bytes(), maintype='message', subtype='rfc822')

    result = parse_email(outer.as_bytes())

    assert result.get('extraction_source') == 'rfc822_attachment'
    content = result['email_content']
    assert content['subject'] == 'Middle'
    assert len(content['attachments']) == 1
    attachment = content['attachments'][0]
    assert attachment['is_email'] is True
    assert 'parsed_email' not in attachment
