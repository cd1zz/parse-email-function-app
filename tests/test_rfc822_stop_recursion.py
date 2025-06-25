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


def test_rfc822_attachment_recurses_to_inner():
    inner = build_simple_email('Inner', 'inner body')

    middle = build_simple_email('Middle', 'middle body')
    middle.add_attachment(inner.as_bytes(), maintype='message', subtype='rfc822')

    outer = build_simple_email('Outer', 'outer body')
    outer.add_attachment(middle.as_bytes(), maintype='message', subtype='rfc822')

    result = parse_email(outer.as_bytes(), first_email_only=True)

    content = result['email_content']
    assert content['subject'] == 'Inner'
    assert len(content['attachments']) == 0


def test_skip_forwarded_check_when_from_rfc822():
    inner_body = "-----Original Message-----\nFake forwarded text"
    inner = build_simple_email('Inner', inner_body)

    outer = build_simple_email('Outer', 'outer body')
    outer.add_attachment(inner.as_bytes(), maintype='message', subtype='rfc822')

    result = parse_email(outer.as_bytes(), first_email_only=True)

    content = result['email_content']
    assert content['subject'] == 'Inner'
    assert content['reconstruction_method'] == 'direct'
    assert 'forwarded' not in content.get('container_path', [])


def test_default_returns_carrier_and_target():
    inner = build_simple_email('Inner', 'body')
    outer = build_simple_email('Outer', 'outer body')
    outer.add_attachment(inner.as_bytes(), maintype='message', subtype='rfc822')

    result = parse_email(outer.as_bytes())

    carrier = result['carrier_email']
    target = result['target_email']
    assert carrier['subject'] == 'Outer'
    assert target['email_content']['subject'] == 'Inner'
