import pytest
pytest.importorskip('bs4')

from email.message import EmailMessage
from parsers.email_parser import parse_email


BOUNDARY1 = '_002_ec170bda2d714b72b6e43c7380fd7ed9MN2PR04MB6814namprd04pr_'
BOUNDARY2 = '_004_LV8PR18MB600241CE22BFC2863C745AA9CD91ALV8PR18MB6002namp_'
BOUNDARY3 = '_000_LV8PR18MB600241CE22BFC2863C745AA9CD91ALV8PR18MB6002namp_'


def build_nested_email():
    # Level 3: multipart/alternative with custom boundary
    alt = EmailMessage()
    alt.set_content('Phishing plain text', subtype='plain')
    alt.add_alternative('<p>Phishing plain text</p>', subtype='html')
    alt.set_boundary(BOUNDARY3)

    # Level 2: mixed message containing the alt part and a malicious attachment
    inner = EmailMessage()
    inner['Subject'] = 'Level 2 subject'
    inner['From'] = 'attacker@example.com'
    inner['To'] = 'victim@example.com'
    inner.make_mixed()
    inner.attach(alt)
    inner.add_attachment(b'malicious', maintype='application', subtype='octet-stream', filename='evil.exe')
    inner.set_boundary(BOUNDARY2)

    # Level 1: carrier message with the inner email attached
    outer = EmailMessage()
    outer['Subject'] = 'Outer subject'
    outer['From'] = 'carrier@example.com'
    outer['To'] = 'victim@example.com'
    outer.set_content('Carrier text')
    outer.add_attachment(inner.as_bytes(), maintype='message', subtype='rfc822')
    outer.set_boundary(BOUNDARY1)
    return outer


def test_nested_boundaries_parsing():
    outer = build_nested_email()
    result = parse_email(outer.as_bytes())

    carrier = result['carrier_email']
    target = result['target_email']['email_content']

    assert carrier['subject'] == 'Outer subject'
    assert target['subject'] == 'Level 2 subject'
    assert 'Phishing plain text' in target['body']
    # Ensure malicious attachment was extracted
    assert any(att['attachment_name'] == 'evil.exe' for att in target['attachments'])
