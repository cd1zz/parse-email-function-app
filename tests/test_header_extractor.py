import email
from email.message import EmailMessage
from extractors.header_extractor import extract_headers


def build_email():
    msg = EmailMessage()
    msg['Message-ID'] = '<id@example.com>'
    msg['From'] = 'Alice <alice@example.com>'
    msg['To'] = 'Bob <bob@example.com>'
    msg['Subject'] = 'Test Subject'
    msg['Date'] = 'Mon, 1 Jan 2024 10:00:00 -0000'
    msg.set_content('Body')
    return msg


def test_extract_headers_basic():
    msg = build_email()
    headers = extract_headers(msg)
    assert headers['subject'] == 'Test Subject'
    assert headers['sender'] == 'Alice <alice@example.com>'
    assert headers['receiver'] == 'Bob <bob@example.com>'
    assert headers['message_id'] == '<id@example.com>'
    assert headers['authentication'] == {'dkim': '', 'spf': '', 'dmarc': ''}

