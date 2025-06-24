import pytest
pytest.importorskip('bs4')

from email.message import EmailMessage
from extractors.body_extractor import extract_body


def test_extract_body_plain():
    msg = EmailMessage()
    msg.set_content('plain text body')
    result = extract_body(msg)
    assert result['body'] == 'plain text body'


