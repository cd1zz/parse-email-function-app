import sys
import types
import json
import pytest

bs4_available = True
try:
    from bs4 import BeautifulSoup  # noqa: F401
except Exception:
    bs4_available = False

azure_module = types.ModuleType('azure.functions')
class HttpRequest:
    def __init__(self, body=b'', params=None):
        self._body = body
        self.params = params or {}
    def get_body(self):
        return self._body
    def get_json(self):
        return json.loads(self._body.decode('utf-8'))

class HttpResponse:
    def __init__(self, body=None, status_code=200, mimetype=None):
        self.body = body
        self.status_code = status_code
        self.mimetype = mimetype
    def get_body(self):
        return self.body

azure_module.HttpRequest = HttpRequest
azure_module.HttpResponse = HttpResponse
sys.modules.setdefault('azure', types.ModuleType('azure'))
sys.modules.setdefault('azure.functions', azure_module)

if bs4_available:
    from email.message import EmailMessage
    from function_app import parse_email_functionapp
else:
    EmailMessage = None  # type: ignore
    parse_email_functionapp = None  # type: ignore

pytestmark = pytest.mark.skipif(not bs4_available, reason="requires bs4")


def build_simple_email(subject, body):
    msg = EmailMessage()
    msg['Subject'] = subject
    msg['From'] = 'a@example.com'
    msg['To'] = 'b@example.com'
    msg.set_content(body)
    return msg


def test_first_email_only_returns_first_level():
    inner = build_simple_email('Inner', 'inner body')
    middle = build_simple_email('Middle', 'middle body')
    middle.add_attachment(inner.as_bytes(), maintype='message', subtype='rfc822')
    outer = build_simple_email('Outer', 'outer body')
    outer.add_attachment(middle.as_bytes(), maintype='message', subtype='rfc822')

    params = {'first_email_only': 'true'}
    req = HttpRequest(body=outer.as_bytes(), params=params)
    resp = parse_email_functionapp(req)
    assert resp.status_code == 200
    data = json.loads(resp.get_body())
    content = data['email_content']
    assert content['subject'] == 'Middle'
