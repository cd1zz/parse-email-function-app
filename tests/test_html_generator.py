import pytest

jinja2 = pytest.importorskip('jinja2')

from functions.html_report.generator import create_html


def test_create_html_simple():
    data = {'final_assessment': {'category': 'PHISHING', 'score': 5}}
    html = create_html(data)
    assert '<html' in html.lower()
    assert 'PHISHING' in html

