import pytest
pytest.importorskip('bs4')

from utils.url_processing.extractor import UrlExtractor
from utils.url_processing.processor import UrlProcessor
from utils.url_processing.validator import UrlValidator


def test_extract_urls_text():
    text = 'See http://example.com and https://example.com/page.'
    urls = UrlExtractor.extract_urls(text)
    extracted = [u['original_url'] for u in urls]
    assert 'http://example.com' in extracted
    assert 'https://example.com/page' in extracted


def test_validator_is_shortened():
    assert UrlValidator.is_url_shortened('https://bit.ly/abc')
    assert not UrlValidator.is_url_shortened('https://example.com')


def test_url_processor_process_urls():
    urls = ['http://example.com', 'http://example.com', 'https://bit.ly/abc']
    processed = UrlProcessor.process_urls(urls)
    originals = [u['original_url'] for u in processed]
    assert originals.count('http://example.com') == 1
    bitly = [u for u in processed if u['original_url'] == 'https://bit.ly/abc'][0]
    assert bitly['is_shortened'] is True

