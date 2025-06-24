import pytest
pytest.importorskip('bs4')
from email.message import EmailMessage

from extractors.attachment_extractor import process_attachment
import extractors.excel_extractor as excel_extractor
from utils.url_processing.extractor import UrlExtractor


def test_process_attachment_handles_excel_dict(monkeypatch):
    excel_data = b"fake"  # content not parsed because extractor is mocked
    part = EmailMessage()
    part.add_attachment(
        excel_data,
        maintype="application",
        subtype="vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        filename="test.xlsx",
    )
    attachment_part = list(part.iter_attachments())[0]

    excel_result = {
        "text": "sheet text",
        "urls": [{"original_url": "http://example.com", "is_shortened": False, "expanded_url": ""}],
    }

    monkeypatch.setattr(excel_extractor, "extract_text_from_excel", lambda data: excel_result)
    monkeypatch.setattr(UrlExtractor, "extract_urls_by_content_type", staticmethod(lambda **kwargs: []))

    attachment = process_attachment(attachment_part, 0, 5, [], stop_recursion=True)

    assert attachment["attachment_text"] == "sheet text"
    assert attachment["urls"] == excel_result["urls"]
