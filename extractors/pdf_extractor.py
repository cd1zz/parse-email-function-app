from pdfminer.high_level import extract_text
import io
import logging

logger = logging.getLogger(__name__)

def extract_text_from_pdf(pdf_data):
    """
    Extract text content from PDF binary data.
    
    Args:
        pdf_data (bytes): The binary content of the PDF
        
    Returns:
        str: Extracted text from the PDF
    """
    try:
        # Create a file-like object from the binary data
        pdf_file = io.BytesIO(pdf_data)
        
        # Use pdfminer.six to extract text
        text = extract_text(pdf_file)
        
        return text.strip()
    except Exception as e:
        print(f"Error extracting text from PDF: {e}")
        return f"[Error extracting PDF text: {e}]"