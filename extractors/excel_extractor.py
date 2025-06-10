# extractors/excel_extractor.py
import io
import logging
import traceback
import zipfile
import re
from xml.etree import ElementTree as ET
# Import shared utility functions
from utils.url_processing import OfficeUrlExtractor
from utils.office_extraction_utils import (
    extract_urls_from_office_html,
    extract_urls_from_relationship_file,
    extract_urls_from_xml_file,
    extract_urls_from_drawing_files,
    filter_microsoft_urls
)

logger = logging.getLogger(__name__)

def extract_text_from_excel(excel_data):
    """
    Extract text content from Excel binary data.
    
    Args:
        excel_data (bytes): The binary content of the Excel file
        
    Returns:
        dict: Dictionary containing the extracted text and URLs
    """
    try:
        # Create a file-like object from the binary data
        excel_file = io.BytesIO(excel_data)
        
        extracted_text = None
        urls = set()
        metadata = []
        
        # Try pandas first for simple structured data extraction
        try:
            import pandas as pd
            
            # Try reading with pandas - handles xls and xlsx
            dfs = pd.read_excel(excel_file, sheet_name=None)
            
            # Concatenate all sheets into a text representation
            text_content = []
            for sheet_name, df in dfs.items():
                text_content.append(f"Sheet: {sheet_name}")
                text_content.append(df.to_string(index=False))
                text_content.append("\n")
            
            result = "\n".join(text_content).strip()
            logger.debug(f"Successfully extracted Excel text using pandas, {len(result)} characters")
            extracted_text = result
            
        except Exception as pandas_err:
            logger.warning(f"Pandas Excel reading failed: {str(pandas_err)}")
        
        # Always run deep extraction for URLs and metadata, regardless of whether text was extracted
        excel_file.seek(0)
        try:
            logger.debug("Running deep extraction for URLs and metadata")
            deep_result = extract_excel_deep(excel_data)
            
            # Extract URLs from the deep extraction result
            if deep_result:
                # If we got URL data in the deep extraction, extract it
                url_section_match = re.search(r"# Additional URLs\n(.*?)(?:\n\n|$)", deep_result, re.DOTALL)
                if url_section_match:
                    deep_urls = url_section_match.group(1).strip().split("\n")
                    urls.update(deep_urls)
                    logger.debug(f"Extracted {len(deep_urls)} URLs from deep extraction")
                
                # Also check for hyperlinks section
                hyperlink_section_match = re.search(r"# Hyperlinks\n(.*?)(?:\n\n|$)", deep_result, re.DOTALL)
                if hyperlink_section_match:
                    hyperlink_urls = hyperlink_section_match.group(1).strip().split("\n")
                    urls.update(hyperlink_urls)
                    logger.debug(f"Extracted {len(hyperlink_urls)} hyperlinks from deep extraction")
                
                # If we didn't get text from simpler methods, use the deep extraction text
                if not extracted_text:
                    extracted_text = deep_result
        except Exception as deep_err:
            logger.warning(f"Deep Excel extraction failed: {str(deep_err)}")
            
            # If deep extraction fails and we still don't have text, try openpyxl
            if not extracted_text:
                excel_file.seek(0)
                try:
                    import openpyxl
                    
                    workbook = openpyxl.load_workbook(excel_file, data_only=True)
                    text_content = []
                    
                    for sheet in workbook.worksheets:
                        text_content.append(f"Sheet: {sheet.title}")
                        
                        for row in sheet.iter_rows():
                            row_values = [str(cell.value) if cell.value is not None else "" for cell in row]
                            text_content.append("\t".join(row_values))
                        
                        text_content.append("\n")
                    
                    result = "\n".join(text_content).strip()
                    logger.debug(f"Successfully extracted Excel text using openpyxl, {len(result)} characters")
                    extracted_text = result
                    
                except Exception as openpyxl_err:
                    logger.warning(f"Openpyxl Excel reading failed: {str(openpyxl_err)}, trying xlrd")
                    
                    # Reset file position
                    excel_file.seek(0)
                    
                    # Try xlrd as a last resort for xls files
                    try:
                        import xlrd
                        
                        workbook = xlrd.open_workbook(file_contents=excel_data)
                        text_content = []
                        
                        for sheet_idx in range(workbook.nsheets):
                            sheet = workbook.sheet_by_index(sheet_idx)
                            text_content.append(f"Sheet: {sheet.name}")
                            
                            for row_idx in range(sheet.nrows):
                                row_values = [str(cell.value) for cell in sheet.row(row_idx)]
                                text_content.append("\t".join(row_values))
                            
                            text_content.append("\n")
                        
                        result = "\n".join(text_content).strip()
                        logger.debug(f"Successfully extracted Excel text using xlrd, {len(result)} characters")
                        extracted_text = result
                        
                    except Exception as xlrd_err:
                        logger.error(f"All Excel reading methods failed: {str(xlrd_err)}")
        
        # Convert all URLs to the format expected by url_processor.py
        formatted_urls = []
        for url in urls:
            formatted_urls.append({
                "original_url": url,
                "is_shortened": False,  # This will be processed later
                "expanded_url": ""      # This will be processed later
            })
        
        # If we have URLs, append them to the extracted text
        if urls:
            url_text = "\n\n# URLs\n" + "\n".join(urls)
            logger.debug(f"Adding {len(urls)} URLs to output")
            
            if extracted_text:
                # Only append URLs if they're not already in the text
                if "# URLs" not in extracted_text and "# Additional URLs" not in extracted_text and "# Hyperlinks" not in extracted_text:
                    extracted_text += url_text
            else:
                # If we somehow have URLs but no text
                extracted_text = "[No text content found in Excel file]" + url_text
        
        # Create a result object that includes both text and URLs
        result = {
            "text": extracted_text if extracted_text else "[Error: Could not extract Excel text with any available method]",
            "urls": formatted_urls
        }
        
        return result
    
    except Exception as e:
        logger.error(f"Error extracting text from Excel: {str(e)}")
        logger.debug(traceback.format_exc())
        return {
            "text": f"[Error extracting Excel text: {str(e)}]",
            "urls": []
        }
    
def extract_excel_deep(excel_data):
    """
    Extract detailed information from Excel files including text, URLs, VBA code, etc.
    
    Args:
        excel_data (bytes): The binary content of the Excel file
        
    Returns:
        str: Extracted text content and metadata
    """
    excel_bytes = io.BytesIO(excel_data)
    extracted_text = []
    metadata = []
    urls = set()
    hyperlinks = []
    formulas = []
    comments = []

    try:
        logger.info("Performing deep extraction from Excel file")
        
        with zipfile.ZipFile(excel_bytes, 'r') as z:
            # Log all files in the archive for debugging
            all_files = z.namelist()
            logger.debug(f"Files in Excel document: {all_files}")
            
            # Log specific files we're looking for
            html_files = [f for f in all_files if f.endswith('.htm') or f.endswith('.html')]
            logger.debug(f"HTML files found: {html_files}")
            
            rels_files = [f for f in all_files if f.endswith('.rels')]
            logger.debug(f"Relationship files found: {rels_files}")
            
            xml_files = [f for f in all_files if f.endswith('.xml')]
            logger.debug(f"XML files found: {xml_files}")
            
            drawing_files = [f for f in all_files if 
                             '/drawings/' in f or 
                             '/diagrams/' in f or
                             '/charts/' in f]
            logger.debug(f"Drawing files found: {drawing_files}")
            
            # Process VBA code if present
            if 'xl/vbaProject.bin' in z.namelist():
                try:
                    vba_binary = z.read('xl/vbaProject.bin')
                    # Look for VBA code segments
                    modules = re.findall(b'Attribute VB_Name = "([^"]+)".*?(?=Attribute VB_Name|$)', 
                                       vba_binary, re.DOTALL)
                    
                    if modules:
                        metadata.append("# Excel VBA Code")
                    
                    for i, module in enumerate(modules):
                        try:
                            decoded_content = module.decode('utf-8', errors='ignore')
                            cleaned_content = re.sub(r'[\x00-\x08\x0b\x0c\x0e-\x1f]', '', decoded_content)
                            if cleaned_content.strip():  # Only add if there's content
                                metadata.append(f"# Module {i}")
                                metadata.append(cleaned_content)
                                
                                # Look for URLs in VBA code
                                vba_urls = re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s"\'<>]*', cleaned_content)
                                urls.update(vba_urls)
                        except Exception as e:
                            logger.warning(f"Could not decode VBA module {i}: {str(e)}")
                except Exception as e:
                    logger.warning(f"Error processing VBA project: {str(e)}")

            # Process relationship files for hyperlinks
            for rels_file in rels_files:
                logger.debug(f"About to call extract_urls_from_relationship_file for {rels_file}")
                rel_urls = OfficeUrlExtractor.extract_urls_from_relationship_file(z, rels_file)
                logger.debug(f"extract_urls_from_relationship_file returned {len(rel_urls)} URLs")
                urls.update(rel_urls)
                
                # Also keep track of hyperlinks for the hyperlinks section
                try:
                    content = z.read(rels_file).decode('utf-8', errors='ignore')
                    root = ET.fromstring(content)
                    for relationship in root.findall('.//{http://schemas.openxmlformats.org/package/2006/relationships}Relationship'):
                        rel_type = relationship.get('Type', '')
                        target = relationship.get('Target', '')
                        
                        if 'hyperlink' in rel_type.lower() and target:  # Only add if target exists
                            hyperlinks.append(target)
                except Exception as e:
                    logger.warning(f"Error processing relationships for hyperlink list in {rels_file}: {str(e)}")
            
            # Maintain original hyperlinks section for compatibility
            if hyperlinks:
                metadata.append("# Hyperlinks")
                metadata.append("\n".join(hyperlinks))
            
            # Process XML files for content
            for xml_file in xml_files:
                try:
                    content = z.read(xml_file).decode('utf-8', errors='ignore')
                    root = ET.fromstring(content)
                    
                    # Extract text content
                    for elem in root.iter():
                        if elem.text and elem.text.strip():
                            extracted_text.append(elem.text.strip())
                    
                    # Extract URLs using the utility function
                    logger.debug(f"About to call extract_urls_from_xml_file for {xml_file}")
                    xml_urls = OfficeUrlExtractor.extract_urls_from_xml_file(z, xml_file)
                    logger.debug(f"extract_urls_from_xml_file returned {len(xml_urls)} URLs")
                    urls.update(xml_urls)
                    
                    # Extract formulas
                    for formula in root.findall('.//*[@f]'):
                        formula_text = formula.get('f')
                        if formula_text:  # Only add if formula exists
                            formulas.append(formula_text)
                    
                    # Extract comments
                    namespaces = {'mc': 'http://schemas.openxmlformats.org/spreadsheetml/2006/main'}
                    found_comments = (root.findall('.//comment') + 
                                      root.findall('.//mc:comment', namespaces))
                    for comment in found_comments:
                        if comment.text and comment.text.strip():
                            comments.append(comment.text.strip())
                            
                except ET.ParseError as e:
                    logger.warning(f"Could not parse XML in {xml_file}: {str(e)}")
                except Exception as e:
                    logger.warning(f"Error processing XML in {xml_file}: {str(e)}")
            
            # Process HTML files in the Excel file
            if html_files:
                logger.info(f"Found {len(html_files)} HTML files in XLSX")
                for html_file in html_files:
                    logger.debug(f"About to call extract_urls_from_office_html for {html_file}")
                    html_urls = OfficeUrlExtractor.extract_urls_from_office_html(z, html_file)
                    logger.debug(f"extract_urls_from_office_html returned {len(html_urls)} URLs")
                    urls.update(html_urls)
            
            # Process drawing files (often contain linked images)
            for drawing_file in drawing_files:
                logger.debug(f"About to call extract_urls_from_drawing_files for {drawing_file}")
                drawing_urls = OfficeUrlExtractor.extract_urls_from_drawing_files(z, drawing_file)
                logger.debug(f"extract_urls_from_drawing_files returned {len(drawing_urls)} URLs")
                urls.update(drawing_urls)

            # Add formulas and comments to metadata
            if formulas:
                metadata.append("# Formulas")
                metadata.append("\n".join(formulas))
            
            if comments:
                metadata.append("# Comments")
                metadata.append("\n".join(comments))
            
            # Filter Microsoft URLs using the utility function
            logger.debug(f"About to call filter_microsoft_urls with {len(urls)} URLs")
            filtered_urls = OfficeUrlExtractor.filter_microsoft_urls(urls)
            logger.debug(f"filter_microsoft_urls returned {len(filtered_urls)} URLs")
            
            if filtered_urls:
                metadata.append("# Additional URLs")
                metadata.append("\n".join(filtered_urls))

            # Check for embedded files
            embedded_files = []
            for filename in z.namelist():
                if 'embeddings' in filename.lower():
                    try:
                        embedded_files.append(f"{filename} ({z.getinfo(filename).file_size} bytes)")
                    except Exception as e:
                        logger.warning(f"Error processing embedded file {filename}: {str(e)}")
            
            if embedded_files:
                metadata.append("# Embedded Files")
                metadata.append("\n".join(embedded_files))

        # Clean and join the extracted text
        if extracted_text:  # Only process if we have text
            full_text = ' '.join(extracted_text)
            cleaned_text = re.sub(r'[^\x20-\x7E\n\r]+', '', full_text)
            cleaned_text = re.sub(r'\s+', ' ', cleaned_text).strip()
            
            # Combine main text and metadata
            result = cleaned_text
            if metadata:
                result += "\n\n" + "\n\n".join(metadata)
            
            return result
        elif metadata:
            # Return just metadata if no text content
            return "\n\n".join(metadata)
        else:
            return "[No text content found in Excel file]"

    except zipfile.BadZipFile:
        logger.warning("Not a valid XLSX file (bad zip format), passing to other extractors")
        raise
    except Exception as e:
        logger.error(f"Failed to extract text from Excel (deep extraction): {str(e)}")
        logger.debug(traceback.format_exc())
        raise