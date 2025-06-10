"""
URL extractor module for Office documents (Word, Excel, PowerPoint).
"""

import logging
import re
from xml.etree import ElementTree as ET
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

class OfficeUrlExtractor:
    """
    Class for extracting URLs from Office document components like
    relationship files, HTML, XML, and drawing files.
    """
    
    # Microsoft-related domains to filter out
    MICROSOFT_DOMAINS = [
        'microsoft.com', 'live.com', 'office.com', 'purl.org',
        'microsoftonline.com', 'openxmlformats.org', 'w3.org'
    ]
    
    @staticmethod
    def extract_urls_from_office_html(zipfile_obj, html_file):
        """
        Extract URLs from HTML files within Office documents.
        
        Args:
            zipfile_obj: Open ZipFile object
            html_file: Path to HTML file within the archive
            
        Returns:
            set: Set of extracted URLs
        """
        logger.debug(f"Extracting URLs from Office HTML file: {html_file}")
        
        urls = set()
        
        try:
            html_content = zipfile_obj.read(html_file).decode('utf-8', errors='ignore')
            
            # Use BeautifulSoup to parse the HTML and extract links
            soup = BeautifulSoup(html_content, 'html.parser')

            # Extract links from anchor tags
            for a_tag in soup.find_all('a', href=True):
                href = a_tag['href'].strip()
                if href and not href.startswith(('#', 'javascript:', 'mailto:')):
                    if not (href.startswith('http') or href.startswith('mailto:')):
                        href = 'http://' + href
                    urls.add(href)
            
            # Extract image sources
            for img_tag in soup.find_all('img', src=True):
                src = img_tag['src'].strip()
                if src and not src.startswith(('data:', 'cid:')):
                    if not src.startswith('http') and not src.startswith('/'):
                        src = 'http://' + src
                    urls.add(src)
            
            # Check for image maps
            for map_tag in soup.find_all('map'):
                for area in map_tag.find_all('area', href=True):
                    href = area['href'].strip()
                    if href and not href.startswith(('#', 'javascript:', 'mailto:')):
                        if not (href.startswith('http') or href.startswith('mailto:')):
                            href = 'http://' + href
                        urls.add(href)
            
            # Extract URLs from inline styles
            for tag in soup.find_all(style=True):
                style_urls = re.findall(r'url\([\'"]?(https?://[^\'"\)]+)[\'"]?\)', tag['style'])
                urls.update(style_urls)
            
            # Extract URLs from style tags
            for style in soup.find_all('style'):
                if style.string:
                    style_urls = re.findall(r'url\([\'"]?(https?://[^\'"\)]+)[\'"]?\)', style.string)
                    urls.update(style_urls)
            
            # Also use regex to find URLs in case some are in script blocks or other places
            found_urls = re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s"\'<>]*', html_content)
            urls.update(found_urls)
            
        except Exception as e:
            logger.error(f"Error processing HTML file {html_file}: {str(e)}", exc_info=True)
        
        return urls
    
    @staticmethod
    def extract_urls_from_relationship_file(zipfile_obj, rels_file):
        """
        Extract URLs from relationship files within Office documents.
        
        Args:
            zipfile_obj: Open ZipFile object
            rels_file: Path to relationship file within the archive
            
        Returns:
            set: Set of extracted URLs
        """
        logger.debug(f"Extracting URLs from relationship file: {rels_file}")
        
        urls = set()
        
        try:
            content = zipfile_obj.read(rels_file).decode('utf-8', errors='ignore')
            
            root = ET.fromstring(content)
            
            for relationship in root.findall('.//{http://schemas.openxmlformats.org/package/2006/relationships}Relationship'):
                rel_type = relationship.get('Type', '')
                target = relationship.get('Target', '')
                
                if 'hyperlink' in rel_type.lower() and target:
                    # Exclude internal links
                    if not target.startswith('#'):
                        # Add http:// prefix if missing and not a mailto:
                        if not (target.startswith('http') or target.startswith('mailto:')):
                            target = 'http://' + target
                        urls.add(target)
            
        except ET.ParseError as e:
            logger.error(f"XML parse error in {rels_file}: {str(e)}", exc_info=True)
        except Exception as e:
            logger.error(f"Error processing relationships in {rels_file}: {str(e)}", exc_info=True)
        
        return urls
    
    @staticmethod
    def extract_urls_from_xml_file(zipfile_obj, xml_file):
        """
        Extract URLs from XML files within Office documents.
        
        Args:
            zipfile_obj: Open ZipFile object
            xml_file: Path to XML file within the archive
            
        Returns:
            set: Set of extracted URLs
        """
        logger.debug(f"Extracting URLs from XML file: {xml_file}")
        
        urls = set()
        
        try:
            content = zipfile_obj.read(xml_file).decode('utf-8', errors='ignore')
            
            # Regular expression for finding URLs
            found_urls = re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s"\'<>]*', content)
            
            for url in found_urls:
                if url and not any(domain in url.lower() for domain in OfficeUrlExtractor.MICROSOFT_DOMAINS):
                    urls.add(url)
            
        except Exception as e:
            logger.error(f"Error extracting URLs from {xml_file}: {str(e)}", exc_info=True)
        
        return urls
    
    @staticmethod
    def extract_urls_from_drawing_files(zipfile_obj, drawing_file):
        """
        Extract URLs from drawing files within Office documents.
        
        Args:
            zipfile_obj: Open ZipFile object
            drawing_file: Path to drawing file within the archive
            
        Returns:
            set: Set of extracted URLs
        """
        logger.debug(f"Extracting URLs from drawing file: {drawing_file}")
        
        urls = set()
        
        try:
            content = zipfile_obj.read(drawing_file).decode('utf-8', errors='ignore')
            
            # Look for URLs in drawing files
            found_urls = re.findall(r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+[^\s"\'<>]*', content)
            
            for url in found_urls:
                if url and not any(domain in url.lower() for domain in OfficeUrlExtractor.MICROSOFT_DOMAINS):
                    urls.add(url)
            
        except Exception as e:
            logger.error(f"Error processing drawing file {drawing_file}: {str(e)}", exc_info=True)
        
        return urls
    
    @staticmethod
    def filter_microsoft_urls(urls):
        """
        Filter out Microsoft-related URLs.
        
        Args:
            urls: Set of URLs to filter
            
        Returns:
            set: Filtered set of URLs
        """
        logger.debug(f"Filtering Microsoft-related URLs from {len(urls)} URLs")
        
        filtered_urls = {url for url in urls if not any(domain in url.lower() 
                                                       for domain in OfficeUrlExtractor.MICROSOFT_DOMAINS)}
        
        return filtered_urls