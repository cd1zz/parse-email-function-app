import warnings

warnings.warn(
    "The utils.office_extraction_utils module is deprecated. Please use utils.url_processing.office_extractor instead.",
    DeprecationWarning,
    stacklevel=2
)

# Import from the new modules to maintain backward compatibility
from utils.url_processing.office_extractor import OfficeUrlExtractor

# Re-export the functions to maintain backward compatibility
extract_urls_from_office_html = OfficeUrlExtractor.extract_urls_from_office_html
extract_urls_from_relationship_file = OfficeUrlExtractor.extract_urls_from_relationship_file
extract_urls_from_xml_file = OfficeUrlExtractor.extract_urls_from_xml_file
extract_urls_from_drawing_files = OfficeUrlExtractor.extract_urls_from_drawing_files
filter_microsoft_urls = OfficeUrlExtractor.filter_microsoft_urls