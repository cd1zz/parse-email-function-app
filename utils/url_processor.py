import warnings

warnings.warn(
    "The utils.url_processor module is deprecated. Please use utils.url_processing package instead.",
    DeprecationWarning,
    stacklevel=2
)

# Import from the new modules to maintain backward compatibility
from utils.url_processing.extractor import UrlExtractor
from utils.url_processing.decoder import UrlDecoder
from utils.url_processing.validator import UrlValidator
from utils.url_processing.processor import UrlProcessor

# Re-export the functions to maintain backward compatibility
extract_urls = UrlExtractor.extract_urls
extract_urls_from_html = UrlExtractor.extract_urls_from_html
extract_urls_by_content_type = UrlExtractor.extract_urls_by_content_type
extract_all_urls_from_email = UrlExtractor.extract_all_urls_from_email

decode_safelinks = UrlDecoder.decode_safelinks
decode_proofpoint_urls = UrlDecoder.decode_proofpoint_urls
decode_quoted_printable = UrlDecoder.decode_quoted_printable

clean_url = UrlValidator.clean_url
is_url_shortened = UrlValidator.is_url_shortened
is_image_url = UrlValidator.is_image_url

expand_url = UrlProcessor.expand_url
batch_expand_urls = UrlProcessor.batch_expand_urls
process_urls = UrlProcessor.process_urls
dedupe_to_base_urls = UrlProcessor.dedupe_to_base_urls
fix_url_expansions = UrlProcessor.fix_url_expansions

# Add the new function
extract_urls_from_attachments = UrlProcessor.extract_urls_from_attachments