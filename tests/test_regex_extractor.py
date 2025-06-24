import sys
import types

# Provide minimal azure.functions stub for import
azure_module = types.ModuleType('azure.functions')
class _HR:
    pass
azure_module.HttpRequest = _HR
azure_module.HttpResponse = _HR
sys.modules.setdefault('azure', types.ModuleType('azure'))
sys.modules.setdefault('azure.functions', azure_module)

from functions.regex_extractor.extractor import extract_with_regex


def test_extract_with_regex_match():
    value, error = extract_with_regex('hello 123 world', r'hello (\d+) world')
    assert value == '123'
    assert error is None


def test_extract_with_regex_invalid_pattern():
    value, error = extract_with_regex('test', r'[')
    assert value is None
    assert 'Invalid regex pattern' in error

