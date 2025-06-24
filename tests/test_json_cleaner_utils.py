import sys
import types

# Provide minimal azure.functions stub for import
azure_module = types.ModuleType('azure.functions')
class _HR:  # minimal HttpRequest/HttpResponse
    pass
azure_module.HttpRequest = _HR
azure_module.HttpResponse = _HR
sys.modules.setdefault('azure', types.ModuleType('azure'))
sys.modules.setdefault('azure.functions', azure_module)

from functions.json_cleaner.cleaner import (
    remove_markdown_notation,
    sanitize_problematic_characters,
    replace_nulls_with_none,
)


def test_remove_markdown_notation():
    inp = "```json\n{\"a\":1}\n```"
    assert remove_markdown_notation(inp) == '{"a":1}'


def test_sanitize_problematic_characters():
    inp = 'ab`cd\ff'
    assert sanitize_problematic_characters(inp) == "ab'cd\\ff"


def test_replace_nulls_with_none():
    data = {"a": None, "b": [1, None]}
    assert replace_nulls_with_none(data) == {"a": "None", "b": [1, "None"]}

