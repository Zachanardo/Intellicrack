"""Protocol parsers for various licensing and protection systems.

This package contains parsers for different licensing and protection protocols,
enabling analysis and understanding of communication patterns.
"""

import logging

logger = logging.getLogger(__name__)

# Import protocol parsers
_parsers = {}
_parser_modules = [
    ('adobe_parser', 'Adobe licensing protocol parser'),
    ('autodesk_parser', 'Autodesk licensing protocol parser'),
    ('codemeter_parser', 'CodeMeter protocol parser'),
    ('flexlm_parser', 'FlexLM licensing protocol parser'),
    ('hasp_parser', 'HASP/Sentinel protocol parser'),
]

# Load parsers with error tolerance
for module_name, description in _parser_modules:
    try:
        module = __import__(f'{__name__}.{module_name}', fromlist=[module_name])
        _parsers[module_name] = module
        logger.debug("Loaded protocol parser: %s (%s)", module_name, description)
    except ImportError as e:
        logger.debug("Protocol parser not available: %s (%s) - %s", module_name, description, e)
    except Exception as e:
        logger.warning("Error loading protocol parser %s: %s", module_name, e)

def get_available_parsers():
    """Get list of successfully loaded protocol parsers."""
    return list(_parsers.keys())

def get_parser(parser_name):
    """Get a specific protocol parser if available.

    Args:
        parser_name (str): Name of the parser module

    Returns:
        module: The parser module, or None if not available

    """
    return _parsers.get(parser_name)

def is_parser_available(parser_name):
    """Check if a specific protocol parser is available.

    Args:
        parser_name (str): Name of the parser to check

    Returns:
        bool: True if parser is available, False otherwise

    """
    return parser_name in _parsers

def get_supported_protocols():
    """Get list of protocols supported by available parsers."""
    protocols = []
    parser_protocol_map = {
        'adobe_parser': 'adobe',
        'autodesk_parser': 'autodesk',
        'codemeter_parser': 'codemeter',
        'flexlm_parser': 'flexlm',
        'hasp_parser': 'hasp',
    }

    for parser_name, protocol in parser_protocol_map.items():
        if is_parser_available(parser_name):
            protocols.append(protocol)

    return protocols

__all__ = [
    'get_available_parsers',
    'get_parser',
    'is_parser_available',
    'get_supported_protocols',
] + list(_parsers.keys())
