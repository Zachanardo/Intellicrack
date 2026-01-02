"""Provide HTML templates to eliminate code duplication.

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see https://www.gnu.org/licenses/.
"""


def get_base_html_template(
    title: str = "Intellicrack Report",
    custom_css: str = "",
    custom_js: str = "",
) -> str:
    """Generate base HTML template with common structure.

    Provides a standardized HTML framework with consistent styling for analysis
    reports, including support for custom CSS and JavaScript injection.

    Args:
        title: Page title displayed in browser tab and header. Defaults to
            "Intellicrack Report".
        custom_css: Additional CSS styles to inject into the document head.
            Defaults to empty string.
        custom_js: Additional JavaScript to inject into the document head.
            Defaults to empty string.

    Returns:
        Opening tags and structure of the document with applied styles and
        scripts.

    """
    return f"""<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <title>{title}</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 20px; }}
        h1, h2, h3 {{ color: #2c3e50; }}
        h2 {{ border-bottom: 1px solid #3498db; padding-bottom: 5px; }}
        table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
        tr:nth-child(even) {{ background-color: #f9f9f9; }}
        .vulnerability {{ color: #e74c3c; }}
        .protection {{ color: #27ae60; }}
        .license {{ color: #f39c12; }}
        .code {{ font-family: monospace; background-color: #f8f8f8; padding: 10px; border: 1px solid #ddd; }}
        .summary {{ background-color: #eee; padding: 10px; border-radius: 5px; }}
        {custom_css}
    </style>
    {custom_js}
</head>
<body>"""


def get_cfg_html_template(function_name: str) -> str:
    """Generate HTML template for control flow graph visualization.

    Creates an HTML document configured for rendering D3.js-based control flow
    graph visualizations with licensing-specific node styling and tooltips.

    Args:
        function_name: Name of the function being analyzed. Used in the page
            title and report header.

    Returns:
        HTML document with D3.js library loaded and CFG visualization styles
        applied.

    """
    custom_css = """
        body { margin: 0; overflow: hidden; }
        .node { stroke: #fff; stroke-width: 1.5px; }
        .node.license { fill: #ff7777; }
        .node.normal { fill: #77aaff; }
        .link { stroke: #999; stroke-opacity: 0.6; stroke-width: 1px; }
        .label { font-size: 10px; pointer-events: none; }
        #tooltip {
            position: absolute;
            background: rgba(0, 0, 0, 0.7);
            color: white;
            padding: 5px;
            border-radius: 4px;
            font-size: 12px;
            pointer-events: none;
        }
    """
    custom_js = '<script src="https://d3js.org/d3.v7.min.js"></script>'
    return get_base_html_template(f"CFG: {function_name}", custom_css, custom_js)


def get_traffic_html_template() -> str:
    """Generate HTML template for license traffic analysis visualization.

    Creates an HTML document configured for displaying network traffic analysis
    and license communication protocol visualization with centered image display.

    Returns:
        HTML document with traffic analysis styling applied.

    """
    custom_css = """
        .visualization { text-align: center; margin: 20px 0; }
        .visualization img { max-width: 100%; border: 1px solid #ddd; }
    """
    return get_base_html_template("License Traffic Analysis Report", custom_css)


def get_report_html_template(binary_name: str) -> str:
    """Generate HTML template for comprehensive analysis report.

    Creates an HTML document configured for displaying detailed binary analysis
    findings with report-specific color scheme and typography styling.

    Args:
        binary_name: Name or path of the binary being analyzed. Used in the
            page title and report header.

    Returns:
        HTML document with analysis report styling applied.

    """
    custom_css = """
        h1 { color: #2c3e50; }
        h2 { color: #3498db; }
        h3 { color: #2980b9; }
        th { background-color: #3498db; color: white; }
    """
    return get_base_html_template(f"Intellicrack Analysis Report - {binary_name}", custom_css)


def close_html() -> str:
    """Get HTML closing tags.

    Returns:
        HTML closing tags for body and html elements.

    """
    return "</body></html>"
