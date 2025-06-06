"""Common HTML templates to eliminate code duplication."""

def get_base_html_template(title="Intellicrack Report", custom_css="", custom_js=""):
    """Get base HTML template with common structure."""
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

def get_cfg_html_template(function_name):
    """Get CFG-specific HTML template."""
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

def get_traffic_html_template():
    """Get traffic analysis HTML template."""
    custom_css = """
        .visualization { text-align: center; margin: 20px 0; }
        .visualization img { max-width: 100%; border: 1px solid #ddd; }
    """
    return get_base_html_template("License Traffic Analysis Report", custom_css)

def get_report_html_template(binary_name):
    """Get analysis report HTML template."""
    custom_css = """
        h1 { color: #2c3e50; }
        h2 { color: #3498db; }
        h3 { color: #2980b9; }
        th { background-color: #3498db; color: white; }
    """
    return get_base_html_template(f"Intellicrack Analysis Report - {binary_name}", custom_css)

def close_html():
    """Get HTML closing tags."""
    return "</body></html>"