"""
Common report generation utilities to avoid code duplication.
"""


def generate_analysis_report(app, report_type, results_data, generator_func=None):
    """
    Common function to generate analysis reports.
    
    Args:
        app: Application instance for UI dialogs
        report_type: Type of report (e.g., "ROP chain generation", "taint analysis")
        results_data: Data to include in the report
        generator_func: Optional function to generate the report content
        
    Returns:
        str or None: Path to generated report file, or None if cancelled
    """
    try:
        from ...utils.ui_common import ask_yes_no_question, show_file_dialog
    except ImportError:
        # Fallback if UI common not available
        return None

    generate_report = ask_yes_no_question(
        app,
        "Generate Report",
        f"Do you want to generate a report of the {report_type} results?"
    )

    if not generate_report:
        return None

    filename = show_file_dialog(app, "Save Report")

    if not filename:
        return None

    if not filename.endswith('.html'):
        filename += '.html'

    # Generate report using provided function or default
    if generator_func:
        report_path = generator_func(filename, results_data)
    else:
        report_path = _generate_default_report(filename, report_type, results_data)

    return report_path


def _generate_default_report(filename, report_type, results_data):
    """
    Generate a default HTML report.
    
    Args:
        filename: Output filename
        report_type: Type of analysis
        results_data: Results to include
        
    Returns:
        str: Path to generated report
    """
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>{report_type.title()} Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            h1 {{ color: #333; }}
            .results {{ background: #f5f5f5; padding: 15px; border-radius: 5px; }}
            pre {{ background: #eee; padding: 10px; overflow-x: auto; }}
        </style>
    </head>
    <body>
        <h1>{report_type.title()} Report</h1>
        <div class="results">
            <h2>Results</h2>
            <pre>{str(results_data)}</pre>
        </div>
    </body>
    </html>
    """

    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(html_content)
        return filename
    except (OSError, ValueError, RuntimeError) as e:
        print(f"Error generating report: {e}")
        return None


def ensure_html_extension(filename):
    """
    Ensure filename has .html extension.
    
    Args:
        filename: Input filename
        
    Returns:
        str: Filename with .html extension
    """
    if not filename.endswith('.html'):
        return filename + '.html'
    return filename
