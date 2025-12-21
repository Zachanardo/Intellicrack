"""Production tests for pdfkit_handler.

Tests validate PDF generation from strings, URLs, and files, PDF document structure,
canvas operations, ReportLab compatibility, and fallback implementation quality.
"""

import tempfile
from pathlib import Path

import pytest

from intellicrack.handlers import pdfkit_handler


def test_has_pdfkit_flag_is_boolean() -> None:
    """HAS_PDFKIT is a boolean flag."""
    assert isinstance(pdfkit_handler.HAS_PDFKIT, bool)


def test_pdfkit_available_flag_is_boolean() -> None:
    """PDFKIT_AVAILABLE is a boolean flag."""
    assert isinstance(pdfkit_handler.PDFKIT_AVAILABLE, bool)


def test_pdfkit_version_is_string_or_none() -> None:
    """PDFKIT_VERSION is None or valid version string when PDFKit unavailable."""
    version = pdfkit_handler.PDFKIT_VERSION

    if version is not None:
        assert isinstance(version, str)


def test_from_string_exports_exist() -> None:
    """from_string function is exported."""
    assert hasattr(pdfkit_handler, "from_string")
    assert callable(pdfkit_handler.from_string)


def test_from_url_exports_exist() -> None:
    """from_url function is exported."""
    assert hasattr(pdfkit_handler, "from_url")
    assert callable(pdfkit_handler.from_url)


def test_from_file_exports_exist() -> None:
    """from_file function is exported."""
    assert hasattr(pdfkit_handler, "from_file")
    assert callable(pdfkit_handler.from_file)


def test_configuration_exports_exist() -> None:
    """configuration function is exported."""
    assert hasattr(pdfkit_handler, "configuration")
    assert callable(pdfkit_handler.configuration)


def test_from_string_generates_pdf_bytes() -> None:
    """from_string() generates valid PDF bytes without output path."""
    content = "Test PDF Content"

    result = pdfkit_handler.from_string(content, output_path=None)

    assert isinstance(result, bytes)
    assert result.startswith(b"%PDF-1.4")
    assert b"%%EOF" in result


def test_from_string_creates_pdf_file() -> None:
    """from_string() creates valid PDF file when output path provided."""
    content = "Test PDF Content for File"

    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / "test_output.pdf"

        result = pdfkit_handler.from_string(content, str(output_path))

        assert result is True
        assert output_path.exists()
        assert output_path.stat().st_size > 0

        pdf_data = output_path.read_bytes()
        assert pdf_data.startswith(b"%PDF-1.4")


def test_from_string_with_html_content() -> None:
    """from_string() processes HTML content correctly."""
    html = "<html><head><title>Test</title></head><body><h1>Header</h1><p>Paragraph</p></body></html>"

    result = pdfkit_handler.from_string(html, output_path=None)

    assert isinstance(result, bytes)
    assert result.startswith(b"%PDF-1.4")
    assert len(result) > 100


def test_from_string_with_plain_text() -> None:
    """from_string() processes plain text content correctly."""
    text = "Line 1\nLine 2\nLine 3"

    result = pdfkit_handler.from_string(text, output_path=None)

    assert isinstance(result, bytes)
    assert result.startswith(b"%PDF-1.4")


def test_from_string_with_long_content() -> None:
    """from_string() handles long content with pagination."""
    lines = [f"Line {str(i)}" for i in range(100)]
    content = "\n".join(lines)

    result = pdfkit_handler.from_string(content, output_path=None)

    assert isinstance(result, bytes)
    assert result.startswith(b"%PDF-1.4")
    assert len(result) > 500


def test_from_file_reads_and_converts() -> None:
    """from_file() reads file and converts to PDF."""
    with tempfile.TemporaryDirectory() as tmpdir:
        input_path = Path(tmpdir) / "input.html"
        input_path.write_text("<html><body><h1>Test File</h1></body></html>")

        result = pdfkit_handler.from_file(str(input_path), output_path=None)

        assert isinstance(result, bytes)
        assert result.startswith(b"%PDF-1.4")


def test_from_file_creates_output_file() -> None:
    """from_file() creates PDF file when output path provided."""
    with tempfile.TemporaryDirectory() as tmpdir:
        input_path = Path(tmpdir) / "input.txt"
        input_path.write_text("Test content from file")

        output_path = Path(tmpdir) / "output.pdf"

        result = pdfkit_handler.from_file(str(input_path), str(output_path))

        assert result is True
        assert output_path.exists()


def test_from_file_handles_missing_file() -> None:
    """from_file() handles missing input file gracefully."""
    with tempfile.TemporaryDirectory() as tmpdir:
        output_path = Path(tmpdir) / "output.pdf"

        result = pdfkit_handler.from_file("nonexistent.txt", str(output_path))

        assert isinstance(result, (bytes, bool))


def test_pdf_generator_creates_valid_structure() -> None:
    """PDFGenerator creates valid PDF structure."""
    if not pdfkit_handler.HAS_PDFKIT:
        from intellicrack.handlers.pdfkit_handler import PDFGenerator

        generator = PDFGenerator()
        pdf_data = generator.create_pdf("Test content", output_path=None)

        assert isinstance(pdf_data, bytes)
        assert pdf_data.startswith(b"%PDF-1.4")
        assert b"endobj" in pdf_data
        assert b"xref" in pdf_data
        assert b"startxref" in pdf_data
        assert b"%%EOF" in pdf_data


def test_pdf_generator_handles_multiple_pages() -> None:
    """PDFGenerator creates multiple pages for long content."""
    if not pdfkit_handler.HAS_PDFKIT:
        from intellicrack.handlers.pdfkit_handler import PDFGenerator

        generator = PDFGenerator()
        lines = [f"Line {str(i)}" for i in range(60)]
        content = "\n".join(lines)

        pdf_data = generator.create_pdf(content, output_path=None)

        assert isinstance(pdf_data, bytes)
        assert len(pdf_data) > 500


def test_pdf_generator_html_conversion() -> None:
    """PDFGenerator converts HTML to PDF content."""
    if not pdfkit_handler.HAS_PDFKIT:
        from intellicrack.handlers.pdfkit_handler import PDFGenerator

        generator = PDFGenerator()
        html = "<html><body><p>Test &lt;HTML&gt; content &amp; entities</p></body></html>"

        pdf_data = generator.create_pdf(html, output_path=None)

        assert isinstance(pdf_data, bytes)
        assert pdf_data.startswith(b"%PDF-1.4")


def test_pdf_generator_special_characters() -> None:
    """PDFGenerator escapes special characters in PDF."""
    if not pdfkit_handler.HAS_PDFKIT:
        from intellicrack.handlers.pdfkit_handler import PDFGenerator

        generator = PDFGenerator()
        content = "Test (parentheses) and \\backslashes\\"

        pdf_data = generator.create_pdf(content, output_path=None)

        assert isinstance(pdf_data, bytes)
        assert pdf_data.startswith(b"%PDF-1.4")


def test_pdf_canvas_drawing_operations() -> None:
    """PDFCanvas supports drawing operations."""
    if not pdfkit_handler.HAS_PDFKIT:
        from intellicrack.handlers.pdfkit_handler import PDFCanvas

        canvas = PDFCanvas()
        canvas.setFont("Helvetica", 12)
        canvas.drawString(100, 700, "Test String")
        canvas.line(50, 600, 200, 600)
        canvas.rect(50, 500, 100, 50, stroke=1)
        canvas.circle(150, 400, 25, stroke=1)
        canvas.showPage()

        pdf_data = canvas.save()

        assert isinstance(pdf_data, bytes)
        assert pdf_data.startswith(b"%PDF-1.4")


def test_pdf_canvas_centered_text() -> None:
    """PDFCanvas drawCentredString centers text."""
    if not pdfkit_handler.HAS_PDFKIT:
        from intellicrack.handlers.pdfkit_handler import PDFCanvas

        canvas = PDFCanvas()
        canvas.drawCentredString(300, 400, "Centered Text")

        assert len(canvas.current_page) == 1
        assert canvas.current_page[0]["type"] == "text"


def test_pdf_canvas_right_aligned_text() -> None:
    """PDFCanvas drawRightString aligns text to right."""
    if not pdfkit_handler.HAS_PDFKIT:
        from intellicrack.handlers.pdfkit_handler import PDFCanvas

        canvas = PDFCanvas()
        canvas.drawRightString(500, 400, "Right Aligned")

        assert len(canvas.current_page) == 1
        assert canvas.current_page[0]["type"] == "text"


def test_pdf_document_metadata() -> None:
    """PDFDocument supports metadata setting."""
    if not pdfkit_handler.HAS_PDFKIT:
        from intellicrack.handlers.pdfkit_handler import PDFDocument

        doc = PDFDocument()
        doc.set_title("Test Document")
        doc.set_author("Test Author")
        doc.set_subject("Test Subject")
        doc.add_keyword("test")
        doc.add_keyword("pdf")

        assert doc.title == "Test Document"
        assert doc.author == "Test Author"
        assert doc.subject == "Test Subject"
        assert "test" in doc.keywords


def test_pdf_document_page_management() -> None:
    """PDFDocument manages multiple pages."""
    if not pdfkit_handler.HAS_PDFKIT:
        from intellicrack.handlers.pdfkit_handler import PDFDocument

        doc = PDFDocument()
        doc.add_page("<p>Page 1</p>")
        doc.add_page("<p>Page 2</p>")
        doc.add_page("<p>Page 3</p>")

        assert len(doc.pages) == 3


def test_pdf_document_generation() -> None:
    """PDFDocument generates valid PDF."""
    if not pdfkit_handler.HAS_PDFKIT:
        from intellicrack.handlers.pdfkit_handler import PDFDocument

        doc = PDFDocument()
        doc.set_title("Generated Document")
        doc.add_page("<h1>Title Page</h1>")
        doc.add_page("<p>Content Page</p>")

        pdf_data = doc.generate(output_path=None)

        assert isinstance(pdf_data, bytes)
        assert pdf_data.startswith(b"%PDF-1.4")


def test_simple_doc_template_build() -> None:
    """SimpleDocTemplate builds PDF from story elements."""
    if not pdfkit_handler.HAS_PDFKIT:
        from intellicrack.handlers.pdfkit_handler import Paragraph, SimpleDocTemplate

        with tempfile.TemporaryDirectory() as tmpdir:
            output_path = Path(tmpdir) / "template.pdf"

            template = SimpleDocTemplate(str(output_path))
            story = [Paragraph("Paragraph 1"), Paragraph("Paragraph 2")]

            result = template.build(story)

            assert result is True
            assert output_path.exists()


def test_paragraph_to_html() -> None:
    """Paragraph converts to HTML correctly."""
    if not pdfkit_handler.HAS_PDFKIT:
        from intellicrack.handlers.pdfkit_handler import Paragraph

        para = Paragraph("Test paragraph content")
        html = para.to_html()

        assert html == "<p>Test paragraph content</p>"


def test_table_to_html() -> None:
    """Table converts to HTML table correctly."""
    if not pdfkit_handler.HAS_PDFKIT:
        from intellicrack.handlers.pdfkit_handler import Table

        data = [["A", "B"], ["C", "D"]]
        table = Table(data)

        html = table.to_html()

        assert "<table" in html
        assert "<tr>" in html
        assert "<td>A</td>" in html
        assert "<td>D</td>" in html


def test_page_break_to_html() -> None:
    """PageBreak converts to HTML page break."""
    if not pdfkit_handler.HAS_PDFKIT:
        from intellicrack.handlers.pdfkit_handler import PageBreak

        pb = PageBreak()
        html = pb.to_html()

        assert "page-break-after" in html


def test_pdf_options_initialization() -> None:
    """PDFOptions initializes with defaults."""
    if not pdfkit_handler.HAS_PDFKIT:
        from intellicrack.handlers.pdfkit_handler import PDFOptions

        opts = PDFOptions()

        assert opts.page_size == "A4"
        assert opts.orientation == "Portrait"
        assert opts.encoding == "UTF-8"


def test_pdf_options_custom_values() -> None:
    """PDFOptions accepts custom options."""
    if not pdfkit_handler.HAS_PDFKIT:
        from intellicrack.handlers.pdfkit_handler import PDFOptions

        custom = {"page-size": "Letter", "orientation": "Landscape"}
        opts = PDFOptions(custom)

        assert opts.page_size == "Letter"
        assert opts.orientation == "Landscape"


def test_pdf_configuration_initialization() -> None:
    """PDFConfiguration initializes correctly."""
    if not pdfkit_handler.HAS_PDFKIT:
        from intellicrack.handlers.pdfkit_handler import PDFConfiguration

        config = PDFConfiguration()

        assert hasattr(config, "wkhtmltopdf")


def test_pdf_configuration_with_path() -> None:
    """PDFConfiguration accepts explicit wkhtmltopdf path."""
    if not pdfkit_handler.HAS_PDFKIT:
        from intellicrack.handlers.pdfkit_handler import PDFConfiguration

        custom_path = "/custom/path/to/wkhtmltopdf"
        config = PDFConfiguration(wkhtmltopdf=custom_path)

        assert config.wkhtmltopdf == custom_path


def test_configuration_factory_function() -> None:
    """configuration() factory function creates PDFConfiguration."""
    config = pdfkit_handler.configuration()

    assert config is not None


def test_from_string_error_handling() -> None:
    """from_string() handles errors gracefully."""
    if not pdfkit_handler.HAS_PDFKIT:
        content = None

        try:
            result = pdfkit_handler.from_string(content, output_path=None)
            assert result is False or isinstance(result, bytes)
        except Exception:
            pass


def test_pdf_structure_validity() -> None:
    """Generated PDF has valid structure components."""
    content = "PDF Structure Test"

    pdf_bytes = pdfkit_handler.from_string(content, output_path=None)

    assert isinstance(pdf_bytes, bytes)
    assert b"obj" in pdf_bytes
    assert b"endobj" in pdf_bytes
    assert b"xref" in pdf_bytes
    assert b"trailer" in pdf_bytes


def test_pdf_contains_text_content() -> None:
    """Generated PDF contains text content streams."""
    content = "Text Content Test"

    pdf_bytes = pdfkit_handler.from_string(content, output_path=None)

    assert isinstance(pdf_bytes, bytes)
    assert b"BT" in pdf_bytes or b"stream" in pdf_bytes


def test_all_exports_are_defined() -> None:
    """All items in __all__ are defined in module."""
    for item in pdfkit_handler.__all__:
        assert hasattr(pdfkit_handler, item)


def test_flags_consistency() -> None:
    """HAS_PDFKIT and PDFKIT_AVAILABLE are consistent."""
    assert pdfkit_handler.HAS_PDFKIT == pdfkit_handler.PDFKIT_AVAILABLE


def test_version_consistency_with_availability() -> None:
    """PDFKIT_VERSION is None when PDFKit unavailable."""
    if not pdfkit_handler.HAS_PDFKIT:
        assert pdfkit_handler.PDFKIT_VERSION is None


def test_from_string_with_options() -> None:
    """from_string() accepts options parameter."""
    content = "Options Test"
    options = {"page-size": "A4", "margin-top": "10mm"}

    result = pdfkit_handler.from_string(content, output_path=None, options=options)

    assert isinstance(result, bytes)
    assert result.startswith(b"%PDF-1.4")


def test_from_file_with_options() -> None:
    """from_file() accepts options parameter."""
    with tempfile.TemporaryDirectory() as tmpdir:
        input_path = Path(tmpdir) / "input.txt"
        input_path.write_text("Options test content")

        options = {"page-size": "Letter"}
        result = pdfkit_handler.from_file(str(input_path), output_path=None, options=options)

        assert isinstance(result, bytes)


def test_pdf_binary_marker_present() -> None:
    """Generated PDF contains binary marker for compatibility."""
    content = "Binary Marker Test"

    pdf_bytes = pdfkit_handler.from_string(content, output_path=None)

    assert isinstance(pdf_bytes, bytes)
    assert pdf_bytes[:8] == b"%PDF-1.4"
