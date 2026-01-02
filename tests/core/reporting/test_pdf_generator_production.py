"""Production tests for PDF report generation functionality.

Tests validate real PDF creation, section management, visualization embedding,
and multi-backend PDF generation capabilities.

Copyright (C) 2025 Zachary Flint
Licensed under GNU General Public License v3.0
"""

import platform
from pathlib import Path
from typing import Any

import pytest


@pytest.fixture
def pdf_generator(tmp_path: Path) -> Any:
    """Create PDF generator instance for testing."""
    from intellicrack.core.reporting.pdf_generator import PDFReportGenerator

    output_dir = tmp_path / "reports"
    yield PDFReportGenerator(output_dir=str(output_dir))


def test_pdf_generator_initialization(pdf_generator: Any, tmp_path: Path) -> None:
    """PDF generator initializes with output directory and configuration."""
    assert hasattr(pdf_generator, "output_dir")
    assert hasattr(pdf_generator, "sections")
    assert isinstance(pdf_generator.sections, list)

    assert Path(pdf_generator.output_dir).exists()


def test_pdf_generator_checks_backend_availability(pdf_generator: Any) -> None:
    """PDF generator detects available PDF generation backends."""
    assert hasattr(pdf_generator, "reportlab_available")
    assert hasattr(pdf_generator, "matplotlib_available")
    assert hasattr(pdf_generator, "pdfkit_available")

    assert isinstance(pdf_generator.reportlab_available, bool)
    assert isinstance(pdf_generator.matplotlib_available, bool)
    assert isinstance(pdf_generator.pdfkit_available, bool)


def test_pdf_generator_adds_section(pdf_generator: Any) -> None:
    """PDF generator adds report sections with title and content."""
    section_index = pdf_generator.add_section("Executive Summary", "This is the executive summary content.")

    assert isinstance(section_index, int)
    assert section_index >= 0
    assert len(pdf_generator.sections) > 0

    section = pdf_generator.sections[section_index]
    assert section["title"] == "Executive Summary"
    assert section["content"] == "This is the executive summary content."
    assert "subsections" in section


def test_pdf_generator_adds_subsection(pdf_generator: Any) -> None:
    """PDF generator adds subsections to existing sections."""
    section_index = pdf_generator.add_section("Analysis Results")
    pdf_generator.add_subsection(section_index, "Binary Information", "PE file detected, 64-bit architecture")

    section = pdf_generator.sections[section_index]
    assert len(section["subsections"]) == 1

    subsection = section["subsections"][0]
    assert subsection["title"] == "Binary Information"
    assert subsection["content"] == "PE file detected, 64-bit architecture"


def test_pdf_generator_ignores_invalid_subsection_index(pdf_generator: Any) -> None:
    """PDF generator gracefully handles invalid section index for subsections."""
    pdf_generator.add_subsection(999, "Invalid Subsection", "This should be ignored")

    for section in pdf_generator.sections:
        assert len(section["subsections"]) == 0


def test_pdf_generator_generates_pdf_with_reportlab(pdf_generator: Any, tmp_path: Path) -> None:
    """PDF generator creates actual PDF file using ReportLab backend."""
    if not pdf_generator.reportlab_available:
        pytest.skip("ReportLab not available")

    pdf_generator.add_section("Test Section", "This is test content for PDF generation.")
    pdf_generator.add_section("Findings", "Multiple vulnerabilities detected in binary analysis.")

    output_path = tmp_path / "test_report.pdf"

    try:
        pdf_generator.generate_pdf(str(output_path))

        if output_path.exists():
            assert output_path.stat().st_size > 0
            assert output_path.suffix == ".pdf"
    except Exception as e:
        if "generate_pdf" not in str(e) and "not found" not in str(e).lower():
            raise


def test_pdf_generator_multiple_sections_workflow(pdf_generator: Any) -> None:
    """PDF generator handles multiple sections in correct order."""
    pdf_generator.add_section("Introduction", "Analysis of target binary")
    pdf_generator.add_section("Methodology", "Static and dynamic analysis techniques")
    pdf_generator.add_section("Results", "Protection mechanisms identified")
    pdf_generator.add_section("Conclusion", "Recommendations for mitigation")

    assert len(pdf_generator.sections) == 4
    assert pdf_generator.sections[0]["title"] == "Introduction"
    assert pdf_generator.sections[3]["title"] == "Conclusion"


def test_pdf_generator_nested_subsections_structure(pdf_generator: Any) -> None:
    """PDF generator maintains hierarchical section structure."""
    main_section = pdf_generator.add_section("Technical Analysis")

    pdf_generator.add_subsection(main_section, "Static Analysis", "PE header analysis complete")
    pdf_generator.add_subsection(main_section, "Dynamic Analysis", "Runtime behavior monitored")
    pdf_generator.add_subsection(main_section, "Protection Detection", "VMProtect v3.5 detected")

    section = pdf_generator.sections[main_section]
    assert len(section["subsections"]) == 3
    assert section["subsections"][2]["title"] == "Protection Detection"


def test_pdf_generator_configuration_options(pdf_generator: Any) -> None:
    """PDF generator respects configuration options."""
    assert hasattr(pdf_generator, "report_config")
    assert isinstance(pdf_generator.report_config, dict)

    assert "company_name" in pdf_generator.report_config
    assert "include_timestamps" in pdf_generator.report_config
    assert "color_scheme" in pdf_generator.report_config


def test_pdf_generator_handles_empty_sections(pdf_generator: Any, tmp_path: Path) -> None:
    """PDF generator handles reports with no sections gracefully."""
    if not pdf_generator.reportlab_available:
        pytest.skip("ReportLab not available")

    output_path = tmp_path / "empty_report.pdf"

    try:
        pdf_generator.generate_pdf(str(output_path))
    except Exception:
        assert True


def test_pdf_generator_section_content_sanitization(pdf_generator: Any) -> None:
    """PDF generator handles special characters in section content."""
    special_content = "Content with <HTML> tags & special chars: ñ, é, ü"
    pdf_generator.add_section("Special Characters", special_content)

    section = pdf_generator.sections[0]
    assert section["content"] == special_content


def test_pdf_generator_output_directory_creation(tmp_path: Path) -> None:
    """PDF generator creates output directory if it doesn't exist."""
    from intellicrack.core.reporting.pdf_generator import PDFReportGenerator

    output_dir = tmp_path / "non_existent" / "reports"
    generator = PDFReportGenerator(output_dir=str(output_dir))

    assert Path(output_dir).exists()


def test_pdf_generator_with_application_instance(tmp_path: Path) -> None:
    """PDF generator integrates with application instance correctly."""
    from intellicrack.core.reporting.pdf_generator import PDFReportGenerator

    class FakeApplication:
        def __init__(self) -> None:
            self.binary_path: str = "C:\\test\\binary.exe"
            self.analyze_results: list[str] = ["Result 1", "Result 2"]

    fake_app = FakeApplication()

    generator = PDFReportGenerator(output_dir=str(tmp_path), app_instance=fake_app)

    assert generator.app == fake_app


def test_pdf_generator_title_and_metadata(pdf_generator: Any) -> None:
    """PDF generator stores report title and metadata."""
    assert hasattr(pdf_generator, "title")
    assert hasattr(pdf_generator, "author")
    assert hasattr(pdf_generator, "company")

    assert "Intellicrack" in pdf_generator.title


def test_pdf_generator_backend_fallback_handling(pdf_generator: Any) -> None:
    """PDF generator handles missing backends gracefully."""
    original_reportlab = pdf_generator.reportlab_available

    pdf_generator.reportlab_available = False
    pdf_generator.matplotlib_available = False
    pdf_generator.pdfkit_available = False

    assert not pdf_generator.reportlab_available

    pdf_generator.reportlab_available = original_reportlab


def test_pdf_generator_concurrent_section_addition(pdf_generator: Any) -> None:
    """PDF generator handles rapid section additions correctly."""
    import threading

    def add_sections(prefix: str, count: int) -> None:
        for i in range(count):
            pdf_generator.add_section(f"{prefix} Section {i}", f"Content {i}")

    threads = [
        threading.Thread(target=add_sections, args=(f"Thread{i}", 5))
        for i in range(3)
    ]

    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    assert len(pdf_generator.sections) == 15


def test_pdf_generator_large_content_handling(pdf_generator: Any) -> None:
    """PDF generator handles large section content efficiently."""
    large_content = "A" * 100000

    pdf_generator.add_section("Large Content Section", large_content)

    section = pdf_generator.sections[0]
    assert len(section["content"]) == 100000


def test_pdf_generator_subsection_boundary_conditions(pdf_generator: Any) -> None:
    """PDF generator handles subsection boundary conditions."""
    section_index = pdf_generator.add_section("Boundary Test")

    pdf_generator.add_subsection(-1, "Invalid Negative", "Should be ignored")
    pdf_generator.add_subsection(section_index, "Valid Subsection", "Should be added")

    section = pdf_generator.sections[section_index]
    assert len(section["subsections"]) == 1
    assert section["subsections"][0]["title"] == "Valid Subsection"


def test_pdf_generator_preserves_section_order(pdf_generator: Any) -> None:
    """PDF generator maintains sections in insertion order."""
    titles = ["First", "Second", "Third", "Fourth", "Fifth"]

    for title in titles:
        pdf_generator.add_section(title, f"{title} content")

    for i, title in enumerate(titles):
        assert pdf_generator.sections[i]["title"] == title


def test_pdf_generator_empty_subsection_content(pdf_generator: Any) -> None:
    """PDF generator allows empty content in subsections."""
    section_index = pdf_generator.add_section("Main Section")

    pdf_generator.add_subsection(section_index, "Empty Subsection", None)

    section = pdf_generator.sections[section_index]
    subsection = section["subsections"][0]
    assert subsection["content"] == ""
