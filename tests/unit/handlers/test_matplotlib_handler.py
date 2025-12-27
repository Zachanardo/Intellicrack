"""Production tests for Matplotlib handler fallback functionality.

Tests validate that the fallback implementation provides genuine visualization
capabilities including figure creation, plotting, SVG/PNG generation, and
PDF export when matplotlib is unavailable. These tests prove the handler
works for real binary analysis visualization scenarios.
"""

import struct
from pathlib import Path

import pytest

try:
    from intellicrack.handlers import matplotlib_handler
    MATPLOTLIB_HANDLER_AVAILABLE = True
except ImportError:
    matplotlib_handler = None
    MATPLOTLIB_HANDLER_AVAILABLE = False

pytestmark = pytest.mark.skipif(
    not MATPLOTLIB_HANDLER_AVAILABLE,
    reason="matplotlib_handler not available"
)


class TestMatplotlibHandlerAvailability:
    """Test matplotlib availability detection and module exports."""

    def test_has_matplotlib_flag_is_boolean(self) -> None:
        """Matplotlib availability flag is a valid boolean."""
        assert isinstance(matplotlib_handler.HAS_MATPLOTLIB, bool)

    def test_matplotlib_version_type(self) -> None:
        """Matplotlib version is string if available, None if not."""
        if matplotlib_handler.HAS_MATPLOTLIB:
            assert isinstance(matplotlib_handler.MATPLOTLIB_VERSION, str)
            assert len(matplotlib_handler.MATPLOTLIB_VERSION) > 0
        else:
            assert matplotlib_handler.MATPLOTLIB_VERSION is None

    def test_matplotlib_available_matches_has_matplotlib(self) -> None:
        """MATPLOTLIB_AVAILABLE matches HAS_MATPLOTLIB for consistency."""
        assert matplotlib_handler.MATPLOTLIB_AVAILABLE == matplotlib_handler.HAS_MATPLOTLIB

    def test_qt_backend_loading_result(self) -> None:
        """Qt backend name is set appropriately."""
        assert isinstance(matplotlib_handler.qt_backend_name, (str, type(None)))

        if matplotlib_handler.qt_backend_name:
            assert matplotlib_handler.qt_backend_name in [
                "QtAgg",
                "Qt5Agg",
                "Agg",
                "default",
            ]


class TestFallbackFigureCreation:
    """Test fallback figure object functionality."""

    def test_create_fallback_figure_with_default_params(self) -> None:
        """Fallback Figure can be created with default parameters."""
        if matplotlib_handler.HAS_MATPLOTLIB:
            pytest.skip("Testing fallback implementation only")

        fig = matplotlib_handler.FallbackFigure()

        assert fig.figsize == (8, 6)
        assert fig.dpi == 100
        assert fig.facecolor == "white"
        assert fig.edgecolor == "black"
        assert isinstance(fig.axes, list)
        assert len(fig.axes) == 0

    def test_create_fallback_figure_with_custom_params(self) -> None:
        """Fallback Figure accepts custom dimensions and properties."""
        if matplotlib_handler.HAS_MATPLOTLIB:
            pytest.skip("Testing fallback implementation only")

        fig = matplotlib_handler.FallbackFigure(
            figsize=(12, 8), dpi=150, facecolor="gray", edgecolor="red"
        )

        assert fig.figsize == (12, 8)
        assert fig.dpi == 150
        assert fig.facecolor == "gray"
        assert fig.edgecolor == "red"

    def test_add_subplot_creates_axes(self) -> None:
        """add_subplot creates and tracks axes objects."""
        if matplotlib_handler.HAS_MATPLOTLIB:
            pytest.skip("Testing fallback implementation only")

        fig = matplotlib_handler.FallbackFigure()
        ax = fig.add_subplot(1, 1, 1)

        assert ax is not None
        assert len(fig.axes) == 1
        assert fig.axes[0] == ax
        assert ax.nrows == 1
        assert ax.ncols == 1
        assert ax.index == 1

    def test_add_multiple_subplots(self) -> None:
        """Multiple subplots can be added to figure."""
        if matplotlib_handler.HAS_MATPLOTLIB:
            pytest.skip("Testing fallback implementation only")

        fig = matplotlib_handler.FallbackFigure()

        ax1 = fig.add_subplot(2, 2, 1)
        ax2 = fig.add_subplot(2, 2, 2)
        ax3 = fig.add_subplot(2, 2, 3)
        ax4 = fig.add_subplot(2, 2, 4)

        assert len(fig.axes) == 4
        assert all(ax.nrows == 2 and ax.ncols == 2 for ax in fig.axes)
        assert [ax.index for ax in fig.axes] == [1, 2, 3, 4]

    def test_gca_returns_current_axes(self) -> None:
        """gca() returns current axes, creating one if needed."""
        if matplotlib_handler.HAS_MATPLOTLIB:
            pytest.skip("Testing fallback implementation only")

        fig = matplotlib_handler.FallbackFigure()

        ax = fig.gca()

        assert ax is not None
        assert len(fig.axes) == 1

        ax2 = fig.gca()
        assert ax2 == ax


class TestFallbackAxesPlotting:
    """Test fallback axes plotting functionality."""

    def test_plot_line_with_data(self) -> None:
        """plot() stores line data correctly."""
        if matplotlib_handler.HAS_MATPLOTLIB:
            pytest.skip("Testing fallback implementation only")

        fig = matplotlib_handler.FallbackFigure()
        ax = fig.add_subplot(1, 1, 1)

        x_data = [1, 2, 3, 4, 5]
        y_data = [1, 4, 9, 16, 25]
        ax.plot(x_data, y_data, color="red", linewidth=2, label="squares")

        assert len(ax.lines) == 1
        line = ax.lines[0]
        assert line["x"] == x_data
        assert line["y"] == y_data
        assert line["color"] == "red"
        assert line["linewidth"] == 2
        assert line["label"] == "squares"

    def test_scatter_plot_stores_data(self) -> None:
        """scatter() stores scatter point data."""
        if matplotlib_handler.HAS_MATPLOTLIB:
            pytest.skip("Testing fallback implementation only")

        fig = matplotlib_handler.FallbackFigure()
        ax = fig.add_subplot(1, 1, 1)

        x_data = [1, 2, 3, 4, 5]
        y_data = [2, 4, 6, 8, 10]
        ax.scatter(x_data, y_data, s=50, c="blue", alpha=0.7, label="data")

        assert len(ax.scatter_data) == 1
        scatter = ax.scatter_data[0]
        assert scatter["x"] == x_data
        assert scatter["y"] == y_data
        assert scatter["s"] == 50
        assert scatter["c"] == "blue"
        assert scatter["alpha"] == 0.7

    def test_bar_plot_with_values(self) -> None:
        """bar() creates bar plot with heights and positions."""
        if matplotlib_handler.HAS_MATPLOTLIB:
            pytest.skip("Testing fallback implementation only")

        fig = matplotlib_handler.FallbackFigure()
        ax = fig.add_subplot(1, 1, 1)

        x = [1, 2, 3, 4]
        heights = [10, 15, 13, 17]
        ax.bar(x, heights, width=0.5, color="green", label="data")

        assert len(ax.bars) == 1
        bar_group = ax.bars[0]
        assert bar_group["x"] == x
        assert bar_group["height"] == heights
        assert bar_group["width"] == 0.5
        assert bar_group["color"] == "green"

    def test_histogram_calculates_bins(self) -> None:
        """hist() calculates histogram bins from data."""
        if matplotlib_handler.HAS_MATPLOTLIB:
            pytest.skip("Testing fallback implementation only")

        fig = matplotlib_handler.FallbackFigure()
        ax = fig.add_subplot(1, 1, 1)

        data = [1, 2, 2, 3, 3, 3, 4, 4, 5]
        ax.hist(data, bins=5, color="orange")

        assert len(ax.bars) == 1

    def test_axes_labels_and_title(self) -> None:
        """set_title, set_xlabel, set_ylabel work correctly."""
        if matplotlib_handler.HAS_MATPLOTLIB:
            pytest.skip("Testing fallback implementation only")

        fig = matplotlib_handler.FallbackFigure()
        ax = fig.add_subplot(1, 1, 1)

        ax.set_title("Test Plot")
        ax.set_xlabel("X Axis")
        ax.set_ylabel("Y Axis")

        assert ax.title == "Test Plot"
        assert ax.xlabel_text == "X Axis"
        assert ax.ylabel_text == "Y Axis"

    def test_axes_limits_setting(self) -> None:
        """set_xlim and set_ylim configure axis limits."""
        if matplotlib_handler.HAS_MATPLOTLIB:
            pytest.skip("Testing fallback implementation only")

        fig = matplotlib_handler.FallbackFigure()
        ax = fig.add_subplot(1, 1, 1)

        ax.set_xlim(0, 100)
        ax.set_ylim(-50, 50)

        assert ax.xlim == (0, 100)
        assert ax.ylim == (-50, 50)

    def test_legend_creation(self) -> None:
        """legend() registers legend items."""
        if matplotlib_handler.HAS_MATPLOTLIB:
            pytest.skip("Testing fallback implementation only")

        fig = matplotlib_handler.FallbackFigure()
        ax = fig.add_subplot(1, 1, 1)

        ax.plot([1, 2, 3], [1, 2, 3], label="line1")
        ax.plot([1, 2, 3], [3, 2, 1], label="line2")

        assert len(ax.legend_items) == 2
        assert ("line1", "blue") in ax.legend_items or any(
            label == "line1" for label, _ in ax.legend_items
        )

    def test_grid_enable_disable(self) -> None:
        """grid() enables and disables grid display."""
        if matplotlib_handler.HAS_MATPLOTLIB:
            pytest.skip("Testing fallback implementation only")

        fig = matplotlib_handler.FallbackFigure()
        ax = fig.add_subplot(1, 1, 1)

        assert not ax.grid_enabled

        ax.grid(True)
        assert ax.grid_enabled

        ax.grid(False)
        assert not ax.grid_enabled


class TestFallbackSVGGeneration:
    """Test SVG file generation from fallback figures."""

    def test_save_figure_as_svg(self, temp_workspace: Path) -> None:
        """savefig() generates valid SVG file."""
        if matplotlib_handler.HAS_MATPLOTLIB:
            pytest.skip("Testing fallback implementation only")

        fig = matplotlib_handler.FallbackFigure(figsize=(10, 8), dpi=100)
        ax = fig.add_subplot(1, 1, 1)
        ax.plot([1, 2, 3, 4], [1, 4, 9, 16], color="blue")
        ax.set_title("Test SVG")

        svg_file = temp_workspace / "test_plot.svg"
        fig.savefig(svg_file, format="svg")

        assert svg_file.exists()
        assert svg_file.stat().st_size > 0

        content = svg_file.read_text()
        assert "<svg" in content
        assert "</svg>" in content
        assert "width" in content
        assert "height" in content

    def test_svg_contains_title(self, temp_workspace: Path) -> None:
        """Generated SVG includes figure title."""
        if matplotlib_handler.HAS_MATPLOTLIB:
            pytest.skip("Testing fallback implementation only")

        fig = matplotlib_handler.FallbackFigure()
        fig.suptitle("Binary Analysis Results")
        ax = fig.add_subplot(1, 1, 1)
        ax.plot([1, 2, 3], [1, 2, 3])

        svg_file = temp_workspace / "titled_plot.svg"
        fig.savefig(svg_file, format="svg")

        content = svg_file.read_text()
        assert "Binary Analysis Results" in content

    def test_svg_contains_plot_data(self, temp_workspace: Path) -> None:
        """Generated SVG includes actual plot data elements."""
        if matplotlib_handler.HAS_MATPLOTLIB:
            pytest.skip("Testing fallback implementation only")

        fig = matplotlib_handler.FallbackFigure()
        ax = fig.add_subplot(1, 1, 1)
        ax.plot([0, 1, 2], [0, 1, 4], color="red")

        svg_file = temp_workspace / "data_plot.svg"
        fig.savefig(svg_file, format="svg")

        content = svg_file.read_text()
        assert "<polyline" in content or "<line" in content
        assert 'stroke="red"' in content


class TestFallbackPNGGeneration:
    """Test PNG file generation from fallback figures."""

    def test_save_figure_as_png_with_pil_fallback(self, temp_workspace: Path) -> None:
        """savefig() generates PNG file (with or without PIL)."""
        if matplotlib_handler.HAS_MATPLOTLIB:
            pytest.skip("Testing fallback implementation only")

        fig = matplotlib_handler.FallbackFigure(figsize=(8, 6), dpi=100)
        ax = fig.add_subplot(1, 1, 1)
        ax.plot([1, 2, 3], [1, 2, 3])

        png_file = temp_workspace / "test_plot.png"
        fig.savefig(png_file, format="png")

        assert png_file.exists()
        assert png_file.stat().st_size > 0

        with open(png_file, "rb") as f:
            header = f.read(8)
            assert header == b"\x89PNG\r\n\x1a\n", "Should have valid PNG header"

    def test_png_dimensions_match_figsize(self, temp_workspace: Path) -> None:
        """Generated PNG has correct dimensions based on figsize and DPI."""
        if matplotlib_handler.HAS_MATPLOTLIB:
            pytest.skip("Testing fallback implementation only")

        figsize = (6, 4)
        dpi = 100
        fig = matplotlib_handler.FallbackFigure(figsize=figsize, dpi=dpi)

        png_file = temp_workspace / "sized_plot.png"
        fig.savefig(png_file, format="png", dpi=dpi)

        assert png_file.exists()

        with open(png_file, "rb") as f:
            f.read(8)
            ihdr = f.read(25)

            width = struct.unpack(">I", ihdr[8:12])[0]
            height = struct.unpack(">I", ihdr[12:16])[0]

            expected_width = int(figsize[0] * dpi)
            expected_height = int(figsize[1] * dpi)

            assert width == expected_width
            assert height == expected_height


class TestFallbackPyplotInterface:
    """Test fallback pyplot-style interface."""

    def test_pyplot_figure_creation(self) -> None:
        """plt.figure() creates and returns figure."""
        if matplotlib_handler.HAS_MATPLOTLIB:
            pytest.skip("Testing fallback implementation only")

        plt = matplotlib_handler.get_plt()

        fig = plt.figure(figsize=(10, 8))

        assert fig is not None
        assert fig.figsize == (10, 8)

    def test_pyplot_subplot_creation(self) -> None:
        """plt.subplot() creates subplot axes."""
        if matplotlib_handler.HAS_MATPLOTLIB:
            pytest.skip("Testing fallback implementation only")

        plt = matplotlib_handler.get_plt()

        ax = plt.subplot(2, 2, 1)

        assert ax is not None
        assert ax.nrows == 2
        assert ax.ncols == 2
        assert ax.index == 1

    def test_pyplot_subplots_returns_fig_and_axes(self) -> None:
        """plt.subplots() returns figure and axes array."""
        if matplotlib_handler.HAS_MATPLOTLIB:
            pytest.skip("Testing fallback implementation only")

        plt = matplotlib_handler.get_plt()

        fig, axes = plt.subplots(2, 2, figsize=(12, 10))

        assert fig is not None
        assert isinstance(axes, list)
        assert len(axes) == 2
        assert len(axes[0]) == 2

    def test_pyplot_plot_on_current_axes(self) -> None:
        """plt.plot() plots on current axes."""
        if matplotlib_handler.HAS_MATPLOTLIB:
            pytest.skip("Testing fallback implementation only")

        plt = matplotlib_handler.get_plt()

        plt.figure()
        plt.plot([1, 2, 3], [1, 4, 9], color="blue")

        fig = plt.gcf()
        ax = fig.gca()

        assert len(ax.lines) == 1

    def test_pyplot_savefig(self, temp_workspace: Path) -> None:
        """plt.savefig() saves current figure."""
        if matplotlib_handler.HAS_MATPLOTLIB:
            pytest.skip("Testing fallback implementation only")

        plt = matplotlib_handler.get_plt()

        plt.figure()
        plt.plot([1, 2, 3], [1, 2, 3])
        plt.title("Test")

        output_file = temp_workspace / "pyplot_test.svg"
        plt.savefig(output_file)

        assert output_file.exists()


class TestFallbackPdfPages:
    """Test PDF multi-page export functionality."""

    def test_create_pdfpages_context_manager(self, temp_workspace: Path) -> None:
        """PdfPages can be used as context manager."""
        if matplotlib_handler.HAS_MATPLOTLIB:
            pytest.skip("Testing fallback implementation only")

        pdf_file = temp_workspace / "test_report.pdf"

        with matplotlib_handler.FallbackPdfPages(pdf_file) as pdf:
            assert pdf is not None
            assert not pdf.closed

        assert pdf.closed

    def test_pdfpages_savefig_creates_pages(self, temp_workspace: Path) -> None:
        """savefig() adds pages to PDF."""
        if matplotlib_handler.HAS_MATPLOTLIB:
            pytest.skip("Testing fallback implementation only")

        pdf_file = temp_workspace / "multi_page.pdf"

        with matplotlib_handler.FallbackPdfPages(pdf_file) as pdf:
            fig1 = matplotlib_handler.FallbackFigure()
            fig1.suptitle("Page 1")
            pdf.savefig(fig1)

            fig2 = matplotlib_handler.FallbackFigure()
            fig2.suptitle("Page 2")
            pdf.savefig(fig2)

            assert len(pdf.pages) == 2

    def test_pdfpages_generates_pdf_file(self, temp_workspace: Path) -> None:
        """PdfPages creates actual PDF file on close."""
        if matplotlib_handler.HAS_MATPLOTLIB:
            pytest.skip("Testing fallback implementation only")

        pdf_file = temp_workspace / "output.pdf"

        with matplotlib_handler.FallbackPdfPages(pdf_file) as pdf:
            fig = matplotlib_handler.FallbackFigure()
            pdf.savefig(fig)

        assert pdf_file.exists()
        assert pdf_file.stat().st_size > 0

        content = pdf_file.read_text(errors="ignore")
        assert "%PDF" in content
        assert "%%EOF" in content


class TestFallbackPatches:
    """Test geometric patch objects."""

    def test_rectangle_patch_creation(self) -> None:
        """Rectangle patch stores position and dimensions."""
        if matplotlib_handler.HAS_MATPLOTLIB:
            pytest.skip("Testing fallback implementation only")

        rect = matplotlib_handler.FallbackRectangle(
            xy=(10, 20), width=50, height=30, facecolor="red", edgecolor="black"
        )

        assert rect.xy == (10, 20)
        assert rect.width == 50
        assert rect.height == 30
        assert rect.facecolor == "red"
        assert rect.edgecolor == "black"

    def test_circle_patch_creation(self) -> None:
        """Circle patch stores center and radius."""
        if matplotlib_handler.HAS_MATPLOTLIB:
            pytest.skip("Testing fallback implementation only")

        circle = matplotlib_handler.FallbackCircle(
            xy=(50, 50), radius=25, facecolor="blue", alpha=0.5
        )

        assert circle.xy == (50, 50)
        assert circle.radius == 25
        assert circle.facecolor == "blue"
        assert circle.alpha == 0.5

    def test_polygon_patch_creation(self) -> None:
        """Polygon patch stores vertices."""
        if matplotlib_handler.HAS_MATPLOTLIB:
            pytest.skip("Testing fallback implementation only")

        vertices = [(0, 0), (1, 0), (1, 1), (0, 1)]
        polygon = matplotlib_handler.FallbackPolygon(vertices, closed=True)

        assert polygon.xy == vertices
        assert polygon.closed


class TestGetterFunctions:
    """Test module-level getter functions."""

    def test_get_plt_returns_callable_object(self) -> None:
        """get_plt() returns object with plotting methods."""
        plt = matplotlib_handler.get_plt()

        assert hasattr(plt, "figure")
        assert hasattr(plt, "plot")
        assert hasattr(plt, "scatter")
        assert hasattr(plt, "savefig")

    def test_get_figure_class_returns_class(self) -> None:
        """get_figure_class() returns Figure class."""
        FigureClass = matplotlib_handler.get_figure_class()

        assert FigureClass is not None
        fig = FigureClass()
        assert hasattr(fig, "add_subplot")
        assert hasattr(fig, "savefig")

    def test_get_axes_class_returns_class(self) -> None:
        """get_axes_class() returns Axes class."""
        AxesClass = matplotlib_handler.get_axes_class()

        assert AxesClass is not None

    def test_get_pdfpages_class_returns_class(self) -> None:
        """get_pdfpages_class() returns PdfPages class."""
        PdfPagesClass = matplotlib_handler.get_pdfpages_class()

        assert PdfPagesClass is not None


@pytest.mark.real_data
class TestRealVisualizationWorkflow:
    """Integration tests for complete visualization workflows."""

    def test_complete_analysis_plot_workflow(self, temp_workspace: Path) -> None:
        """Complete binary analysis visualization workflow."""
        if matplotlib_handler.HAS_MATPLOTLIB:
            pytest.skip("Testing fallback implementation only")

        entropy_data = [0.2, 0.3, 0.8, 0.9, 0.7, 0.3, 0.2, 0.1]
        addresses = list(range(0x1000, 0x1000 + len(entropy_data) * 0x100, 0x100))

        plt = matplotlib_handler.get_plt()

        fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 8))

        ax1.plot(addresses, entropy_data, color="blue", linewidth=2, label="Entropy")
        ax1.set_title("Binary Entropy Analysis")
        ax1.set_xlabel("Address")
        ax1.set_ylabel("Entropy")
        ax1.grid(True)
        ax1.legend()

        section_sizes = [1024, 2048, 512, 4096]
        section_names = [".text", ".data", ".rdata", ".rsrc"]
        ax2.bar(range(len(section_sizes)), section_sizes, color="green")
        ax2.set_title("Section Sizes")

        output_file = temp_workspace / "binary_analysis.svg"
        plt.savefig(output_file)

        assert output_file.exists()
        content = output_file.read_text()
        assert "Binary Entropy Analysis" in content
        assert "Section Sizes" in content

    def test_multi_page_pdf_report(self, temp_workspace: Path) -> None:
        """Multi-page PDF report generation."""
        if matplotlib_handler.HAS_MATPLOTLIB:
            pytest.skip("Testing fallback implementation only")

        pdf_file = temp_workspace / "analysis_report.pdf"

        PdfPages = matplotlib_handler.get_pdfpages_class()

        with PdfPages(pdf_file) as pdf:
            fig1 = matplotlib_handler.FallbackFigure()
            ax1 = fig1.add_subplot(1, 1, 1)
            ax1.plot([1, 2, 3], [10, 20, 15], color="red")
            ax1.set_title("Execution Flow")
            pdf.savefig(fig1)

            fig2 = matplotlib_handler.FallbackFigure()
            ax2 = fig2.add_subplot(1, 1, 1)
            ax2.bar([0, 1, 2], [100, 200, 150], color="blue")
            ax2.set_title("API Calls")
            pdf.savefig(fig2)

        assert pdf_file.exists()
        assert pdf_file.stat().st_size > 100
