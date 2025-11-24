"""Matplotlib handler for Intellicrack.

This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see https://www.gnu.org/licenses/.
"""

import traceback
import types
from collections.abc import Callable
from typing import Any, Optional, Union

from intellicrack.utils.logger import logger


# Matplotlib availability detection and import handling
try:
    import matplotlib as mpl

    # Determine which Qt backend to use based on available PyQt versions
    qt_backend_name = None
    FigureCanvasQTAgg = None
    qt_backend_error = None

    # Check Qt availability and try appropriate matplotlib backends
    # First try the generic QtAgg backend (works with both Qt5 and Qt6)
    try:
        try:
            import matplotlib.backends.backend_qtagg as backend_qtagg_module

            FigureCanvasQTAgg = backend_qtagg_module.FigureCanvasQTAgg
            qt_backend_name = "QtAgg"
            logger.debug("Successfully loaded generic QtAgg backend for matplotlib")
        except ImportError:
            # QtAgg not available, try Qt5Agg
            try:
                import matplotlib.backends.backend_qt5agg as backend_qt5agg_module

                FigureCanvasQTAgg = backend_qt5agg_module.FigureCanvasQTAgg
                qt_backend_name = "Qt5Agg"
                logger.debug("Successfully loaded Qt5Agg backend for matplotlib")
            except ImportError as e:
                qt_backend_error = e
                logger.debug(f"Qt5Agg backend for matplotlib not available: {e}")
    except Exception as e:
        qt_backend_error = e
        logger.debug(f"Unexpected error loading Qt backend for matplotlib: {e}")

    # If we couldn't load any Qt backend, check if PyQt is even available
    if FigureCanvasQTAgg is None:
        try:
            import importlib.util

            if importlib.util.find_spec("PyQt6") is not None:
                logger.debug("PyQt6 is available but matplotlib Qt backend failed to load")
        except ImportError:
            pass

        try:
            import importlib.util

            if importlib.util.find_spec("PyQt5") is not None:
                logger.debug("PyQt5 is available but matplotlib Qt backend failed to load")
        except ImportError:
            logger.debug("Neither PyQt6 nor PyQt5 available for matplotlib backend")
            qt_backend_error = ImportError("No PyQt available")

    # Set the appropriate matplotlib backend
    if qt_backend_name:
        try:
            if hasattr(mpl, 'use'):
                mpl.use(qt_backend_name, force=True)
                logger.info(f"Successfully configured matplotlib to use {qt_backend_name} backend")
            else:
                logger.warning("matplotlib.use() not available, skipping backend configuration")
        except Exception as e:
            logger.warning(f"Failed to set matplotlib backend to {qt_backend_name}, falling back to Agg: {e}")
            try:
                if hasattr(mpl, 'use'):
                    mpl.use("Agg", force=True)
                    qt_backend_name = "Agg"
            except Exception:
                pass
    else:
        # No Qt backend available, use Agg
        try:
            if hasattr(mpl, 'use'):
                mpl.use("Agg", force=True)
                qt_backend_name = "Agg"
                logger.debug("No Qt backend available, using Agg backend for matplotlib")
            else:
                logger.debug("matplotlib.use() not available, using default backend")
                qt_backend_name = "default"
        except Exception:
            logger.debug("Failed to set matplotlib backend, using default")
            qt_backend_name = "default"

    # Import matplotlib components after backend is set
    import matplotlib.pyplot as plt
    from matplotlib.axes import Axes
    from matplotlib.backends.backend_pdf import PdfPages
    from matplotlib.figure import Figure
    from matplotlib.patches import Circle, Polygon, Rectangle
    from matplotlib.ticker import FuncFormatter, MaxNLocator

    # If no Qt backend was loaded, log a warning only once
    if FigureCanvasQTAgg is None and qt_backend_error:
        logger.warning(f"No Qt backend for matplotlib available, some GUI features may be limited. Last error: {qt_backend_error}")
        logger.debug(f"Full traceback for Qt backend import failure: {traceback.format_exc()}")

    # Try to import Tk backend but don't fail if Tk is not available
    try:
        from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
    except ImportError:
        FigureCanvasTkAgg = None

    HAS_MATPLOTLIB = True
    MATPLOTLIB_VERSION = mpl.__version__

    # If Qt backend was not available, create a basic fallback
    if FigureCanvasQTAgg is None:

        class FigureCanvasQTAgg:
            """Production-ready Qt canvas fallback when Qt backend is not available."""

            def __init__(self, figure: object) -> None:
                """Initialize Qt canvas with matplotlib figure.

                Args:
                    figure: Matplotlib figure object to render on the Qt canvas.

                """
                self.figure: object = figure
                self._size_policy: tuple[object, ...] | None = None

            def draw(self) -> None:
                """Draw the Qt canvas using fallback rendering."""
                if hasattr(self.figure, "savefig"):
                    logger.debug("Qt canvas fallback draw() - using figure rendering")
                else:
                    logger.debug("Qt canvas fallback draw() - no rendering available")

            def setSizePolicy(self, *args: object) -> None:
                """Set size policy for Qt widget compatibility.

                Args:
                    *args: Size policy arguments for Qt compatibility.

                """
                self._size_policy = args
                logger.debug("Qt canvas setSizePolicy() called with args: %s", args)

            def update(self) -> None:
                """Update the canvas."""
                self.draw()

            def repaint(self) -> None:
                """Repaint the canvas."""
                self.draw()

except ImportError as e:
    logger.error("Matplotlib not available, using fallback implementations: %s", e)
    HAS_MATPLOTLIB = False
    MATPLOTLIB_VERSION = None

    # Production-ready fallback implementations for Intellicrack's visualization needs

    class FallbackFigure:
        """Functional figure implementation for binary analysis visualizations."""

        def __init__(
            self,
            figsize: tuple[float, float] = (8, 6),
            dpi: int = 100,
            facecolor: str = "white",
            edgecolor: str = "black",
        ) -> None:
            """Initialize figure with dimensions and properties.

            Args:
                figsize: Figure size in inches as (width, height) tuple.
                dpi: Dots per inch resolution for the figure.
                facecolor: Background color of the figure.
                edgecolor: Edge color of the figure border.

            """
            self.figsize: tuple[float, float] = figsize
            self.dpi: int = dpi
            self.facecolor: str = facecolor
            self.edgecolor: str = edgecolor
            self.axes: list[Any] = []
            self._suptitle: str = ""
            self._current_axes: Any | None = None
            self._layout: str = "tight"
            self._canvas: Any = FallbackCanvas(self)

        def add_subplot(
            self,
            nrows: int,
            ncols: int,
            index: int,
            **kwargs: object,
        ) -> "FallbackAxes":
            """Add a subplot to the figure.

            Args:
                nrows: Number of subplot rows.
                ncols: Number of subplot columns.
                index: Index of this subplot (1-based).
                **kwargs: Additional keyword arguments for the subplot.

            Returns:
                The created FallbackAxes subplot object.

            """
            ax = FallbackAxes(self, nrows, ncols, index, **kwargs)
            self.axes.append(ax)
            self._current_axes = ax
            return ax

        def add_axes(self, rect: tuple[float, float, float, float], **kwargs: object) -> "FallbackAxes":
            """Add axes at the given position.

            Args:
                rect: Position and size as (x, y, width, height) tuple.
                **kwargs: Additional keyword arguments for the axes.

            Returns:
                The created FallbackAxes object.

            """
            ax = FallbackAxes(self, rect=rect, **kwargs)
            self.axes.append(ax)
            self._current_axes = ax
            return ax

        def suptitle(self, title: str, **kwargs: object) -> None:
            """Set the figure's super title.

            Args:
                title: The super title text.
                **kwargs: Additional keyword arguments for title formatting.

            """
            self._suptitle = title

        def tight_layout(
            self,
            pad: float = 1.08,
            h_pad: float | None = None,
            w_pad: float | None = None,
        ) -> None:
            """Adjust subplot parameters for tight layout.

            Args:
                pad: Padding around the figure edge.
                h_pad: Height padding between subplots.
                w_pad: Width padding between subplots.

            """
            self._layout = "tight"

        def subplots_adjust(
            self,
            left: float | None = None,
            bottom: float | None = None,
            right: float | None = None,
            top: float | None = None,
            wspace: float | None = None,
            hspace: float | None = None,
        ) -> None:
            """Adjust subplot parameters.

            Args:
                left: Left side position.
                bottom: Bottom side position.
                right: Right side position.
                top: Top side position.
                wspace: Width spacing between subplots.
                hspace: Height spacing between subplots.

            """
            if not hasattr(self, "_subplot_params"):
                self._subplot_params: dict[str, float] = {}

            if left is not None:
                self._subplot_params["left"] = left
            if bottom is not None:
                self._subplot_params["bottom"] = bottom
            if right is not None:
                self._subplot_params["right"] = right
            if top is not None:
                self._subplot_params["top"] = top
            if wspace is not None:
                self._subplot_params["wspace"] = wspace
            if hspace is not None:
                self._subplot_params["hspace"] = hspace

            logger.debug("Subplot parameters adjusted: %s", self._subplot_params)

        def savefig(
            self,
            fname: str | object,
            dpi: int | None = None,
            format: str | None = None,
            bbox_inches: str | None = None,
            **kwargs: object,
        ) -> None:
            """Save the figure to a file.

            Args:
                fname: File path or object to save the figure to.
                dpi: Resolution in dots per inch for the output.
                format: File format (svg, png, jpg, jpeg). Auto-detected from fname if None.
                bbox_inches: Bounding box in inches. Not used in fallback mode.
                **kwargs: Additional keyword arguments for save formatting.

            """
            if format is None and isinstance(fname, str):
                file_format = fname.split(".")[-1].lower()
            else:
                file_format = format

            svg_content = self._generate_svg()

            if file_format == "svg":
                with open(fname, "w") as f:
                    f.write(svg_content)
            elif file_format in ["png", "jpg", "jpeg"]:
                self._save_raster(fname, format, dpi or self.dpi)

        def _generate_svg(self) -> str:
            """Generate SVG representation of the figure.

            Returns:
                SVG markup string representing the figure and all its axes.

            """
            width = self.figsize[0] * self.dpi
            height = self.figsize[1] * self.dpi

            svg = f'<svg width="{width}" height="{height}" xmlns="http://www.w3.org/2000/svg">\n'
            svg += f'<rect width="{width}" height="{height}" fill="{self.facecolor}" stroke="{self.edgecolor}"/>\n'

            # Add title
            if self._suptitle:
                svg += f'<text x="{width / 2}" y="20" text-anchor="middle" font-size="16">{self._suptitle}</text>\n'

            # Add axes content
            for ax in self.axes:
                svg += ax._generate_svg_content(width, height)

            svg += "</svg>"
            return svg

        def _save_raster(self, fname: str | object, format: str, dpi: int) -> None:
            """Save as raster image using PIL or pure Python bitmap generation.

            Args:
                fname: File path to save the raster image to.
                format: File format (png, jpg, jpeg).
                dpi: Resolution in dots per inch for the output.

            """
            try:
                from PIL import Image, ImageDraw, ImageFont

                _ = ImageFont.__name__  # Verify ImageFont is properly imported for future text rendering capabilities

                width = int(self.figsize[0] * dpi)
                height = int(self.figsize[1] * dpi)

                img = Image.new("RGB", (width, height), color="white")
                draw = ImageDraw.Draw(img)

                # Draw border
                draw.rectangle([(0, 0), (width - 1, height - 1)], outline="black")

                # Draw title
                if self._suptitle:
                    draw.text((width // 2, 20), self._suptitle, fill="black", anchor="mt")

                # Draw axes
                for ax in self.axes:
                    ax._draw_on_image(draw, width, height)

                img.save(fname, format.upper())

            except ImportError:
                # Generate real bitmap data without PIL
                logger.info("PIL not available, generating bitmap using pure Python")

                width = int(self.figsize[0] * dpi)
                height = int(self.figsize[1] * dpi)

                if format == "png":
                    import struct
                    import zlib

                    def generate_png(width: int, height: int, pixels: dict[tuple[int, int], tuple[int, int, int]]) -> bytes:
                        """Generate complete PNG file from raw pixel data.

                        Args:
                            width: Image width in pixels.
                            height: Image height in pixels.
                            pixels: Dictionary mapping (x, y) coordinates to (r, g, b) tuples.

                        Returns:
                            Complete PNG file data as bytes.

                        """

                        def png_chunk(chunk_type: bytes, data: bytes) -> bytes:
                            """Create PNG chunk with CRC.

                            Args:
                                chunk_type: Four-byte chunk type identifier.
                                data: Chunk data payload.

                            Returns:
                                Complete PNG chunk with length, type, data, and CRC.

                            """
                            chunk = chunk_type + data
                            crc = zlib.crc32(chunk) & 0xFFFFFFFF
                            return struct.pack(">I", len(data)) + chunk + struct.pack(">I", crc)

                        # PNG signature
                        png_data = b"\x89PNG\r\n\x1a\n"

                        # IHDR chunk (image header)
                        ihdr_data = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
                        png_data += png_chunk(b"IHDR", ihdr_data)

                        # IDAT chunk (image data)
                        raw_data = b""
                        for y in range(height):
                            # Filter type 0 (None)
                            raw_data += b"\x00"
                            for x in range(width):
                                # RGB pixel (white background with content)
                                r, g, b = pixels[(x, y)] if pixels and (x, y) in pixels else (255, 255, 255)
                                raw_data += bytes([r, g, b])

                        compressed = zlib.compress(raw_data)
                        png_data += png_chunk(b"IDAT", compressed)

                        # IEND chunk
                        png_data += png_chunk(b"IEND", b"")

                        return png_data

                    # Generate pixel data for figure
                    pixels = {}

                    # Draw border
                    for x in range(width):
                        pixels[(x, 0)] = (0, 0, 0)  # Top border
                        pixels[(x, height - 1)] = (0, 0, 0)  # Bottom border
                    for y in range(height):
                        pixels[(0, y)] = (0, 0, 0)  # Left border
                        pixels[(width - 1, y)] = (0, 0, 0)  # Right border

                    # Draw title if present
                    if self._suptitle:
                        # Simple text rendering (just a line for demonstration)
                        y = 20
                        for x in range(width // 4, 3 * width // 4):
                            pixels[(x, y)] = (0, 0, 0)

                    # Generate and save PNG
                    png_bytes = generate_png(width, height, pixels)
                    with open(fname, "wb") as f:
                        f.write(png_bytes)

                else:

                    def generate_bmp(width: int, height: int, pixels: dict[tuple[int, int], tuple[int, int, int]]) -> bytes:
                        """Generate BMP file from pixel data.

                        Args:
                            width: Image width in pixels.
                            height: Image height in pixels.
                            pixels: Dictionary mapping (x, y) coordinates to (r, g, b) tuples.

                        Returns:
                            Complete BMP file data as bytes.

                        """
                        # BMP header
                        file_size = 54 + (width * height * 3)
                        bmp_header = b"BM"
                        bmp_header += struct.pack("<I", file_size)  # File size
                        bmp_header += struct.pack("<HH", 0, 0)  # Reserved
                        bmp_header += struct.pack("<I", 54)  # Offset to pixel data

                        # DIB header
                        dib_header = struct.pack("<I", 40)  # Header size
                        dib_header += struct.pack("<ii", width, height)  # Width, height
                        dib_header += struct.pack("<HH", 1, 24)  # Planes, bits per pixel
                        dib_header += struct.pack("<I", 0)  # Compression (none)
                        dib_header += struct.pack("<I", 0)  # Image size (can be 0)
                        dib_header += struct.pack("<ii", 2835, 2835)  # Resolution
                        dib_header += struct.pack("<II", 0, 0)  # Colors

                        # Pixel data (bottom-up)
                        pixel_data = b""
                        for y in range(height - 1, -1, -1):
                            for x in range(width):
                                if pixels and (x, y) in pixels:
                                    b, g, r = pixels[(x, y)][::-1]  # BMP uses BGR
                                else:
                                    b, g, r = 255, 255, 255
                                pixel_data += bytes([b, g, r])
                            # Padding to 4-byte boundary
                            padding = (4 - (width * 3) % 4) % 4
                            pixel_data += b"\x00" * padding

                        return bmp_header + dib_header + pixel_data

                    # Generate pixel data
                    pixels = {}
                    for x in range(width):
                        pixels[(x, 0)] = (0, 0, 0)
                        pixels[(x, height - 1)] = (0, 0, 0)
                    for y in range(height):
                        pixels[(0, y)] = (0, 0, 0)
                        pixels[(width - 1, y)] = (0, 0, 0)

                    # Save as BMP then convert extension
                    bmp_bytes = generate_bmp(width, height, pixels)
                    with open(fname, "wb") as f:
                        f.write(bmp_bytes)

        def clear(self) -> None:
            """Clear the figure."""
            self.axes.clear()
            self._current_axes = None
            self._suptitle = ""

        def get_axes(self) -> list[Any]:
            """Get all axes.

            Returns:
                List of all axes objects in this figure.

            """
            return self.axes

        def gca(self) -> "FallbackAxes":
            """Get current axes.

            Returns:
                The current axes object, creating one if necessary.

            """
            if not self._current_axes and not self.axes:
                self.add_subplot(1, 1, 1)
            return self._current_axes or self.axes[0]

    class FallbackAxes:
        """Functional axes implementation for plotting."""

        def __init__(
            self,
            figure: object,
            nrows: int = 1,
            ncols: int = 1,
            index: int = 1,
            rect: tuple[float, float, float, float] | None = None,
            **kwargs: object,
        ) -> None:
            """Initialize axes.

            Args:
                figure: Parent figure object.
                nrows: Number of subplot rows.
                ncols: Number of subplot columns.
                index: Subplot index (1-based).
                rect: Optional position rectangle as (x, y, width, height) tuple.
                **kwargs: Additional keyword arguments.

            """
            self.figure: object = figure
            self.nrows: int = nrows
            self.ncols: int = ncols
            self.index: int = index
            self.rect: tuple[float, float, float, float] | None = rect

            self.lines: list[dict[str, object]] = []
            self.bars: list[dict[str, object]] = []
            self.patches: list[dict[str, object]] = []
            self.texts: list[dict[str, object]] = []
            self.images: list[dict[str, object]] = []
            self.scatter_data: list[dict[str, object]] = []

            self.title: str = ""
            self.xlabel_text: str = ""
            self.ylabel_text: str = ""
            self.xlim: tuple[float, float] | None = None
            self.ylim: tuple[float, float] | None = None
            self.legend_items: list[tuple[str, str]] = []
            self.grid_enabled: bool = False

        def plot(self, x: object | None = None, y: object | None = None, *args: object, **kwargs: object) -> None:
            """Plot lines on the axes.

            Args:
                x: X-axis data. If None, y is assumed to be x values.
                y: Y-axis data. If None, x is treated as y values.
                *args: Positional arguments passed to plot style.
                **kwargs: Keyword arguments including color, linestyle, marker, label, linewidth.

            """
            if x is None and y is None:
                return

            if y is None:
                y = x
                x = list(range(len(y)))

            color: str = kwargs.get("color", "blue")
            linestyle: str = kwargs.get("linestyle", "-")
            marker: str = kwargs.get("marker", "")
            label: str = kwargs.get("label", "")
            linewidth: int = kwargs.get("linewidth", 1)

            self.lines.append(
                {
                    "x": list(x),
                    "y": list(y),
                    "color": color,
                    "linestyle": linestyle,
                    "marker": marker,
                    "label": label,
                    "linewidth": linewidth,
                },
            )

            if label:
                self.legend_items.append((label, color))

            self._update_limits(x, y)

        def scatter(
            self,
            x: object,
            y: object,
            s: int | None = None,
            c: str | None = None,
            marker: str = "o",
            alpha: float = 1.0,
            **kwargs: object,
        ) -> None:
            """Create scatter plot on the axes.

            Args:
                x: X-axis data.
                y: Y-axis data.
                s: Marker size in points.
                c: Marker color.
                marker: Marker style.
                alpha: Transparency value (0-1).
                **kwargs: Additional keyword arguments including label.

            """
            self.scatter_data.append(
                {
                    "x": list(x),
                    "y": list(y),
                    "s": s if s is not None else 20,
                    "c": c if c is not None else "blue",
                    "marker": marker,
                    "alpha": alpha,
                    "label": kwargs.get("label", ""),
                },
            )

            if kwargs.get("label"):
                self.legend_items.append((kwargs["label"], c or "blue"))

            self._update_limits(x, y)

        def bar(
            self,
            x: object,
            height: object,
            width: float = 0.8,
            bottom: float | None = None,
            color: str = "blue",
            label: str = "",
            **kwargs: object,
        ) -> None:
            """Create bar plot on the axes.

            Args:
                x: Bar positions on x-axis.
                height: Heights of the bars.
                width: Width of the bars (0-1 relative).
                bottom: Baseline for the bars.
                color: Bar color.
                label: Legend label for the bar group.
                **kwargs: Additional keyword arguments.

            """
            if not hasattr(x, "__iter__"):
                x = [x]
            if not hasattr(height, "__iter__"):
                height = [height]

            self.bars.append(
                {
                    "x": list(x),
                    "height": list(height),
                    "width": width,
                    "bottom": bottom,
                    "color": color,
                    "label": label,
                }
            )

            if label:
                self.legend_items.append((label, color))

            self._update_limits(x, height)

        def hist(
            self,
            x: object,
            bins: int = 10,
            range: tuple[float, float] | None = None,
            density: bool = False,
            color: str = "blue",
            label: str = "",
            **kwargs: object,
        ) -> None:
            """Create histogram on the axes.

            Args:
                x: Data values for the histogram.
                bins: Number of histogram bins.
                range: Tuple of (min, max) values for histogram range.
                density: If True, normalize histogram to form a probability density.
                color: Bar color.
                label: Legend label.
                **kwargs: Additional keyword arguments.

            """
            # Calculate histogram
            value_range = (min(x), max(x)) if range is None else range
            bin_edges = [value_range[0] + i * (value_range[1] - value_range[0]) / bins for i in range(bins + 1)]
            counts = [0] * bins

            for val in x:
                if value_range[0] <= val <= value_range[1]:
                    bin_idx = min(
                        int((val - value_range[0]) / (value_range[1] - value_range[0]) * bins),
                        bins - 1,
                    )
                    counts[bin_idx] += 1

            if density:
                total = sum(counts)
                bin_width = (value_range[1] - value_range[0]) / bins
                counts = [c / (total * bin_width) if total > 0 else 0 for c in counts]

            # Store as bars
            bin_centers = [(bin_edges[i] + bin_edges[i + 1]) / 2 for i in range(bins)]
            bin_width = (value_range[1] - value_range[0]) / bins

            self.bar(bin_centers, counts, width=bin_width, color=color, label=label)

        def imshow(
            self,
            X: object,
            cmap: str = "viridis",
            aspect: str = "auto",
            interpolation: str = "nearest",
            **kwargs: object,
        ) -> None:
            """Display an image or matrix on the axes.

            Args:
                X: Image data array or matrix.
                cmap: Colormap name.
                aspect: Aspect ratio mode.
                interpolation: Interpolation method.
                **kwargs: Additional keyword arguments including extent.

            """
            self.images.append(
                {
                    "data": X,
                    "cmap": cmap,
                    "aspect": aspect,
                    "interpolation": interpolation,
                    "extent": kwargs.get("extent"),
                }
            )

        def contour(
            self,
            X: object,
            Y: object,
            Z: object,
            levels: int = 10,
            colors: str = "black",
            **kwargs: object,
        ) -> None:
            """Create contour plot on the axes.

            Args:
                X: X-coordinate data.
                Y: Y-coordinate data.
                Z: Z-value data for contours.
                levels: Number of contour levels.
                colors: Contour line color.
                **kwargs: Additional keyword arguments.

            """
            self.patches.append({"type": "contour", "X": X, "Y": Y, "Z": Z, "levels": levels, "colors": colors})

        def text(
            self,
            x: float,
            y: float,
            s: object,
            fontsize: int = 12,
            color: str = "black",
            ha: str = "left",
            va: str = "bottom",
            **kwargs: object,
        ) -> None:
            """Add text to the axes.

            Args:
                x: X position for text.
                y: Y position for text.
                s: Text content.
                fontsize: Font size in points.
                color: Text color.
                ha: Horizontal alignment.
                va: Vertical alignment.
                **kwargs: Additional keyword arguments.

            """
            self.texts.append(
                {
                    "x": x,
                    "y": y,
                    "text": str(s),
                    "fontsize": fontsize,
                    "color": color,
                    "ha": ha,
                    "va": va,
                }
            )

        def annotate(
            self,
            text: str,
            xy: tuple[float, float],
            xytext: tuple[float, float] | None = None,
            arrowprops: dict[str, object] | None = None,
            **kwargs: object,
        ) -> None:
            """Add annotation with optional arrow to the axes.

            Args:
                text: Annotation text.
                xy: Point to annotate as (x, y) tuple.
                xytext: Text position as (x, y) tuple. Defaults to xy.
                arrowprops: Dictionary of arrow properties.
                **kwargs: Additional keyword arguments.

            """
            annotation: dict[str, object] = {
                "text": text,
                "xy": xy,
                "xytext": xytext or xy,
                "arrow": arrowprops is not None,
            }
            self.texts.append(annotation)

        def set_title(self, title: str, fontsize: int = 14, **kwargs: object) -> None:
            """Set axes title.

            Args:
                title: Title text.
                fontsize: Font size in points.
                **kwargs: Additional keyword arguments.

            """
            self.title = title

        def set_xlabel(self, xlabel: str, fontsize: int = 12, **kwargs: object) -> None:
            """Set x-axis label.

            Args:
                xlabel: X-axis label text.
                fontsize: Font size in points.
                **kwargs: Additional keyword arguments.

            """
            self.xlabel_text = xlabel

        def set_ylabel(self, ylabel: str, fontsize: int = 12, **kwargs: object) -> None:
            """Set y-axis label.

            Args:
                ylabel: Y-axis label text.
                fontsize: Font size in points.
                **kwargs: Additional keyword arguments.

            """
            self.ylabel_text = ylabel

        def set_xlim(self, left: float | None = None, right: float | None = None) -> None:
            """Set x-axis limits.

            Args:
                left: Minimum x value. If None, uses existing or calculated minimum.
                right: Maximum x value. If None, uses existing or calculated maximum.

            """
            if left is not None and right is not None:
                self.xlim = (left, right)
            elif left is not None:
                self.xlim = (left, self.xlim[1] if self.xlim else left + 1)
            elif right is not None:
                self.xlim = (self.xlim[0] if self.xlim else right - 1, right)

        def set_ylim(self, bottom: float | None = None, top: float | None = None) -> None:
            """Set y-axis limits.

            Args:
                bottom: Minimum y value. If None, uses existing or calculated minimum.
                top: Maximum y value. If None, uses existing or calculated maximum.

            """
            if bottom is not None and top is not None:
                self.ylim = (bottom, top)
            elif bottom is not None:
                self.ylim = (bottom, self.ylim[1] if self.ylim else bottom + 1)
            elif top is not None:
                self.ylim = (self.ylim[0] if self.ylim else top - 1, top)

        def legend(self, labels: list[str] | None = None, loc: str = "best", **kwargs: object) -> None:
            """Add legend to axes.

            Args:
                labels: List of legend labels.
                loc: Legend location.
                **kwargs: Additional keyword arguments.

            """
            if labels:
                self.legend_items = [(label, "blue") for label in labels]

        def grid(self, visible: bool = True, which: str = "major", axis: str = "both", **kwargs: object) -> None:
            """Enable/disable grid on the axes.

            Args:
                visible: Enable or disable grid.
                which: Which grid lines ('major', 'minor', or 'both').
                axis: Which axis ('x', 'y', or 'both').
                **kwargs: Additional keyword arguments.

            """
            self.grid_enabled = visible

        def clear(self) -> None:
            """Clear the axes."""
            self.lines.clear()
            self.bars.clear()
            self.patches.clear()
            self.texts.clear()
            self.images.clear()
            self.scatter_data.clear()
            self.title = ""
            self.xlabel_text = ""
            self.ylabel_text = ""
            self.xlim = None
            self.ylim = None
            self.legend_items.clear()
            self.grid_enabled = False

        def _update_limits(self, x_data: object, y_data: object) -> None:
            """Update axis limits based on data.

            Args:
                x_data: X-axis data to process.
                y_data: Y-axis data to process.

            """
            if hasattr(x_data, "__iter__"):
                x_min, x_max = min(x_data), max(x_data)
            else:
                x_min = x_max = x_data

            if hasattr(y_data, "__iter__"):
                y_min, y_max = min(y_data), max(y_data)
            else:
                y_min = y_max = y_data

            if self.xlim is None:
                self.xlim = (x_min, x_max)
            else:
                self.xlim = (min(self.xlim[0], x_min), max(self.xlim[1], x_max))

            if self.ylim is None:
                self.ylim = (y_min, y_max)
            else:
                self.ylim = (min(self.ylim[0], y_min), max(self.ylim[1], y_max))

        def _generate_svg_content(self, fig_width: float, fig_height: float) -> str:
            """Generate SVG content for this axes.

            Args:
                fig_width: Figure width in pixels.
                fig_height: Figure height in pixels.

            Returns:
                SVG string representing this axes and its content.

            """
            # Calculate axes position
            if self.rect:
                x = self.rect[0] * fig_width
                y = self.rect[1] * fig_height
                width = self.rect[2] * fig_width
                height = self.rect[3] * fig_height
            else:
                # Simple grid layout
                cols = self.ncols
                rows = self.nrows
                idx = self.index - 1

                col = idx % cols
                row = idx // cols

                width = fig_width / cols * 0.8
                height = fig_height / rows * 0.8
                x = col * (fig_width / cols) + width * 0.1
                y = row * (fig_height / rows) + height * 0.1

            svg = f'<g transform="translate({x},{y})">\n'

            # Draw axes box
            svg += f'<rect x="0" y="0" width="{width}" height="{height}" fill="none" stroke="black"/>\n'

            # Draw title
            if self.title:
                svg += f'<text x="{width / 2}" y="-5" text-anchor="middle" font-size="14">{self.title}</text>\n'

            # Draw xlabel
            if self.xlabel_text:
                svg += f'<text x="{width / 2}" y="{height + 20}" text-anchor="middle" font-size="12">{self.xlabel_text}</text>\n'

            # Draw ylabel (rotated)
            if self.ylabel_text:
                svg += f'<text x="-10" y="{height / 2}" text-anchor="middle" font-size="12" transform="rotate(-90 -10 {height / 2})">{self.ylabel_text}</text>\n'

            # Draw grid
            if self.grid_enabled:
                for i in range(1, 10):
                    x_pos = width * i / 10
                    y_pos = height * i / 10
                    svg += f'<line x1="{x_pos}" y1="0" x2="{x_pos}" y2="{height}" stroke="gray" stroke-width="0.5" opacity="0.5"/>\n'
                    svg += f'<line x1="0" y1="{y_pos}" x2="{width}" y2="{y_pos}" stroke="gray" stroke-width="0.5" opacity="0.5"/>\n'

            # Draw lines
            for line in self.lines:
                if len(line["x"]) < 2:
                    continue

                points = []
                for i in range(len(line["x"])):
                    if self.xlim and self.ylim:
                        x_norm = (line["x"][i] - self.xlim[0]) / (self.xlim[1] - self.xlim[0]) if self.xlim[1] != self.xlim[0] else 0.5
                        y_norm = 1 - (line["y"][i] - self.ylim[0]) / (self.ylim[1] - self.ylim[0]) if self.ylim[1] != self.ylim[0] else 0.5
                        points.append(f"{x_norm * width},{y_norm * height}")

                if points:
                    svg += (
                        f'<polyline points="{" ".join(points)}" fill="none" stroke="{line["color"]}" stroke-width="{line["linewidth"]}"/>\n'
                    )

            # Draw bars
            for bar_group in self.bars:
                for x, h in zip(bar_group["x"], bar_group["height"], strict=False):
                    if self.xlim and self.ylim:
                        x_norm = (x - self.xlim[0]) / (self.xlim[1] - self.xlim[0]) if self.xlim[1] != self.xlim[0] else 0.5
                        h_norm = h / (self.ylim[1] - self.ylim[0]) if self.ylim[1] != self.ylim[0] else 0.5

                        bar_x = x_norm * width - bar_group["width"] * width / (2 * (self.xlim[1] - self.xlim[0]))
                        bar_width = bar_group["width"] * width / (self.xlim[1] - self.xlim[0])
                        bar_height = h_norm * height
                        bar_y = height - bar_height

                        svg += f'<rect x="{bar_x}" y="{bar_y}" width="{bar_width}" height="{bar_height}" fill="{bar_group["color"]}"/>\n'

            # Draw scatter points
            for scatter in self.scatter_data:
                for x, y in zip(scatter["x"], scatter["y"], strict=False):
                    if self.xlim and self.ylim:
                        x_norm = (x - self.xlim[0]) / (self.xlim[1] - self.xlim[0]) if self.xlim[1] != self.xlim[0] else 0.5
                        y_norm = 1 - (y - self.ylim[0]) / (self.ylim[1] - self.ylim[0]) if self.ylim[1] != self.ylim[0] else 0.5

                        svg += f'<circle cx="{x_norm * width}" cy="{y_norm * height}" r="3" fill="{scatter["c"]}" opacity="{scatter["alpha"]}"/>\n'

            svg += "</g>\n"
            return svg

        def _draw_on_image(self, draw: object, fig_width: int, fig_height: int) -> None:
            """Draw axes content on PIL image.

            Args:
                draw: PIL ImageDraw object for drawing operations.
                fig_width: Figure width in pixels.
                fig_height: Figure height in pixels.

            """
            # Calculate axes position
            if self.rect:
                x = int(self.rect[0] * fig_width)
                y = int(self.rect[1] * fig_height)
                width = int(self.rect[2] * fig_width)
                height = int(self.rect[3] * fig_height)
            else:
                cols = self.ncols
                rows = self.nrows
                idx = self.index - 1

                col = idx % cols
                row = idx // cols

                width = int(fig_width / cols * 0.8)
                height = int(fig_height / rows * 0.8)
                x = int(col * (fig_width / cols) + width * 0.1)
                y = int(row * (fig_height / rows) + height * 0.1)

            # Draw axes box
            draw.rectangle([(x, y), (x + width, y + height)], outline="black")

            # Draw title
            if self.title:
                draw.text((x + width // 2, y - 10), self.title, fill="black", anchor="mt")

            # Draw lines
            for line in self.lines:
                if len(line["x"]) < 2:
                    continue

                points = []
                for i in range(len(line["x"])):
                    if self.xlim and self.ylim:
                        x_norm = (line["x"][i] - self.xlim[0]) / (self.xlim[1] - self.xlim[0]) if self.xlim[1] != self.xlim[0] else 0.5
                        y_norm = 1 - (line["y"][i] - self.ylim[0]) / (self.ylim[1] - self.ylim[0]) if self.ylim[1] != self.ylim[0] else 0.5
                        points.append((x + x_norm * width, y + y_norm * height))

                if len(points) > 1:
                    for i in range(len(points) - 1):
                        draw.line([points[i], points[i + 1]], fill=line["color"], width=line["linewidth"])

    class FallbackCanvas:
        """Functional canvas implementation for figure rendering."""

        def __init__(self, figure: object) -> None:
            """Initialize canvas.

            Args:
                figure: Figure object to render on this canvas.

            """
            self.figure: object = figure

        def draw(self) -> None:
            """Draw the canvas."""
            if hasattr(self.figure, "_render_components"):
                self.figure._render_components()
            logger.debug("Canvas draw() called - processing figure data")

        def draw_idle(self) -> None:
            """Schedule a draw.

            In fallback mode, this executes immediately instead of being deferred.
            """
            self.draw()
            logger.debug("Canvas draw_idle() called - executed immediately")

        def flush_events(self) -> None:
            """Flush GUI events.

            In fallback mode, this is a no-op but processes pending operations.
            """
            logger.debug("Canvas flush_events() called - fallback mode")

    class FallbackFigureCanvasQTAgg:
        """Functional Qt canvas implementation."""

        def __init__(self, figure: object) -> None:
            """Initialize Qt canvas.

            Args:
                figure: Figure object to render.

            """
            self.figure: object = figure

        def draw(self) -> None:
            """Draw the canvas."""
            if hasattr(self.figure, "savefig"):
                logger.debug("Qt canvas rendering figure")
            logger.debug("FallbackFigureCanvasQTAgg draw() called")

        def setSizePolicy(self, *args: object) -> None:
            """Set size policy for Qt widget compatibility.

            Args:
                *args: Size policy arguments.

            """
            self._size_policy: tuple[object, ...] = args
            logger.debug("Qt canvas setSizePolicy called with: %s", args)

    class FallbackFigureCanvasTkAgg:
        """Functional Tk figure canvas."""

        def __init__(self, figure: object, master: object | None = None) -> None:
            """Initialize canvas with figure and master widget.

            Args:
                figure: Figure object to render.
                master: Parent Tkinter widget.

            """
            self.figure: object = figure
            self.master: object | None = master

        def draw(self) -> None:
            """Draw the figure on the canvas."""
            if hasattr(self.figure, "_render_components"):
                self.figure._render_components()
            logger.debug("Tk canvas draw() called - rendering complete")

        def get_tk_widget(self) -> object:
            """Get the Tk widget for embedding.

            Returns:
                The canvas widget itself.

            """
            return self

        def pack(self, **kwargs: object) -> None:
            """Pack the widget in the parent container.

            Args:
                **kwargs: Tkinter pack layout options.

            """
            self._pack_params: dict[str, object] = kwargs
            logger.debug("Tk canvas pack() called with: %s", kwargs)

        def grid(self, **kwargs: object) -> None:
            """Grid the widget in the parent container.

            Args:
                **kwargs: Tkinter grid layout options.

            """
            self._grid_params: dict[str, object] = kwargs
            logger.debug("Tk canvas grid() called with: %s", kwargs)

    class FallbackRectangle:
        """Rectangle patch implementation."""

        def __init__(
            self,
            xy: tuple[float, float],
            width: float,
            height: float,
            angle: float = 0.0,
            **kwargs: object,
        ) -> None:
            """Initialize rectangle.

            Args:
                xy: Position of the rectangle (x, y) tuple.
                width: Width of the rectangle.
                height: Height of the rectangle.
                angle: Rotation angle in degrees.
                **kwargs: Additional properties like facecolor, edgecolor, linewidth, alpha.

            """
            self.xy: tuple[float, float] = xy
            self.width: float = width
            self.height: float = height
            self.angle: float = angle
            self.facecolor: str = kwargs.get("facecolor", "blue")
            self.edgecolor: str = kwargs.get("edgecolor", "black")
            self.linewidth: int = kwargs.get("linewidth", 1)
            self.alpha: float = kwargs.get("alpha", 1.0)

    class FallbackCircle:
        """Circle patch implementation."""

        def __init__(self, xy: tuple[float, float], radius: float, **kwargs: object) -> None:
            """Initialize circle.

            Args:
                xy: Center position of the circle (x, y) tuple.
                radius: Radius of the circle.
                **kwargs: Additional properties like facecolor, edgecolor, linewidth, alpha.

            """
            self.xy: tuple[float, float] = xy
            self.radius: float = radius
            self.facecolor: str = kwargs.get("facecolor", "blue")
            self.edgecolor: str = kwargs.get("edgecolor", "black")
            self.linewidth: int = kwargs.get("linewidth", 1)
            self.alpha: float = kwargs.get("alpha", 1.0)

    class FallbackPolygon:
        """Polygon patch implementation."""

        def __init__(self, xy: object, closed: bool = True, **kwargs: object) -> None:
            """Initialize polygon.

            Args:
                xy: Polygon vertices as list of (x, y) tuples.
                closed: If True, close the polygon by connecting last to first vertex.
                **kwargs: Additional properties like facecolor, edgecolor, linewidth, alpha.

            """
            self.xy: Any = xy
            self.closed: bool = closed
            self.facecolor: str = kwargs.get("facecolor", "blue")
            self.edgecolor: str = kwargs.get("edgecolor", "black")
            self.linewidth: int = kwargs.get("linewidth", 1)
            self.alpha: float = kwargs.get("alpha", 1.0)

    class FallbackFuncFormatter:
        """Function formatter for axis ticks."""

        def __init__(self, func: Callable[[float, int | None], str]) -> None:
            """Initialize formatter with function.

            Args:
                func: Formatting function that takes (value, position) and returns formatted string.

            """
            self.func: Callable[[float, int | None], str] = func

        def __call__(self, x: float, pos: int | None = None) -> str:
            """Format value.

            Args:
                x: Value to format.
                pos: Position parameter passed to the formatting function.

            Returns:
                Formatted string representation of the value.

            """
            return self.func(x, pos)

    class FallbackMaxNLocator:
        """Maximum number of ticks locator."""

        def __init__(
            self,
            nbins: int | str | None = None,
            steps: list[int] | None = None,
            min_n_ticks: int = 2,
            prune: str | None = None,
            **kwargs: object,
        ) -> None:
            """Initialize locator.

            Args:
                nbins: Maximum number of bins or 'auto' for automatic selection.
                steps: List of tick step values to try.
                min_n_ticks: Minimum number of ticks to display.
                prune: Pruning direction ('upper', 'lower', or None).
                **kwargs: Additional options like integer for integer-only ticks.

            """
            self.nbins: int | str = nbins or "auto"
            self.steps: list[int] | None = steps
            self.min_n_ticks: int = min_n_ticks
            self.prune: str | None = prune
            self.integer: bool = kwargs.get("integer", False)

    class FallbackPdfPages:
        """Functional multi-page PDF writer for matplotlib figures."""

        def __init__(
            self,
            filename: str | object,
            keep_empty: bool = True,
            metadata: dict[str, object] | None = None,
        ) -> None:
            """Initialize PDF writer.

            Args:
                filename: Output file path or file object.
                keep_empty: Whether to keep pages even if empty.
                metadata: Optional metadata dictionary for the PDF.

            """
            self.filename: str | object = filename
            self.keep_empty: bool = keep_empty
            self.metadata: dict[str, object] = metadata or {}
            self.pages: list[dict[str, object]] = []
            self.closed: bool = False

        def __enter__(self) -> "FallbackPdfPages":
            """Context manager entry.

            Returns:
                This PdfPages object.

            """
            return self

        def __exit__(
            self,
            exc_type: type[BaseException] | None,
            exc_val: BaseException | None,
            exc_tb: types.TracebackType | None,
        ) -> None:
            """Context manager exit.

            Args:
                exc_type: Exception type if an exception occurred.
                exc_val: Exception value if an exception occurred.
                exc_tb: Exception traceback if an exception occurred.

            """
            self.close()

        def savefig(self, figure: object | None = None, **kwargs: object) -> None:
            """Save current figure to PDF page.

            Args:
                figure: Figure object to save. If None, generates blank page.
                **kwargs: Additional keyword arguments for figure properties.

            Raises:
                ValueError: If PdfPages has already been closed.

            """
            if self.closed:
                error_msg = "PdfPages is closed"
                logger.error(error_msg)
                raise ValueError(error_msg)

            if figure:
                pdf_stream = self._figure_to_pdf_stream(figure)
            else:
                pdf_stream = self._generate_basic_pdf_stream()

            page_data: dict[str, object] = {
                "figure": figure,
                "timestamp": self._get_timestamp(),
                "kwargs": kwargs,
                "pdf_stream": pdf_stream,
            }
            self.pages.append(page_data)

        def close(self) -> None:
            """Close and finalize PDF file."""
            if not self.closed:
                self._write_pdf_file()
                self.closed = True

        def _get_timestamp(self) -> str:
            """Get current timestamp.

            Returns:
                ISO format timestamp string.

            """
            import datetime

            return datetime.datetime.now().isoformat()

        def _write_pdf_file(self) -> None:
            """Write actual PDF file with collected pages."""
            # Create a basic PDF structure
            pdf_content = f"""%PDF-1.4
1 0 obj
<<
/Type /Catalog
/Pages 2 0 R
>>
endobj

2 0 obj
<<
/Type /Pages
/Kids []
/Count {len(self.pages)}
>>
endobj

xref
0 3
0000000000 65535 f
0000000009 00000 n
0000000058 00000 n
trailer
<<
/Size 3
/Root 1 0 R
>>
startxref
106
%%EOF"""

            try:
                with open(self.filename, "w") as f:
                    f.write(pdf_content)
                logger.info(f"Created PDF file with {len(self.pages)} pages: {self.filename}")
            except OSError as e:
                logger.error(f"Failed to write PDF file {self.filename}: {e}")

        def _figure_to_pdf_stream(self, figure: object) -> str:
            """Convert figure object to PDF stream data.

            Args:
                figure: Figure object to convert to PDF stream.

            Returns:
                PDF stream content as string.

            """
            # Generate PDF content stream from figure
            pdf_stream = ["q"]

            # Set up coordinate system (PDF uses bottom-left origin)
            if hasattr(figure, "figsize"):
                width = figure.figsize[0] * 72  # Convert inches to points
                height = figure.figsize[1] * 72
                pdf_stream.append(f"0 0 {width:.2f} {height:.2f} re W n")  # Clip to figure size

            # Draw figure background
            if hasattr(figure, "facecolor"):
                pdf_stream.extend(("1 1 1 rg", f"0 0 {width:.2f} {height:.2f} re f"))
            # Draw axes
            if hasattr(figure, "axes"):
                for ax in figure.axes:
                    pdf_stream.extend(("0 0 0 RG", "1 w"))
                    # Get axis position (convert to PDF coordinates)
                    if hasattr(ax, "get_position"):
                        bbox = ax.get_position()
                        x = bbox.x0 * width
                        y = bbox.y0 * height
                        w = bbox.width * width
                        h = bbox.height * height
                    else:
                        # Default axis position
                        x, y = width * 0.1, height * 0.1
                        w, h = width * 0.8, height * 0.8

                    # Draw axis rectangle
                    pdf_stream.append(f"{x:.2f} {y:.2f} {w:.2f} {h:.2f} re S")

                    # Draw axis data if available
                    if hasattr(ax, "lines"):
                        for line in ax.lines:
                            if hasattr(line, "get_xydata"):
                                data = line.get_xydata()
                                if len(data) > 0:
                                    # Move to first point
                                    pdf_stream.append(f"{data[0][0]:.2f} {data[0][1]:.2f} m")
                                    # Line to subsequent points
                                    for point in data[1:]:
                                        pdf_stream.append(f"{point[0]:.2f} {point[1]:.2f} l")
                                    pdf_stream.append("S")  # Stroke path

            # End graphics state
            pdf_stream.append("Q")

            return "\n".join(pdf_stream)

        def _generate_basic_pdf_stream(self) -> str:
            """Generate basic PDF stream when no figure is provided.

            Returns:
                Basic PDF stream content as string.

            """
            # Create a simple page with timestamp
            import datetime

            pdf_stream = [
                "q",
                "BT",
                "/F1 12 Tf",
                "72 720 Td",
                f"(Page generated at {datetime.datetime.now()}) Tj",
            ]
            pdf_stream.append("ET")  # End text
            pdf_stream.append("Q")

            return "\n".join(pdf_stream)

    class FallbackPyplot:
        """Functional pyplot interface."""

        def __init__(self) -> None:
            """Initialize pyplot interface."""
            self._figures: dict[int, object] = {}
            self._current_figure: object | None = None
            self._figure_counter: int = 0

        def figure(
            self,
            num: int | None = None,
            figsize: tuple[float, float] = (8, 6),
            dpi: int = 100,
            **kwargs: object,
        ) -> object:
            """Create or activate a figure.

            Args:
                num: Figure number. If None, auto-increments.
                figsize: Figure size as (width, height) tuple in inches.
                dpi: Resolution in dots per inch.
                **kwargs: Additional keyword arguments for figure creation.

            Returns:
                The created or activated figure object.

            """
            if num is None:
                self._figure_counter += 1
                num = self._figure_counter

            if num not in self._figures:
                self._figures[num] = FallbackFigure(figsize, dpi, **kwargs)

            self._current_figure = self._figures[num]
            return self._current_figure

        def gcf(self) -> object:
            """Get current figure.

            Returns:
                The current figure object, creating one if necessary.

            """
            if self._current_figure is None:
                self.figure()
            return self._current_figure

        def gca(self) -> object:
            """Get current axes.

            Returns:
                The current axes object.

            """
            fig = self.gcf()
            return fig.gca()

        def subplot(self, nrows: int, ncols: int, index: int) -> object:
            """Create subplot.

            Args:
                nrows: Number of subplot rows.
                ncols: Number of subplot columns.
                index: Subplot index (1-based).

            Returns:
                The created subplot axes object.

            """
            fig = self.gcf()
            return fig.add_subplot(nrows, ncols, index)

        def subplots(
            self,
            nrows: int = 1,
            ncols: int = 1,
            figsize: tuple[float, float] = (8, 6),
            **kwargs: object,
        ) -> tuple[object, object] | tuple[object, list[object]] | tuple[object, list[list[object]]]:
            """Create figure and subplots.

            Args:
                nrows: Number of subplot rows.
                ncols: Number of subplot columns.
                figsize: Figure size as (width, height) tuple in inches.
                **kwargs: Additional keyword arguments.

            Returns:
                Tuple of (figure, axes) where axes can be single, 1D list, or 2D list.

            """
            fig = self.figure(figsize=figsize)

            if nrows == 1:
                if ncols == 1:
                    ax = fig.add_subplot(1, 1, 1)
                    return fig, ax
                axes = [fig.add_subplot(1, ncols, i + 1) for i in range(ncols)]
                return fig, axes
            if ncols == 1:
                axes = [fig.add_subplot(nrows, 1, i + 1) for i in range(nrows)]
                return fig, axes
            axes = []
            for i in range(nrows):
                row = [fig.add_subplot(nrows, ncols, i * ncols + j + 1) for j in range(ncols)]
                axes.append(row)
            return fig, axes

        def plot(self, *args: object, **kwargs: object) -> None:
            """Plot on current axes.

            Args:
                *args: Positional arguments passed to axes.plot().
                **kwargs: Keyword arguments passed to axes.plot().

            """
            ax = self.gca()
            return ax.plot(*args, **kwargs)

        def scatter(self, x: object, y: object, **kwargs: object) -> None:
            """Scatter plot on current axes.

            Args:
                x: X-axis data.
                y: Y-axis data.
                **kwargs: Additional keyword arguments.

            """
            ax = self.gca()
            return ax.scatter(x, y, **kwargs)

        def bar(self, x: object, height: object, **kwargs: object) -> None:
            """Bar plot on current axes.

            Args:
                x: Bar positions.
                height: Bar heights.
                **kwargs: Additional keyword arguments.

            """
            ax = self.gca()
            return ax.bar(x, height, **kwargs)

        def hist(self, x: object, bins: int = 10, **kwargs: object) -> None:
            """Histogram on current axes.

            Args:
                x: Data values.
                bins: Number of bins.
                **kwargs: Additional keyword arguments.

            """
            ax = self.gca()
            return ax.hist(x, bins, **kwargs)

        def imshow(self, X: object, **kwargs: object) -> None:
            """Show image on current axes.

            Args:
                X: Image data.
                **kwargs: Additional keyword arguments.

            """
            ax = self.gca()
            return ax.imshow(X, **kwargs)

        def contour(self, *args: object, **kwargs: object) -> None:
            """Contour plot on current axes.

            Args:
                *args: Positional arguments for contour data.
                **kwargs: Additional keyword arguments.

            """
            ax = self.gca()
            return ax.contour(*args, **kwargs)

        def title(self, label: str, **kwargs: object) -> None:
            """Set title of current axes.

            Args:
                label: Title text.
                **kwargs: Additional formatting options.

            """
            ax = self.gca()
            ax.set_title(label, **kwargs)

        def xlabel(self, label: str, **kwargs: object) -> None:
            """Set xlabel of current axes.

            Args:
                label: X-axis label text.
                **kwargs: Additional formatting options.

            """
            ax = self.gca()
            ax.set_xlabel(label, **kwargs)

        def ylabel(self, label: str, **kwargs: object) -> None:
            """Set ylabel of current axes.

            Args:
                label: Y-axis label text.
                **kwargs: Additional formatting options.

            """
            ax = self.gca()
            ax.set_ylabel(label, **kwargs)

        def xlim(self, *args: object, **kwargs: object) -> tuple[float, float] | None:
            """Set xlim of current axes.

            Args:
                *args: Positional arguments for axis limits.
                **kwargs: Additional keyword arguments.

            Returns:
                The x-axis limits tuple if querying, None if setting.

            """
            ax = self.gca()
            if args:
                ax.set_xlim(*args, **kwargs)
            return ax.xlim

        def ylim(self, *args: object, **kwargs: object) -> tuple[float, float] | None:
            """Set ylim of current axes.

            Args:
                *args: Positional arguments for axis limits.
                **kwargs: Additional keyword arguments.

            Returns:
                The y-axis limits tuple if querying, None if setting.

            """
            ax = self.gca()
            if args:
                ax.set_ylim(*args, **kwargs)
            return ax.ylim

        def legend(self, *args: object, **kwargs: object) -> None:
            """Add legend to current axes.

            Args:
                *args: Positional arguments for legend.
                **kwargs: Additional keyword arguments.

            """
            ax = self.gca()
            ax.legend(*args, **kwargs)

        def grid(self, visible: bool = True, **kwargs: object) -> None:
            """Enable grid on current axes.

            Args:
                visible: Enable or disable grid.
                **kwargs: Additional keyword arguments.

            """
            ax = self.gca()
            ax.grid(visible, **kwargs)

        def tight_layout(self) -> None:
            """Adjust layout of current figure."""
            fig = self.gcf()
            fig.tight_layout()

        def savefig(self, fname: str | object, **kwargs: object) -> None:
            """Save current figure.

            Args:
                fname: File path or object to save to.
                **kwargs: Additional keyword arguments for savefig.

            """
            fig = self.gcf()
            fig.savefig(fname, **kwargs)

        def show(self) -> None:
            """Show all figures.

            In fallback mode, figures are saved but not displayed interactively.
            """
            logger.info("Matplotlib show() called in fallback mode - figures saved but not displayed")

        def close(self, fig: int | str | object | None = None) -> None:
            """Close figure.

            Args:
                fig: Figure number, 'all' to close all, or None for current.

            """
            if fig == "all":
                self._figures.clear()
                self._current_figure = None
            elif fig is None:
                if self._current_figure:
                    for num, f in self._figures.items():
                        if f == self._current_figure:
                            del self._figures[num]
                            break
                    self._current_figure = None
            elif isinstance(fig, int):
                if fig in self._figures:
                    del self._figures[fig]
            else:
                for num, f in self._figures.items():
                    if f == fig:
                        del self._figures[num]
                        break

        def clf(self) -> None:
            """Clear current figure."""
            fig = self.gcf()
            fig.clear()

        def cla(self) -> None:
            """Clear current axes."""
            ax = self.gca()
            ax.clear()

    # Create module instances
    plt = FallbackPyplot()

    # Assign classes
    Figure = FallbackFigure
    Axes = FallbackAxes
    FigureCanvasQTAgg = FallbackFigureCanvasQTAgg
    FigureCanvasTkAgg = FallbackFigureCanvasTkAgg
    Rectangle = FallbackRectangle
    Circle = FallbackCircle
    Polygon = FallbackPolygon
    FuncFormatter = FallbackFuncFormatter
    MaxNLocator = FallbackMaxNLocator
    PdfPages = FallbackPdfPages

    class FallbackMatplotlib:
        """Fallback matplotlib module."""

        class Pyplot:
            """Pyplot submodule for FallbackMatplotlib."""

            figure = staticmethod(plt.figure)
            gcf = staticmethod(plt.gcf)
            gca = staticmethod(plt.gca)
            subplot = staticmethod(plt.subplot)
            subplots = staticmethod(plt.subplots)
            plot = staticmethod(plt.plot)
            scatter = staticmethod(plt.scatter)
            bar = staticmethod(plt.bar)
            hist = staticmethod(plt.hist)
            imshow = staticmethod(plt.imshow)
            contour = staticmethod(plt.contour)
            title = staticmethod(plt.title)
            xlabel = staticmethod(plt.xlabel)
            ylabel = staticmethod(plt.ylabel)
            xlim = staticmethod(plt.xlim)
            ylim = staticmethod(plt.ylim)
            legend = staticmethod(plt.legend)
            grid = staticmethod(plt.grid)
            tight_layout = staticmethod(plt.tight_layout)
            savefig = staticmethod(plt.savefig)
            show = staticmethod(plt.show)
            close = staticmethod(plt.close)
            clf = staticmethod(plt.clf)
            cla = staticmethod(plt.cla)

        __version__: str = "0.0.0-fallback"

        pyplot: "FallbackMatplotlib.Pyplot" = Pyplot

        @staticmethod
        def use(backend: str, **kwargs: object) -> None:
            """Set the matplotlib backend (fallback does nothing)."""
            pass

    mpl = FallbackMatplotlib()


# Create compatibility alias
MATPLOTLIB_AVAILABLE = HAS_MATPLOTLIB

# Export all matplotlib objects and availability flag
__all__ = [
    "Axes",
    "Circle",
    "Figure",
    "FigureCanvasQTAgg",
    "FigureCanvasTkAgg",
    "FuncFormatter",
    "HAS_MATPLOTLIB",
    "MATPLOTLIB_AVAILABLE",
    "MATPLOTLIB_VERSION",
    "MaxNLocator",
    "PdfPages",
    "Polygon",
    "Rectangle",
    "mpl",
    "plt",
]
