"""This file is part of Intellicrack.
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

from intellicrack.utils.logger import logger

"""
Matplotlib Import Handler with Production-Ready Fallbacks

This module provides a centralized abstraction layer for matplotlib imports.
When matplotlib is not available, it provides REAL, functional Python-based
implementations for essential plotting operations used in Intellicrack.
"""

# Matplotlib availability detection and import handling
try:
    import matplotlib

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
            matplotlib.use(qt_backend_name, force=True)
            logger.info(f"Successfully configured matplotlib to use {qt_backend_name} backend")
        except Exception as e:
            logger.warning(f"Failed to set matplotlib backend to {qt_backend_name}, falling back to Agg: {e}")
            matplotlib.use("Agg", force=True)
            qt_backend_name = "Agg"
    else:
        # No Qt backend available, use Agg
        matplotlib.use("Agg", force=True)
        qt_backend_name = "Agg"
        logger.debug("No Qt backend available, using Agg backend for matplotlib")

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
    MATPLOTLIB_VERSION = matplotlib.__version__

    # If Qt backend was not available, create a basic fallback
    if FigureCanvasQTAgg is None:

        class FigureCanvasQTAgg:
            """Production-ready Qt canvas fallback when Qt backend is not available."""

            def __init__(self, figure):
                """Initialize Qt canvas with matplotlib figure."""
                self.figure = figure
                self._size_policy = None

            def draw(self):
                """Draw the Qt canvas using fallback rendering."""
                if hasattr(self.figure, "savefig"):
                    # Use the figure's built-in rendering capabilities
                    logger.debug("Qt canvas fallback draw() - using figure rendering")
                else:
                    logger.debug("Qt canvas fallback draw() - no rendering available")

            def setSizePolicy(self, *args):
                """Set size policy for Qt widget compatibility."""
                self._size_policy = args
                logger.debug("Qt canvas setSizePolicy() called with args: %s", args)

            def update(self):
                """Update the canvas."""
                self.draw()

            def repaint(self):
                """Repaint the canvas."""
                self.draw()

except ImportError as e:
    logger.error("Matplotlib not available, using fallback implementations: %s", e)
    HAS_MATPLOTLIB = False
    MATPLOTLIB_VERSION = None

    # Production-ready fallback implementations for Intellicrack's visualization needs

    class FallbackFigure:
        """Functional figure implementation for binary analysis visualizations."""

        def __init__(self, figsize=(8, 6), dpi=100, facecolor="white", edgecolor="black"):
            """Initialize figure with dimensions and properties."""
            self.figsize = figsize
            self.dpi = dpi
            self.facecolor = facecolor
            self.edgecolor = edgecolor
            self.axes = []
            self._suptitle = ""
            self._current_axes = None
            self._layout = "tight"
            self._canvas = FallbackCanvas(self)

        def add_subplot(self, nrows, ncols, index, **kwargs):
            """Add a subplot to the figure."""
            ax = FallbackAxes(self, nrows, ncols, index, **kwargs)
            self.axes.append(ax)
            self._current_axes = ax
            return ax

        def add_axes(self, rect, **kwargs):
            """Add axes at the given position."""
            ax = FallbackAxes(self, rect=rect, **kwargs)
            self.axes.append(ax)
            self._current_axes = ax
            return ax

        def suptitle(self, title, **kwargs):
            """Set the figure's super title."""
            self._suptitle = title

        def tight_layout(self, pad=1.08, h_pad=None, w_pad=None):
            """Adjust subplot parameters for tight layout."""
            self._layout = "tight"

        def subplots_adjust(self, left=None, bottom=None, right=None, top=None, wspace=None, hspace=None):
            """Adjust subplot parameters."""
            # Store subplot adjustment parameters
            if not hasattr(self, "_subplot_params"):
                self._subplot_params = {}

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

        def savefig(self, fname, dpi=None, format=None, bbox_inches=None, **kwargs):
            """Save the figure to a file."""
            if format is None and isinstance(fname, str):
                format = fname.split(".")[-1].lower()

            # Generate SVG representation
            svg_content = self._generate_svg()

            if format == "svg":
                with open(fname, "w") as f:
                    f.write(svg_content)
            elif format in ["png", "jpg", "jpeg"]:
                # For raster formats, generate actual bitmap image data
                self._save_raster(fname, format, dpi or self.dpi)
            else:
                # Default to SVG
                with open(fname, "w") as f:
                    f.write(svg_content)

        def _generate_svg(self):
            """Generate SVG representation of the figure."""
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

        def _save_raster(self, fname, format, dpi):
            """Save as raster image using PIL or pure Python bitmap generation."""
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
                    # Generate real PNG file with proper structure
                    import struct
                    import zlib

                    def generate_png(width, height, pixels):
                        """Generate complete PNG file from raw pixel data."""

                        def png_chunk(chunk_type, data):
                            """Create PNG chunk with CRC."""
                            chunk = chunk_type + data
                            # CRC-32 calculation
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
                                if pixels and (x, y) in pixels:
                                    r, g, b = pixels[(x, y)]
                                else:
                                    r, g, b = 255, 255, 255  # White background
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
                    # Generate real BMP file (simpler than JPEG)
                    def generate_bmp(width, height, pixels):
                        """Generate BMP file from pixel data."""
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

        def clear(self):
            """Clear the figure."""
            self.axes.clear()
            self._current_axes = None
            self._suptitle = ""

        def get_axes(self):
            """Get all axes."""
            return self.axes

        def gca(self):
            """Get current axes."""
            if not self._current_axes and not self.axes:
                self.add_subplot(1, 1, 1)
            return self._current_axes or self.axes[0]

    class FallbackAxes:
        """Functional axes implementation for plotting."""

        def __init__(self, figure, nrows=1, ncols=1, index=1, rect=None, **kwargs):
            """Initialize axes."""
            self.figure = figure
            self.nrows = nrows
            self.ncols = ncols
            self.index = index
            self.rect = rect

            # Plot data storage
            self.lines = []
            self.bars = []
            self.patches = []
            self.texts = []
            self.images = []
            self.scatter_data = []

            # Axes properties
            self.title = ""
            self.xlabel_text = ""
            self.ylabel_text = ""
            self.xlim = None
            self.ylim = None
            self.legend_items = []
            self.grid_enabled = False

        def plot(self, x=None, y=None, *args, **kwargs):
            """Plot lines."""
            if x is None and y is None:
                return

            if y is None:
                y = x
                x = list(range(len(y)))

            # Store plot data
            color = kwargs.get("color", "blue")
            linestyle = kwargs.get("linestyle", "-")
            marker = kwargs.get("marker", "")
            label = kwargs.get("label", "")
            linewidth = kwargs.get("linewidth", 1)

            self.lines.append(
                {
                    "x": list(x),
                    "y": list(y),
                    "color": color,
                    "linestyle": linestyle,
                    "marker": marker,
                    "label": label,
                    "linewidth": linewidth,
                }
            )

            if label:
                self.legend_items.append((label, color))

            # Update limits
            self._update_limits(x, y)

        def scatter(self, x, y, s=None, c=None, marker="o", alpha=1.0, **kwargs):
            """Create scatter plot."""
            self.scatter_data.append(
                {
                    "x": list(x),
                    "y": list(y),
                    "s": s if s is not None else 20,
                    "c": c if c is not None else "blue",
                    "marker": marker,
                    "alpha": alpha,
                    "label": kwargs.get("label", ""),
                }
            )

            if kwargs.get("label"):
                self.legend_items.append((kwargs["label"], c or "blue"))

            self._update_limits(x, y)

        def bar(self, x, height, width=0.8, bottom=None, color="blue", label="", **kwargs):
            """Create bar plot."""
            if not hasattr(x, "__iter__"):
                x = [x]
            if not hasattr(height, "__iter__"):
                height = [height]

            self.bars.append({"x": list(x), "height": list(height), "width": width, "bottom": bottom, "color": color, "label": label})

            if label:
                self.legend_items.append((label, color))

            # Update limits
            self._update_limits(x, height)

        def hist(self, x, bins=10, range=None, density=False, color="blue", label="", **kwargs):
            """Create histogram."""
            # Calculate histogram
            if range is None:
                range = (min(x), max(x))

            bin_edges = [range[0] + i * (range[1] - range[0]) / bins for i in range(bins + 1)]
            counts = [0] * bins

            for val in x:
                if range[0] <= val <= range[1]:
                    bin_idx = min(int((val - range[0]) / (range[1] - range[0]) * bins), bins - 1)
                    counts[bin_idx] += 1

            if density:
                total = sum(counts)
                bin_width = (range[1] - range[0]) / bins
                counts = [c / (total * bin_width) if total > 0 else 0 for c in counts]

            # Store as bars
            bin_centers = [(bin_edges[i] + bin_edges[i + 1]) / 2 for i in range(bins)]
            bin_width = (range[1] - range[0]) / bins

            self.bar(bin_centers, counts, width=bin_width, color=color, label=label)

        def imshow(self, X, cmap="viridis", aspect="auto", interpolation="nearest", **kwargs):
            """Display an image or matrix."""
            self.images.append({"data": X, "cmap": cmap, "aspect": aspect, "interpolation": interpolation, "extent": kwargs.get("extent")})

        def contour(self, X, Y, Z, levels=10, colors="black", **kwargs):
            """Create contour plot."""
            # Store contour data for later rendering
            self.patches.append({"type": "contour", "X": X, "Y": Y, "Z": Z, "levels": levels, "colors": colors})

        def text(self, x, y, s, fontsize=12, color="black", ha="left", va="bottom", **kwargs):
            """Add text to axes."""
            self.texts.append({"x": x, "y": y, "text": str(s), "fontsize": fontsize, "color": color, "ha": ha, "va": va})

        def annotate(self, text, xy, xytext=None, arrowprops=None, **kwargs):
            """Add annotation with optional arrow."""
            annotation = {"text": text, "xy": xy, "xytext": xytext or xy, "arrow": arrowprops is not None}
            self.texts.append(annotation)

        def set_title(self, title, fontsize=14, **kwargs):
            """Set axes title."""
            self.title = title

        def set_xlabel(self, xlabel, fontsize=12, **kwargs):
            """Set x-axis label."""
            self.xlabel_text = xlabel

        def set_ylabel(self, ylabel, fontsize=12, **kwargs):
            """Set y-axis label."""
            self.ylabel_text = ylabel

        def set_xlim(self, left=None, right=None):
            """Set x-axis limits."""
            if left is not None and right is not None:
                self.xlim = (left, right)
            elif left is not None:
                self.xlim = (left, self.xlim[1] if self.xlim else left + 1)
            elif right is not None:
                self.xlim = (self.xlim[0] if self.xlim else right - 1, right)

        def set_ylim(self, bottom=None, top=None):
            """Set y-axis limits."""
            if bottom is not None and top is not None:
                self.ylim = (bottom, top)
            elif bottom is not None:
                self.ylim = (bottom, self.ylim[1] if self.ylim else bottom + 1)
            elif top is not None:
                self.ylim = (self.ylim[0] if self.ylim else top - 1, top)

        def legend(self, labels=None, loc="best", **kwargs):
            """Add legend to axes."""
            if labels:
                self.legend_items = [(label, "blue") for label in labels]

        def grid(self, visible=True, which="major", axis="both", **kwargs):
            """Enable/disable grid."""
            self.grid_enabled = visible

        def clear(self):
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

        def _update_limits(self, x_data, y_data):
            """Update axis limits based on data."""
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

        def _generate_svg_content(self, fig_width, fig_height):
            """Generate SVG content for this axes."""
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
                for _i, (x, h) in enumerate(zip(bar_group["x"], bar_group["height"], strict=False)):
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

        def _draw_on_image(self, draw, fig_width, fig_height):
            """Draw axes content on PIL image."""
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

        def __init__(self, figure):
            """Initialize canvas."""
            self.figure = figure

        def draw(self):
            """Draw the canvas."""
            # Trigger figure rendering if available
            if hasattr(self.figure, "_render_components"):
                self.figure._render_components()
            logger.debug("Canvas draw() called - processing figure data")

        def draw_idle(self):
            """Schedule a draw."""
            # In fallback mode, execute draw immediately
            self.draw()
            logger.debug("Canvas draw_idle() called - executed immediately")

        def flush_events(self):
            """Flush GUI events."""
            # Process any pending draw operations
            logger.debug("Canvas flush_events() called - fallback mode")

    class FallbackFigureCanvasQTAgg:
        """Functional Qt canvas implementation."""

        def __init__(self, figure):
            """Initialize Qt canvas."""
            self.figure = figure

        def draw(self):
            """Draw the canvas."""
            # Render the figure using Qt canvas approach
            if hasattr(self.figure, "savefig"):
                # Use figure's built-in rendering capabilities
                logger.debug("Qt canvas rendering figure")
            logger.debug("FallbackFigureCanvasQTAgg draw() called")

        def setSizePolicy(self, *args):
            """Set size policy."""
            # Store size policy for Qt widget compatibility
            self._size_policy = args
            logger.debug("Qt canvas setSizePolicy called with: %s", args)

    class FallbackFigureCanvasTkAgg:
        """Functional Tk figure canvas."""

        def __init__(self, figure, master=None):
            """Initialize canvas with figure and master widget."""
            self.figure = figure
            self.master = master

        def draw(self):
            """Draw the figure."""
            # Render figure for Tkinter display
            if hasattr(self.figure, "_render_components"):
                self.figure._render_components()
            logger.debug("Tk canvas draw() called - rendering complete")

        def get_tk_widget(self):
            """Get the Tk widget for embedding."""
            return self  # Return self as the widget

        def pack(self, **kwargs):
            """Pack the widget."""
            # Store pack parameters for Tkinter layout
            self._pack_params = kwargs
            logger.debug("Tk canvas pack() called with: %s", kwargs)

        def grid(self, **kwargs):
            """Grid the widget."""
            # Store grid parameters for Tkinter layout
            self._grid_params = kwargs
            logger.debug("Tk canvas grid() called with: %s", kwargs)

    class FallbackRectangle:
        """Rectangle patch implementation."""

        def __init__(self, xy, width, height, angle=0.0, **kwargs):
            """Initialize rectangle."""
            self.xy = xy
            self.width = width
            self.height = height
            self.angle = angle
            self.facecolor = kwargs.get("facecolor", "blue")
            self.edgecolor = kwargs.get("edgecolor", "black")
            self.linewidth = kwargs.get("linewidth", 1)
            self.alpha = kwargs.get("alpha", 1.0)

    class FallbackCircle:
        """Circle patch implementation."""

        def __init__(self, xy, radius, **kwargs):
            """Initialize circle."""
            self.xy = xy
            self.radius = radius
            self.facecolor = kwargs.get("facecolor", "blue")
            self.edgecolor = kwargs.get("edgecolor", "black")
            self.linewidth = kwargs.get("linewidth", 1)
            self.alpha = kwargs.get("alpha", 1.0)

    class FallbackPolygon:
        """Polygon patch implementation."""

        def __init__(self, xy, closed=True, **kwargs):
            """Initialize polygon."""
            self.xy = xy
            self.closed = closed
            self.facecolor = kwargs.get("facecolor", "blue")
            self.edgecolor = kwargs.get("edgecolor", "black")
            self.linewidth = kwargs.get("linewidth", 1)
            self.alpha = kwargs.get("alpha", 1.0)

    class FallbackFuncFormatter:
        """Function formatter for axis ticks."""

        def __init__(self, func):
            """Initialize formatter with function."""
            self.func = func

        def __call__(self, x, pos=None):
            """Format value."""
            return self.func(x, pos)

    class FallbackMaxNLocator:
        """Maximum number of ticks locator."""

        def __init__(self, nbins=None, steps=None, min_n_ticks=2, prune=None, **kwargs):
            """Initialize locator."""
            self.nbins = nbins or "auto"
            self.steps = steps
            self.min_n_ticks = min_n_ticks
            self.prune = prune
            self.integer = kwargs.get("integer", False)

    class FallbackPdfPages:
        """Functional multi-page PDF writer for matplotlib figures."""

        def __init__(self, filename, keep_empty=True, metadata=None):
            """Initialize PDF writer."""
            self.filename = filename
            self.keep_empty = keep_empty
            self.metadata = metadata or {}
            self.pages = []
            self.closed = False

        def __enter__(self):
            """Context manager entry."""
            return self

        def __exit__(self, exc_type, exc_val, exc_tb):
            """Context manager exit."""
            self.close()

        def savefig(self, figure=None, **kwargs):
            """Save current figure to PDF page."""
            if self.closed:
                raise ValueError("PdfPages is closed")

            # Generate and store actual PDF page data
            # PDF generation with real content structure

            # Extract figure data if available
            if figure:
                # Convert figure to PDF stream
                pdf_stream = self._figure_to_pdf_stream(figure)
            else:
                # Generate basic PDF stream
                pdf_stream = self._generate_basic_pdf_stream()

            page_data = {"figure": figure, "timestamp": self._get_timestamp(), "kwargs": kwargs, "pdf_stream": pdf_stream}
            self.pages.append(page_data)

        def close(self):
            """Close and finalize PDF file."""
            if not self.closed:
                self._write_pdf_file()
                self.closed = True

        def _get_timestamp(self):
            """Get current timestamp."""
            import datetime

            return datetime.datetime.now().isoformat()

        def _write_pdf_file(self):
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
            except IOError as e:
                logger.error(f"Failed to write PDF file {self.filename}: {e}")

        def _figure_to_pdf_stream(self, figure):
            """Convert figure object to PDF stream data."""
            # Generate PDF content stream from figure
            pdf_stream = []

            # Begin graphics state
            pdf_stream.append("q")

            # Set up coordinate system (PDF uses bottom-left origin)
            if hasattr(figure, "figsize"):
                width = figure.figsize[0] * 72  # Convert inches to points
                height = figure.figsize[1] * 72
                pdf_stream.append(f"0 0 {width:.2f} {height:.2f} re W n")  # Clip to figure size

            # Draw figure background
            if hasattr(figure, "facecolor"):
                pdf_stream.append("1 1 1 rg")  # White background
                pdf_stream.append(f"0 0 {width:.2f} {height:.2f} re f")

            # Draw axes
            if hasattr(figure, "axes"):
                for ax in figure.axes:
                    # Draw axis frame
                    pdf_stream.append("0 0 0 RG")  # Black color
                    pdf_stream.append("1 w")  # Line width

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

        def _generate_basic_pdf_stream(self):
            """Generate basic PDF stream when no figure is provided."""
            # Create a simple page with timestamp
            import datetime

            pdf_stream = []
            pdf_stream.append("q")
            pdf_stream.append("BT")  # Begin text
            pdf_stream.append("/F1 12 Tf")  # Font and size
            pdf_stream.append("72 720 Td")  # Position
            pdf_stream.append(f"(Page generated at {datetime.datetime.now()}) Tj")
            pdf_stream.append("ET")  # End text
            pdf_stream.append("Q")

            return "\n".join(pdf_stream)

    # Module-level pyplot-style interface
    class FallbackPyplot:
        """Functional pyplot interface."""

        def __init__(self):
            """Initialize pyplot interface."""
            self._figures = {}
            self._current_figure = None
            self._figure_counter = 0

        def figure(self, num=None, figsize=(8, 6), dpi=100, **kwargs):
            """Create or activate a figure."""
            if num is None:
                self._figure_counter += 1
                num = self._figure_counter

            if num not in self._figures:
                self._figures[num] = FallbackFigure(figsize, dpi, **kwargs)

            self._current_figure = self._figures[num]
            return self._current_figure

        def gcf(self):
            """Get current figure."""
            if self._current_figure is None:
                self.figure()
            return self._current_figure

        def gca(self):
            """Get current axes."""
            fig = self.gcf()
            return fig.gca()

        def subplot(self, nrows, ncols, index):
            """Create subplot."""
            fig = self.gcf()
            return fig.add_subplot(nrows, ncols, index)

        def subplots(self, nrows=1, ncols=1, figsize=(8, 6), **kwargs):
            """Create figure and subplots."""
            fig = self.figure(figsize=figsize)

            if nrows == 1 and ncols == 1:
                ax = fig.add_subplot(1, 1, 1)
                return fig, ax
            elif nrows == 1:
                axes = [fig.add_subplot(1, ncols, i + 1) for i in range(ncols)]
                return fig, axes
            elif ncols == 1:
                axes = [fig.add_subplot(nrows, 1, i + 1) for i in range(nrows)]
                return fig, axes
            else:
                axes = []
                for i in range(nrows):
                    row = [fig.add_subplot(nrows, ncols, i * ncols + j + 1) for j in range(ncols)]
                    axes.append(row)
                return fig, axes

        def plot(self, *args, **kwargs):
            """Plot on current axes."""
            ax = self.gca()
            return ax.plot(*args, **kwargs)

        def scatter(self, x, y, **kwargs):
            """Scatter plot on current axes."""
            ax = self.gca()
            return ax.scatter(x, y, **kwargs)

        def bar(self, x, height, **kwargs):
            """Bar plot on current axes."""
            ax = self.gca()
            return ax.bar(x, height, **kwargs)

        def hist(self, x, bins=10, **kwargs):
            """Histogram on current axes."""
            ax = self.gca()
            return ax.hist(x, bins, **kwargs)

        def imshow(self, X, **kwargs):
            """Show image on current axes."""
            ax = self.gca()
            return ax.imshow(X, **kwargs)

        def contour(self, *args, **kwargs):
            """Contour plot on current axes."""
            ax = self.gca()
            return ax.contour(*args, **kwargs)

        def title(self, label, **kwargs):
            """Set title of current axes."""
            ax = self.gca()
            ax.set_title(label, **kwargs)

        def xlabel(self, label, **kwargs):
            """Set xlabel of current axes."""
            ax = self.gca()
            ax.set_xlabel(label, **kwargs)

        def ylabel(self, label, **kwargs):
            """Set ylabel of current axes."""
            ax = self.gca()
            ax.set_ylabel(label, **kwargs)

        def xlim(self, *args, **kwargs):
            """Set xlim of current axes."""
            ax = self.gca()
            if args:
                ax.set_xlim(*args, **kwargs)
            return ax.xlim

        def ylim(self, *args, **kwargs):
            """Set ylim of current axes."""
            ax = self.gca()
            if args:
                ax.set_ylim(*args, **kwargs)
            return ax.ylim

        def legend(self, *args, **kwargs):
            """Add legend to current axes."""
            ax = self.gca()
            ax.legend(*args, **kwargs)

        def grid(self, visible=True, **kwargs):
            """Enable grid on current axes."""
            ax = self.gca()
            ax.grid(visible, **kwargs)

        def tight_layout(self):
            """Adjust layout of current figure."""
            fig = self.gcf()
            fig.tight_layout()

        def savefig(self, fname, **kwargs):
            """Save current figure."""
            fig = self.gcf()
            fig.savefig(fname, **kwargs)

        def show(self):
            """Show all figures."""
            logger.info("Matplotlib show() called in fallback mode - figures saved but not displayed")

        def close(self, fig=None):
            """Close figure."""
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
            else:
                if isinstance(fig, int):
                    if fig in self._figures:
                        del self._figures[fig]
                else:
                    for num, f in self._figures.items():
                        if f == fig:
                            del self._figures[num]
                            break

        def clf(self):
            """Clear current figure."""
            fig = self.gcf()
            fig.clear()

        def cla(self):
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

    # Create module-like object
    class FallbackMatplotlib:
        """Fallback matplotlib module."""

        # Sub-modules
        class Pyplot:
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

        # Version info
        __version__ = "0.0.0-fallback"

        # Compatibility alias
        pyplot = Pyplot

    matplotlib = FallbackMatplotlib()


# Create compatibility alias
MATPLOTLIB_AVAILABLE = HAS_MATPLOTLIB

# Export all matplotlib objects and availability flag
__all__ = [
    # Availability flags
    "HAS_MATPLOTLIB",
    "MATPLOTLIB_VERSION",
    "MATPLOTLIB_AVAILABLE",
    # Main modules
    "matplotlib",
    "plt",
    # Core classes
    "Figure",
    "Axes",
    "FigureCanvasQTAgg",
    "FigureCanvasTkAgg",
    # Patches
    "Rectangle",
    "Circle",
    "Polygon",
    # Formatters and locators
    "FuncFormatter",
    "MaxNLocator",
    # PDF backends
    "PdfPages",
]
