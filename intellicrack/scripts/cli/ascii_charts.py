#!/usr/bin/env python3
"""
ASCII Charts - Visual terminal graphs for analysis results

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
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

from collections import Counter
from typing import Any, Dict, List, Tuple, Union

# Optional imports for enhanced charts
try:
    from rich.align import Align
    from rich.columns import Columns
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


class ASCIIChartGenerator:
    """Generate ASCII charts and graphs for analysis data visualization."""

    def __init__(self, width: int = 80, height: int = 20):
        """Initialize chart generator.

        Args:
            width: Chart width in characters
            height: Chart height in characters
        """
        self.width = width
        self.height = height
        self.console = Console() if RICH_AVAILABLE else None

        # Chart symbols
        self.symbols = {
            'bar_full': '█',
            'bar_three_quarters': '▉',
            'bar_half': '▌',
            'bar_quarter': '▎',
            'line_horizontal': '─',
            'line_vertical': '│',
            'corner_top_left': '┌',
            'corner_top_right': '┐',
            'corner_bottom_left': '└',
            'corner_bottom_right': '┘',
            'cross': '┼',
            'tee_up': '┴',
            'tee_down': '┬',
            'tee_left': '┤',
            'tee_right': '├',
            'dot': '•',
            'circle': '○',
            'diamond': '◆',
            'triangle': '▲'
        }

    def generate_bar_chart(self, data: Dict[str, Union[int, float]],
                          title: str = "Bar Chart",
                          show_values: bool = True,
                          color_coding: bool = True) -> str:
        """Generate horizontal bar chart.

        Args:
            data: Dictionary of label -> value pairs
            title: Chart title
            show_values: Whether to show numeric values
            color_coding: Whether to use color coding (if Rich available)

        Returns:
            ASCII bar chart as string
        """
        if not data:
            return "No data to display"

        # Calculate dimensions
        max_label_len = max(len(str(k)) for k in data.keys())
        max_value = max(data.values())
        bar_width = self.width - max_label_len - 15  # Leave space for labels and values

        lines = []
        lines.append(f" {title} ")
        lines.append("=" * len(lines[0]))
        lines.append("")

        # Sort data by value (descending)
        sorted_data = sorted(data.items(), key=lambda x: x[1], reverse=True)

        for label, value in sorted_data:
            # Calculate bar length
            if max_value > 0:
                bar_len = int((value / max_value) * bar_width)
            else:
                bar_len = 0

            # Create bar
            full_bars = bar_len
            bar = self.symbols['bar_full'] * full_bars

            # Add value display
            if show_values:
                value_str = f" {value}"
            else:
                value_str = ""

            # Format line
            line = f"{label:<{max_label_len}} │{bar:<{bar_width}}{value_str}"
            lines.append(line)

        return "\n".join(lines)

    def generate_histogram(self, values: List[Union[int, float]],
                          bins: int = 10,
                          title: str = "Histogram") -> str:
        """Generate histogram chart.

        Args:
            values: List of numeric values
            bins: Number of histogram bins
            title: Chart title

        Returns:
            ASCII histogram as string
        """
        if not values:
            return "No data to display"

        # Calculate bins
        min_val = min(values)
        max_val = max(values)
        bin_width = (max_val - min_val) / bins

        # Create bins
        bin_counts = [0] * bins
        bin_labels = []

        for i in range(bins):
            bin_start = min_val + i * bin_width
            bin_end = min_val + (i + 1) * bin_width
            bin_labels.append(f"{bin_start:.1f}-{bin_end:.1f}")

            # Count values in this bin
            for value in values:
                if bin_start <= value < bin_end or (i == bins - 1 and value == bin_end):
                    bin_counts[i] += 1

        # Create bar chart from histogram data
        hist_data = dict(zip(bin_labels, bin_counts, strict=False))
        return self.generate_bar_chart(hist_data, title)

    def generate_line_chart(self, data: Dict[str, Union[int, float]],
                           title: str = "Line Chart") -> str:
        """Generate simple line chart.

        Args:
            data: Dictionary of x-label -> y-value pairs
            title: Chart title

        Returns:
            ASCII line chart as string
        """
        if not data:
            return "No data to display"

        lines = []
        lines.append(f" {title} ")
        lines.append("=" * len(lines[0]))
        lines.append("")

        # Prepare data
        sorted_items = sorted(data.items())
        labels = [item[0] for item in sorted_items]
        values = [item[1] for item in sorted_items]

        if not values:
            return "No data to display"

        # Calculate scale
        min_val = min(values)
        max_val = max(values)
        value_range = max_val - min_val

        if value_range == 0:
            value_range = 1

        chart_height = self.height - 5  # Leave space for title and axes
        chart_width = min(len(labels) * 3, self.width - 10)

        # Create chart grid
        chart = [[' ' for _ in range(chart_width)] for _ in range(chart_height)]

        # Plot points
        for i, value in enumerate(values):
            if i * 3 < chart_width:
                # Normalize value to chart height
                y = int(((value - min_val) / value_range) * (chart_height - 1))
                y = chart_height - 1 - y  # Flip y-axis
                x = i * 3

                if 0 <= x < chart_width and 0 <= y < chart_height:
                    chart[y][x] = self.symbols['dot']

                    # Connect to previous point
                    if i > 0 and (i - 1) * 3 < chart_width:
                        prev_val = values[i - 1]
                        prev_y = int(((prev_val - min_val) / value_range) * (chart_height - 1))
                        prev_y = chart_height - 1 - prev_y
                        prev_x = (i - 1) * 3

                        # Simple line connection
                        if prev_x < chart_width and prev_y < chart_height:
                            start_x, start_y = prev_x, prev_y
                            end_x, end_y = x, y

                            # Draw line between points
                            steps = max(abs(end_x - start_x), abs(end_y - start_y))
                            if steps > 0:
                                for step in range(1, steps):
                                    intermediate_x = start_x + (end_x - start_x) * step // steps
                                    intermediate_y = start_y + (end_y - start_y) * step // steps
                                    if (0 <= intermediate_x < chart_width and
                                        0 <= intermediate_y < chart_height):
                                        if chart[intermediate_y][intermediate_x] == ' ':
                                            chart[intermediate_y][intermediate_x] = '·'

        # Add chart to lines
        for row in chart:
            lines.append("".join(row))

        # Add x-axis labels
        lines.append("")
        label_line = ""
        for i, label in enumerate(labels):
            if i * 3 < chart_width:
                pos = i * 3
                if pos + len(label) <= chart_width:
                    label_line += " " * (pos - len(label_line)) + label[:3]
        lines.append(label_line)

        return "\n".join(lines)

    def display_chart_rich(self, chart_content: str, title: str = "Analysis Chart") -> None:
        """Display chart with rich formatting and alignment.

        Args:
            chart_content: ASCII chart content to display
            title: Chart title
        """
        if not RICH_AVAILABLE:
            print(f"\n{title}\n{'=' * len(title)}")
            print(chart_content)
            return

        # Create styled title with rich Text formatting
        styled_title = Text(title, style="bold blue")

        # Center align the title
        centered_title = Align.center(styled_title)

        # Create chart content with monospace font for proper alignment
        chart_text = Text(chart_content, style="white")
        centered_chart = Align.center(chart_text)

        # Display with panels and spacing
        self.console.print()
        self.console.print(Panel(centered_title, border_style="blue"))
        self.console.print()
        self.console.print(Panel(centered_chart, border_style="cyan", title="Chart Data"))
        self.console.print()

    def create_styled_legend(self, data: Dict[str, Union[int, float]],
                           title: str = "Legend") -> None:
        """Create a styled legend for chart data using rich Text formatting.

        Args:
            data: Dictionary of label -> value pairs
            title: Legend title
        """
        if not RICH_AVAILABLE:
            print(f"\n{title}:")
            for label, value in data.items():
                print(f"  {label}: {value}")
            return

        # Create styled legend entries
        legend_entries = []
        colors = ["red", "green", "blue", "yellow", "magenta", "cyan"]

        for i, (label, value) in enumerate(data.items()):
            color = colors[i % len(colors)]
            # Create styled text for each legend entry
            entry = Text()
            entry.append("■ ", style=f"bold {color}")  # Colored square
            entry.append(f"{label}: ", style="bold white")
            entry.append(f"{value}", style=f"{color}")
            legend_entries.append(entry)

        # Display legend with alignment
        legend_title = Text(title, style="bold underline")
        self.console.print(Align.center(legend_title))
        self.console.print()

        for entry in legend_entries:
            self.console.print(Align.center(entry))
        self.console.print()

    def generate_pie_chart(self, data: Dict[str, Union[int, float]],
                          title: str = "Pie Chart") -> str:
        """Generate ASCII pie chart representation.

        Args:
            data: Dictionary of label -> value pairs
            title: Chart title

        Returns:
            ASCII pie chart as string
        """
        if not data:
            return "No data to display"

        lines = []
        lines.append(f" {title} ")
        lines.append("=" * len(lines[0]))
        lines.append("")

        total = sum(data.values())
        if total == 0:
            return "No data to display"

        # Calculate percentages
        percentages = {k: (v / total) * 100 for k, v in data.items()}

        # Sort by percentage (descending)
        sorted_data = sorted(percentages.items(), key=lambda x: x[1], reverse=True)

        # Generate pie slices using text representation
        symbols = ['█', '▉', '▊', '▋', '▌', '▍', '▎', '▏']

        for label, percentage in sorted_data:
            # Create visual bar representing percentage
            bar_length = int(percentage / 100 * 50)  # 50 chars max width
            bar = symbols[0] * bar_length

            lines.append(f"{label:<20} {bar} {percentage:5.1f}%")

        return "\n".join(lines)

    def generate_scatter_plot(self, points: List[Tuple[float, float]],
                             title: str = "Scatter Plot") -> str:
        """Generate scatter plot.

        Args:
            points: List of (x, y) coordinate tuples
            title: Chart title

        Returns:
            ASCII scatter plot as string
        """
        if not points:
            return "No data to display"

        lines = []
        lines.append(f" {title} ")
        lines.append("=" * len(lines[0]))
        lines.append("")

        # Find data bounds
        x_values = [p[0] for p in points]
        y_values = [p[1] for p in points]

        min_x, max_x = min(x_values), max(x_values)
        min_y, max_y = min(y_values), max(y_values)

        x_range = max_x - min_x
        y_range = max_y - min_y

        if x_range == 0:
            x_range = 1
        if y_range == 0:
            y_range = 1

        chart_height = self.height - 5
        chart_width = self.width - 10

        # Create chart grid
        chart = [[' ' for _ in range(chart_width)] for _ in range(chart_height)]

        # Plot points
        for x, y in points:
            # Normalize coordinates
            norm_x = int(((x - min_x) / x_range) * (chart_width - 1))
            norm_y = int(((y - min_y) / y_range) * (chart_height - 1))
            norm_y = chart_height - 1 - norm_y  # Flip y-axis

            if 0 <= norm_x < chart_width and 0 <= norm_y < chart_height:
                chart[norm_y][norm_x] = self.symbols['dot']

        # Add chart to lines
        for row in chart:
            lines.append("".join(row))

        return "\n".join(lines)

    def generate_analysis_summary_chart(self, analysis_results: Dict[str, Any]) -> str:
        """Generate comprehensive analysis summary chart.

        Args:
            analysis_results: Analysis results dictionary

        Returns:
            Multi-chart summary as string
        """
        charts = []

        # 1. Analysis categories bar chart
        category_counts = {}
        for category, data in analysis_results.items():
            if isinstance(data, dict):
                category_counts[category.replace('_', ' ').title()] = len(data)
            elif isinstance(data, list):
                category_counts[category.replace('_', ' ').title()] = len(data)
            else:
                category_counts[category.replace('_', ' ').title()] = 1

        if category_counts:
            charts.append(self.generate_bar_chart(
                category_counts,
                "Analysis Categories"
            ))

        # 2. Vulnerability severity distribution
        vuln_data = analysis_results.get('vulnerabilities', {})
        if isinstance(vuln_data, dict) and 'vulnerabilities' in vuln_data:
            vulns = vuln_data['vulnerabilities']
            if isinstance(vulns, list):
                severity_counts = Counter()
                for vuln in vulns:
                    if isinstance(vuln, dict):
                        severity = vuln.get('severity', 'Unknown')
                        severity_counts[severity.title()] += 1

                if severity_counts:
                    charts.append("\n" + "="*50 + "\n")
                    charts.append(self.generate_pie_chart(
                        dict(severity_counts),
                        "Vulnerability Severity Distribution"
                    ))

        # 3. Protection status
        prot_data = analysis_results.get('protections', {})
        if isinstance(prot_data, dict):
            enabled_count = sum(1 for v in prot_data.values() if v)
            disabled_count = len(prot_data) - enabled_count

            if enabled_count + disabled_count > 0:
                charts.append("\n" + "="*50 + "\n")
                charts.append(self.generate_pie_chart(
                    {'Enabled': enabled_count, 'Disabled': disabled_count},
                    "Security Protections Status"
                ))

        # 4. String analysis histogram
        strings_data = analysis_results.get('strings', [])
        if isinstance(strings_data, list) and strings_data:
            string_lengths = [len(s) for s in strings_data if isinstance(s, str)]
            if string_lengths:
                charts.append("\n" + "="*50 + "\n")
                charts.append(self.generate_histogram(
                    string_lengths,
                    bins=8,
                    title="String Length Distribution"
                ))

        return "\n".join(charts) if charts else "No chartable data available"

    def generate_rich_dashboard(self, analysis_results: Dict[str, Any]) -> None:
        """Generate rich terminal dashboard with multiple charts.

        Args:
            analysis_results: Analysis results dictionary
        """
        if not RICH_AVAILABLE or not self.console:
            print("Rich dashboard not available")
            return

        self.console.clear()

        # Title
        title_panel = Panel(
            "[bold cyan]Intellicrack Analysis Dashboard[/bold cyan]",
            style="blue"
        )
        self.console.print(title_panel)

        # Create layout with multiple charts
        charts = []

        # Summary statistics table
        stats_table = Table(title="Analysis Summary")
        stats_table.add_column("Category", style="cyan")
        stats_table.add_column("Count", style="yellow")
        stats_table.add_column("Details", style="green")

        for category, data in analysis_results.items():
            if isinstance(data, dict):
                count = len(data)
                details = f"{count} items"
            elif isinstance(data, list):
                count = len(data)
                details = f"{count} entries"
            else:
                count = 1
                details = "Single value"

            stats_table.add_row(
                category.replace('_', ' ').title(),
                str(count),
                details
            )

        charts.append(Panel(stats_table, title="📊 Summary"))

        # Vulnerability chart
        vuln_data = analysis_results.get('vulnerabilities', {})
        if isinstance(vuln_data, dict) and 'vulnerabilities' in vuln_data:
            vulns = vuln_data['vulnerabilities']
            if isinstance(vulns, list) and vulns:
                vuln_table = Table(title="🔴 Vulnerabilities by Severity")
                vuln_table.add_column("Severity", style="red")
                vuln_table.add_column("Count", style="yellow")
                vuln_table.add_column("Percentage", style="green")

                severity_counts = Counter()
                for vuln in vulns:
                    if isinstance(vuln, dict):
                        severity = vuln.get('severity', 'Unknown')
                        severity_counts[severity.title()] += 1

                total_vulns = sum(severity_counts.values())
                for severity, count in severity_counts.most_common():
                    percentage = (count / total_vulns) * 100
                    vuln_table.add_row(
                        severity,
                        str(count),
                        f"{percentage:.1f}%"
                    )

                charts.append(Panel(vuln_table, title="🔍 Security Issues"))

        # Protection status
        prot_data = analysis_results.get('protections', {})
        if isinstance(prot_data, dict) and prot_data:
            prot_table = Table(title="🛡️ Security Protections")
            prot_table.add_column("Protection", style="cyan")
            prot_table.add_column("Status", style="bold")
            prot_table.add_column("Description", style="dim")

            prot_descriptions = {
                'aslr': 'Address Space Layout Randomization',
                'dep': 'Data Execution Prevention',
                'canary': 'Stack Canary Protection',
                'pie': 'Position Independent Executable',
                'relro': 'Relocation Read-Only'
            }

            for prot, enabled in prot_data.items():
                status = "[green]✅ Enabled[/green]" if enabled else "[red]❌ Disabled[/red]"
                desc = prot_descriptions.get(prot, "Security feature")
                prot_table.add_row(
                    prot.upper(),
                    status,
                    desc
                )

            charts.append(Panel(prot_table, title="🔒 Protections"))

        # Display charts in columns
        if len(charts) >= 2:
            columns = Columns(charts, equal=True, expand=True)
            self.console.print(columns)
        else:
            for chart in charts:
                self.console.print(chart)

    def generate_vulnerability_trend_chart(self, vulnerability_data: List[Dict[str, Any]]) -> str:
        """Generate trend chart for vulnerability analysis.

        Args:
            vulnerability_data: List of vulnerability dictionaries

        Returns:
            ASCII trend chart as string
        """
        if not vulnerability_data:
            return "No vulnerability data available"

        # Group by severity
        severity_counts = Counter()
        for vuln in vulnerability_data:
            if isinstance(vuln, dict):
                severity = vuln.get('severity', 'Unknown')
                severity_counts[severity.title()] += 1

        # Create bar chart
        return self.generate_bar_chart(
            dict(severity_counts),
            "Vulnerability Distribution by Severity",
            show_values=True
        )


def create_analysis_charts(analysis_results: Dict[str, Any],
                          chart_type: str = "summary",
                          use_rich: bool = True) -> str:
    """Create charts from analysis results.

    Args:
        analysis_results: Analysis results dictionary
        chart_type: Type of chart (summary, bar, pie, histogram, dashboard)
        use_rich: Whether to use rich formatting

    Returns:
        Chart as string or displays rich dashboard
    """
    generator = ASCIIChartGenerator()

    if chart_type == "summary":
        return generator.generate_analysis_summary_chart(analysis_results)
    elif chart_type == "dashboard" and use_rich and RICH_AVAILABLE:
        generator.generate_rich_dashboard(analysis_results)
        return ""
    elif chart_type == "vulnerability":
        vuln_data = analysis_results.get('vulnerabilities', {})
        if isinstance(vuln_data, dict) and 'vulnerabilities' in vuln_data:
            return generator.generate_vulnerability_trend_chart(vuln_data['vulnerabilities'])
        else:
            return "No vulnerability data available"
    else:
        return generator.generate_analysis_summary_chart(analysis_results)


if __name__ == "__main__":
    # Test the chart generator
    test_data = {
        'vulnerabilities': {
            'vulnerabilities': [
                {'severity': 'high', 'type': 'buffer_overflow'},
                {'severity': 'medium', 'type': 'format_string'},
                {'severity': 'low', 'type': 'info_leak'},
                {'severity': 'high', 'type': 'injection'}
            ]
        },
        'protections': {
            'aslr': True,
            'dep': True,
            'canary': False,
            'pie': True
        },
        'strings': ['test1', 'test2', 'longer_string_here', 'short']
    }

    print(create_analysis_charts(test_data, "summary"))
