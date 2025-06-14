#!/usr/bin/env python3
"""
Terminal Dashboard - ASCII-based status overview for Intellicrack

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

import os
import sys
import time
import psutil
import threading
from typing import Dict, Any, List, Optional, Callable
from datetime import datetime, timedelta
from dataclasses import dataclass, field

# Optional imports for enhanced dashboard
try:
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.layout import Layout
    from rich.text import Text
    from rich.progress import Progress, BarColumn, TextColumn, TimeElapsedColumn
    from rich.live import Live
    from rich.align import Align
    from rich.columns import Columns
    from rich.tree import Tree
    from rich.status import Status
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


@dataclass
class SystemMetrics:
    """System performance metrics."""
    cpu_percent: float = 0.0
    memory_percent: float = 0.0
    disk_usage: float = 0.0
    network_sent: int = 0
    network_recv: int = 0
    process_count: int = 0
    uptime: float = 0.0
    load_average: Optional[List[float]] = None


@dataclass
class AnalysisStats:
    """Analysis statistics."""
    total_binaries: int = 0
    analyses_completed: int = 0
    vulnerabilities_found: int = 0
    active_projects: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    analysis_time_avg: float = 0.0
    last_analysis: Optional[str] = None


@dataclass
class SessionInfo:
    """Current session information."""
    start_time: datetime = field(default_factory=datetime.now)
    commands_executed: int = 0
    current_binary: Optional[str] = None
    current_project: Optional[str] = None
    ai_queries: int = 0
    exports_created: int = 0
    errors_encountered: int = 0


class TerminalDashboard:
    """ASCII-based terminal dashboard for Intellicrack status overview."""
    
    def __init__(self, update_interval: float = 1.0):
        """Initialize terminal dashboard.
        
        Args:
            update_interval: Update frequency in seconds
        """
        self.console = Console() if RICH_AVAILABLE else None
        self.update_interval = update_interval
        self.running = False
        self.update_thread = None
        
        # Dashboard data
        self.system_metrics = SystemMetrics()
        self.analysis_stats = AnalysisStats()
        self.session_info = SessionInfo()
        
        # Dashboard components
        self.components = {
            'system': True,
            'analysis': True,
            'session': True,
            'recent_activity': True,
            'quick_stats': True
        }
        
        # Activity log
        self.activity_log = []
        self.max_activity_entries = 10
        
        # Performance history
        self.cpu_history = []
        self.memory_history = []
        self.max_history = 30
        
        # Callbacks for external updates
        self.callbacks = {}
    
    def register_callback(self, event: str, callback: Callable):
        """Register callback for dashboard events.
        
        Args:
            event: Event name
            callback: Callback function
        """
        if event not in self.callbacks:
            self.callbacks[event] = []
        self.callbacks[event].append(callback)
    
    def log_activity(self, message: str, level: str = "info"):
        """Log activity to dashboard.
        
        Args:
            message: Activity message
            level: Log level (info, warning, error, success)
        """
        timestamp = datetime.now().strftime("%H:%M:%S")
        activity = {
            'timestamp': timestamp,
            'message': message,
            'level': level
        }
        
        self.activity_log.append(activity)
        
        # Keep only recent entries
        if len(self.activity_log) > self.max_activity_entries:
            self.activity_log.pop(0)
    
    def update_analysis_stats(self, **kwargs):
        """Update analysis statistics.
        
        Args:
            **kwargs: Analysis stats to update
        """
        for key, value in kwargs.items():
            if hasattr(self.analysis_stats, key):
                setattr(self.analysis_stats, key, value)
    
    def update_session_info(self, **kwargs):
        """Update session information.
        
        Args:
            **kwargs: Session info to update
        """
        for key, value in kwargs.items():
            if hasattr(self.session_info, key):
                setattr(self.session_info, key, value)
    
    def increment_counter(self, counter: str):
        """Increment a counter in session info.
        
        Args:
            counter: Counter name
        """
        if hasattr(self.session_info, counter):
            current = getattr(self.session_info, counter, 0)
            setattr(self.session_info, counter, current + 1)
    
    def _update_system_metrics(self):
        """Update system performance metrics."""
        try:
            # CPU and memory
            self.system_metrics.cpu_percent = psutil.cpu_percent(interval=0.1)
            self.system_metrics.memory_percent = psutil.virtual_memory().percent
            
            # Disk usage
            disk = psutil.disk_usage('/')
            self.system_metrics.disk_usage = (disk.used / disk.total) * 100
            
            # Network I/O
            net_io = psutil.net_io_counters()
            self.system_metrics.network_sent = net_io.bytes_sent
            self.system_metrics.network_recv = net_io.bytes_recv
            
            # Process count
            self.system_metrics.process_count = len(psutil.pids())
            
            # System uptime
            boot_time = psutil.boot_time()
            self.system_metrics.uptime = time.time() - boot_time
            
            # Load average (Unix systems)
            try:
                self.system_metrics.load_average = os.getloadavg()
            except (OSError, AttributeError):
                self.system_metrics.load_average = None
            
            # Update history
            self.cpu_history.append(self.system_metrics.cpu_percent)
            self.memory_history.append(self.system_metrics.memory_percent)
            
            if len(self.cpu_history) > self.max_history:
                self.cpu_history.pop(0)
            if len(self.memory_history) > self.max_history:
                self.memory_history.pop(0)
                
        except Exception:
            pass  # Ignore errors in metrics collection
    
    def _create_system_panel(self) -> Panel:
        """Create system metrics panel."""
        if not self.console:
            return None
        
        # CPU indicator
        cpu_bar = self._create_progress_bar(
            self.system_metrics.cpu_percent, 
            100, 
            "CPU", 
            width=20
        )
        
        # Memory indicator
        memory_bar = self._create_progress_bar(
            self.system_metrics.memory_percent,
            100,
            "Memory",
            width=20
        )
        
        # Disk indicator
        disk_bar = self._create_progress_bar(
            self.system_metrics.disk_usage,
            100,
            "Disk",
            width=20
        )
        
        # Uptime
        uptime_str = self._format_duration(self.system_metrics.uptime)
        
        content = f"""[bold cyan]System Performance[/bold cyan]

{cpu_bar}
{memory_bar}
{disk_bar}

[yellow]Uptime:[/yellow] {uptime_str}
[yellow]Processes:[/yellow] {self.system_metrics.process_count}"""

        if self.system_metrics.load_average:
            load_str = ", ".join(f"{load:.2f}" for load in self.system_metrics.load_average)
            content += f"\n[yellow]Load Avg:[/yellow] {load_str}"
        
        return Panel(content, title="🖥️ System", border_style="green")
    
    def _create_analysis_panel(self) -> Panel:
        """Create analysis statistics panel."""
        if not self.console:
            return None
        
        # Calculate success rate
        total_attempts = self.analysis_stats.analyses_completed + self.analysis_stats.cache_hits + self.analysis_stats.cache_misses
        success_rate = 0.0
        if total_attempts > 0:
            success_rate = (self.analysis_stats.analyses_completed / total_attempts) * 100
        
        # Cache hit rate
        cache_attempts = self.analysis_stats.cache_hits + self.analysis_stats.cache_misses
        cache_rate = 0.0
        if cache_attempts > 0:
            cache_rate = (self.analysis_stats.cache_hits / cache_attempts) * 100
        
        content = f"""[bold cyan]Analysis Statistics[/bold cyan]

[yellow]Binaries Analyzed:[/yellow] {self.analysis_stats.total_binaries}
[yellow]Completed:[/yellow] {self.analysis_stats.analyses_completed}
[yellow]Vulnerabilities:[/yellow] {self.analysis_stats.vulnerabilities_found}
[yellow]Active Projects:[/yellow] {self.analysis_stats.active_projects}

[bold green]Performance:[/bold green]
[yellow]Success Rate:[/yellow] {success_rate:.1f}%
[yellow]Cache Hit Rate:[/yellow] {cache_rate:.1f}%
[yellow]Avg Analysis Time:[/yellow] {self.analysis_stats.analysis_time_avg:.1f}s"""

        if self.analysis_stats.last_analysis:
            content += f"\n[yellow]Last Analysis:[/yellow] {self.analysis_stats.last_analysis}"
        
        return Panel(content, title="🔍 Analysis", border_style="blue")
    
    def _create_session_panel(self) -> Panel:
        """Create session information panel."""
        if not self.console:
            return None
        
        # Session duration
        session_duration = datetime.now() - self.session_info.start_time
        duration_str = self._format_duration(session_duration.total_seconds())
        
        content = f"""[bold cyan]Current Session[/bold cyan]

[yellow]Started:[/yellow] {self.session_info.start_time.strftime('%H:%M:%S')}
[yellow]Duration:[/yellow] {duration_str}
[yellow]Commands:[/yellow] {self.session_info.commands_executed}
[yellow]AI Queries:[/yellow] {self.session_info.ai_queries}
[yellow]Exports:[/yellow] {self.session_info.exports_created}
[yellow]Errors:[/yellow] {self.session_info.errors_encountered}"""

        if self.session_info.current_binary:
            binary_name = os.path.basename(self.session_info.current_binary)
            content += f"\n\n[bold green]Current Binary:[/bold green]\n{binary_name}"
        
        if self.session_info.current_project:
            content += f"\n\n[bold green]Current Project:[/bold green]\n{self.session_info.current_project}"
        
        return Panel(content, title="📊 Session", border_style="yellow")
    
    def _create_activity_panel(self) -> Panel:
        """Create recent activity panel."""
        if not self.console:
            return None
        
        if not self.activity_log:
            content = "[dim]No recent activity[/dim]"
        else:
            content_lines = []
            for activity in self.activity_log[-8:]:  # Show last 8 activities
                timestamp = activity['timestamp']
                message = activity['message']
                level = activity['level']
                
                # Color code by level
                if level == 'error':
                    line = f"[red]{timestamp}[/red] {message}"
                elif level == 'warning':
                    line = f"[yellow]{timestamp}[/yellow] {message}"
                elif level == 'success':
                    line = f"[green]{timestamp}[/green] {message}"
                else:
                    line = f"[dim]{timestamp}[/dim] {message}"
                
                content_lines.append(line)
            
            content = "\n".join(content_lines)
        
        return Panel(content, title="📋 Recent Activity", border_style="cyan")
    
    def _create_quick_stats_panel(self) -> Panel:
        """Create quick statistics panel."""
        if not self.console:
            return None
        
        # Performance trend
        cpu_trend = self._get_trend(self.cpu_history)
        memory_trend = self._get_trend(self.memory_history)
        
        # Quick metrics
        content = f"""[bold cyan]Quick Stats[/bold cyan]

[bold green]Trends:[/bold green]
CPU: {cpu_trend} Memory: {memory_trend}

[bold green]Efficiency:[/bold green]
Cmd/Min: {self._calculate_commands_per_minute():.1f}
Uptime: {self._format_duration(self.system_metrics.uptime)}

[bold green]Health:[/bold green]
System: {'🟢' if self.system_metrics.cpu_percent < 80 else '🟡' if self.system_metrics.cpu_percent < 95 else '🔴'}
Memory: {'🟢' if self.system_metrics.memory_percent < 80 else '🟡' if self.system_metrics.memory_percent < 95 else '🔴'}"""
        
        return Panel(content, title="⚡ Quick Stats", border_style="magenta")
    
    def _create_progress_bar(self, value: float, max_value: float, label: str, width: int = 20) -> str:
        """Create ASCII progress bar.
        
        Args:
            value: Current value
            max_value: Maximum value
            label: Progress bar label
            width: Bar width in characters
            
        Returns:
            Formatted progress bar string
        """
        if max_value == 0:
            percentage = 0
        else:
            percentage = min(100, (value / max_value) * 100)
        
        filled = int((percentage / 100) * width)
        bar = "█" * filled + "░" * (width - filled)
        
        # Color coding
        if percentage < 50:
            color = "green"
        elif percentage < 80:
            color = "yellow"
        else:
            color = "red"
        
        return f"[yellow]{label:<8}[/yellow] [{color}]{bar}[/{color}] {percentage:5.1f}%"
    
    def _get_trend(self, history: List[float]) -> str:
        """Get trend indicator from history.
        
        Args:
            history: List of historical values
            
        Returns:
            Trend indicator string
        """
        if len(history) < 3:
            return "→"
        
        recent = sum(history[-3:]) / 3
        older = sum(history[-6:-3]) / 3 if len(history) >= 6 else recent
        
        diff = recent - older
        
        if diff > 5:
            return "↗️"
        elif diff < -5:
            return "↘️"
        else:
            return "→"
    
    def _calculate_commands_per_minute(self) -> float:
        """Calculate commands per minute rate."""
        session_duration = datetime.now() - self.session_info.start_time
        duration_minutes = session_duration.total_seconds() / 60
        
        if duration_minutes > 0:
            return self.session_info.commands_executed / duration_minutes
        return 0.0
    
    def _format_duration(self, seconds: float) -> str:
        """Format duration in human-readable format.
        
        Args:
            seconds: Duration in seconds
            
        Returns:
            Formatted duration string
        """
        if seconds < 60:
            return f"{seconds:.0f}s"
        elif seconds < 3600:
            minutes = seconds / 60
            return f"{minutes:.1f}m"
        else:
            hours = seconds / 3600
            return f"{hours:.1f}h"
    
    def show_dashboard(self, duration: Optional[float] = None):
        """Show dashboard for specified duration.
        
        Args:
            duration: Display duration in seconds (None for indefinite)
        """
        if not self.console:
            self._show_basic_dashboard(duration)
            return
        
        start_time = time.time()
        
        try:
            with Live(self._create_dashboard_layout(), refresh_per_second=1) as live:
                while True:
                    # Update metrics
                    self._update_system_metrics()
                    
                    # Update display
                    live.update(self._create_dashboard_layout())
                    
                    # Check duration
                    if duration and (time.time() - start_time) >= duration:
                        break
                    
                    time.sleep(self.update_interval)
                    
        except KeyboardInterrupt:
            pass
    
    def _create_dashboard_layout(self) -> Layout:
        """Create dashboard layout."""
        layout = Layout()
        
        # Create main sections
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="main"),
            Layout(name="footer", size=3)
        )
        
        # Header
        header_text = Text(
            "🚀 Intellicrack Terminal Dashboard", 
            style="bold cyan", 
            justify="center"
        )
        layout["header"].update(Panel(Align.center(header_text), style="blue"))
        
        # Main content
        layout["main"].split_row(
            Layout(name="left"),
            Layout(name="right")
        )
        
        # Left column
        layout["left"].split_column(
            Layout(self._create_system_panel(), name="system"),
            Layout(self._create_session_panel(), name="session")
        )
        
        # Right column
        layout["right"].split_column(
            Layout(self._create_analysis_panel(), name="analysis"),
            Layout(self._create_activity_panel(), name="activity")
        )
        
        # Footer
        footer_text = Text(
            f"Press Ctrl+C to exit | Updated: {datetime.now().strftime('%H:%M:%S')}", 
            style="dim", 
            justify="center"
        )
        layout["footer"].update(Panel(Align.center(footer_text), style="dim"))
        
        return layout
    
    def _show_basic_dashboard(self, duration: Optional[float] = None):
        """Show basic text dashboard without Rich."""
        start_time = time.time()
        
        try:
            while True:
                os.system('cls' if os.name == 'nt' else 'clear')
                
                print("=" * 60)
                print("           INTELLICRACK TERMINAL DASHBOARD")
                print("=" * 60)
                
                # Update metrics
                self._update_system_metrics()
                
                # System metrics
                print(f"\nSYSTEM METRICS:")
                print(f"  CPU Usage:     {self.system_metrics.cpu_percent:5.1f}%")
                print(f"  Memory Usage:  {self.system_metrics.memory_percent:5.1f}%")
                print(f"  Disk Usage:    {self.system_metrics.disk_usage:5.1f}%")
                print(f"  Processes:     {self.system_metrics.process_count}")
                print(f"  Uptime:        {self._format_duration(self.system_metrics.uptime)}")
                
                # Analysis stats
                print(f"\nANALYSIS STATISTICS:")
                print(f"  Binaries:      {self.analysis_stats.total_binaries}")
                print(f"  Completed:     {self.analysis_stats.analyses_completed}")
                print(f"  Vulnerabilities: {self.analysis_stats.vulnerabilities_found}")
                print(f"  Projects:      {self.analysis_stats.active_projects}")
                
                # Session info
                session_duration = datetime.now() - self.session_info.start_time
                print(f"\nCURRENT SESSION:")
                print(f"  Duration:      {self._format_duration(session_duration.total_seconds())}")
                print(f"  Commands:      {self.session_info.commands_executed}")
                print(f"  AI Queries:    {self.session_info.ai_queries}")
                print(f"  Exports:       {self.session_info.exports_created}")
                
                if self.session_info.current_binary:
                    print(f"  Binary:        {os.path.basename(self.session_info.current_binary)}")
                
                # Recent activity
                if self.activity_log:
                    print(f"\nRECENT ACTIVITY:")
                    for activity in self.activity_log[-5:]:
                        print(f"  {activity['timestamp']} - {activity['message']}")
                
                print(f"\nPress Ctrl+C to exit | Updated: {datetime.now().strftime('%H:%M:%S')}")
                print("=" * 60)
                
                # Check duration
                if duration and (time.time() - start_time) >= duration:
                    break
                
                time.sleep(self.update_interval)
                
        except KeyboardInterrupt:
            pass
    
    def create_status_summary(self) -> str:
        """Create brief status summary.
        
        Returns:
            Status summary string
        """
        self._update_system_metrics()
        
        cpu_status = "🟢" if self.system_metrics.cpu_percent < 80 else "🟡" if self.system_metrics.cpu_percent < 95 else "🔴"
        memory_status = "🟢" if self.system_metrics.memory_percent < 80 else "🟡" if self.system_metrics.memory_percent < 95 else "🔴"
        
        session_duration = datetime.now() - self.session_info.start_time
        
        summary = f"""System: {cpu_status} CPU {self.system_metrics.cpu_percent:.0f}% | {memory_status} Memory {self.system_metrics.memory_percent:.0f}%
Session: {self.session_info.commands_executed} commands in {self._format_duration(session_duration.total_seconds())}
Analysis: {self.analysis_stats.total_binaries} binaries, {self.analysis_stats.vulnerabilities_found} vulnerabilities"""
        
        return summary


def create_dashboard() -> TerminalDashboard:
    """Create dashboard instance."""
    return TerminalDashboard()


if __name__ == "__main__":
    # Test dashboard
    dashboard = TerminalDashboard()
    dashboard.log_activity("Dashboard started", "success")
    dashboard.log_activity("Test analysis completed", "info")
    dashboard.update_analysis_stats(total_binaries=5, vulnerabilities_found=3)
    dashboard.show_dashboard(duration=10)