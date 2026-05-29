from datetime import datetime
from typing import List, Optional

from rich.align import Align
from rich.console import Console
from rich.layout import Layout
from rich.panel import Panel
from rich.text import Text


_ACTIVE_DASHBOARD = None


class Dashboard:
    """
    Minimal Rich dashboard for separating system logs from AI analysis output.
    """

    def __init__(self, title: str = "GlitchReconAI"):
        self.console = Console()
        self.title = title
        self.logs: List[str] = []
        self.last_ai_output = "Waiting for AI analysis..."

    def log(self, message: str) -> None:
        """
        Add a message to the system log panel and refresh the dashboard.
        """
        timestamp = datetime.now().strftime("%H:%M:%S")
        line = f"[{timestamp}] {message}"
        self.logs.append(line)
        self.render()

    def ai_output(self, message: str) -> None:
        """
        Store Ollama analysis in the AI panel and refresh the dashboard.
        """
        self.last_ai_output = (message or "No AI output.").strip()
        self.render()

    def render(self) -> None:
        """
        Render the full automatic split dashboard.
        """
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="logs", ratio=1),
            Layout(name="ai", ratio=2),
        )

        layout["header"].update(
            Panel(
                Align.center(f"[bold green]{self.title}[/bold green]"),
                border_style="bright_green",
            )
        )
        layout["logs"].update(
            Panel(
                self._build_log_text(),
                title="[bold green]SYSTEM LOGS[/bold green]",
                border_style="green",
            )
        )
        layout["ai"].update(
            Panel(
                self.last_ai_output,
                title="[bold cyan]AI ANALYSIS PANEL[/bold cyan]",
                border_style="cyan",
            )
        )

        self.console.clear()
        self.console.print(layout)

    def _build_log_text(self) -> Text:
        recent_logs = self.logs[-18:]
        text = Text()

        if not recent_logs:
            text.append("Waiting for tool execution...\n", style="dim")
            return text

        for line in recent_logs:
            text.append(line)
            text.append("\n")

        return text


def set_dashboard(dashboard: Optional[Dashboard]) -> None:
    global _ACTIVE_DASHBOARD
    _ACTIVE_DASHBOARD = dashboard


def get_dashboard() -> Dashboard:
    global _ACTIVE_DASHBOARD

    if _ACTIVE_DASHBOARD is None:
        _ACTIVE_DASHBOARD = Dashboard()

    return _ACTIVE_DASHBOARD
