from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Callable

from textual.app import App, ComposeResult
from textual.containers import Horizontal, Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Input, Label, ListItem, ListView, RichLog, Static

from core.agent import (
    assetfinder_agent,
    gau_agent,
    httpx_agent,
    katana_agent,
    subfinder_agent,
    waybackurls_agent,
    nikto_agent,
    ffuf_agent,
)


@dataclass(frozen=True)
class MenuEntry:
    key: str
    label: str
    description: str = ""


@dataclass(frozen=True)
class ToolEntry:
    key: str
    label: str
    task_name: str
    input_label: str
    runner: Callable[[str, object], None]


MAIN_MENU = [
    MenuEntry("recon", "Reconnaissance", "Passive discovery and crawling"),
    MenuEntry("intel", "Intelligence", "Not wired yet"),
    MenuEntry("scan", "Scanning", "Web vulnerability scanning"),
    MenuEntry("web", "Web Testing", "Not wired yet"),
]


def _run_subfinder(target: str, dashboard: object) -> None:
    subfinder_agent(target, mode="single", dashboard=dashboard)


RECON_TOOLS = [
    ToolEntry(
        "subfinder",
        "Subfinder",
        "Running Subfinder",
        "Target domain",
        _run_subfinder,
    ),
    ToolEntry(
        "assetfinder",
        "Assetfinder",
        "Running Assetfinder",
        "Target domain",
        assetfinder_agent,
    ),
    ToolEntry(
        "httpx",
        "Httpx",
        "Running Httpx",
        "Target list file path",
        httpx_agent,
    ),
    ToolEntry(
        "katana",
        "Katana",
        "Running Katana",
        "Target URL/domain",
        katana_agent,
    ),
    ToolEntry(
        "waybackurls",
        "Waybackurls",
        "Running Waybackurls",
        "Target domain/URL",
        waybackurls_agent,
    ),
    ToolEntry(
        "gau",
        "GAU",
        "Running GAU",
        "Target domain",
        gau_agent,
    ),
]
SCAN_TOOLS = [
    ToolEntry(
        "nikto",
        "Nikto",
        "Running Nikto",
        "Target URL/domain",
        nikto_agent,
    ),
    ToolEntry(
        "ffuf",
        "FFUF",
        "Running FFUF",
        "Target URL/domain",
        ffuf_agent,
    ),
]




class TargetInputScreen(ModalScreen[str | None]):
    """
    Modal prompt for target/domain/path input.
    """

    CSS = """
    TargetInputScreen {
        align: center middle;
    }

    #target-dialog {
        width: 64;
        height: auto;
        border: round $accent;
        background: $surface;
        padding: 1 2;
    }

    #target-dialog-title {
        text-style: bold;
        margin-bottom: 1;
    }

    #target-dialog-help {
        color: $text-muted;
        margin-bottom: 1;
    }

    #target-buttons {
        height: auto;
        margin-top: 1;
    }

    #target-buttons Button {
        margin-right: 1;
    }
    """

    BINDINGS = [
        ("escape", "cancel", "Cancel"),
    ]

    def __init__(self, title: str, prompt: str) -> None:
        super().__init__()
        self.title_text = title
        self.prompt = prompt

    def compose(self) -> ComposeResult:
        with Vertical(id="target-dialog"):
            yield Label(self.title_text, id="target-dialog-title")
            yield Label(self.prompt, id="target-dialog-help")
            yield Input(placeholder=self.prompt, id="target-input")
            with Horizontal(id="target-buttons"):
                yield Button("Run", variant="success", id="run-target")
                yield Button("Cancel", variant="default", id="cancel-target")

    def on_mount(self) -> None:
        self.query_one("#target-input", Input).focus()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "run-target":
            self._submit()
        else:
            self.dismiss(None)

    def on_input_submitted(self, event: Input.Submitted) -> None:
        self._submit()

    def action_cancel(self) -> None:
        self.dismiss(None)

    def _submit(self) -> None:
        value = self.query_one("#target-input", Input).value.strip()
        self.dismiss(value or None)


class TuiDashboardAdapter:
    """
    Compatibility adapter for existing core.agent dashboard calls.
    """

    def __init__(self, app: "GlitchReconApp") -> None:
        self.app = app

    def start(self) -> None:
        return

    def stop(self) -> None:
        return

    def log(self, message: str) -> None:
        self.add_log(message)

    def ai_output(self, message: str) -> None:
        self.update_ai_output(message)

    def add_log(self, message: str) -> None:
        self._call_ui(self.app.add_log, message)

    def set_status(self, message: str) -> None:
        self._call_ui(self.app.set_status, message)

    def set_task(self, message: str) -> None:
        self._call_ui(self.app.set_task, message)

    def set_target(self, target: str) -> None:
        self._call_ui(self.app.set_target, target)

    def update_ai_output(self, text: str) -> None:
        self._call_ui(self.app.update_ai_output, text)

    def append_ai_output(self, text: str) -> None:
        self._call_ui(self.app.append_ai_output, text)

    def _call_ui(self, callback: Callable[..., None], *args: object) -> None:
        try:
            self.app.call_from_thread(callback, *args)
        except RuntimeError:
            callback(*args)


class GlitchReconApp(App[None]):
    """
    Full-screen terminal dashboard for GlitchReconAI.
    """

    TITLE = "GlitchReconAI"
    CSS = """
    Screen {
        background: $background;
    }

    #root {
        height: 100%;
        width: 100%;
    }

    #status-header {
        height: 5;
        border: heavy $success;
        padding: 0 1;
        background: $surface;
    }

    #brand {
        text-style: bold;
        color: $success;
    }

    #main-region {
        height: 1fr;
        min-height: 12;
    }

    #menu-panel {
        width: 26;
        min-width: 22;
        border: heavy $success;
        padding: 0 1;
        background: $surface;
    }

    #menu-title {
        height: 1;
        text-style: bold;
        color: $success;
        margin-bottom: 1;
    }

    #menu-hint {
        height: 1;
        color: $text-muted;
        margin-top: 1;
    }

    #menu-list {
        height: 1fr;
        border: none;
    }

    #menu-list ListItem {
        height: 3;
    }

    #ai-panel {
        border: heavy $accent;
        padding: 0 1;
        background: $surface;
    }

    #ai-title {
        height: 1;
        text-style: bold;
        color: $accent;
    }

    #ai-output {
        height: 1fr;
        overflow-y: auto;
        padding-top: 1;
    }

    #log-panel {
        height: 11;
        min-height: 8;
        border: heavy $warning;
        padding: 0 1;
        background: $surface;
    }

    #log-title {
        height: 1;
        text-style: bold;
        color: $warning;
    }

    #logs {
        height: 1fr;
    }
    """
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("escape", "go_back", "Back"),
        ("backspace", "go_back", "Back"),
    ]

    def __init__(self) -> None:
        super().__init__()
        self.current_menu = "main"
        self.current_target = "-"
        self.current_task = "Idle"
        self.status = "Ready"
        self.dashboard = TuiDashboardAdapter(self)
        self._active_tool: ToolEntry | None = None

    def compose(self) -> ComposeResult:
        with Vertical(id="root"):
            yield Static(id="status-header")
            with Horizontal(id="main-region"):
                with Vertical(id="menu-panel"):
                    yield Label("MENU", id="menu-title")
                    yield ListView(id="menu-list")
                    yield Label("Enter: select | Esc: back | q: quit", id="menu-hint")
                with Vertical(id="ai-panel"):
                    yield Label("AI PANEL", id="ai-title")
                    yield RichLog(id="ai-output", markup=False, highlight=False, wrap=True)
            with Vertical(id="log-panel"):
                yield Label("LOGS", id="log-title")
                yield RichLog(id="logs", markup=True, highlight=False, wrap=True)

    def on_mount(self) -> None:
        self._render_header()
        self._set_menu("main")
        self.update_ai_output("Waiting...")
        self.add_log("[+] Dashboard ready.")

    def action_go_back(self) -> None:
        if self.current_menu in {"recon", "scan"}:
            self._set_menu("main")
            self.set_task("Idle")
            self.set_status("Ready")

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        selected_key = event.item.id or ""

        if self.current_menu == "main":
            if selected_key == "recon":
                self._set_menu("recon")
                self.set_task("Reconnaissance")
                self.set_status("Select a tool")
                return
            
            if selected_key == "scan":
                self._set_menu("scan")
                self.set_task("Scanning")
                self.set_status("Select a tool")
                return

            self.add_log(f"[-] {self._main_label(selected_key)} is not wired yet.")
            self.set_task(self._main_label(selected_key))
            self.set_status("Not wired yet")
            return

        tool = self._tool_by_key(selected_key)
        if tool is None:
            return

        self._active_tool = tool
        self.push_screen(
            TargetInputScreen(tool.label, tool.input_label),
            callback=self._run_tool_from_input,
        )

    def add_log(self, message: str) -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.query_one("#logs", RichLog).write(f"[dim]{timestamp}[/dim] {message}")

    def set_status(self, message: str) -> None:
        self.status = message.strip() if message else "-"
        self._render_header()

    def set_task(self, message: str) -> None:
        self.current_task = message.strip() if message else "-"
        self._render_header()

    def set_target(self, target: str) -> None:
        self.current_target = target.strip() if target else "-"
        self._render_header()

    def update_ai_output(self, text: str) -> None:
        ai_output = self.query_one("#ai-output", RichLog)
        ai_output.clear()
        ai_output.write((text or "No AI output.").strip())

    def append_ai_output(self, text: str) -> None:
        self.query_one("#ai-output", RichLog).write(text or "")

    def _run_tool_from_input(self, target: str | None) -> None:
        tool = self._active_tool
        self._active_tool = None

        if tool is None:
            return

        if not target:
            self.add_log("[-] No target provided.")
            self.set_status("Ready")
            return

        self.set_target(target)
        self.set_task(tool.task_name)
        self.set_status("Active")
        self.update_ai_output("Waiting for AI analysis...")
        self.add_log(f"[+] Queued {tool.label} for {target}.")

        self.run_worker(
            lambda: self._run_agent(tool, target),
            thread=True,
            name=f"{tool.key}:{target}",
            exclusive=False,
        )

    def _run_agent(self, tool: ToolEntry, target: str) -> None:
        try:
            self.dashboard.add_log(f"[+] Starting {tool.label}.")
            tool.runner(target, self.dashboard)
        except Exception as exc:
            self.dashboard.add_log(f"[ERROR] {tool.label} failed: {exc}")
            self.dashboard.set_status("Error")
        else:
            self.dashboard.add_log(f"[+] {tool.label} finished.")
            self.dashboard.set_status("Ready")
            self.dashboard.set_task("Idle")

    def _set_menu(self, menu_name: str) -> None:
        self.current_menu = menu_name
        menu_list = self.query_one("#menu-list", ListView)
        menu_list.clear()

        if menu_name == "main":
            entries = MAIN_MENU
            title = "MENU"
        elif menu_name == "recon":
            entries = [
                MenuEntry(tool.key, tool.label, tool.input_label)
                for tool in RECON_TOOLS
            ]
            title = "RECONNAISSANCE"
        elif menu_name == "scan":
            entries = [
                MenuEntry(tool.key, tool.label, tool.input_label)
                for tool in SCAN_TOOLS
            ]
            title = "SCANNING"
        else:
            entries = []
            title = menu_name.upper()

        for entry in entries:
            label = entry.label
            if entry.description:
                label = f"{entry.label}\n[dim]{entry.description}[/dim]"
            menu_list.append(ListItem(Label(label), id=entry.key))

        self.query_one("#menu-title", Label).update(title)
        menu_list.index = 0
        menu_list.focus()

    def _render_header(self) -> None:
        header = (
            "[bold green]GlitchReconAI[/bold green]\n"
            f"Current Target: [cyan]{self.current_target}[/cyan]    "
            f"Current Task: [cyan]{self.current_task}[/cyan]    "
            f"Status: [cyan]{self.status}[/cyan]"
        )
        self.query_one("#status-header", Static).update(header)

    def _tool_by_key(self, key: str) -> ToolEntry | None:
        tools = RECON_TOOLS if self.current_menu == "recon" else SCAN_TOOLS

        for tool in tools:
            if tool.key == key:
                return tool

        return None

    def _main_label(self, key: str) -> str:
        for entry in MAIN_MENU:
            if entry.key == key:
                return entry.label
        return key or "Unknown"
