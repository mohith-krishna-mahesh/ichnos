"""Interactive Candidate Selector modal screen for inspecting and chaining candidate results."""

from __future__ import annotations

import time
from typing import TYPE_CHECKING

from rich.panel import Panel
from rich.text import Text
from textual.binding import Binding
from textual.containers import Container
from textual.screen import ModalScreen
from textual.widgets import DataTable, Footer, Static

from ichnos.core.detection import printable_ratio, shannon_entropy
from ichnos.core.models import Candidate, Input, SourceType
from ichnos.ui.state import DEFAULT_SCRATCH_DIR
from ichnos.ui.widgets.output import IchnosOutput
from ichnos.ui.widgets.status import IchnosStatusBar

if TYPE_CHECKING:
    from ichnos.core.models import Result
    from ichnos.ui.app import IchnosApp


class CandidateSelectorScreen(ModalScreen[None]):
    """Interactive modal screen for candidate exploration, inspection, and chaining."""

    DEFAULT_CSS = """
    CandidateSelectorScreen {
        align: center middle;
        background: rgba(10, 11, 10, 0.85);
    }

    #selector-container {
        width: 90%;
        height: 85%;
        border: double $primary;
        background: $surface;
        padding: 1 2;
    }

    #candidate-table {
        height: 50%;
        border: solid $border-color;
        background: $panel;
    }

    #candidate-detail {
        height: 45%;
        border: solid $border-color;
        background: $prompt-bg;
        padding: 1;
        overflow-y: scroll;
        margin-top: 1;
    }

    #selector-title {
        color: $primary;
        text-style: bold;
        text-align: center;
        margin-bottom: 1;
    }
    """

    BINDINGS = [
        Binding("enter", "use_as_target", "use as target", show=True),
        Binding("d", "chain_decode", "decode", show=True),
        Binding("a", "chain_analyze", "analyze", show=True),
        Binding("x", "chain_extract", "export", show=True),
        Binding("g", "scroll_top", "top", show=False),
        Binding("G", "scroll_bottom", "bottom", show=False),
        Binding("/", "filter_search", "filter", show=False),
        Binding("escape", "dismiss_modal", "back", show=True),
    ]

    def __init__(self, result: Result, **kwargs):
        super().__init__(**kwargs)
        self.result = result
        self.candidates: list[Candidate] = result.candidates or []
        self._current_index: int = 0

    def compose(self):
        with Container(id="selector-container"):
            yield Static(
                f"Candidate Selector — {len(self.candidates)} candidates",
                id="selector-title",
            )
            yield DataTable(id="candidate-table")
            yield Static(id="candidate-detail")
            yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#candidate-table", DataTable)
        table.cursor_type = "row"
        table.add_columns("#", "Method", "Match", "Preview")

        for idx, c in enumerate(self.candidates, start=1):
            key_info = f" ({c.key})" if c.key is not None else ""
            method_str = f"{c.method}{key_info}"
            preview = c.decoded_str.replace("\n", " ").replace("\r", "")
            if len(preview) > 55:
                preview = preview[:52] + "..."
            table.add_row(
                str(idx), method_str, f"{int(c.confidence * 100)}%", preview, key=str(idx - 1)
            )

        table.focus()
        if self.candidates:
            self._display_candidate_detail(0)

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key and event.row_key.value:
            try:
                idx = int(event.row_key.value)
                self._current_index = idx
                self._display_candidate_detail(idx)
            except (ValueError, IndexError):
                pass

    def on_data_table_row_selected(self, event: DataTable.RowSelected) -> None:
        if event.row_key and event.row_key.value:
            try:
                self._current_index = int(event.row_key.value)
            except (ValueError, IndexError):
                pass
        self.action_use_as_target()

    def _display_candidate_detail(self, index: int) -> None:
        if not (0 <= index < len(self.candidates)):
            return

        c = self.candidates[index]
        detail_view = self.query_one("#candidate-detail", Static)

        # Candidate payload metrics
        if isinstance(c.decoded, bytes):
            payload_bytes = c.decoded
        else:
            payload_bytes = c.decoded_str.encode("utf-8", errors="replace")

        ent = shannon_entropy(payload_bytes)
        pr = printable_ratio(payload_bytes)

        # Hex dump preview (first 96 bytes)
        hex_lines = []
        for i in range(0, min(len(payload_bytes), 96), 16):
            chunk = payload_bytes[i : i + 16]
            hex_part = " ".join(f"{b:02x}" for b in chunk).ljust(48)
            ascii_part = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
            hex_lines.append(f"{i:04x}: {hex_part} |{ascii_part}|")
        hex_dump = "\n".join(hex_lines)

        primary = "#8ba4b0"
        secondary = "#8992a7"
        fg = "#BBBBBB"
        if hasattr(self, "app") and hasattr(self.app, "current_theme") and self.app.current_theme:
            theme = self.app.current_theme
            primary = getattr(theme, "primary", None) or primary
            secondary = getattr(theme, "secondary", None) or secondary
            fg = getattr(theme, "foreground", None) or fg

        text = Text()
        text.append(f"Candidate #{index + 1}: ", style=f"bold {primary}")
        text.append(f"{c.method} (key: {c.key})\n")
        match_str = f"{int(c.confidence * 100)}%"
        text.append(
            f"Match: {match_str} · {len(payload_bytes)} B · entropy: {ent:.2f} · printable: {pr * 100:.0f}%\n\n",
            style="dim",
        )
        text.append("Decoded Content:\n", style=f"bold {fg}")
        text.append(c.decoded_str + "\n\n")
        text.append("Hex Preview:\n", style="dim")
        text.append(hex_dump, style=f"{secondary}")

        detail_view.update(Panel(text, border_style=primary))

    def action_dismiss_modal(self) -> None:
        self.dismiss()

    def _get_current_payload(self) -> tuple[bytes, Candidate]:
        c = self.candidates[self._current_index]
        if isinstance(c.decoded, bytes):
            return c.decoded, c
        return c.decoded_str.encode("utf-8", errors="replace"), c

    def action_use_as_target(self) -> None:
        if not self.candidates:
            self.dismiss()
            return

        payload_bytes, _ = self._get_current_payload()
        self.dismiss()

        app: IchnosApp = self.app  # type: ignore
        new_inp = Input(
            data=payload_bytes,
            source_type=SourceType.RAW,
            detected_type="text" if printable_ratio(payload_bytes) > 0.8 else "binary",
        )
        app.ui_state.set_active_input(new_inp)

        from ichnos.ui.screens.main import MainScreen

        screen = app.get_screen("main")
        if isinstance(screen, MainScreen):
            output = screen.query_one("#output-view", IchnosOutput)
            output.write_success(f"Candidate #{self._current_index + 1} set as target.")
            status_bar = screen.query_one("#status-bar", IchnosStatusBar)
            status_bar.update_status()

    def action_chain_decode(self) -> None:
        if not self.candidates:
            self.dismiss()
            return

        payload_bytes, _ = self._get_current_payload()
        self.dismiss()

        app: IchnosApp = self.app  # type: ignore
        new_inp = Input(
            data=payload_bytes,
            source_type=SourceType.RAW,
            detected_type="text",
        )
        app.ui_state.set_active_input(new_inp)
        app.dispatch_chained_command("encoding auto", f"candidate #{self._current_index + 1}")

    def action_chain_analyze(self) -> None:
        if not self.candidates:
            self.dismiss()
            return

        payload_bytes, _ = self._get_current_payload()
        self.dismiss()

        app: IchnosApp = self.app  # type: ignore
        new_inp = Input(
            data=payload_bytes,
            source_type=SourceType.RAW,
            detected_type="unknown",
        )
        app.ui_state.set_active_input(new_inp)
        app.dispatch_chained_command("analyze", f"candidate #{self._current_index + 1}")

    def action_chain_extract(self) -> None:
        if not self.candidates:
            self.dismiss()
            return

        payload_bytes, candidate = self._get_current_payload()
        self.dismiss()

        target_dir = DEFAULT_SCRATCH_DIR
        fname = f"extracted_{int(time.time())}.bin"
        try:
            target_dir.mkdir(parents=True, exist_ok=True)
            out_path = target_dir / fname
            out_path.write_bytes(payload_bytes)
        except (OSError, PermissionError):
            from pathlib import Path

            target_dir = Path.cwd() / "scratch"
            target_dir.mkdir(parents=True, exist_ok=True)
            out_path = target_dir / fname
            out_path.write_bytes(payload_bytes)

        app: IchnosApp = self.app  # type: ignore
        new_inp = Input(
            data=payload_bytes,
            source_type=SourceType.FILE,
            path=out_path,
            filename=fname,
            detected_type="unknown",
        )
        app.ui_state.set_active_input(new_inp)
        app.handle_extraction_complete(out_path, len(payload_bytes), candidate.method)

    def action_scroll_top(self) -> None:
        table = self.query_one("#candidate-table", DataTable)
        if self.candidates:
            table.move_cursor(row=0)

    def action_scroll_bottom(self) -> None:
        table = self.query_one("#candidate-table", DataTable)
        if self.candidates:
            table.move_cursor(row=len(self.candidates) - 1)

    def action_filter_search(self) -> None:
        pass


class StepSelectorScreen(ModalScreen[None]):
    """Interactive modal screen for stepping through deduction traces."""

    DEFAULT_CSS = """
    StepSelectorScreen {
        align: center middle;
        background: rgba(10, 11, 10, 0.85);
    }

    #step-container {
        width: 90%;
        height: 85%;
        border: double $accent;
        background: $surface;
        padding: 1 2;
    }

    #step-table {
        height: 50%;
        border: solid $border-color;
        background: $panel;
    }

    #step-detail {
        height: 45%;
        border: solid $border-color;
        background: $prompt-bg;
        padding: 1;
        overflow-y: scroll;
        margin-top: 1;
    }

    #step-title {
        color: $accent;
        text-style: bold;
        text-align: center;
        margin-bottom: 1;
    }
    """

    BINDINGS = [
        Binding("escape", "dismiss_modal", "back", show=True),
        Binding("g", "scroll_top", "top", show=False),
        Binding("G", "scroll_bottom", "bottom", show=False),
        Binding("/", "filter_search", "filter", show=False),
    ]

    def __init__(self, result: Result, **kwargs):
        super().__init__(**kwargs)
        self.result = result
        self.steps = result.steps or []
        self._current_index: int = 0

    def compose(self):
        with Container(id="step-container"):
            yield Static(
                f"Deduction Steps — {len(self.steps)} steps",
                id="step-title",
            )
            yield DataTable(id="step-table")
            yield Static(id="step-detail")
            yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#step-table", DataTable)
        table.cursor_type = "row"
        table.add_columns("#", "Phase / Rationale", "Step", "Detail")

        for idx, s in enumerate(self.steps, start=1):
            table.add_row(
                str(idx), s.rationale or "Analysis", s.label, s.detail[:60], key=str(idx - 1)
            )

        table.focus()
        if self.steps:
            self._display_step_detail(0)

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.row_key and event.row_key.value:
            try:
                idx = int(event.row_key.value)
                self._current_index = idx
                self._display_step_detail(idx)
            except (ValueError, IndexError):
                pass

    def _display_step_detail(self, index: int) -> None:
        if not (0 <= index < len(self.steps)):
            return

        s = self.steps[index]
        detail_view = self.query_one("#step-detail", Static)

        accent = "#8ea4a2"
        secondary = "#8992a7"
        fg = "#BBBBBB"
        if hasattr(self, "app") and hasattr(self.app, "current_theme") and self.app.current_theme:
            theme = self.app.current_theme
            accent = getattr(theme, "accent", None) or accent
            secondary = getattr(theme, "secondary", None) or secondary
            fg = getattr(theme, "foreground", None) or fg

        text = Text()
        text.append(f"Step #{index + 1}: ", style=f"bold {accent}")
        text.append(f"{s.label}\n\n", style=f"bold {fg}")
        text.append("Rationale / Phase:\n", style="bold")
        text.append(f"  {s.rationale or 'N/A'}\n\n", style=f"{secondary}")
        text.append("Details:\n", style="bold")
        text.append(f"  {s.detail or 'N/A'}\n\n")

        if s.intermediate_values:
            import json

            text.append("Intermediate Values:\n", style="bold")
            vals_str = json.dumps(s.intermediate_values, indent=2, default=str)
            text.append(vals_str, style="dim")

        detail_view.update(Panel(text, border_style=accent))

    def action_dismiss_modal(self) -> None:
        self.dismiss()

    def action_scroll_top(self) -> None:
        table = self.query_one("#step-table", DataTable)
        if self.steps:
            table.move_cursor(row=0)

    def action_scroll_bottom(self) -> None:
        table = self.query_one("#step-table", DataTable)
        if self.steps:
            table.move_cursor(row=len(self.steps) - 1)

    def action_filter_search(self) -> None:
        pass
