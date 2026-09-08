"""Scrollable output display widget for Ichnos TUI."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from rich.console import RenderableType
from rich.markup import escape
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from textual.containers import VerticalScroll
from textual.widgets import Static

from ichnos.core.security import sanitize_terminal_output

if TYPE_CHECKING:
    from ichnos.core.models import Result


class IchnosOutput(VerticalScroll):
    """Scrollable terminal log and results display area."""

    def write_line(self, renderable: RenderableType | str) -> None:
        """Appends a new line or rich renderable to the output log."""
        if isinstance(renderable, str):
            widget = Static(Text.from_markup(renderable))
        else:
            widget = Static(renderable)
        if self.is_attached:
            self.mount(widget)
            widget.scroll_visible()

    def _get_theme_styles(self) -> dict[str, str]:
        primary = "cyan"
        secondary = "blue"
        accent = "magenta"
        fg = "white"
        warning = "yellow"
        error = "red"
        success = "green"
        muted = "#8992a7"
        border = "#2f384e"

        if hasattr(self, "app") and hasattr(self.app, "current_theme") and self.app.current_theme:
            t = self.app.current_theme
            primary = t.primary
            secondary = t.secondary
            accent = t.accent
            fg = t.foreground
            warning = t.warning
            error = t.error
            success = t.success
            if hasattr(t, "variables") and t.variables:
                muted = t.variables.get("text-muted", muted)
                border = t.variables.get("border-color", border)

        return {
            "primary": primary,
            "secondary": secondary,
            "accent": accent,
            "foreground": fg,
            "warning": warning,
            "error": error,
            "success": success,
            "muted": muted,
            "border": border,
        }

    def write_info(self, message: str) -> None:
        sty = self._get_theme_styles()
        self.write_line(f"[{sty['primary']}]ℹ[/{sty['primary']}] {escape(sanitize_terminal_output(message))}")

    def write_success(self, message: str) -> None:
        sty = self._get_theme_styles()
        self.write_line(f"[{sty['success']}]✓[/{sty['success']}] {escape(sanitize_terminal_output(message))}")

    def write_warning(self, message: str) -> None:
        sty = self._get_theme_styles()
        self.write_line(f"[{sty['warning']}]⚠[/{sty['warning']}] {escape(sanitize_terminal_output(message))}")

    def write_error(self, message: str) -> None:
        sty = self._get_theme_styles()
        self.write_line(f"[{sty['error']}]✗[/{sty['error']}] {escape(sanitize_terminal_output(message))}")

    def clear_output(self) -> None:
        """Removes all children from the output view."""
        self.remove_children()

    def render_result(self, res: Result) -> None:
        """Renders structured Result (Findings, Candidates, and Raw Data) into rich widgets."""
        if not self.is_attached:
            return

        sty = self._get_theme_styles()

        mode = "expert"
        if hasattr(self, "app") and hasattr(self.app, "ui_state"):
            mode = getattr(self.app.ui_state, "mode", "expert")

        # In Expert Mode: Output clean 1-line answer + 1-line how
        if mode == "expert" and res.candidates:
            top_c = res.candidates[0]
            ans_clean = sanitize_terminal_output(top_c.decoded_str).strip().replace("\n", " ").replace("\r", "")
            if len(ans_clean) > 85:
                ans_clean = ans_clean[:82] + "..."
            key_info = f" | key={top_c.key}" if top_c.key is not None else ""
            ans_escaped = escape(ans_clean)
            self.write_line(f"[{sty['success']}]Answer:[/{sty['success']}] [bold]{ans_escaped}[/bold]")
            self.write_line(
                f"[dim {sty['secondary']}]How: {escape(top_c.method)}{escape(key_info)} | confidence={int(top_c.confidence * 100)}%[/dim {sty['secondary']}]"
            )

        # In Learner Mode: Output pedagogical note and deduction step trail
        if mode == "learner":
            from ichnos.core.pedagogy import get_pedagogical_note

            note = res.learner_note
            if not note and res.candidates:
                note = get_pedagogical_note(res.candidates[0].method)
            elif not note and res.findings:
                note = get_pedagogical_note(res.findings[0].label)

            if note:
                note_panel = Panel(
                    Text(note, style=sty["foreground"]),
                    title="[bold]Pedagogical Explanation (Learner Mode)[/bold]",
                    border_style=sty["accent"],
                    expand=True,
                )
                self.mount(Static(note_panel))

            if res.steps:
                step_table = Table(
                    title=f"Deduction Trail ({len(res.steps)} Steps)",
                    expand=True,
                    title_style=f"bold {sty['accent']}",
                    border_style=sty["border"],
                )
                step_table.add_column("#", justify="right", style="bold", width=4)
                step_table.add_column("Phase / Rationale", style=sty["secondary"], width=22)
                step_table.add_column("Step", style=f"bold {sty['foreground']}", width=25)
                step_table.add_column("Detail", style=sty["muted"])
                for s_idx, s in enumerate(res.steps, 1):
                    step_table.add_row(str(s_idx), s.rationale or "Analysis", s.label, s.detail)
                self.mount(Static(step_table))
                self.write_line(
                    f"[dim {sty['primary']}]Type 'steps' to interactively inspect each deduction step.[/dim {sty['primary']}]"
                )

        # 1. Findings Table
        if res.findings:
            table = Table(
                title=f"Findings ({len(res.findings)})",
                expand=True,
                title_style=f"bold {sty['primary']}",
                border_style=sty["border"],
            )
            table.add_column("Match", justify="right", style="bold", width=7)
            table.add_column("Module", style=sty["secondary"], width=10)
            table.add_column("Finding", style=f"bold {sty['foreground']}", width=25)
            table.add_column("Details / Hint", style=sty["muted"])

            for f in res.findings:
                conf_val = f.confidence
                conf_str = f"{int(conf_val * 100)}%"
                if conf_val >= 0.8:
                    conf_badge = f"[{sty['success']}]{conf_str}[/{sty['success']}]"
                elif conf_val >= 0.5:
                    conf_badge = f"[{sty['warning']}]{conf_str}[/{sty['warning']}]"
                else:
                    conf_badge = f"[dim]{conf_str}[/dim]"

                hint = f.detail
                if f.command_hint and f.command_hint != f.detail:
                    hint += f" [dim {sty['primary']}]➔ {f.command_hint}[/dim {sty['primary']}]"
                table.add_row(conf_badge, f.module, f.label, hint)

            self.mount(Static(table))

        # 2. Candidates Table
        if res.candidates:
            table = Table(
                title=f"Candidates ({len(res.candidates)})",
                expand=True,
                title_style=f"bold {sty['primary']}",
                border_style=sty["border"],
            )
            table.add_column("#", justify="right", style="bold", width=4)
            table.add_column("Method / Key", style=sty["secondary"], width=22)
            table.add_column("Match", justify="right", width=7)
            table.add_column("Decoded Output Preview", style=sty["foreground"])

            for idx, c in enumerate(res.candidates[:25], start=1):
                key_info = f" ({c.key})" if c.key is not None else ""
                method_str = f"{c.method}{key_info}"
                conf_val = c.confidence
                conf_str = f"{int(conf_val * 100)}%"
                if conf_val >= 0.8:
                    conf_badge = f"[{sty['success']}]{conf_str}[/{sty['success']}]"
                elif conf_val >= 0.5:
                    conf_badge = f"[{sty['warning']}]{conf_str}[/{sty['warning']}]"
                else:
                    conf_badge = f"[dim]{conf_str}[/dim]"

                preview = c.decoded_str.replace("\n", " ").replace("\r", "")
                if len(preview) > 65:
                    preview = preview[:62] + "..."

                table.add_row(str(idx), method_str, conf_badge, preview)

            self.mount(Static(table))
            self.write_line(
                f"[dim {sty['primary']}]Type 'select' to inspect candidates.[/dim {sty['primary']}]"
            )

        # 3. Raw Output / Deduction Trace
        if (not res.findings and not res.candidates and res.raw_output) or (
            res.command == "solve" and res.raw_output
        ):
            if isinstance(res.raw_output, dict):
                raw_str = json.dumps(res.raw_output, indent=2, default=str)
            else:
                raw_str = str(res.raw_output)
            panel = Panel(
                Text(raw_str, style=sty["foreground"]),
                title=f"[bold]Output ({res.command or 'result'})[/bold]",
                border_style=sty["primary"],
                expand=True,
            )
            self.mount(Static(panel))

        # 4. Status Banner
        if res.status == "error":
            self.write_error(f"Command failed: {res.command}")
        elif not res.findings and not res.candidates:
            summary = f" [dim]Target: {res.input_summary}[/dim]" if res.input_summary else ""
            self.write_success(f"Executed [bold]{res.command}[/bold]{summary}")
