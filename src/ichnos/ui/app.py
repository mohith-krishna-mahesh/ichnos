"""Main Textual application class for Ichnos."""

from __future__ import annotations

from pathlib import Path

from textual import work
from textual.app import App

from ichnos.core.input import read_input
from ichnos.core.models import Input, Result, SourceType
from ichnos.core.registry import registry
from ichnos.core.runner import CommandRunner
from ichnos.ui.screens.main import MainScreen
from ichnos.ui.screens.result import CandidateSelectorScreen, StepSelectorScreen
from ichnos.ui.screens.startup import StartupScreen
from ichnos.ui.state import UIState
from ichnos.ui.widgets.output import IchnosOutput
from ichnos.ui.widgets.progress import IchnosProgress
from ichnos.ui.widgets.prompt import IchnosPrompt
from ichnos.ui.widgets.status import IchnosStatusBar

_THEME_TCSS_FILE = Path(__file__).parent / "theme.tcss"
_EMBEDDED_TCSS = """
Screen {
    background: $background;
    color: $foreground;
}
StartupScreen {
    align: center middle;
    background: $background;
}
#startup-container {
    width: 104;
    max-width: 98%;
    height: auto;
    border: double $primary;
    padding: 1 1;
    background: $surface;
    align: center middle;
    content-align: center middle;
}
MascotWidget {
    color: $primary;
    text-align: center;
    align: center middle;
    content-align: center middle;
    width: 100%;
    height: auto;
}
#startup-logo {
    color: $primary;
    text-align: center;
    align: center middle;
    content-align: center middle;
    width: 100%;
    text-style: bold;
}
#startup-disclaimer {
    color: $text-dim;
    text-align: center;
    align: center middle;
    content-align: center middle;
    text-style: italic;
    margin: 1 0;
    width: 100%;
}
#startup-prompt {
    color: $primary;
    text-style: bold;
    text-align: center;
    align: center middle;
    content-align: center middle;
    margin-top: 1;
    width: 100%;
}
MainScreen {
    layout: vertical;
    background: $background;
}
IchnosHeader {
    dock: top;
    height: 3;
    background: $header-bg;
    border-bottom: solid $border-color;
    color: $foreground;
    padding: 0 1;
}
IchnosOutput {
    height: 1fr;
    background: $output-bg;
    border: round $border-color;
    padding: 1 1;
    overflow-y: scroll;
}
#prompt-container {
    dock: bottom;
    height: auto;
    background: $header-bg;
    border-top: solid $border-color;
    padding: 0 1;
}
IchnosPrompt {
    width: 100%;
    height: 3;
    border: solid $border-color;
    background: $prompt-bg;
    color: $foreground;
}
IchnosPrompt:focus {
    border: double $border-focused;
}
#completions-view {
    dock: bottom;
    max-height: 8;
    background: $header-bg;
    border: solid $border-focused;
    color: $text-muted;
    padding: 0 1;
}
.completion-item {
    padding: 0 1;
}
.completion-item-active {
    background: $border-color;
    color: $primary;
    text-style: bold;
}
IchnosStatusBar {
    dock: bottom;
    height: 1;
    background: $status-bg;
    color: $text-muted;
    padding: 0 1;
}
IchnosProgress {
    height: 1;
    color: $warning;
    text-style: bold;
    background: $status-bg;
}
"""

try:
    if _THEME_TCSS_FILE.is_file():
        _APP_CSS = _THEME_TCSS_FILE.read_text(encoding="utf-8")
    else:
        _APP_CSS = _EMBEDDED_TCSS
except Exception:
    _APP_CSS = _EMBEDDED_TCSS


# Fallback defaults for custom CSS variables defined in .theme files.
# These are injected via get_css_variables() so the stylesheet can parse
# successfully even before a custom Ichnos theme is activated (Textual
# initializes the stylesheet while the default 'textual-dark' theme is
# still active, which defines none of these).
_CUSTOM_VAR_DEFAULTS: dict[str, str] = {
    "text-dim": "#625e5a",
    "header-bg": "#111111",
    "output-bg": "#0D0E0D",
    "border-color": "#393836",
    "border-focused": "#8ba4b0",
    "status-bg": "#111111",
    "prompt-bg": "#0A0B0A",
}


class IchnosApp(App):
    """Interactive persistent terminal application for Ichnos."""

    TITLE = "Ichnos"
    SUB_TITLE = "Modular Security / CTF Toolkit"
    DEFAULT_CSS = _APP_CSS

    SCREENS = {
        "startup": StartupScreen,
        "main": MainScreen,
    }

    def get_css_variables(self) -> dict[str, str]:
        """Return CSS variables with fallback defaults for custom theme vars.

        Textual calls this during App.__init__() to seed the stylesheet,
        at which point the active theme is still 'textual-dark' (no custom
        variables).  The fallback defaults ensure $text-dim, $header-bg, etc.
        are always defined so the stylesheet never fails to parse.  When a
        real Ichnos theme is later activated its values overwrite these.
        """
        variables = super().get_css_variables()
        return {**_CUSTOM_VAR_DEFAULTS, **variables}

    def __init__(self, initial_theme: str | None = None, **kwargs):
        super().__init__(**kwargs)
        self.ui_state = UIState()
        self._active_worker = None
        self.explicit_theme = initial_theme
        from ichnos.ui.theme import register_ichnos_themes

        register_ichnos_themes(self)
        # Force the stylesheet to pick up the real theme variables now,
        # before the event loop starts and before the first CSS parse.
        self.stylesheet.set_variables(self.get_css_variables())
        if self.explicit_theme:
            try:
                self.theme = self.explicit_theme
            except Exception:
                pass

    def on_mount(self) -> None:
        from ichnos.ui.theme import register_ichnos_themes

        register_ichnos_themes(self)
        if self.explicit_theme:
            try:
                self.theme = self.explicit_theme
            except Exception:
                pass
        self.ui_state.load_history()
        self.push_screen("startup")

    def dispatch_command(self, cmd_line: str) -> None:
        """Dispatches user command string through builtins or the core runner."""
        raw_cmd = cmd_line.strip()
        if not raw_cmd:
            return

        screen = self.get_screen("main")
        if not isinstance(screen, MainScreen):
            return

        output = screen.query_one("#output-view", IchnosOutput)
        status_bar = screen.query_one("#status-bar", IchnosStatusBar)

        parts = raw_cmd.split()
        cmd_verb = parts[0].lower()

        primary = "#8ba4b0"
        secondary = "#8992a7"
        accent = "#8ea4a2"
        if hasattr(self, "current_theme") and self.current_theme:
            theme = self.current_theme
            primary = getattr(theme, "primary", None) or primary
            secondary = getattr(theme, "secondary", None) or secondary
            accent = getattr(theme, "accent", None) or accent

        # Builtin: help [module | command]
        if cmd_verb == "help" and len(parts) >= 2:
            arg = parts[1].lower()
            if arg in registry.get_command_modules():
                sub = parts[2].lower() if len(parts) >= 3 else None
                self._display_module_help(arg, sub)
                return
            cmd_def = registry.get_command("core", arg)
            if cmd_def:
                self._display_command_help(cmd_def)
                return

        if cmd_verb == "solve" and len(parts) >= 2 and parts[1].lower() in ("help", "--help", "-h"):
            cmd_def = registry.get_command("core", "solve")
            if cmd_def:
                self._display_command_help(cmd_def)
                return

        if cmd_verb == "help":
            modules = [m for m in registry.get_command_modules() if m != "core"]
            output.write_line(
                f"[bold {primary}]Ichnos Interactive Shell[/]\n\n"
                "[bold]Workflow:[/bold]\n"
                f"  [{primary}]solve \\[path][/]       Autonomously solve CTF challenge workspace or active target\n"
                f"  [{primary}]load <path>[/]         Load file or directory as target\n"
                f"  [{primary}]set <text>[/]          Set raw text as target\n"
                f"  [{primary}]analyze[/]             Run automated triage on target\n"
                f"  [{primary}]select[/]              Inspect candidates from last operation\n"
                f"  [{primary}]steps[/]               Inspect deduction steps from last operation\n\n"
                "[bold]Session:[/bold]\n"
                f"  [{primary}]target[/]              Show current target\n"
                f"  [{primary}]mode \\[name][/]         Toggle mode (learner or expert)\n"
                f"  [{primary}]copy[/]                Copy clean result plaintext to clipboard\n"
                f"  [{primary}]theme \\[name][/]        Show or change theme\n"
                f"  [{primary}]history[/]             Recent commands\n"
                f"  [{primary}]clear[/]               Clear screen\n"
                f"  [{primary}]exit[/]                Exit shell\n\n"
                f"[bold]Modules:[/bold]\n"
                f"  [{secondary}]" + ", ".join(modules) + "[/]\n\n"
                "[bold]Examples:[/bold]\n"
                f"  [{accent}]solve ./challenge_folder[/]\n"
                f"  [{accent}]solve chall.py output.txt[/]\n"
                f"  [{accent}]crypto caesar --brute[/]\n"
                f"  [{accent}]crypto xor repeating[/]\n"
                f"  [{accent}]encoding auto[/]\n"
                f"  [{accent}]stego png file.png[/]\n"
                f"  [{accent}]binary strings file.bin[/]"
            )
            return

        # Direct module command listing: e.g. 'crypto', 'web', 'crypto xor'
        if cmd_verb in registry.get_command_modules():
            if len(parts) == 1 or (
                len(parts) == 2 and parts[1].lower() in ("help", "--help", "-h")
            ):
                self._display_module_help(cmd_verb)
                return
            if len(parts) == 2 or (
                len(parts) == 3 and parts[2].lower() in ("help", "--help", "-h")
            ):
                sub = parts[1].lower()
                sub_cmds = [
                    c
                    for c in registry.list_commands(cmd_verb)
                    if c.command.lower() == sub and c.subcommand
                ]
                if sub_cmds and not registry.get_command(cmd_verb, sub):
                    self._display_module_help(cmd_verb, sub)
                    return

        # Builtin: load <path>
        if cmd_verb == "load":
            if len(parts) < 2:
                output.write_error("Usage: load <path>")
                return
            path_str = raw_cmd[len(parts[0]) :].strip()
            try:
                inp = read_input(path_str)
                self.ui_state.set_active_input(inp)
                if inp.source_type == SourceType.DIRECTORY:
                    from ichnos.core.workspace import ChallengeWorkspace

                    ws = ChallengeWorkspace.load(inp.path)
                    summary = ws.summary()
                    cat_counts = (
                        ", ".join(f"{v} {k}" for k, v in summary["categories"].items())
                        if summary["categories"]
                        else "empty"
                    )
                    output.write_success(
                        f"Target directory set: [{primary}]{path_str}[/] ({summary['total_files']} files: {cat_counts})\n"
                        f"[dim {primary}]Type 'solve' to autonomously solve challenges in this workspace.[/dim {primary}]"
                    )
                    status_bar.update_status(
                        f"Target: {inp.path.name}/ ({summary['total_files']} files)"
                    )
                else:
                    output.write_success(
                        f"Target set: [{primary}]{path_str}[/] ({inp.size} B, {inp.detected_type})"
                    )
                    status_bar.update_status(f"Target: {inp.path.name if inp.path else path_str}")
            except Exception as e:
                output.write_error(f"Failed to load target: {e}")
            return

        # Builtin: set <text>
        if cmd_verb == "set":
            if len(parts) < 2:
                output.write_error("Usage: set <text>")
                return
            text_val = raw_cmd[len(parts[0]) :].strip()
            inp = Input(
                data=text_val.encode("utf-8"),
                source_type=SourceType.RAW,
                detected_type="text",
            )
            self.ui_state.set_active_input(inp)
            output.write_success(f"Target set: [dim]{text_val[:60]}[/dim] ({len(inp.data)} B)")
            status_bar.update_status("Target: text")
            return

        # Builtin: target / input
        if cmd_verb in ("target", "input"):
            active = self.ui_state.active_input
            if not active:
                output.write_line("[dim]target: none[/dim]")
            else:
                src = (
                    active.path.name
                    if active.path
                    else (active.filename if active.filename else str(active.source_type.value))
                )
                output.write_line(
                    f"target: [bold]{src}[/bold] ({active.size} B, {active.detected_type})"
                )
            return

        # Builtin: history
        if cmd_verb == "history":
            recent = self.ui_state.command_history[-20:]
            if not recent:
                output.write_info("Command history is empty.")
            else:
                lines = [f"  {idx}: [{primary}]{c}[/]" for idx, c in enumerate(recent, 1)]
                output.write_info("[bold]Command History:[/bold]\n" + "\n".join(lines))
            return

        # Builtin: select
        if cmd_verb == "select":
            if self.ui_state.active_result and self.ui_state.active_result.candidates:
                self.push_screen(CandidateSelectorScreen(self.ui_state.active_result))
            else:
                output.write_warning(
                    "No candidates available in current result to inspect. "
                    f"Run a command first (e.g. [{primary}]crypto caesar --brute[/])."
                )
            return

        # Builtin: steps
        if cmd_verb == "steps":
            if self.ui_state.active_result and self.ui_state.active_result.steps:
                self.push_screen(StepSelectorScreen(self.ui_state.active_result))
            else:
                output.write_warning(
                    "No deduction steps available in current result to inspect."
                )
            return

        # Builtin: mode [learner|expert]
        if cmd_verb == "mode":
            if len(parts) < 2:
                output.write_info(
                    f"Current session mode: [bold]{self.ui_state.mode}[/bold] (Options: learner, expert)"
                )
                return
            target_mode = parts[1].lower()
            if target_mode in ("learner", "expert"):
                self.ui_state.mode = target_mode
                output.write_success(f"Session mode set to [bold]{target_mode}[/bold].")
                status_bar.update_status(f"Mode: {target_mode}")
            else:
                output.write_error(f"Invalid mode '{target_mode}'. Choose 'learner' or 'expert'.")
            return

        # Builtin: copy
        if cmd_verb == "copy":
            self.action_copy_clean_result()
            return

        # Builtin: mascot
        if cmd_verb == "mascot":
            from rich.text import Text

            from ichnos.ui.mascot.frames import IDLE

            output.write_line(Text.from_ansi(IDLE, no_wrap=True))
            return

        # Builtin: theme [name]
        if cmd_verb == "theme":
            from ichnos.ui.theme import (
                get_active_theme_name,
                get_available_themes,
                set_active_theme_name,
            )

            avail = get_available_themes()
            if len(parts) < 2 or parts[1].lower() in ("list", "show"):
                curr = get_active_theme_name()
                lines = []
                for t in avail:
                    mark = " (active)" if t == curr else ""
                    style = f"bold {primary}" if t == curr else secondary
                    lines.append(f"  [{style}]{t}{mark}[/{style}]")
                output.write_line(
                    "[bold]Themes:[/bold]\n"
                    + "\n".join(lines)
                    + "\n\n[dim]Type 'theme <name>' to switch.[/dim]"
                )
                return

            target_theme = parts[1].lower()
            if target_theme in avail:
                try:
                    self.theme = target_theme
                    set_active_theme_name(target_theme)
                    output.write_success(f"Theme set to '{target_theme}'.")
                    status_bar.update_status(f"Theme: {target_theme}")
                except Exception as e:
                    output.write_error(f"Failed to apply theme '{target_theme}': {e}")
            else:
                output.write_error(f"Unknown theme '{target_theme}'. Available: {', '.join(avail)}")
            return

        # Check if long running
        cmd_def, _ = CommandRunner._resolve_command(parts)
        if cmd_def and cmd_def.is_long_running:
            self._execute_async_worker(raw_cmd)
        else:
            res = CommandRunner.run(raw_cmd, active_input=self.ui_state.active_input)
            self.ui_state.add_result(res)
            output.render_result(res)
            status_bar.update_status(f"Executed {res.command}")

    def _display_module_help(self, module: str, subgroup: str | None = None) -> None:
        """Renders formatted command listing for a module or subgroup in the output view."""
        from ichnos.core.registry import registry
        from ichnos.ui.widgets.output import IchnosOutput

        screen = self.get_screen("main")
        if not isinstance(screen, MainScreen):
            return

        output = screen.query_one("#output-view", IchnosOutput)
        primary = "#8ba4b0"
        accent = "#8ea4a2"
        fg = "#BBBBBB"
        if hasattr(self, "current_theme") and self.current_theme:
            theme = self.current_theme
            primary = getattr(theme, "primary", None) or primary
            accent = getattr(theme, "accent", None) or accent
            fg = getattr(theme, "foreground", None) or fg

        target_name = f"{module} {subgroup}" if subgroup else module
        commands = registry.list_commands(module)
        if subgroup:
            commands = [c for c in commands if c.command.lower() == subgroup.lower()]

        seen = set()
        unique_cmds = []
        for c in sorted(commands, key=lambda x: x.full_name):
            if c.full_name not in seen:
                seen.add(c.full_name)
                unique_cmds.append(c)

        if not unique_cmds:
            output.write_line(f"[bold {primary}]No commands registered for '{target_name}'.[/]")
            return

        title = (
            "Available workflow commands:"
            if target_name == "core"
            else f"Available commands for '{target_name}':"
        )
        lines = [f"[bold {primary}]{title}[/]\n"]
        for c in unique_cmds:
            arg_hints = []
            for arg in c.args:
                if not arg.is_option:
                    arg_hints.append(f"<{arg.name}>")
                elif arg.short_flag:
                    arg_hints.append(f"[{arg.short_flag}]")
                else:
                    arg_hints.append(f"[--{arg.name.replace('_', '-')}]")
            arg_str = f" [dim]{' '.join(arg_hints)}[/dim]" if arg_hints else ""
            desc = c.description or "No description"
            cmd_display = c.command if c.module == "core" else c.full_name
            cmd_with_args = f"[{accent}]{cmd_display}[/]{arg_str}"
            lines.append(f"  {cmd_with_args}")
            lines.append(f"    [dim {fg}]{desc}[/dim {fg}]")

        output.write_line("\n".join(lines))

    def _display_command_help(self, cmd_def) -> None:
        """Renders formatted help for an individual command."""
        from ichnos.ui.widgets.output import IchnosOutput

        screen = self.get_screen("main")
        if not isinstance(screen, MainScreen):
            return

        output = screen.query_one("#output-view", IchnosOutput)
        primary = "#8ba4b0"
        accent = "#8ea4a2"
        fg = "#BBBBBB"
        if hasattr(self, "current_theme") and self.current_theme:
            theme = self.current_theme
            primary = getattr(theme, "primary", None) or primary
            accent = getattr(theme, "accent", None) or accent
            fg = getattr(theme, "foreground", None) or fg

        arg_hints = []
        for arg in cmd_def.args:
            if not arg.is_option:
                arg_hints.append(f"<{arg.name}>")
            elif arg.short_flag:
                arg_hints.append(f"[{arg.short_flag}]")
            else:
                arg_hints.append(f"[--{arg.name.replace('_', '-')}]")
        arg_str = f" [dim]{' '.join(arg_hints)}[/dim]" if arg_hints else ""
        cmd_display = cmd_def.command if cmd_def.module == "core" else cmd_def.full_name

        lines = [
            f"[bold {primary}]Command:[/] [{accent}]{cmd_display}[/]{arg_str}",
            f"  [dim {fg}]{cmd_def.description or 'No description'}[/dim {fg}]\n",
        ]
        if cmd_def.args:
            lines.append(f"[bold {primary}]Arguments:[/]")
            for arg in cmd_def.args:
                opt_str = " [dim](optional)[/dim]" if not arg.required else ""
                lines.append(f"  [{accent}]{arg.name:<16}[/] {arg.description}{opt_str}")

        if cmd_def.command == "solve":
            lines.append(f"\n[bold {primary}]Examples:[/]")
            lines.append(
                f"  [{accent}]solve[/]                         Solve active target workspace"
            )
            lines.append(
                f"  [{accent}]solve ./challenge_folder[/]      Solve directory of challenge files"
            )
            lines.append(
                f"  [{accent}]solve chall.py output.txt[/]     Solve specific script and log files"
            )

        output.write_line("\n".join(lines))

    def dispatch_chained_command(self, cmd_line: str, origin: str) -> None:
        """Dispatches a piped/chained workflow command from candidate inspection."""
        screen = self.get_screen("main")
        if isinstance(screen, MainScreen):
            output = screen.query_one("#output-view", IchnosOutput)
            output.write_line(f"[dim]Target set to {origin} → {cmd_line}...[/dim]")
        self.dispatch_command(cmd_line)

    def handle_extraction_complete(self, path, size: int, method: str) -> None:
        """Handles post-extraction messaging and status update."""
        screen = self.get_screen("main")
        if isinstance(screen, MainScreen):
            output = screen.query_one("#output-view", IchnosOutput)
            status_bar = screen.query_one("#status-bar", IchnosStatusBar)
            output.write_success(f"Exported to [cyan]{path}[/cyan] → set as target.")
            status_bar.update_status(f"Target: {path.name}")

    @work(thread=True)
    def _execute_async_worker(self, cmd_line: str) -> None:
        """Executes long-running command in a background worker thread."""
        self.ui_state.running_operation = cmd_line
        self.call_from_thread(self._start_progress_ui, cmd_line)

        try:
            res = CommandRunner.run(cmd_line, active_input=self.ui_state.active_input)
            if self.ui_state.running_operation is None:
                # Cancelled mid-flight
                return
            self.call_from_thread(self._finish_worker_success, res)
        except Exception as e:
            self.call_from_thread(self._finish_worker_error, cmd_line, str(e))
        finally:
            self.ui_state.running_operation = None
            self.call_from_thread(self._stop_progress_ui)

    def _start_progress_ui(self, cmd_line: str) -> None:
        screen = self.get_screen("main")
        if isinstance(screen, MainScreen):
            progress = screen.query_one("#progress-indicator", IchnosProgress)
            status_bar = screen.query_one("#status-bar", IchnosStatusBar)
            progress.start(f"Running {cmd_line}")
            status_bar.update_status(f"Running {cmd_line}")

    def _stop_progress_ui(self) -> None:
        screen = self.get_screen("main")
        if isinstance(screen, MainScreen):
            progress = screen.query_one("#progress-indicator", IchnosProgress)
            status_bar = screen.query_one("#status-bar", IchnosStatusBar)
            progress.stop()
            status_bar.update_status("Ready")

    def _finish_worker_success(self, res: Result) -> None:
        self.ui_state.add_result(res)
        screen = self.get_screen("main")
        if isinstance(screen, MainScreen):
            output = screen.query_one("#output-view", IchnosOutput)
            output.render_result(res)

    def _finish_worker_error(self, cmd_line: str, error_msg: str) -> None:
        screen = self.get_screen("main")
        if isinstance(screen, MainScreen):
            output = screen.query_one("#output-view", IchnosOutput)
            output.write_error(f"Execution error on '{cmd_line}': {error_msg}")

    def cancel_active_worker(self) -> None:
        """Cancels running async background worker."""
        self.ui_state.running_operation = None
        self._stop_progress_ui()

    def handle_autocomplete(self, current_text: str, cursor_pos: int) -> None:
        """Context-aware tab autocompletion handler."""
        import os

        screen = self.get_screen("main")
        if not isinstance(screen, MainScreen):
            return

        prompt = screen.query_one("#command-prompt", IchnosPrompt)
        output = screen.query_one("#output-view", IchnosOutput)

        prefix_text = current_text[:cursor_pos]
        if not prefix_text.strip():
            tokens = [""]
        elif prefix_text.endswith(" "):
            tokens = prefix_text.split() + [""]
        else:
            tokens = prefix_text.split()

        if tokens and tokens[0].lower() == "theme":
            from ichnos.ui.theme import get_available_themes

            sub_tok = tokens[1].lower() if len(tokens) > 1 else ""
            completions = [
                (t, f"{t} theme") for t in get_available_themes() if t.startswith(sub_tok)
            ]
        else:
            completions = registry.get_completions(tokens)
        if not completions:
            return

        if len(completions) == 1:
            match_str = completions[0][0]
            if prefix_text.endswith(" "):
                new_prefix = prefix_text + match_str
            else:
                last_space = prefix_text.rfind(" ")
                if last_space == -1:
                    new_prefix = match_str
                else:
                    new_prefix = prefix_text[: last_space + 1] + match_str

            if not match_str.endswith("/"):
                new_prefix += " "

            prompt.value = new_prefix + current_text[cursor_pos:]
            prompt.cursor_position = len(new_prefix)
        else:
            match_names = [m[0] for m in completions]
            common = os.path.commonprefix(match_names)
            last_tok = tokens[-1]
            if len(common) > len(last_tok):
                last_space = prefix_text.rfind(" ")
                if last_space == -1:
                    new_prefix = common
                else:
                    new_prefix = prefix_text[: last_space + 1] + common
                prompt.value = new_prefix + current_text[cursor_pos:]
                prompt.cursor_position = len(new_prefix)
            else:
                items = [
                    f"[bold cyan]{name}[/bold cyan] [dim]({desc})[/dim]"
                    for name, desc in completions[:12]
                ]
                output.write_line("  ".join(items))

    def action_copy_clean_result(self) -> None:
        """Copies clean plain text of current result to clipboard (OSC 52 + pyperclip fallback)."""
        screen = self.get_screen("main")
        output = (
            screen.query_one("#output-view", IchnosOutput)
            if isinstance(screen, MainScreen)
            else None
        )

        res = self.ui_state.active_result
        if not res and self.ui_state.result_history:
            res = self.ui_state.result_history[-1]

        if not res:
            if output:
                output.write_warning("No result available to copy.")
            return

        # Reconstruct clean plain text without borders/ANSI
        text_to_copy = ""
        if res.candidates:
            text_to_copy = res.candidates[0].decoded_str
        elif res.findings:
            text_to_copy = "\n".join(
                f"{f.label} ({int(f.confidence * 100)}%): {f.detail}" for f in res.findings
            )
        elif res.raw_output:
            if isinstance(res.raw_output, dict):
                import json

                text_to_copy = json.dumps(res.raw_output, indent=2, default=str)
            else:
                text_to_copy = str(res.raw_output)

        if not text_to_copy.strip():
            if output:
                output.write_warning("Active result has no text to copy.")
            return

        copied = False
        try:
            self.copy_to_clipboard(text_to_copy)
            copied = True
        except Exception:
            pass

        if not copied:
            try:
                import pyperclip

                pyperclip.copy(text_to_copy)
                copied = True
            except Exception:
                pass

        if output:
            preview = text_to_copy.replace("\n", " ").replace("\r", "")
            if len(preview) > 50:
                preview = preview[:47] + "..."
            output.write_success(f"Copied clean text to clipboard: [bold]{preview}[/bold]")
