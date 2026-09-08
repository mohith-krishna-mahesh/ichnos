"""Main terminal screen for interactive command execution."""

from __future__ import annotations

from textual.containers import Vertical
from textual.screen import Screen

from ichnos.ui.widgets.banner import IchnosHeader
from ichnos.ui.widgets.output import IchnosOutput
from ichnos.ui.widgets.progress import IchnosProgress
from ichnos.ui.widgets.prompt import IchnosPrompt
from ichnos.ui.widgets.status import IchnosStatusBar


class MainScreen(Screen):
    """Main interactive terminal screen."""

    def compose(self):
        yield IchnosHeader()
        yield IchnosOutput(id="output-view")
        yield IchnosProgress(id="progress-indicator")
        with Vertical(id="prompt-container"):
            yield IchnosPrompt(state=self.app.ui_state, id="command-prompt")
        yield IchnosStatusBar(state=self.app.ui_state, id="status-bar")

    def on_mount(self) -> None:
        prompt = self.query_one("#command-prompt", IchnosPrompt)
        prompt.focus()
        output = self.query_one("#output-view", IchnosOutput)
        output.write_line("Ichnos interactive shell. Type 'help' for commands.")

    def on_ichnos_prompt_submitted_command(self, event: IchnosPrompt.SubmittedCommand) -> None:
        cmd = event.command
        output = self.query_one("#output-view", IchnosOutput)
        primary = "#8ba4b0"
        if hasattr(self.app, "current_theme") and self.app.current_theme:
            primary = self.app.current_theme.primary
        output.write_line(f"[bold {primary}]ichnos>[/bold {primary}] {cmd}")
        self.app.ui_state.add_command(cmd)

        if cmd.lower() in ("exit", "quit", "q"):
            self.app.exit()
            return

        if cmd.lower() == "clear":
            output.clear_output()
            return

        # Execution will be dispatched via runner (Phase 4)
        self.app.dispatch_command(cmd)

    def on_ichnos_prompt_cancel_requested(self, event: IchnosPrompt.CancelRequested) -> None:
        prompt = self.query_one("#command-prompt", IchnosPrompt)
        status = self.query_one("#status-bar", IchnosStatusBar)
        output = self.query_one("#output-view", IchnosOutput)

        # 3-Tier Priority Rule
        # 1. Active Worker
        if self.app.ui_state.running_operation:
            self.app.cancel_active_worker()
            output.write_warning("[Interrupted]")
            status.update_status("Operation cancelled")
            return

        # 2. Uncommitted Text
        if prompt.value:
            prompt.value = ""
            status.update_status("Line cleared")
            return

        # 3. Empty & Idle
        status.update_status("Press Ctrl+D or type 'exit' to quit")

    def on_ichnos_prompt_exit_requested(self, event: IchnosPrompt.ExitRequested) -> None:
        self.app.exit()

    def on_ichnos_prompt_clear_view_requested(self, event: IchnosPrompt.ClearViewRequested) -> None:
        output = self.query_one("#output-view", IchnosOutput)
        output.clear_output()

    def on_ichnos_prompt_autocomplete_requested(
        self, event: IchnosPrompt.AutocompleteRequested
    ) -> None:
        self.app.handle_autocomplete(event.current_text, event.cursor_pos)

    def on_ichnos_prompt_page_up_requested(self, event: IchnosPrompt.PageUpRequested) -> None:
        output = self.query_one("#output-view", IchnosOutput)
        output.scroll_page_up()

    def on_ichnos_prompt_page_down_requested(self, event: IchnosPrompt.PageDownRequested) -> None:
        output = self.query_one("#output-view", IchnosOutput)
        output.scroll_page_down()

    def on_ichnos_prompt_copy_result_requested(
        self, event: IchnosPrompt.CopyResultRequested
    ) -> None:
        if hasattr(self.app, "action_copy_clean_result"):
            self.app.action_copy_clean_result()
