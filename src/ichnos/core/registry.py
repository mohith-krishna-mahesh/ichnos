"""Module/command registry — powers the `analyze` command's dispatch.

Modules register analyzers via the @registry.analyzer decorator.
Each analyzer must implement:
  - can_handle(input: Input) -> float   (confidence 0–1)
  - suggest(input: Input) -> list[str]  (CLI command suggestions)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Callable, Protocol

if TYPE_CHECKING:
    from ichnos.core.models import Finding, Input


class Analyzer(Protocol):
    """Protocol that all registered analyzers must implement."""

    module: str
    name: str

    def can_handle(self, inp: Input) -> float: ...
    def suggest(self, inp: Input) -> list[str]: ...


@dataclass
class AnalyzerEntry:
    """Internal registry entry wrapping an analyzer."""

    analyzer: Analyzer
    module: str
    name: str


@dataclass
class CommandArg:
    """Specification of an argument or option accepted by a command."""

    name: str
    type: type = str
    description: str = ""
    default: Any = None
    required: bool = True
    is_option: bool = False
    short_flag: str | None = None
    is_flag: bool = False
    is_path: bool = False
    choices: list[str] | None = None


@dataclass
class CommandDef:
    """Registered command definition serving CLI and TUI dispatch."""

    module: str
    command: str
    subcommand: str | None = None
    handler: Callable[..., Any] | None = None
    description: str = ""
    args: list[CommandArg] = field(default_factory=list)
    is_long_running: bool = False

    @property
    def full_name(self) -> str:
        if self.subcommand:
            return f"{self.module} {self.command} {self.subcommand}"
        return f"{self.module} {self.command}"


BUILTIN_COMMANDS: list[tuple[str, str]] = [
    ("help", "Show help and available commands"),
    ("load", "Load input file into active session: load <path>"),
    ("set", "Set active session text input: set <text>"),
    ("input", "Show currently loaded active input details"),
    ("clear", "Clear terminal output screen"),
    ("history", "Show session command history"),
    ("select", "Open interactive candidate selector"),
    ("theme", "View or switch color themes: theme <name>"),
    ("mascot", "Display Ichnos mascot illustration"),
    ("exit", "Exit Ichnos interactive terminal"),
    ("quit", "Exit Ichnos interactive terminal"),
]


def complete_path(prefix: str) -> list[tuple[str, str]]:
    """Completes filesystem path matching prefix."""
    import os

    expanded = os.path.expanduser(prefix)
    if os.path.isdir(expanded) and prefix.endswith(os.sep):
        dirname = expanded
        stub = ""
    else:
        dirname = os.path.dirname(expanded) or "."
        stub = os.path.basename(expanded)

    results: list[tuple[str, str]] = []
    try:
        if os.path.exists(dirname) and os.path.isdir(dirname):
            for entry in sorted(os.listdir(dirname)):
                if entry.startswith(stub):
                    if not stub and entry.startswith("."):
                        continue
                    full = os.path.join(dirname, entry)
                    is_dir = os.path.isdir(full)
                    # Reconstruct display path
                    orig_dir = os.path.dirname(prefix)
                    display = os.path.join(orig_dir, entry) if orig_dir else entry
                    if is_dir:
                        display = display.rstrip("/") + "/"
                        results.append((display, "directory"))
                    else:
                        results.append((display, "file"))
    except Exception:
        pass
    return results[:40]


class Registry:
    """Central registry of analyzers and commands used across CLI and TUI."""

    def __init__(self) -> None:
        self._analyzers: list[AnalyzerEntry] = []
        self._commands: dict[tuple[str, str, str | None], CommandDef] = {}

    # =========================================================================
    # Analyzer Registration (for `analyze`)
    # =========================================================================

    def analyzer(self, *, module: str, name: str | None = None):
        """Decorator to register an analyzer class."""

        def decorator(cls):
            instance = cls()
            entry = AnalyzerEntry(
                analyzer=instance,
                module=module,
                name=name or getattr(instance, "name", cls.__name__),
            )
            self._analyzers.append(entry)
            return cls

        return decorator

    def query_all(self, inp: Input) -> list[Finding]:
        """Query all registered analyzers and return sorted findings."""
        from ichnos.core.models import Finding

        findings: list[Finding] = []
        for entry in self._analyzers:
            try:
                confidence = entry.analyzer.can_handle(inp)
                if confidence > 0.0:
                    suggestions = entry.analyzer.suggest(inp)
                    for suggestion in suggestions:
                        findings.append(
                            Finding(
                                label=f"{entry.name} detection",
                                confidence=confidence,
                                detail=suggestion,
                                module=entry.module,
                                command_hint=suggestion,
                            )
                        )
                    if not suggestions and confidence > 0.0:
                        findings.append(
                            Finding(
                                label=f"{entry.name} detection",
                                confidence=confidence,
                                module=entry.module,
                            )
                        )
            except Exception:
                continue

        return sorted(findings, key=lambda f: f.confidence, reverse=True)

    @property
    def registered_modules(self) -> list[str]:
        return sorted({e.module for e in self._analyzers})

    # =========================================================================
    # Command Dispatch Registration (Single Source of Truth)
    # =========================================================================

    def register_command(self, cmd_def: CommandDef) -> None:
        """Registers a command definition into the dispatch table."""
        key = (
            cmd_def.module.lower(),
            cmd_def.command.lower(),
            cmd_def.subcommand.lower() if cmd_def.subcommand else None,
        )
        self._commands[key] = cmd_def

    def command(
        self,
        module: str,
        name: str,
        subcommand: str | None = None,
        description: str = "",
        args: list[CommandArg] | None = None,
        is_long_running: bool = False,
    ):
        """Decorator to register a command handler function."""

        def decorator(fn: Callable[..., Any]):
            cmd_def = CommandDef(
                module=module,
                command=name,
                subcommand=subcommand,
                handler=fn,
                description=description,
                args=args or [],
                is_long_running=is_long_running,
            )
            self.register_command(cmd_def)
            return fn

        return decorator

    def get_command(
        self, module: str, command: str, subcommand: str | None = None
    ) -> CommandDef | None:
        """Looks up a registered command definition."""
        key = (
            module.lower(),
            command.lower(),
            subcommand.lower() if subcommand else None,
        )
        return self._commands.get(key)

    def list_commands(self, module: str | None = None) -> list[CommandDef]:
        """Lists all registered command definitions, optionally filtered by module."""
        if module:
            mod_low = module.lower()
            return [cmd for key, cmd in self._commands.items() if key[0] == mod_low]
        return list(self._commands.values())

    def get_command_modules(self) -> list[str]:
        """Returns sorted list of modules that have registered commands."""
        return sorted({key[0] for key in self._commands})

    def get_completions(self, tokens: list[str]) -> list[tuple[str, str]]:
        """Provides context-aware tab completions for command tokens."""
        if not tokens:
            tokens = [""]

        # Token 0: Builtins, modules, top-level commands, or path
        if len(tokens) == 1:
            prefix = tokens[0].lower()
            if prefix.startswith(("/", "./", "../", "~")):
                return complete_path(tokens[0])

            matches: list[tuple[str, str]] = []
            # Builtins
            for name, desc in BUILTIN_COMMANDS:
                if name.startswith(prefix):
                    matches.append((name, desc))
            # Modules
            for mod in self.get_command_modules():
                if mod.startswith(prefix) and (mod, f"{mod} module") not in matches:
                    matches.append((mod, f"{mod} module"))
            # Top-level commands (e.g. analyze)
            for (mod, cmd, sub), cmd_def in self._commands.items():
                if mod == "core" and cmd.startswith(prefix):
                    matches.append((cmd, cmd_def.description))
            return matches

        first = tokens[0].lower()

        # Builtin 'load' takes a path
        if first == "load":
            return complete_path(tokens[1] if len(tokens) > 1 else "")

        # Top-level command (e.g. analyze)
        top_cmd = self.get_command("core", first)
        if top_cmd:
            last = tokens[-1]
            if last.startswith("-"):
                return [
                    (f"--{arg.name.replace('_', '-')}", arg.description)
                    for arg in top_cmd.args
                    if arg.is_option and f"--{arg.name.replace('_', '-')}".startswith(last)
                ]
            # Analyze source is a path
            return complete_path(last)

        # Module + command lookup
        mod = first
        if len(tokens) == 2:
            prefix = tokens[1].lower()
            if not prefix.startswith("-") and not prefix.startswith(("/", "./", "../", "~")):
                matches = []
                for (m, cmd, sub), cmd_def in self._commands.items():
                    if m == mod and cmd.startswith(prefix):
                        desc = cmd_def.description or f"{cmd} command"
                        matches.append((cmd, desc))
                if matches:
                    return matches

        # Token 3+ or option/path completion
        cmd = tokens[1].lower() if len(tokens) >= 2 else ""
        cmd_def = self.get_command(mod, cmd)
        if cmd_def:
            last_tok = tokens[-1]
            if last_tok.startswith("-"):
                matches = []
                for arg in cmd_def.args:
                    if arg.is_option:
                        flag = f"--{arg.name.replace('_', '-')}"
                        if flag.startswith(last_tok):
                            matches.append((flag, arg.description))
                return matches

            if last_tok.startswith(("/", "./", "../", "~")):
                return complete_path(last_tok)

            # Check positional arguments for path hint
            positional_args = [arg for arg in cmd_def.args if not arg.is_option]
            pos_index = max(0, len(tokens) - 3)
            if pos_index < len(positional_args) and positional_args[pos_index].is_path:
                return complete_path(last_tok)

        return []


# Global singleton registry
registry = Registry()
