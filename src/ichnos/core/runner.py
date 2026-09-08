"""Command runner for dispatching parsed CLI/TUI command strings to registry handlers."""

from __future__ import annotations

import shlex
from typing import Any

# Ensure commands are registered
import ichnos.core.commands  # noqa: F401
from ichnos.core.models import Finding, Input, Result
from ichnos.core.registry import registry


class CommandRunner:
    """Dispatches command strings to registered handlers and normalizes output to Result."""

    @classmethod
    def run(cls, cmd_line: str, active_input: Input | None = None) -> Result:
        raw_cmd = cmd_line.strip()
        if not raw_cmd:
            return Result(command="", status="error", raw_output={"error": "Empty command"})

        try:
            tokens = shlex.split(raw_cmd)
        except ValueError as e:
            return Result(
                command=raw_cmd,
                status="error",
                findings=[
                    Finding(label="Syntax Error", confidence=1.0, detail=str(e), module="core")
                ],
                raw_output={"error": str(e)},
            )

        if not tokens:
            return Result(command="", status="error", raw_output={"error": "Empty command"})

        first = tokens[0].lower()

        # Check if user requested module or command help via 'help <target>'
        if first == "help" and len(tokens) >= 2:
            target = tokens[1].lower()
            if target in registry.get_command_modules():
                sub = tokens[2].lower() if len(tokens) >= 3 else None
                return cls._get_module_help_result(target, sub)
            cmd_def = registry.get_command("core", target)
            if cmd_def:
                return cls._get_command_help_result(cmd_def)
            if len(tokens) >= 3:
                cmd_def = registry.get_command(target, tokens[2].lower())
                if cmd_def:
                    return cls._get_command_help_result(cmd_def)

        # Check if command called with --help, -h, or help
        if len(tokens) >= 2 and tokens[-1].lower() in ("--help", "-h", "help"):
            cmd_def, _ = cls._resolve_command(tokens[:-1])
            if cmd_def:
                return cls._get_command_help_result(cmd_def)

        # Check if user typed just module name or subgroup (e.g. 'crypto', 'web', 'crypto xor')
        if first in registry.get_command_modules():
            if len(tokens) == 1 or (
                len(tokens) == 2 and tokens[1].lower() in ("help", "--help", "-h")
            ):
                return cls._get_module_help_result(first)
            if len(tokens) == 2 or (
                len(tokens) == 3 and tokens[2].lower() in ("help", "--help", "-h")
            ):
                sub = tokens[1].lower()
                sub_cmds = [
                    c
                    for c in registry.list_commands(first)
                    if c.command.lower() == sub and c.subcommand
                ]
                if sub_cmds and not registry.get_command(first, sub):
                    return cls._get_module_help_result(first, sub)

        # Resolve command definition
        cmd_def, remaining_tokens = cls._resolve_command(tokens)
        if not cmd_def:
            available = ", ".join(registry.get_command_modules())
            return Result(
                command=raw_cmd,
                status="error",
                findings=[
                    Finding(
                        label="Unknown Command",
                        confidence=1.0,
                        detail=f"Unknown command: '{raw_cmd}'. Available modules: {available}",
                        module="core",
                    )
                ],
                raw_output={"error": f"Command not found: {raw_cmd}"},
            )

        # Parse arguments against cmd_def.args
        try:
            kwargs = cls._parse_args(cmd_def, remaining_tokens, active_input)
        except Exception as e:
            return Result(
                command=raw_cmd,
                status="error",
                findings=[
                    Finding(
                        label="Argument Error", confidence=1.0, detail=str(e), module=cmd_def.module
                    )
                ],
                raw_output={"error": str(e)},
            )

        # Execute handler
        try:
            if not cmd_def.handler:
                raise RuntimeError(f"No handler registered for {cmd_def.full_name}")

            res = cmd_def.handler(**kwargs, active_input=active_input)
            if isinstance(res, Result):
                return res
            return Result(command=raw_cmd, raw_output={"result": res})
        except Exception as e:
            return Result(
                command=raw_cmd,
                status="error",
                findings=[
                    Finding(
                        label="Execution Error",
                        confidence=1.0,
                        detail=str(e),
                        module=cmd_def.module,
                    )
                ],
                raw_output={"error": str(e)},
            )

    @classmethod
    def _get_module_help_result(cls, mod: str, subgroup: str | None = None) -> Result:
        commands = registry.list_commands(mod)
        if subgroup:
            commands = [c for c in commands if c.command.lower() == subgroup.lower()]
            target_name = f"{mod} {subgroup}"
        else:
            target_name = mod

        # Deduplicate and sort commands by full_name
        seen = set()
        unique_cmds = []
        for c in sorted(commands, key=lambda x: x.full_name):
            if c.full_name not in seen:
                seen.add(c.full_name)
                unique_cmds.append(c)

        if not unique_cmds:
            return Result(
                command=target_name,
                status="success",
                raw_output=f"No commands found for module '{target_name}'.",
            )

        lines = [f"Available commands for '{target_name}':"]
        for c in unique_cmds:
            arg_hints = []
            for arg in c.args:
                if not arg.is_option:
                    arg_hints.append(f"<{arg.name}>")
                elif arg.short_flag:
                    arg_hints.append(f"[{arg.short_flag}]")
                else:
                    arg_hints.append(f"[--{arg.name.replace('_', '-')}]")
            arg_str = f" {' '.join(arg_hints)}" if arg_hints else ""
            cmd_with_args = f"{c.full_name}{arg_str}"
            desc = c.description or "No description"
            lines.append(f"  {cmd_with_args:<38} {desc}")

        help_text = "\n".join(lines)
        return Result(
            command=target_name,
            status="success",
            raw_output=help_text,
        )

    @classmethod
    def _get_command_help_result(cls, cmd_def) -> Result:
        arg_hints = []
        for arg in cmd_def.args:
            if not arg.is_option:
                arg_hints.append(f"<{arg.name}>")
            elif arg.short_flag:
                arg_hints.append(f"[{arg.short_flag}]")
            else:
                arg_hints.append(f"[--{arg.name.replace('_', '-')}]")
        arg_str = f" {' '.join(arg_hints)}" if arg_hints else ""
        cmd_display = cmd_def.command if cmd_def.module == "core" else cmd_def.full_name
        lines = [
            f"Command: {cmd_display}{arg_str}",
            f"Description: {cmd_def.description or 'No description'}",
        ]
        if cmd_def.args:
            lines.append("\nArguments:")
            for arg in cmd_def.args:
                opt_str = " (optional)" if not arg.required else ""
                lines.append(f"  {arg.name:<18} {arg.description}{opt_str}")
        if cmd_def.command == "solve":
            lines.append("\nExamples:")
            lines.append("  solve                         Solve active target workspace")
            lines.append("  solve ./challenge_folder      Solve directory of challenge files")
            lines.append("  solve chall.py output.txt     Solve specific script and log files")
        return Result(command=cmd_display, status="success", raw_output="\n".join(lines))

    @classmethod
    def _resolve_command(cls, tokens: list[str]):
        """Resolves tokens to (CommandDef, remaining_tokens)."""
        first = tokens[0].lower()

        # Check top-level (e.g. analyze)
        cmd_def = registry.get_command("core", first)
        if cmd_def:
            return cmd_def, tokens[1:]

        if len(tokens) >= 2:
            mod = tokens[0].lower()
            cmd = tokens[1].lower()
            # Check 3-token command (module command subcommand)
            if len(tokens) >= 3:
                sub = tokens[2].lower()
                sub_def = registry.get_command(mod, cmd, sub)
                if sub_def:
                    return sub_def, tokens[3:]

            # 2-token command (module command)
            cmd_def = registry.get_command(mod, cmd)
            if cmd_def:
                return cmd_def, tokens[2:]

        return None, tokens

    @classmethod
    def _parse_args(cls, cmd_def, tokens: list[str], active_input: Input | None) -> dict[str, Any]:
        """Maps remaining tokens to keyword arguments based on CommandArg definitions."""
        kwargs: dict[str, Any] = {}
        positional_args = [arg for arg in cmd_def.args if not arg.is_option]
        option_args = {
            f"--{arg.name.replace('_', '-')}": arg for arg in cmd_def.args if arg.is_option
        }
        for arg in cmd_def.args:
            if arg.short_flag:
                option_args[arg.short_flag] = arg

        pos_idx = 0
        i = 0
        while i < len(tokens):
            tok = tokens[i]
            if tok.startswith("-"):
                # Option or flag
                flag_name = tok
                flag_val = None
                if "=" in tok:
                    flag_name, flag_val = tok.split("=", 1)

                if flag_name in option_args:
                    arg_spec = option_args[flag_name]
                    if arg_spec.is_flag:
                        kwargs[arg_spec.name] = True
                    else:
                        if flag_val is not None:
                            val = flag_val
                        elif i + 1 < len(tokens) and not tokens[i + 1].startswith("-"):
                            i += 1
                            val = tokens[i]
                        else:
                            raise ValueError(f"Option {flag_name} requires a value")

                        # Cast value
                        if arg_spec.type is int:
                            val = int(val)
                        elif arg_spec.type is float:
                            val = float(val)
                        kwargs[arg_spec.name] = val
                else:
                    raise ValueError(f"Unknown option: {tok}")
            else:
                # Positional argument
                if pos_idx < len(positional_args):
                    arg_spec = positional_args[pos_idx]
                    kwargs[arg_spec.name] = tok
                    pos_idx += 1
                else:
                    # Excess positional arguments joined into last positional or ignored
                    if pos_idx > 0:
                        prev_arg = positional_args[pos_idx - 1]
                        kwargs[prev_arg.name] = f"{kwargs[prev_arg.name]} {tok}"
                    else:
                        pos_idx += 1
            i += 1

        # Check required arguments
        for arg in positional_args:
            if arg.name not in kwargs:
                if arg.default is not None:
                    kwargs[arg.name] = arg.default
                elif arg.required:
                    # If active_input is available, default to '-' or None
                    if active_input is not None:
                        kwargs[arg.name] = None
                    else:
                        raise ValueError(f"Missing required argument: <{arg.name}>")

        return kwargs


def run_command(cmd_line: str, active_input: Input | None = None) -> Result:
    """Convenience functional wrapper for CommandRunner.run."""
    return CommandRunner.run(cmd_line, active_input=active_input)
