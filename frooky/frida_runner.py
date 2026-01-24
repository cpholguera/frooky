from __future__ import annotations

import frida
import time
import subprocess
import sys
import json
import shutil
from dataclasses import dataclass
from importlib import resources
from pathlib import Path
from typing import Optional

from .resources import read_text


BRIDGES = [
    "frida-java-bridge",
    "frida-objc-bridge",
    "frida-swift-bridge",
]


@dataclass
class RunnerOptions:
    """Options for the FrookyRunner."""
    platform: str
    hook_paths: list[Path]
    output_path: Path
    device_id: Optional[str] = None
    use_usb: bool = False
    attach_frontmost: bool = False
    attach_name: Optional[str] = None
    attach_identifier: Optional[str] = None
    attach_pid: Optional[int] = None
    spawn: Optional[str] = None
    keep_artifacts: bool = False


class FrookyRunner:
    """Runs Frooky hooks using Frida."""

    def __init__(self, options: RunnerOptions):
        self.options = options
        self.session: Optional[frida.core.Session] = None
        self.script: Optional[frida.core.Script] = None
        self.device: Optional[frida.core.Device] = None
        self.spawned_pid: Optional[int] = None
        self.event_count: int = 0
        self.last_event: str = "Waiting for events..."
        self.total_hooks: Optional[int] = None
        self.total_errors: int = 0

    def _ensure_bridges(self) -> None:
        """Ensure Frida bridges are installed."""
        for bridge in BRIDGES:
            try:
                subprocess.check_call(
                    ["frida-pm", "install", bridge],
                    stdout=sys.stdout,
                    stderr=sys.stderr,
                )
            except subprocess.CalledProcessError:
                pass

    def _compile_agent(self, tmp_dir: Path):
        """Combine user hooks.json and compile the agent using the node build script"""

        platform = self.options.platform

        frooky_agent_dir = Path(__file__).parent / "frooky-agent"
        subprocess.run(
            ["npm", "run", f"build-{platform}", "--"] + self.options.hook_paths,
            cwd=frooky_agent_dir,
            check=True
        )

        # copy the compiled _agent.ts from frooky-agent to the local tmp
        source = Path(frooky_agent_dir, "tmp", "_agent.js")
        destination = Path(tmp_dir, "_agent.js")
        shutil.copy2(source, destination)


    def _create_message_handler(self):
        """Create a message handler closure with access to output path."""
        output_path = self.options.output_path

        def on_message(message, data):
            if message.get("type") != "send":
                print("MSG", message)
                return

            payload = message.get("payload")

            if isinstance(payload, dict) or isinstance(payload, list):
                with open(output_path, "a", encoding="utf-8") as f:
                    json.dump(payload, f)
                    f.write("\n")
                
                # Check if this is a summary event
                if isinstance(payload, dict):
                    event_type = payload.get("type")
                    
                    if event_type == "summary":
                        # Store summary info and print once
                        self.total_hooks = payload.get("totalHooks", 0)
                        self.total_errors = payload.get("totalErrors", 0)
                        self._print_hooks_line()
                    elif event_type == "hook":
                        # Only count hook events
                        self.event_count += 1
                        # Extract event info for status line
                        method = payload.get("method", payload.get("symbol", "unknown"))
                        class_name = payload.get("class", "")
                        if class_name:
                            self.last_event = f"{class_name}.{method}"
                        else:
                            self.last_event = method
                        self._update_status_line()
            else:
                try:
                    parsed = json.loads(payload)
                    with open(output_path, "a", encoding="utf-8") as f:
                        json.dump(parsed, f)
                        f.write("\n")
                    
                    # Check if this is a summary event
                    if isinstance(parsed, dict):
                        event_type = parsed.get("type")
                        
                        if event_type == "summary":
                            # Store summary info and print once
                            self.total_hooks = parsed.get("totalHooks", 0)
                            self.total_errors = parsed.get("totalErrors", 0)
                            self._print_hooks_line()
                        elif event_type == "hook":
                            # Only count hook events
                            self.event_count += 1
                            # Extract event info for status line
                            method = parsed.get("method", parsed.get("symbol", "unknown"))
                            class_name = parsed.get("class", "")
                            if class_name:
                                self.last_event = f"{class_name}.{method}"
                            else:
                                self.last_event = method
                            self._update_status_line()
                except Exception:
                    print("MSG", payload)

        return on_message

    def _print_hooks_line(self) -> None:
        """Print the hooks summary line once when summary event arrives."""
        hook_line = f"\n  Resolved Hooks: {self.total_hooks}"
        if self.total_errors > 0:
            hook_line += f" | Errors: {self.total_errors}"
        print(hook_line)
        # Print initial events line
        self._update_status_line()

    def _update_status_line(self) -> None:
        """Update the live status line with event count and last event."""
        # Truncate last_event if too long
        max_event_len = 60
        event_display = self.last_event[:max_event_len]
        if len(self.last_event) > max_event_len:
            event_display += "..."
        
        status = f"\r  Events: {self.event_count:,} \t\t| Last: {event_display}"
        # Pad with spaces to clear previous content
        status = status.ljust(100)
        print(status, end="", flush=True)

    def _get_target_description(self) -> str:
        """Get a description of the target for the header."""
        opts = self.options
        
        if opts.attach_frontmost:
            app = self.device.get_frontmost_application()
            if app:
                return f"frontmost application: {app.name} (PID: {app.pid})"
            return "frontmost application"
        elif opts.attach_name:
            return opts.attach_name
        elif opts.attach_identifier:
            return opts.attach_identifier
        elif opts.attach_pid:
            return str(opts.attach_pid)
        elif opts.spawn:
            return f"{opts.spawn} (spawned)"
        return "unknown target"

    def _print_header(self) -> None:
        """Print the Frooky header with session information."""
        # Get Frida version
        frida_version = frida.__version__
        
        # Logo lines
        logo = [
            "   ___    ____           ",
            "  / __\\  / _  |    _     _    _  _   _   _",
            " / _\\   | (_) |  / _ \\ / _ \\ | / /  | | | |",
            "/ /     / / | | | (_) | (_) ||  <   | |_| |",
            "\\/     /_/  |_|  \\___/ \\___/ |_|\\_\\  \\__, |",
            "                                     |___/",
        ]
        
        # Info lines to display on the right
        info = [
            f"Powered by Frida {frida_version}",
            f"Target: {self._get_target_description()}",
            "",
            f"Device: {self.device.name}" + (f" ({self.device.id})" if self.device.id else ""),
            f"Platform: {self.options.platform}",
            f"Hook files: {len(self.options.hook_paths)}",
            f"Output: {self.options.output_path}",
        ]
        
        # Find the width of the widest logo line
        logo_width = max(len(line) for line in logo)
        
        # Combine logo and info side by side
        lines = [""]
        for i in range(max(len(logo), len(info))):
            logo_part = logo[i].ljust(logo_width) if i < len(logo) else " " * logo_width
            info_part = info[i] if i < len(info) else ""
            lines.append(f"{logo_part}   {info_part}")
        
        lines.append("")
        lines.append("  Press Ctrl+C to stop...")
        lines.append("")
        
        print("\n".join(lines))

    def _get_device(self) -> frida.core.Device:
        """Get the Frida device based on options."""
        if self.options.device_id:
            return frida.get_device(self.options.device_id, timeout=5)
        elif self.options.use_usb:
            return frida.get_usb_device(timeout=5)
        else:
            # Default to local device
            return frida.get_local_device()

    def _attach_or_spawn(self) -> frida.core.Session:
        """Attach to or spawn the target process."""
        opts = self.options

        if opts.attach_frontmost:
            app = self.device.get_frontmost_application()
            if app is None:
                raise RuntimeError("No frontmost application found")
            return self.device.attach(app.pid)

        elif opts.attach_name:
            return self.device.attach(opts.attach_name)

        elif opts.attach_identifier:
            # Find process by identifier
            for proc in self.device.enumerate_processes():
                if proc.identifier == opts.attach_identifier:
                    return self.device.attach(proc.pid)
            # Fallback: try attaching by identifier as name
            return self.device.attach(opts.attach_identifier)

        elif opts.attach_pid:
            return self.device.attach(opts.attach_pid)

        elif opts.spawn:
            pid = self.device.spawn(opts.spawn)
            session = self.device.attach(pid)
            self.spawned_pid = pid
            return session

        else:
            raise RuntimeError("No target specified")

    def _cleanup_artifacts(self) -> None:
        """Remove temporary artifacts created during execution."""
        artifacts = [
            Path("tmp"),
            Path("node_modules"),
            Path("package.json"),
            Path("package-lock.json"),
        ]
        
        for artifact in artifacts:
            try:
                if artifact.is_dir():
                    shutil.rmtree(artifact)
                elif artifact.is_file():
                    artifact.unlink()
            except Exception:
                # Silently ignore cleanup errors
                pass

    def run(self) -> int:
        """Run the Frooky hooks."""
        try:
            self._ensure_bridges()

            # Set up paths
            tmp_dir = Path("tmp")
            tmp_dir.mkdir(exist_ok=True)
            built_agent = tmp_dir / "_agent.js"

            # Combine user hooks with platform base script
            self._compile_agent(tmp_dir)

            # Clear/overwrite the output file at start
            with open(self.options.output_path, "w", encoding="utf-8") as f:
                pass  # Truncate file

            # Get device
            self.device = self._get_device()

            # Attach or spawn
            self.session = self._attach_or_spawn()

            # Print header with all session info
            self._print_header()

            # Load script
            with open(built_agent, "r", encoding="utf-8") as f:
                script_source = f.read()

            self.script = self.session.create_script(script_source)
            self.script.on("message", self._create_message_handler())
            self.script.load()

            # Resume if spawned
            if self.options.spawn:
                self.device.resume(self.spawned_pid)

            # Main loop
            while True:
                time.sleep(0.2)

        except KeyboardInterrupt:
            # Overwrite the ^C characters
            print("\b\b  ", end="", flush=True)
            print("\n\n  Stopping ...\n")

        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            return 1

        finally:
            if self.script:
                try:
                    self.script.unload()
                except Exception:
                    pass
            if self.session:
                try:
                    self.session.detach()
                except Exception:
                    pass
            
            # Clean up artifacts unless --keep-artifacts was specified
            if not self.options.keep_artifacts:
                self._cleanup_artifacts()

        return 0
