from __future__ import annotations

import frida
import time
import subprocess
import os
import sys
import json
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

BANNER = r"""
   ___    ____           
  / __\  / _  |    _     _    _  _   _   _
 / _\   | (_) |  / _ \ / _ \ | / /  | | | |
/ /     / / | | | (_) | (_) ||  <   | |_| |
\/     /_/  |_|  \___/ \___/ |_|\_\  \__, |
                                     |___/
"""


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


class FrookyRunner:
    """Runs Frooky hooks using Frida."""

    def __init__(self, options: RunnerOptions):
        self.options = options
        self.session: Optional[frida.core.Session] = None
        self.script: Optional[frida.core.Script] = None
        self.device: Optional[frida.core.Device] = None

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

    def _build_agent(self, src_agent: Path, built_agent: Path) -> None:
        """Build the agent script if needed."""
        if not built_agent.exists() or (
            built_agent.stat().st_mtime < src_agent.stat().st_mtime
        ):
            subprocess.check_call(
                ["npx", "frida-compile", str(src_agent), "-o", str(built_agent)],
                stdout=sys.stdout,
                stderr=sys.stderr,
            )

    def _get_platform_scripts(self) -> list[str]:
        """Get all .js files from the platform folder, with base_script.js last."""
        platform = self.options.platform
        platform_dir = resources.files("frooky").joinpath(platform)
        
        script_files = [
            item.name for item in platform_dir.iterdir()
            if item.name.endswith(".js") and item.name != "base_script.js"
        ]
        script_files.append("base_script.js")
        
        return script_files

    def _prepare_script(self, tmp_dir: Path) -> Path:
        """Combine user hooks with platform scripts."""
        # Read all hook files as JSON and merge hooks arrays
        merged_hooks = []
        category = None
        
        for hook_path in self.options.hook_paths:
            with open(hook_path, "r", encoding="utf-8") as f:
                hook_data = json.load(f)
            
            # Take category from first file that has one
            if category is None and "category" in hook_data:
                category = hook_data["category"]
            
            # Merge hooks
            if "hooks" in hook_data:
                merged_hooks.extend(hook_data["hooks"])
        
        # Build the target object
        target = {
            "category": category or "FROOKY",
            "hooks": merged_hooks
        }
        
        # Generate JavaScript declaration
        user_hooks = f"var target = {json.dumps(target, indent=2)};"

        # Get all platform scripts dynamically
        platform = self.options.platform
        script_files = self._get_platform_scripts()
        
        platform_scripts = []
        for script_file in script_files:
            script_path = f"{platform}/{script_file}"
            try:
                script_content = read_text(script_path)
                platform_scripts.append(script_content)
            except FileNotFoundError:
                pass  # Skip if file doesn't exist

        # Combine: user hooks define 'target', platform scripts use it
        combined = f"{user_hooks}\n\n" + "\n\n".join(platform_scripts)

        # Write merged agent to tmp/agent.js
        combined_path = tmp_dir / "agent.js"
        with open(combined_path, "w", encoding="utf-8") as f:
            f.write(combined)

        return combined_path

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
            else:
                try:
                    parsed = json.loads(payload)
                    with open(output_path, "a", encoding="utf-8") as f:
                        json.dump(parsed, f)
                        f.write("\n")
                except Exception:
                    print("MSG", payload)

        return on_message

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
            print(f"Attaching to frontmost application: {app.name} (PID: {app.pid})")
            return self.device.attach(app.pid)

        elif opts.attach_name:
            print(f"Attaching to process by name: {opts.attach_name}")
            return self.device.attach(opts.attach_name)

        elif opts.attach_identifier:
            print(f"Attaching to process by identifier: {opts.attach_identifier}")
            # Find process by identifier
            for proc in self.device.enumerate_processes():
                if proc.identifier == opts.attach_identifier:
                    return self.device.attach(proc.pid)
            # Fallback: try attaching by identifier as name
            return self.device.attach(opts.attach_identifier)

        elif opts.attach_pid:
            print(f"Attaching to PID: {opts.attach_pid}")
            return self.device.attach(opts.attach_pid)

        elif opts.spawn:
            print(f"Spawning: {opts.spawn}")
            pid = self.device.spawn(opts.spawn)
            session = self.device.attach(pid)
            return session

        else:
            raise RuntimeError("No target specified")

    def run(self) -> int:
        """Run the Frooky hooks."""
        print(BANNER)
        try:
            self._ensure_bridges()

            # Set up paths
            tmp_dir = Path("tmp")
            tmp_dir.mkdir(exist_ok=True)
            built_agent = tmp_dir / "_agent.js"

            # Combine user hooks with platform base script
            src_agent = self._prepare_script(tmp_dir)

            self._build_agent(src_agent, built_agent)

            # Clear/overwrite the output file at start
            with open(self.options.output_path, "w", encoding="utf-8") as f:
                pass  # Truncate file

            # Get device
            self.device = self._get_device()
            print(f"Using device: {self.device.name}")

            # Attach or spawn
            self.session = self._attach_or_spawn()

            # Load script
            with open(built_agent, "r", encoding="utf-8") as f:
                script_source = f.read()

            self.script = self.session.create_script(script_source)
            self.script.on("message", self._create_message_handler())
            self.script.load()

            # Resume if spawned
            if self.options.spawn:
                pid = self.session.pid
                print(f"Resuming PID: {pid}")
                self.device.resume(pid)

            print(f"Script loaded. Writing output to: {self.options.output_path}")
            print("Press Ctrl+C to stop...")

            # Main loop
            while True:
                time.sleep(0.2)

        except KeyboardInterrupt:
            print("\nStopping...")

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

        return 0
