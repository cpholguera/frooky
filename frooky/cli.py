from __future__ import annotations

import sys
import argparse
from pathlib import Path
from importlib.resources import files

from . import __version__
from .frida_runner import FrookyRunner, RunnerOptions


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="frooky",
        description="Run Frooky hooks using Frida's Python bindings."
    )

    parser.suggest_on_error = True

    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"frooky {__version__}",
    )

    # Device selection group
    device_group = parser.add_argument_group("device selection")
    device_group.add_argument("-D", "--device", metavar="ID", help="Connect to device with the given ID")
    device_group.add_argument("-U", "--usb", action="store_true", help="Connect to USB device")

    # Target selection group (mutually exclusive)
    target_group = parser.add_mutually_exclusive_group(required=True)
    target_group.add_argument("-F", "--attach-frontmost", action="store_true", help="Attach to frontmost app")
    target_group.add_argument("-n", "--attach-name", metavar="NAME", help="Attach to NAME")
    target_group.add_argument("-N", "--attach-identifier", metavar="IDENTIFIER", help="Attach to IDENTIFIER (package/bundle ID)")
    target_group.add_argument("-p", "--attach-pid", metavar="PID", type=int, help="Attach to PID")
    target_group.add_argument("-f", "--spawn", metavar="IDENTIFIER", help="Spawn a process by identifier/name")

    parser.add_argument(
        "--platform",
        choices=["android", "ios"],
        required=True,
        help="Select which built-in script set to use",
    )
    parser.add_argument("hooks", nargs="+", help="Path(s) to your input hook JSON file(s)")
    parser.add_argument("-o", "--output", default="output.json", help="Output JSON file")

    return parser


def main() -> int:
    parser = build_parser()
    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    args = parser.parse_args()

    # Validate that the android and ios agents are compiled and accessible
    agent_dist_path = files('frooky') / "agent" / "dist"
    required_files = [
        agent_dist_path / "version.json",
        agent_dist_path / "agent-android.js",
        agent_dist_path / "agent-ios.js"
    ]

    if not all(file.exists() for file in required_files):
        print(f"Frooky agent not found in: {agent_dist_path}\n"
              f"If you don't use the distributed version, make sure to manually compile the agents first.\n",
              file=sys.stderr)
        sys.exit(1)

    # Validate device selection
    device_count = sum([args.usb, args.device is not None])
    if device_count > 1:
        parser.error("Use only one of -D/--device or -U/--usb.")

    hook_paths = []
    for hook in args.hooks:
        hook_path = Path(hook)
        if not hook_path.exists():
            parser.error(f"Hooks file not found: {hook_path}")
        hook_paths.append(hook_path.resolve())

    options = RunnerOptions(
        platform=args.platform,
        hook_paths=hook_paths,
        output_path=Path(args.output),
        device_id=args.device,
        use_usb=args.usb,
        attach_frontmost=args.attach_frontmost,
        attach_name=args.attach_name,
        attach_identifier=args.attach_identifier,
        attach_pid=args.attach_pid,
        spawn=args.spawn,
    )

    runner = FrookyRunner(options)
    return runner.run()


if __name__ == "__main__":
    raise SystemExit(main())
