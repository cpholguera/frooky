"""Shared fixtures for Android integration tests."""
import os
import tempfile
import time
import subprocess
from pathlib import Path
import json
import pytest


@pytest.fixture(params=["android", "ios"])
def platform(request):
    """Platform to test against."""
    return request.param


@pytest.fixture
def mastestapp_start(platform):
    """Returns a maestro flow which pushes the start button from the MAS test app"""
    return Path(__file__).parent / "maestro" / f'{platform}-mastestapp-start.yaml'


@pytest.fixture
def pid(platform):
    """The process id from the running target app"""

    if platform == "android":
        app_id = "org.owasp.mastestapp"

        subprocess.run(['adb', 'wait-for-device'], check=True)
        subprocess.run(
            ['adb', 'shell', 'am', 'start', '-n',
             f'{app_id}/.MainActivity'],
            check=True
        )
        time.sleep(2)

        result = subprocess.run(
            ['adb', 'shell', 'pidof', app_id],
            capture_output=True,
            text=True,
            check=True
        )

        target_app_pid = result.stdout.strip()
        if not pid:
            pytest.fail(f"Could not find PID for Android app  {app_id}")

        return target_app_pid

    elif platform == "ios":
        app_id = "org.owasp.mastestapp.MASTestApp-iOS"

        result = subprocess.run(
            ['xcrun', 'simctl', 'launch', 'booted', app_id],
            capture_output=True,
            text=True,
            check=False
        )

        if result.returncode == 0:
            target_app_pid = result.stdout.strip().split(':')[-1].strip()
            return target_app_pid

        pytest.fail(f"Could not find PID for iOS app {app_id}: {result.stderr}")



@pytest.fixture
def output_file_path():
    """Return path to output.json file."""
    return Path(__file__).parent / "output.json"


@pytest.fixture(autouse=True)
def cleanup_output_json(output_file_path):
    """Remove output.json before and after each test."""
    if output_file_path.exists():
        output_file_path.unlink()

    yield

    if output_file_path.exists():
        output_file_path.unlink()


def matches_subset_pattern_recursive(event, pattern):
    """
    Check if pattern is a subset of event structure.
    - For dicts: pattern keys must exist in event with matching values
    - For lists: pattern and target must have same length, each element must match
    - For primitives: must be equal
    """
    if isinstance(pattern, dict):
        if not isinstance(event, dict):
            return False
        return all(
            key in event and matches_subset_pattern_recursive(
                event[key], value)
            for key, value in pattern.items()
        )
    elif isinstance(pattern, list):
        if not isinstance(event, list):
            return False
        if len(pattern) != len(event):
            return False
        return all(
            matches_subset_pattern_recursive(event[i], pattern[i])
            for i in range(len(pattern))
        )
    else:
        return event == pattern



@pytest.fixture
def number_of_matched_events(output_file_path):
    """Factory fixture to scan output NDJSON for hooks matching the specified patterns."""

    def _count_matches(expected_event):
        matched_events_counter = 0

        with open(output_file_path, 'r', encoding="utf8") as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    if matches_subset_pattern_recursive(entry, expected_event):
                        matched_events_counter += 1
                except json.JSONDecodeError:
                    pass

        return matched_events_counter

    return _count_matches


@pytest.fixture
def run_frooky(platform, pid, output_file_path, mastestapp_start):
    """Factory fixture for running hook tests with Maestro."""

    def _run_frooky(hook):
        # write the hooks into a temporary file
        fd, hook_path = tempfile.mkstemp(suffix='.json', text=True)
        with os.fdopen(fd, 'w') as f:
            json.dump(hook, f)

        # run frooky as background process
        frooky_process = subprocess.Popen(
            [
                "frooky",
                *(["-U"] if platform == "android" else []),
                "-p", pid,
                "--platform", platform,
                "-o", output_file_path,
                hook_path
            ]
        )

        try:
            # run maestro as blocking foreground process
            maestro_timeout = 60

            subprocess.run(
                [
                    "maestro", 
                    "test", 
                    "--platform", platform, 
                    "--reinstall-driver",
                    str(mastestapp_start)
                ],
                timeout=maestro_timeout,
                check=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                stdin=subprocess.DEVNULL
            )
        finally:
            if os.path.exists(hook_path):
                os.remove(hook_path)
            frooky_process.terminate()
            try:
                frooky_process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                frooky_process.kill()
                frooky_process.wait()

    return _run_frooky
