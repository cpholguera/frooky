"""Shared fixtures for Android integration tests."""
import os
import tempfile
import time
import subprocess
from pathlib import Path
import json
import pytest


def _matches_subset_pattern_recursive(event, pattern):
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
            key in event and _matches_subset_pattern_recursive(
                event[key], value)
            for key, value in pattern.items()
        )
    elif isinstance(pattern, list):
        if not isinstance(event, list):
            return False
        if len(pattern) != len(event):
            return False
        return all(
            _matches_subset_pattern_recursive(event[i], pattern[i])
            for i in range(len(pattern))
        )
    else:
        return event == pattern


@pytest.fixture(params=["android", "ios"])
def platform(request):
    """Platform to test against."""
    return request.param


@pytest.fixture
def mastestapp_start_path(platform):
    """Returns a maestro flow which pushes the start button from the MAS test app"""
    return Path(__file__).parent / "maestro" / f'{platform}-mastestapp-start.yaml'


@pytest.fixture
def app_id(platform):
    """Start the app and return PID (Android) or app name (iOS)."""
    if platform == "android":
        app_id = "org.owasp.mastestapp"

        subprocess.run(['adb', 'wait-for-device'], check=True)
        subprocess.run(
            ['adb', 'shell', 'am', 'start', '-n', f'{app_id}/.MainActivity'],
            check=True
        )
        time.sleep(5)

        result = subprocess.run(
            ['adb', 'shell', 'pidof', app_id],
            capture_output=True,
            text=True,
            check=True
        )

        pid = result.stdout.strip()
        if not pid:
            pytest.fail(f"Could not find PID for Android app {app_id}")

        return pid

    else:  # ios
        app_id = "org.owasp.mastestapp.MASTestApp-iOS"
        app_name = "MASTestApp"

        try:
            subprocess.run(
                ['xcrun', 'simctl', 'launch', 'booted', app_id],
                capture_output=True,
                text=True,
                check=True
            )
            time.sleep(5)

            return app_name
        except subprocess.CalledProcessError as e:
            raise RuntimeError(
                f"Could not launch iOS app {app_name}: {e.stderr}") from e


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


@pytest.fixture
def count_matched_events(output_file_path):
    """Factory fixture to scan output NDJSON for hooks matching the specified patterns."""

    def _count_matched_events(expected_event):
        matched_events_counter = 0

        with open(output_file_path, 'r', encoding="utf8") as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    if _matches_subset_pattern_recursive(entry, expected_event):
                        matched_events_counter += 1
                except json.JSONDecodeError:
                    pass

        return matched_events_counter

    return _count_matched_events


@pytest.fixture
def run_frooky(platform, output_file_path, app_id, mastestapp_start_path):
    """Factory fixture for running hook tests with Maestro."""

    def _run_frooky(hook):
        temp_hook_path = None
        frooky_process = None

        # write the hooks into a temporary file
        fd, temp_hook_path = tempfile.mkstemp(suffix='.json', text=True)
        with os.fdopen(fd, 'w') as f:
            json.dump(hook, f)

        try:
            # run frooky as background process
            # start Android with PID, and iOS with app name
            frooky_process = subprocess.Popen([
                "frooky",
                *(["-U"] if platform == "android" else []),
                *(["-p"] if platform == "android" else ["-n"]), app_id,
                "--platform", platform,
                "-o", output_file_path,
                temp_hook_path
            ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            time.sleep(5)

            if frooky_process.poll() is not None:
                _, stderr = frooky_process.communicate()
                raise RuntimeError(f"Frooky failed to start: {stderr}")

            # Run Maestro test
            maestro_timeout = 600
            subprocess.run(
                [
                    "maestro",
                    "test",
                    "--platform", platform,
                    str(mastestapp_start_path)
                ],
                timeout=maestro_timeout,
                check=True,
                capture_output=True,
                text=True
            )

        finally:
            if temp_hook_path and os.path.exists(temp_hook_path):
                os.remove(temp_hook_path)

            if frooky_process:
                frooky_process.terminate()
                try:
                    frooky_process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    frooky_process.kill()
                    frooky_process.wait()

    return _run_frooky
