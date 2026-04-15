"""Shared fixtures for Android integration tests."""
import os
import tempfile
import time
import subprocess
from pathlib import Path
import json
import pytest

# Timeouts
APP_START_TIMEOUT = 30
FROOKY_OUTPUT_TIMEOUT = 30
MAESTRO_TIMEOUT = 600
FROOKY_TERMINATE_TIMEOUT = 5


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
            key in event and _matches_subset_pattern_recursive(event[key], value)
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
def maestro_flow_mastg_demo():
    """Returns a maestro flow which pushes the start button from the MAS test app."""
    return Path(__file__).parent / "maestro" / "mastg_demo.yaml"


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

        with open(output_file_path, "r", encoding="utf8") as f:
            for line in f:
                try:
                    entry = json.loads(line)
                    if _matches_subset_pattern_recursive(entry, expected_event):
                        matched_events_counter += 1
                except json.JSONDecodeError:
                    pass

        return matched_events_counter

    return _count_matched_events


def _start_app(platform, target_app):
    app_bundle_id = "{}.frooky.target.app".format(target_app.replace("-", "_"))

    if platform == "android":
        subprocess.run(["adb", "wait-for-device"], check=True)
        subprocess.run(
            [
                "adb", "shell", "am", "start", "-n",
                "{}/org.owasp.mastestapp.MainActivity".format(app_bundle_id),
            ],
            check=True,
        )

        deadline = time.monotonic() + APP_START_TIMEOUT
        pid = None
        while not pid:
            if time.monotonic() > deadline:
                pytest.fail(
                    "Timed out waiting for PID of Android app {}".format(app_bundle_id)
                )
            result = subprocess.run(
                ["adb", "shell", "pidof", app_bundle_id],
                capture_output=True,
                text=True,
                check=False,
            )
            pid = result.stdout.strip()
            if not pid:
                time.sleep(0.5)

        return pid

    else:  # ios
        try:
            result = subprocess.run(
                ["xcrun", "simctl", "launch", "booted", app_bundle_id],
                capture_output=True,
                text=True,
                check=True,
            )
            # stdout format: "com.example.App: 12345"
            pid = int(result.stdout.strip().split(": ")[1])
            return pid
        except subprocess.CalledProcessError as e:
            raise RuntimeError(
                "Could not launch iOS app {}: {}".format(app_bundle_id, e.stderr)
            ) from e


@pytest.fixture
def run_frooky(platform, output_file_path, maestro_flow_mastg_demo):
    def _run_frooky(hook_file, target_app):
        temp_hook_path = None
        frooky_process = None

        target_app_pid = _start_app(platform, target_app)

        app_bundle_id = "{}.frooky.target.app".format(target_app.replace("-", "_"))

        fd, temp_hook_path = tempfile.mkstemp(suffix=".json", text=True)
        with os.fdopen(fd, "w") as f:
            json.dump(hook_file, f)

        try:
            frooky_process = subprocess.Popen(
                [
                    "frooky",
                    platform,
                    *(["-U"] if platform == "android" else []),
                    "-p", str(target_app_pid),
                    "-o", str(output_file_path),
                    temp_hook_path,
                ],
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )

            deadline = time.monotonic() + FROOKY_OUTPUT_TIMEOUT
            while not os.path.isfile(output_file_path):
                if time.monotonic() > deadline:
                    stdout, stderr = frooky_process.communicate()
                    raise RuntimeError(
                        "Frooky did not produce output file in time. stderr: {}".format(stderr)
                    )
                if frooky_process.poll() is not None:
                    stdout, stderr = frooky_process.communicate()
                    raise RuntimeError("Frooky exited early: {}".format(stderr))
                time.sleep(0.5)

            subprocess.run(
                [
                    "maestro",
                    "test",
                    "--env", "APP_ID={}".format(app_bundle_id),
                    "--platform", platform,
                    str(maestro_flow_mastg_demo),
                ],
                timeout=MAESTRO_TIMEOUT,
                check=True,
                capture_output=True,
                text=True,
            )

        finally:
            if temp_hook_path and os.path.exists(temp_hook_path):
                os.remove(temp_hook_path)

            if frooky_process:
                frooky_process.terminate()
                try:
                    frooky_process.wait(timeout=FROOKY_TERMINATE_TIMEOUT)
                except subprocess.TimeoutExpired:
                    frooky_process.kill()
                    frooky_process.wait()

    return _run_frooky
