"""Shared fixtures for Android integration tests."""
import os
import tempfile
import time
import subprocess
from pathlib import Path
import pytest
import json


@pytest.fixture(params=["android", "ios"])
def mastestapp_start(request):
    """Returns a maestro flow which pushes the start button from the ios MAS test app"""

    platform = request.param

    return Path(__file__).parent / "maestro" / f'{platform}-mastestapp-start.yaml'


@pytest.fixture(params=["android", "ios"])
def pid(request):
    """The process id from the running target app"""
    platform = request.param

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

        pid = result.stdout.strip()
        if not pid:
            pytest.fail(f"Could not find PID for {app_id}")

        return pid

    elif platform == "ios":
        app_id = "org.owasp.mastestapp.MASTestApp-iOS"

        result = subprocess.run(
            ['xcrun', 'simctl', 'launch', 'booted', app_id],
            capture_output=True,
            text=True,
            check=False
        )

        if result.returncode == 0:
            pid = result.stdout.strip().split(':')[-1].strip()
            return pid

        pytest.fail(f"Could not launch {app_id}: {result.stderr}")


@pytest.fixture
def output_file_path():
    """Return path to output.json file."""
    return Path(__file__).parent / "output.json"


@pytest.fixture(autouse=True)
def cleanup_output_json():
    """Remove output.json before and after each test."""
    output_file = Path("output.json")

    if output_file.exists():
        output_file.unlink()

    yield

    if output_file.exists():
        output_file.unlink()


def matches_subset_pattern_recursive(target, pattern):
    """
    Check if pattern is a subset of target structure.
    - For dicts: pattern keys must exist in target with matching values
    - For lists: pattern and target must have same length, each element must match
    - For primitives: must be equal
    """
    if isinstance(pattern, dict):
        if not isinstance(target, dict):
            return False
        return all(
            key in target and matches_subset_pattern_recursive(
                target[key], value)
            for key, value in pattern.items()
        )
    elif isinstance(pattern, list):
        if not isinstance(target, list):
            return False
        if len(pattern) != len(target):
            return False
        return all(
            matches_subset_pattern_recursive(target[i], pattern[i])
            for i in range(len(pattern))
        )
    else:
        return target == pattern


def contains_subset_of(target_hooks, output_file_path):
    """Scan output NDJSON for hooks matching the specified patterns. Returns true if all have been found"""

    found_patterns = [False] * len(target_hooks)

    with open(output_file_path, 'r') as f:
        for line in f:
            try:
                entry = json.loads(line)

                # Compare this entry against each pattern
                for idx, pattern in enumerate(target_hooks):
                    if not found_patterns[idx]:
                        if matches_subset_pattern_recursive(entry, pattern):
                            found_patterns[idx] = True

                            if all(found_patterns):
                                return True

            except json.JSONDecodeError:
                pass

    return all(found_patterns)


def run_frooky(platform, hooks, pid, output_file_path, maestro_flow_path):
    """Common logic for running hook tests with Maestro."""

    # create a temporary hook.json file
    fd, hooks_path = tempfile.mkstemp(suffix='.json', text=True)
    with os.fdopen(fd, 'w') as f:
        json.dump(hooks, f)

    # run frooky as background process
    frooky_process = subprocess.Popen(
        [
            "frooky",
            "-U",
            "-p", pid,
            "--platform", platform,
            "-o", output_file_path,
            hooks_path
        ]
    )

    try:
        # run maestro as blocking foreground process
        maestro_timeout = 60
        subprocess.run(
            ["maestro", "test", str(maestro_flow_path)],
            timeout=maestro_timeout,
            check=True
        )
    finally:
        if os.path.exists(hooks_path):
            os.remove(hooks_path)
        frooky_process.terminate()
        try:
            frooky_process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            frooky_process.kill()
            frooky_process.wait()
