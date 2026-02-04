"""Shared fixtures for Android integration tests."""
import time
import subprocess
from pathlib import Path
import pytest
import json

@pytest.fixture
def hooks_dir():
    """Return path to integration test hooks directory."""
    return Path(__file__).parent / "hooks"


@pytest.fixture
def pid():
    """The process id from the running target app"""
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


@pytest.fixture
def maestro_flow_path():
    """Return path to Maestro flow file."""
    return Path(__file__).parent / "maestro" / "flow.yaml"


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
            key in target and matches_subset_pattern_recursive(target[key], value)
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


def contains_expected_patterns(output_file, target_hooks):
    """Scan output NDJSON for hooks matching the specified patterns. Returns true if all have been found"""

    found_patterns = [False] * len(target_hooks)

    with open(output_file, 'r') as f:
        for line in f:           
            try:
                entry = json.loads(line)

                # Skip summary entries
                if entry.get("type") == "summary":
                    continue

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


def run_frooky(pid, hook_file, output_file, platform):
    """Start Frooky process and return it."""
    return subprocess.Popen(
        [
            "frooky", 
            "-U", 
            "-p", pid, 
            "--platform", platform,
            "-o", output_file,
            hook_file
        ],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

def run_maestro_blocking(flow_path, timeout=60):
    """Run Maestro flow and wait for completion with timeout."""
    process = subprocess.Popen(
        ["maestro", "test", str(flow_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE
    )

    try:
        stdout, stderr = process.communicate(timeout=timeout)
        if stderr:
            print(f"Maestro stderr: {stderr.decode()}")
        if process.returncode != 0:
            print(f"Maestro failed with return code {process.returncode}")
            if stdout:
                print(f"Maestro stdout: {stdout.decode()}")
    except subprocess.TimeoutExpired:
        process.kill()
        stdout, stderr = process.communicate()
        print(f"Maestro timed out after {timeout} seconds")
        if stderr:
            print(f"Maestro stderr: {stderr.decode()}")
        raise


def run_hook_test(hook_file, expected_patterns, pid, maestro_flow_path, platform):
    """Common logic for running hook tests with Maestro."""
    output_file = Path("output.json")

    frooky_process = run_frooky(pid, hook_file, output_file, platform)

    try:
        run_maestro_blocking(maestro_flow_path, timeout=60)
    finally:
        frooky_process.terminate()
        try:
            _, stderr = frooky_process.communicate(timeout=2)
            if stderr:
                print(f"Frooky stderr: {stderr.decode()}")
        except subprocess.TimeoutExpired:
            frooky_process.kill()
            _, stderr = frooky_process.communicate()
            if stderr:
                print(f"Frooky stderr (after kill): {stderr.decode()}")

    assert output_file.exists(), "output.json was not created"
    assert contains_expected_patterns(output_file, expected_patterns), "not all target patterns have been found in output.json"
