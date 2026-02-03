"""Shared fixtures for Android integration tests."""
import time
import subprocess
from pathlib import Path
import pytest


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
