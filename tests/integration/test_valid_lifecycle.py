"""Tests for good case lifecycle."""
import time
import pytest
import json
import subprocess
from pathlib import Path


class TestHookJavaMethod:
    """Tests for handling errors on the target related to Java methods."""

    @pytest.fixture
    def hooks_dir(self):
        """Return path to integration test hooks directory."""
        return Path(__file__).parent / "hooks"

    @pytest.fixture
    def sample_app_process(self):
        """Test app identifier - adjust to your actual test app."""
        return "org.owasp.mastestapp"

    @pytest.fixture(autouse=True)
    def cleanup_output_json(self):
        """Remove output.json before and after each test."""
        output_file = Path("output.json")

        if output_file.exists():
            output_file.unlink()

        yield

        if output_file.exists():
            output_file.unlink()

    def wait_for_target_hook(self, target_class, target_methods, timeout=10):
        """Scan output.json NDJSON for target class and all specified methods."""
        output_file = Path("output.json")
        start_time = time.time()
        found_methods = set()
        target_methods_set = set(target_methods)

        while time.time() - start_time < timeout:
            if output_file.exists():
                try:
                    with open(output_file, 'r') as f:
                        for line in f:
                            if line := line.strip():
                                try:
                                    entry = json.loads(line)
                                    if entry.get("class") == target_class:
                                        if (method := entry.get("method")) in target_methods_set:
                                            found_methods.add(method)
                                            if found_methods == target_methods_set:
                                                return True
                                except json.JSONDecodeError:
                                    continue
                except IOError:
                    pass
            time.sleep(1)

        return False

    def _run_hook_test(self, hook_file, target_class, target_methods, sample_app_process):
        """Common logic for running hook tests."""
        output_file = Path("output.json")

        process = subprocess.Popen(
            ["frooky", "-U", "-f", sample_app_process, "--platform", "android", str(hook_file)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )

        try:
            # Wait for output.json creation
            start_time = time.time()
            while time.time() - start_time < 10:
                if output_file.exists():
                    time.sleep(0.5)
                    break
                time.sleep(0.1)

            assert output_file.exists(), "output.json was not created"
            assert self.wait_for_target_hook(target_class, target_methods), \
                "Target hook(s) not found in output.json"

        finally:
            process.terminate()
            try:
                process.wait(timeout=2)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()

    def test_hook_single_java_method(self, sample_app_process, hooks_dir):
        """Test hooking a single Java method in a real process."""
        self._run_hook_test(
            hooks_dir / "single_java_method.json",
            "android.app.SharedPreferencesImpl$EditorImpl",
            ["putString"],
            sample_app_process
        )

    def test_hook_multiple_java_methods(self, sample_app_process, hooks_dir):
        """Test hooking multiple Java methods in a real process."""
        self._run_hook_test(
            hooks_dir / "multiple_java_methods.json",
            "androidx.security.crypto.EncryptedSharedPreferences$Editor",
            ["putString", "putStringSet"],
            sample_app_process
        )
