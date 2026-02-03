"""Tests for good case lifecycle."""
import time
import pytest
import json
import subprocess
import threading
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

    @pytest.fixture
    def maestro_flow_path(self):
        """Return path to Maestro flow file."""
        return Path(__file__).parent / "maestro" / "flow.yaml"

    @pytest.fixture(autouse=True)
    def cleanup_output_json(self):
        """Remove output.json before and after each test."""
        output_file = Path("output.json")

        if output_file.exists():
            output_file.unlink()

        yield

        if output_file.exists():
            output_file.unlink()

    def _scan_target_hook(self, output_file, target_class, target_methods):
        """Scan output NDJSON for target class and all specified methods."""
        target_methods_set = set(target_methods)
        found_methods = set()

        with open(output_file, 'r') as f:
            for line in f:
                print(line)
                try:
                    entry = json.loads(line.strip())

                    # Check summary entries for hooks
                    if entry.get("type") == "summary" and "hooks" in entry:
                        for hook in entry["hooks"]:
                            if hook.get("class") == target_class and (method := hook.get("method")) in target_methods_set:
                                found_methods.add(method)
                                if found_methods == target_methods_set:
                                    return True

                    # Check individual hook entries
                    if entry.get("class") == target_class and (method := entry.get("method")) in target_methods_set:
                        found_methods.add(method)
                        if found_methods == target_methods_set:
                            return True
                except json.JSONDecodeError:
                    pass

        return False


    def _run_frooky(self, sample_app_process, hook_file, stop_event, output_file):
        """Run Frooky and monitor stop_event."""
        process = subprocess.Popen(
            [
                "frooky", 
                "-U", 
                "-f", sample_app_process, 
                "--platform", "android",
                "-o", str(output_file),  # Add explicit output file
                str(hook_file)
            ],
            stdout=subprocess.PIPE,  # Capture instead of suppressing
            stderr=subprocess.PIPE
        )

        # Wait until stop_event is set
        while not stop_event.is_set():
            time.sleep(1)

        process.terminate()
        try:
            stdout, stderr = process.communicate(timeout=2)
            if stderr:
                print(f"Frooky stderr: {stderr.decode()}")
        except subprocess.TimeoutExpired:
            process.kill()
            stdout, stderr = process.communicate()



    def _run_maestro(self, flow_path):
        """Run Maestro flow and wait for completion."""
        process = subprocess.Popen(
            ["maestro", "test", str(flow_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        process.wait()


    def _run_hook_test(self, hook_file, target_class, target_methods, sample_app_process, maestro_flow_path):
        """Common logic for running hook tests with Maestro."""
        output_file = Path("output.json")
        stop_frooky = threading.Event()

        frooky_thread = threading.Thread(
            target=self._run_frooky, 
            args=(sample_app_process, hook_file, stop_frooky, output_file)
        )
        frooky_thread.start()

        # Give frooky time to attach before starting Maestro
        time.sleep(5)

        maestro_thread = threading.Thread(target=self._run_maestro, args=(maestro_flow_path,))
        maestro_thread.start()
        maestro_thread.join()

        stop_frooky.set()
        frooky_thread.join()

        assert output_file.exists(), f"output.json was not created. Check if frooky supports -o flag or writes to a different location"
        hooks_found = self._scan_target_hook(output_file, target_class, target_methods)
        assert hooks_found, "Target hook(s) not found in output.json"


    def test_hook_single_java_method(self, sample_app_process, hooks_dir, maestro_flow_path):
        """Test hooking a single Java method in a real process."""
        self._run_hook_test(
            hooks_dir / "single_java_method.json",
            "android.app.SharedPreferencesImpl$EditorImpl",
            ["putString"],
            sample_app_process,
            maestro_flow_path
        )

    def test_hook_multiple_java_methods(self, sample_app_process, hooks_dir, maestro_flow_path):
        """Test hooking multiple Java methods in a real process."""
        self._run_hook_test(
            hooks_dir / "multiple_java_methods.json",
            "androidx.security.crypto.EncryptedSharedPreferences$Editor",
            ["putString", "putStringSet"],
            sample_app_process,
            maestro_flow_path
        )
