"""Tests for good case lifecycle on Android."""
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
    def pid(self):
        """The process id from the running target app"""

        app_id = "org.owasp.mastestapp"

        subprocess.run(['adb', 'wait-for-device'], check=True)
        subprocess.run(
            ['adb', 'shell', 'monkey', '-p', app_id, '-c', 
            'android.intent.category.LAUNCHER', '1'],
            check=True
        )
        time.sleep(2)

        # Get PID
        try:
            result = subprocess.run(
                ['frida-ps', '-Uai'],
                capture_output=True,
                text=True,
                check=False
            )
            ps_output = result.stdout
            for line in ps_output.splitlines():
                parts = line.split()
                if len(parts) >= 3 and parts[2] == app_id:
                    return int(parts[0])
            pytest.fail(f"Could not find pid for {app_id}")
        except Exception as e:
            pytest.fail(f"Error getting PID: {e}")

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
            
    # TODO: We should make this method more generic, so we match an incomplete SHOULD json with the ACTUAL json
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


    def _run_frooky(self, pid, hook_file, stop_event, output_file):
        """Run Frooky and monitor stop_event."""
        process = subprocess.Popen(
            [
                "frooky", 
                "-U", 
                "-p", pid, 
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


    def test_hook_single_java_method(self, pid, hooks_dir, maestro_flow_path):
        """Test hooking a single Java method in a real process."""
        self._run_hook_test(
            hooks_dir / "single_java_method.json",
            "android.app.SharedPreferencesImpl$EditorImpl",
            ["putString"],
            pid,
            maestro_flow_path
        )

    def test_hook_multiple_java_methods(self, pid, hooks_dir, maestro_flow_path):
        """Test hooking multiple Java methods in a real process."""
        self._run_hook_test(
            hooks_dir / "multiple_java_methods.json",
            "androidx.security.crypto.EncryptedSharedPreferences$Editor",
            ["putString", "putStringSet"],
            pid,
            maestro_flow_path
        )
