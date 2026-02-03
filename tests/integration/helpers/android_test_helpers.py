"""Helper utilities for Android integration tests."""
import time
import json
import subprocess
import threading
from pathlib import Path


class AndroidTestHelper:
    """Helper class for Android hook testing operations."""

    @staticmethod
    def verify_method_were_hooked(output_file, target_class, target_methods):
        """Scan output NDJSON for target class and all specified methods."""
        target_methods_set = set(target_methods)
        found_methods = set()

        with open(output_file, 'r') as f:
            for line in f:
                try:
                    entry = json.loads(line.strip())

                    if entry.get("type") == "summary" and "hooks" in entry:
                        for hook in entry["hooks"]:
                            if hook.get("class") == target_class and (method := hook.get("method")) in target_methods_set:
                                found_methods.add(method)
                                if found_methods == target_methods_set:
                                    return True

                except json.JSONDecodeError:
                    pass

        return False

    @staticmethod
    def run_frooky(pid, hook_file, stop_event, output_file):
        """Run Frooky and monitor stop_event."""
        process = subprocess.Popen(
            [
                "frooky", 
                "-U", 
                "-p", pid, 
                "--platform", "android",
                "-o", str(output_file),
                str(hook_file)
            ],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )

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

    @staticmethod
    def run_maestro(flow_path):
        """Run Maestro flow and wait for completion."""
        process = subprocess.Popen(
            ["maestro", "test", str(flow_path)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        process.wait()

    @staticmethod
    def run_hook_test(hook_file, target_class, target_methods, sample_app_process, maestro_flow_path):
        """Common logic for running hook tests with Maestro."""
        output_file = Path("output.json")
        stop_frooky = threading.Event()

        frooky_thread = threading.Thread(
            target=AndroidTestHelper.run_frooky, 
            args=(sample_app_process, hook_file, stop_frooky, output_file)
        )
        frooky_thread.start()

        maestro_thread = threading.Thread(
            target=AndroidTestHelper.run_maestro, 
            args=(maestro_flow_path,)
        )
        maestro_thread.start()
        maestro_thread.join()

        stop_frooky.set()
        frooky_thread.join()

        assert output_file.exists(), "output.json was not created"
        hooks_found = AndroidTestHelper.verify_method_were_hooked(output_file, target_class, target_methods)
        assert hooks_found, "Target hook(s) not found in output.json"
