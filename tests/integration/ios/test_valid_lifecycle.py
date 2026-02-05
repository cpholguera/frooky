"""Tests for good case lifecycle on iOS."""
from conftest import run_frooky, contains_subset_of


class TestHookNativeMethod:
    """Tests for handling errors on the target related to Java methods."""

    def test_hook_java_single_method(self, pid, output_file_path, org_owasp_mastestapp_start):
        """Test hooking a single Java method in a real process."""

        hooks = {
            "category": "STORAGE",
            "hooks": [
                {
                    "native": "true",
                    "symbol": "open",
                    "maxFrames": 5,
                    "filterEventsByStacktrace": "MASTestApp",
                    "args": [
                        {
                            "type": "string",
                            "name": "path",
                            "filter": ["Containers/Data/Application/"]
                        }
                    ]
                }
            ]
        }

        run_frooky("ios", hooks, pid, output_file_path,
                   org_owasp_mastestapp_start)

        # expected_patterns = [
        #     {
        #         "class": "android.app.SharedPreferencesImpl$EditorImpl",
        #         "method": "putString",
        #     }
        # ]

        # Read and print entire file content
        with open(output_file_path, 'r') as file:
            content = file.read()
            print(content)

        assert output_file_path.exists(), "output.json was not created"
        # assert contains_subset_of(
        #     expected_patterns, output_file_path), "output.json did not contain the expected pattern as a subset."
