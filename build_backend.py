import subprocess
from pathlib import Path
from setuptools import build_meta as _orig

# Re-export all setuptools build backend functions
prepare_metadata_for_build_wheel = _orig.prepare_metadata_for_build_wheel
build_wheel = _orig.build_wheel
build_sdist = _orig.build_sdist
get_requires_for_build_wheel = _orig.get_requires_for_build_wheel
get_requires_for_build_sdist = _orig.get_requires_for_build_sdist

# PEP 660 editable install support
build_editable = _orig.build_editable
get_requires_for_build_editable = _orig.get_requires_for_build_editable
prepare_metadata_for_build_editable = _orig.prepare_metadata_for_build_editable


def _run_build_scripts():
    """Run the Node.js build scripts in frooky/agent directory."""

    # Install npm
    agent_dir = Path(__file__).parent / "frooky" / "agent"
    subprocess.check_call(['npm', 'ci', '--ignore-scripts'], cwd=agent_dir)

    # Compile frooky agents
    subprocess.run(
        ["npm", "run", "prod-frooky-android"],
        cwd=agent_dir,
        check=True
    )
    subprocess.run(
        ["npm", "run", "prod-frooky-ios"],
        cwd=agent_dir,
        check=True
    )

# Wrap build functions
_orig_build_wheel = build_wheel
def build_wheel(wheel_directory, config_settings=None, metadata_directory=None):
    _run_build_scripts()
    return _orig_build_wheel(wheel_directory, config_settings, metadata_directory)

_orig_build_sdist = build_sdist
def build_sdist(sdist_directory, config_settings=None):
    _run_build_scripts()
    return _orig_build_sdist(sdist_directory, config_settings)

_orig_build_editable = build_editable
def build_editable(wheel_directory, config_settings=None, metadata_directory=None):
    _run_build_scripts()
    return _orig_build_editable(wheel_directory, config_settings, metadata_directory)
