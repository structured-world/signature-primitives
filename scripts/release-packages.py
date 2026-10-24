#!/usr/bin/env python3
"""Select registry qualification packages from one release revision."""

import json
import pathlib
import sys
import tomllib


def selected_packages(metadata, config):
    """Keep release-enabled crates and their original Cargo versions."""
    disabled = {package["name"] for package in config.get("package", [])
                if package.get("release") is False}
    selected = [{"name": package["name"], "version": package["version"]}
                for package in metadata["packages"]
                if package.get("publish") is None and package["name"] not in disabled]
    if not selected:
        raise ValueError("no packages selected for registry qualification")
    return selected


if __name__ == "__main__":
    metadata = json.loads(pathlib.Path(sys.argv[1]).read_text())
    config = tomllib.loads(pathlib.Path(sys.argv[2]).read_text())
    print(json.dumps(selected_packages(metadata, config)))
