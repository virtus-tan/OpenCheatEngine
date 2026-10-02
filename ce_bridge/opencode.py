"""Install the opencode tools and plugin, globally or into a project.

opencode loads tools and plugins from two places:

    <project root>/.opencode/tools/    <project root>/.opencode/plugins/
    ~/.config/opencode/tools/          ~/.config/opencode/plugins/

It does not scan subdirectories, so tools sitting in a subfolder of the project
are invisible. Installing globally puts them in every project, which is what you
want when the game you are working on is somewhere else entirely.
"""

import json
import os
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SOURCE = os.path.join(ROOT, ".opencode")

GLOBAL_DIRS = {
    "config": os.path.join(os.path.expanduser("~"), ".config", "opencode"),
    "legacy": os.path.join(os.path.expanduser("~"), ".opencode"),
}


def global_root():
    """Where this opencode actually keeps its global configuration.

    The documented location is ~/.config/opencode. If that does not exist but the
    older ~/.opencode does, install there instead so the tools are still found.
    """
    if os.path.isdir(GLOBAL_DIRS["config"]):
        return GLOBAL_DIRS["config"]
    if os.path.isdir(GLOBAL_DIRS["legacy"]):
        return GLOBAL_DIRS["legacy"]
    return GLOBAL_DIRS["config"]


def project_root(path=None):
    return os.path.abspath(path or os.getcwd())


def _copy_tree(source, destination):
    copied = 0
    for name in sorted(os.listdir(source)):
        if name in ("node_modules", "package-lock.json", "bun.lock", "bun.lockb"):
            continue
        from_path = os.path.join(source, name)
        if not os.path.isfile(from_path):
            continue
        os.makedirs(destination, exist_ok=True)
        to_path = os.path.join(destination, name)
        shutil.copy2(from_path, to_path)
        copied += 1
    return copied


def _merge_package_json(directory):
    """Add the plugin dependency without disturbing what is already there."""
    path = os.path.join(directory, "package.json")
    data = {}
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as handle:
                data = json.load(handle)
        except Exception:
            data = {}
    data.setdefault("name", "opencode-ce-bridge")
    data["private"] = True
    # The tools are ES modules; without this Node has to reparse them, and
    # opencode's own resolution is cleaner with it set.
    if "type" not in data:
        data["type"] = "module"
    dependencies = dict(data.get("dependencies") or {})
    needed = dependencies.get("@opencode-ai/plugin")
    if not needed or needed == "latest":
        dependencies["@opencode-ai/plugin"] = "latest"
    data["dependencies"] = dependencies
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(data, handle, indent=2)
        handle.write("\n")
    return path


def install(target="global", path=None):
    """Copy the tools, the plugin and the shared client into place.

    target: "global" for every project, or "project" for one directory.
    """
    if not os.path.isdir(SOURCE):
        raise FileNotFoundError(f"no .opencode directory to install from: {SOURCE}")

    if target == "project":
        base = os.path.join(project_root(path), ".opencode")
    else:
        base = global_root()

    tools_source = os.path.join(SOURCE, "tools")
    counts = {
        "tools": _copy_tree(tools_source, os.path.join(base, "tools")),
        "plugins": _copy_tree(os.path.join(SOURCE, "plugins"), os.path.join(base, "plugins")),
        "lib": _copy_tree(os.path.join(SOURCE, "lib"), os.path.join(base, "lib")),
    }
    package = _merge_package_json(base)
    return {
        "ok": True,
        "target": target,
        "installed_to": base,
        "files": counts,
        "total": sum(counts.values()),
        "package_json": package,
        "source": SOURCE,
    }


def status():
    global_base = global_root()
    return {
        "source": SOURCE,
        "source_tools": len([
            name for name in os.listdir(os.path.join(SOURCE, "tools"))
            if name.endswith(".ts")
        ]) if os.path.isdir(os.path.join(SOURCE, "tools")) else 0,
        "global": global_base,
        "global_exists": os.path.isdir(global_base),
        "global_tools": len([
            name for name in os.listdir(os.path.join(global_base, "tools"))
            if name.endswith(".ts")
        ]) if os.path.isdir(os.path.join(global_base, "tools")) else 0,
        "global_plugins": len([
            name for name in os.listdir(os.path.join(global_base, "plugins"))
            if name.endswith(".ts")
        ]) if os.path.isdir(os.path.join(global_base, "plugins")) else 0,
        "project_here": os.path.join(project_root(), ".opencode"),
        "note": "opencode only reads .opencode/tools and .opencode/plugins in the "
                "project root and in the global config directory. A .opencode folder "
                "nested inside a subdirectory is not scanned.",
    }
