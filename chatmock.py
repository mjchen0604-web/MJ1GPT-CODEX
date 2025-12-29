from __future__ import annotations

import importlib.util
import os
import sys


def _bootstrap_package() -> None:
    here = os.path.dirname(__file__)
    pkg_dir = os.path.join(here, "chatmock")
    init_path = os.path.join(pkg_dir, "__init__.py")
    if not (os.path.isdir(pkg_dir) and os.path.isfile(init_path)):
        return
    # Ensure "chatmock" resolves to the package, not this entry script.
    spec = importlib.util.spec_from_file_location(
        "chatmock",
        init_path,
        submodule_search_locations=[pkg_dir],
    )
    if not spec or not spec.loader:
        return
    module = importlib.util.module_from_spec(spec)
    sys.modules["chatmock"] = module
    spec.loader.exec_module(module)


_bootstrap_package()

from chatmock.cli import main

if __name__ == "__main__":
    main()

