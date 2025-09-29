import os
import sys

_project_root = os.path.dirname(__file__)
_src_dir = os.path.join(_project_root, "src")
if os.path.isdir(_src_dir) and _src_dir not in sys.path:
    sys.path.insert(0, _src_dir)
