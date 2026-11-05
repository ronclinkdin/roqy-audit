"""Path classes shared by the static checks and the adapters.

Matches are lowered to P3, not dropped. Test and example code can still be wrong;
it should not lead a report.
"""
import os, re

_NOISE = re.compile(
    r"(^|[\\/])("
    r"tests?|__tests__|__mocks__|spec|fixtures?|examples?|samples?|testdata|"
    r"docs?|documentation|vendor|vendored|third[-_]party|node_modules|"
    r"\.yarn[\\/]releases|site-packages"
    r")([\\/]|$)",
    re.I,
)


def noise_path(path):
    if not path:
        return False
    text = str(path).replace("\\", "/")
    return bool(_NOISE.search("/" + text.strip("/")))


def soften(severity, *paths):
    if severity not in ("P0", "P1", "P2", "P3"):
        return severity
    if any(noise_path(p) for p in paths):
        return "P3"
    return severity


def has_lockfile(directory, root):
    """True when directory or a parent up to root contains a JS lockfile."""
    locks = ("package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json")
    directory = os.path.abspath(directory)
    root = os.path.abspath(root)
    d = directory
    while True:
        if any(os.path.isfile(os.path.join(d, name)) for name in locks):
            return True
        if d == root:
            return False
        parent = os.path.dirname(d)
        if parent == d:
            return False
        d = parent
