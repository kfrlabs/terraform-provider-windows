#!/usr/bin/env python3
"""Plan the testacc-windows acceptance matrix from the files a change touches.

Writes `mode`, `matrix` and `reason` to $GITHUB_OUTPUT and a short report to
$GITHUB_STEP_SUMMARY (both optional, for local runs).

Modes:
  full       every acceptance test of the suite, packed into lanes (see
             pack()), password auth, plus one public-key smoke lane. Used for
             push/workflow_dispatch and whenever a change touches code shared
             by every resource (transport, provider wiring, dependencies, the
             CI itself).
  selective  only the acceptance tests of the resource families the change
             touches, packed the same way, password auth only (public-key auth
             only changes the SSH handshake, which lives in shared winclient
             code and therefore always triggers a full run).
  filter     workflow_dispatch with run_filter: one job per auth mode.
  none       nothing acceptance-relevant changed (unit tests only, ...).

Lanes are sized from .github/testacc-timings.json (measured durations of the
slow tests, a default for the others) and capped in test count: a single test
process that runs ~90 tests in a row exhausts the 4-vCPU windows-latest runner
("The paging file is too small", "Starting the CLR failed"), so no lane may
grow with the suite. New resources are spread automatically; nothing has to
be assigned by hand.

A file the planner cannot attribute to a family falls back to a full run, so
an unknown layout costs time, never coverage.
"""

import argparse
import json
import math
import os
import re
import subprocess
import sys
from pathlib import Path

PROVIDER = "internal/provider/"
WINCLIENT = "internal/winclient/"

# Touching any of these can change every test's behaviour.
FULL_TRIGGERS = {
    "go.mod",
    "go.sum",
    ".github/workflows/testacc-windows.yml",
    ".github/scripts/Invoke-AccTests.ps1",
    ".github/scripts/testacc-plan.py",
    ".github/testacc-groups.json",
    ".github/testacc-timings.json",
}

FAMILY_FILE = re.compile(r"^(resource|datasource)_windows_(?P<family>[a-z0-9_]+)\.go$")
ACC_FILE = re.compile(r"^(resource|datasource)_windows_(?P<family>[a-z0-9_]+)_acc_test\.go$")
TEST_FUNC = re.compile(r"^func (TestAcc\w+)\(t \*testing\.T\)", re.MULTILINE)
# provider.go changes that only (un)register a resource or data source: every
# new family touches it, and the family's own files already select its tests.
REGISTRATION = re.compile(r"^\s*NewWindows\w+(Resource|DataSource),\s*$")
# First line of a new top-level declaration.
TOP_LEVEL_DECL = re.compile(r"^(func|type) ")


def git(root, *args):
    return subprocess.run(["git", *args], cwd=root, check=True, capture_output=True, text=True).stdout


def provider_files(root, ref):
    return [p[len(PROVIDER):] for p in git(root, "ls-tree", "--name-only", ref, PROVIDER).splitlines()]


def provider_families(names):
    return {
        m.group("family")
        for name in names
        if not name.endswith("_test.go") and (m := FAMILY_FILE.match(name))
    }


def family_tests(root, ref, family):
    tests = []
    for kind in ("resource", "datasource"):
        path = f"{PROVIDER}{kind}_windows_{family}_acc_test.go"
        try:
            tests += TEST_FUNC.findall(git(root, "show", f"{ref}:{path}"))
        except subprocess.CalledProcessError:
            pass
    return tests


def all_tests(root, ref, names):
    """{family: [tests]} for every acceptance test file of the suite."""
    suite = {}
    for name in names:
        m = ACC_FILE.match(name)
        if m:
            suite.setdefault(m.group("family"), []).extend(
                TEST_FUNC.findall(git(root, "show", f"{ref}:{PROVIDER}{name}"))
            )
    return {f: t for f, t in suite.items() if t}


def diff_hunks(root, base, head, path):
    """[(removed lines, added lines)] of a zero-context diff."""
    hunks = []
    for line in git(root, "diff", "-U0", f"{base}...{head}", "--", path).splitlines():
        if line.startswith("@@"):
            hunks.append(([], []))
        elif hunks and line[:1] == "-" and not line.startswith("---"):
            hunks[-1][0].append(line[1:])
        elif hunks and line[:1] == "+" and not line.startswith("+++"):
            hunks[-1][1].append(line[1:])
    return hunks


def registration_only(root, base, head, path):
    lines = [l for removed, added in diff_hunks(root, base, head, path) for l in removed + added]
    return bool(lines) and all(REGISTRATION.match(l) for l in lines)


def declarations_only(root, base, head, path):
    """True when every hunk only appends whole new top-level functions or types
    (a helper a new resource needs), so no existing code path changes. An edit
    inside an existing body, a removal or a new init() is not."""
    hunks = diff_hunks(root, base, head, path)
    if not hunks:
        return False
    for removed, added in hunks:
        if removed:
            return False
        code = [l for l in added if l.strip() and not l.startswith("//")]
        if not code or not TOP_LEVEL_DECL.match(code[0]) or code[-1] not in ("}", ")"):
            return False
        if any(l.startswith("func init(") or l.startswith("var ") for l in code):
            return False
        # Unindented lines may only open or close declarations.
        if any(not l[:1].isspace() and not TOP_LEVEL_DECL.match(l) and l not in ("}", ")") for l in code):
            return False
    return True


def match_families(stem, families):
    """Families a shared stem serves: itself and its plural collection data
    source (local_user -> local_user, local_users)."""
    return sorted(f for f in families if f in (stem, stem + "s"))


def classify(path, families):
    """Return ('ignore', why) | ('families', [names]) | ('full', why) |
    ('shared', why): shared code, full run unless the change only adds new
    declarations."""
    if path in FULL_TRIGGERS:
        return "full", f"{path} is shared by every lane"

    if path.startswith(PROVIDER):
        name = path[len(PROVIDER):]
        if "/" in name or not name.endswith(".go"):
            return "full", f"{path}: unrecognised provider file"
        if name.endswith("_acc_test.go"):
            m = FAMILY_FILE.match(name[: -len("_acc_test.go")] + ".go")
            if m:
                return "families", [m.group("family")]
            return "full", f"{path}: shared acceptance helper"
        if name.endswith("_test.go"):
            return "ignore", "unit test (test.yml)"
        m = FAMILY_FILE.match(name)
        if m:
            return "families", [m.group("family")]
        stem = re.sub(r"_ds_shared$", "", name[:-3])
        hits = match_families(stem, families)
        if hits and stem != name[:-3]:
            return "families", hits
        return "shared", f"{path} is shared provider code"

    if path.startswith(WINCLIENT):
        name = path[len(WINCLIENT):]
        if "/" in name or not name.endswith(".go"):
            return "full", f"{path}: unrecognised winclient file"
        if name.endswith("_test.go"):
            return "ignore", "unit test (test.yml)"
        stem = re.sub(r"_(types|helpers)$", "", name[:-3])
        hits = match_families(stem, families)
        if stem.endswith("_common"):
            # Shared by one product's families (iis_common -> iis_app_pool).
            hits = sorted(f for f in families if f.startswith(stem[: -len("common")]))
        if hits:
            return "families", hits
        return "shared", f"{path} is shared transport/client code"

    return "ignore", "not acceptance-relevant"


class Config:
    def __init__(self, root):
        data = json.loads((root / ".github/testacc-groups.json").read_text(encoding="utf-8"))
        self.groups = data["groups"]
        g = data["github"]
        self.lane_seconds = g["laneSeconds"]
        self.lane_max_tests = g["laneMaxTests"]
        self.default_seconds = g["defaultTestSeconds"]
        self.publickey_families = g["publickeyFamilies"]
        timings = json.loads((root / ".github/testacc-timings.json").read_text(encoding="utf-8"))
        self.seconds = timings["seconds"]

    def group_of(self, test):
        for g in self.groups:
            if not g.get("catchAll") and re.search(g["run"], test):
                return g
        return next(g for g in self.groups if g.get("catchAll"))

    def cost(self, test):
        return self.seconds.get(test, self.default_seconds)


def run_regex(tests):
    return "^(" + "|".join(sorted(tests)) + ")$"


def label(families):
    families = sorted(families)
    return ", ".join(families[:3]) + (f" +{len(families) - 3}" if len(families) > 3 else "")


def pack(units, cfg):
    """units: [(family, [tests])] -> [[(family, [tests])]], balanced on
    estimated seconds, at most lane_max_tests tests per lane. A family only
    splits when it alone exceeds a lane."""
    pieces = []
    for family, tests in units:
        tests = sorted(tests, key=lambda t: (-cfg.cost(t), t))
        chunk, secs = [], 0
        for t in tests:
            if chunk and (secs + cfg.cost(t) > cfg.lane_seconds or len(chunk) >= cfg.lane_max_tests):
                pieces.append((family, chunk))
                chunk, secs = [], 0
            chunk.append(t)
            secs += cfg.cost(t)
        if chunk:
            pieces.append((family, chunk))

    total_secs = sum(cfg.cost(t) for _, ts in pieces for t in ts)
    total_tests = sum(len(ts) for _, ts in pieces)
    n = max(1, math.ceil(total_secs / cfg.lane_seconds), math.ceil(total_tests / cfg.lane_max_tests))
    lanes = [[] for _ in range(n)]
    secs = [0.0] * n
    count = [0] * n
    # Longest piece first into the emptiest lane that still has test room.
    for family, tests in sorted(pieces, key=lambda p: (-sum(cfg.cost(t) for t in p[1]), p[0])):
        fits = [i for i in range(len(lanes)) if count[i] + len(tests) <= cfg.lane_max_tests]
        if not fits:
            lanes.append([])
            secs.append(0.0)
            count.append(0)
            fits = [len(lanes) - 1]
        i = min(fits, key=lambda j: secs[j])
        lanes[i].append((family, tests))
        secs[i] += sum(cfg.cost(t) for t in tests)
        count[i] += len(tests)
    return [l for l in lanes if l]


def build_matrix(selected, cfg, publickey):
    """selected: {family: [tests]} -> (matrix, dropped tests)."""
    dedicated, dropped, pool = [], [], {}
    for family, tests in selected.items():
        for t in tests:
            g = cfg.group_of(t)
            if g.get("githubHosted") is False:
                dropped.append(t)
            elif g.get("dedicated"):
                dedicated.append((g["name"], t))
            else:
                pool.setdefault(family, []).append(t)

    matrix = [
        {"auth": "password", "name": name, "lanes": "", "run": run_regex([t])}
        for name, t in sorted(dedicated)
    ]
    lanes = pack(sorted(pool.items()), cfg)
    for i, lane in enumerate(lanes, 1):
        tests = [t for _, ts in lane for t in ts]
        name = f"{i}/{len(lanes)} {label({f for f, _ in lane})}"
        matrix.append({"auth": "password", "name": name, "lanes": "", "run": run_regex(tests)})

    if publickey:
        smoke = [t for f in cfg.publickey_families for t in pool.get(f, [])]
        if smoke:
            matrix.append({"auth": "publickey", "name": "smoke " + label(cfg.publickey_families), "lanes": "", "run": run_regex(smoke)})
    return matrix, sorted(dropped)


def plan(root, event, base="", head="HEAD", run_filter=""):
    cfg = Config(root)
    report = []

    if event == "workflow_dispatch" and run_filter:
        matrix = [{"auth": a, "name": "run-filter", "lanes": "", "run": run_filter} for a in ("password", "publickey")]
        return "filter", matrix, f"run_filter {run_filter}", report

    names = provider_files(root, head)
    full_reason = ""
    selected = {}
    if event != "pull_request":
        full_reason = f"{event}: full suite"
    else:
        families = provider_families(names)
        for path in git(root, "diff", "--name-only", f"{base}...{head}").splitlines():
            if path == PROVIDER + "provider.go" and registration_only(root, base, head, path):
                kind, value = "ignore", "only (un)registers resources/data sources"
            else:
                kind, value = classify(path, families)
                if kind == "shared":
                    if declarations_only(root, base, head, path):
                        kind, value = "ignore", "only adds new top-level declarations"
                    else:
                        kind = "full"
            report.append((path, kind, value if isinstance(value, str) else ", ".join(value)))
            if kind == "full":
                full_reason = full_reason or value
            elif kind == "families":
                for fam in value:
                    selected.setdefault(fam, family_tests(root, head, fam))

    if full_reason:
        matrix, dropped = build_matrix(all_tests(root, head, names), cfg, publickey=True)
        if dropped:
            report.append(("(not on windows-latest, run testacc-lab-container)", "dropped", f"{len(dropped)} tests"))
        return "full", matrix, full_reason, report

    selected = {f: t for f, t in selected.items() if t}
    if not selected:
        return "none", [], "no acceptance test covers the changed files", report

    matrix, dropped = build_matrix(selected, cfg, publickey=False)
    reason = "families: " + ", ".join(sorted(selected))
    if dropped:
        report.append(("(not on windows-latest, run testacc-lab-container)", "dropped", ", ".join(dropped)))
    if not matrix:
        return "none", [], reason + " (only tests that cannot run on windows-latest)", report
    return "selective", matrix, reason, report


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--event", required=True)
    ap.add_argument("--base", default="")
    ap.add_argument("--head", default="HEAD")
    ap.add_argument("--run-filter", default="")
    ap.add_argument("--root", default=".")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    mode, matrix, reason, report = plan(root, args.event, args.base, args.head, args.run_filter)
    cfg = Config(root)

    lines = [f"mode: {mode} ({reason})"]
    lines += [f"  {kind:9} {path}: {why}" for path, kind, why in report]
    for m in matrix:
        tests = m["run"][2:-2].split("|") if m["run"].startswith("^(") else []
        est = f", {len(tests)} tests, ~{round(sum(cfg.cost(t) for t in tests) / 60, 1)}min" if tests else ""
        lines.append(f"  job: acceptance ({m['auth']}, {m['name']}){est}")
    print("\n".join(lines))

    if os.environ.get("GITHUB_OUTPUT"):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as fh:
            fh.write(f"mode={mode}\n")
            fh.write(f"reason={reason}\n")
            fh.write(f"matrix={json.dumps({'include': matrix})}\n")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with open(os.environ["GITHUB_STEP_SUMMARY"], "a", encoding="utf-8") as fh:
            fh.write("### testacc-windows plan\n\n```\n" + "\n".join(lines) + "\n```\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
