#!/usr/bin/env python3
"""Plan the testacc-windows acceptance matrix from the files a change touches.

Writes `mode`, `matrix` and `reason` to $GITHUB_OUTPUT and a short report to
$GITHUB_STEP_SUMMARY (both optional, for local runs).

Modes:
  full       the lane layout from `githubLanes` in testacc-groups.json, both
             auth modes. Used for push/workflow_dispatch and whenever a change
             touches code shared by every resource (transport, provider
             wiring, dependencies, the CI itself).
  selective  only the acceptance tests of the resource families the change
             touches, password auth only (public-key auth only changes the SSH
             handshake, which lives in shared winclient code and therefore
             always triggers a full run).
  filter     workflow_dispatch with run_filter: one job per auth mode.
  none       nothing acceptance-relevant changed (unit tests only, ...).

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
}

# Selective lanes hold at most this many tests (~5-10s each on windows-latest).
LANE_CAPACITY = 30

FAMILY_FILE = re.compile(r"^(resource|datasource)_windows_(?P<family>[a-z0-9_]+)\.go$")
TEST_FUNC = re.compile(r"^func (TestAcc\w+)\(t \*testing\.T\)", re.MULTILINE)
# provider.go changes that only (un)register a resource or data source: every
# new family touches it, and the family's own files already select its tests.
REGISTRATION = re.compile(r"^\s*NewWindows\w+(Resource|DataSource),\s*$")


def git(root, *args):
    return subprocess.run(["git", *args], cwd=root, check=True, capture_output=True, text=True).stdout


def provider_families(root, ref):
    families = set()
    for path in git(root, "ls-tree", "--name-only", ref, PROVIDER).splitlines():
        name = path[len(PROVIDER):]
        m = FAMILY_FILE.match(name)
        if m and not name.endswith("_test.go"):
            families.add(m.group("family"))
    return families


def family_tests(root, ref, family):
    tests = []
    for kind in ("resource", "datasource"):
        path = f"{PROVIDER}{kind}_windows_{family}_acc_test.go"
        try:
            tests += TEST_FUNC.findall(git(root, "show", f"{ref}:{path}"))
        except subprocess.CalledProcessError:
            pass
    return tests


def registration_only(root, base, head, path):
    lines = [
        line[1:]
        for line in git(root, "diff", "-U0", f"{base}...{head}", "--", path).splitlines()
        if line[:1] in "+-" and not line.startswith(("+++", "---"))
    ]
    return bool(lines) and all(REGISTRATION.match(line) for line in lines)


def match_families(stem, families):
    """Families a shared stem serves: itself and its plural collection data
    source (local_user -> local_user, local_users)."""
    return sorted(f for f in families if f in (stem, stem + "s"))


def classify(path, families):
    """Return ('ignore', why) | ('families', [names]) | ('full', why)."""
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
        return "full", f"{path} is shared provider code"

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
        return "full", f"{path} is shared transport/client code"

    return "ignore", "not acceptance-relevant"


def load_groups(root):
    data = json.loads((root / ".github/testacc-groups.json").read_text(encoding="utf-8"))
    return data["groups"], data["githubLanes"]


def group_of(test, groups):
    for g in groups:
        if not g.get("catchAll") and re.search(g["run"], test):
            return g
    return next(g for g in groups if g.get("catchAll"))


def full_matrix(lanes):
    return [
        {"auth": auth, "name": lane["name"], "lanes": lane["lanes"], "run": ""}
        for auth in ("password", "publickey")
        for lane in lanes
        if auth in lane["auths"]
    ]


def run_regex(tests):
    return "^(" + "|".join(sorted(tests)) + ")$"


def selective_matrix(selected, groups):
    """selected: {family: [tests]} -> (matrix, dropped tests)."""
    dedicated, dropped, pool = [], [], {}
    for family, tests in selected.items():
        for t in tests:
            g = group_of(t, groups)
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

    total = sum(len(v) for v in pool.values())
    if total:
        bins = [[] for _ in range(max(1, math.ceil(total / LANE_CAPACITY)))]
        load = [0] * len(bins)
        # Longest family first into the emptiest lane; a family never splits.
        for family in sorted(pool, key=lambda f: (-len(pool[f]), f)):
            i = load.index(min(load))
            bins[i].append(family)
            load[i] += len(pool[family])
        for fams in bins:
            if not fams:
                continue
            fams.sort()
            label = ", ".join(fams[:3]) + (f" +{len(fams) - 3}" if len(fams) > 3 else "")
            tests = [t for f in fams for t in pool[f]]
            matrix.append({"auth": "password", "name": label, "lanes": "", "run": run_regex(tests)})
    return matrix, sorted(dropped)


def plan(root, event, base="", head="HEAD", run_filter=""):
    groups, lanes = load_groups(root)
    report = []

    if event == "workflow_dispatch" and run_filter:
        matrix = [{"auth": a, "name": "run-filter", "lanes": "", "run": run_filter} for a in ("password", "publickey")]
        return "filter", matrix, f"run_filter {run_filter}", report
    if event != "pull_request":
        return "full", full_matrix(lanes), f"{event}: full suite", report

    families = provider_families(root, head)
    selected, full_reasons = {}, []
    for path in git(root, "diff", "--name-only", f"{base}...{head}").splitlines():
        if path == PROVIDER + "provider.go" and registration_only(root, base, head, path):
            kind, value = "ignore", "only (un)registers resources/data sources"
        else:
            kind, value = classify(path, families)
        report.append((path, kind, value if isinstance(value, str) else ", ".join(value)))
        if kind == "full":
            full_reasons.append(value)
        elif kind == "families":
            for fam in value:
                selected.setdefault(fam, family_tests(root, head, fam))

    if full_reasons:
        return "full", full_matrix(lanes), full_reasons[0], report

    selected = {f: t for f, t in selected.items() if t}
    if not selected:
        return "none", [], "no acceptance test covers the changed files", report

    matrix, dropped = selective_matrix(selected, groups)
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

    lines = [f"mode: {mode} ({reason})"]
    lines += [f"  {kind:9} {path}: {why}" for path, kind, why in report]
    lines += [f"  job: acceptance ({m['auth']}, {m['name']})" for m in matrix]
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
