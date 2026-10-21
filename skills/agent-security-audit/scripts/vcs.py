#!/usr/bin/env python3
"""Which revision a target was at, and which files moved since — read-only, name only.

A target pattern says "this symbol is defined at crates/driver/src/lib.rs:142 and reaches
Command::new at unix.rs:88". That is a statement about **one revision**. Reused against a
later revision without checking, it becomes a confident claim about code that may no
longer exist — the worst kind, because it reads as accumulated knowledge.

So the knowledge base records the commit it was derived from, and a later audit compares.

**Only name-level queries are made.** A content diff can invoke a `textconv` program
configured in the repository's own `.gitattributes` and `.git/config`, and the repository
here is the thing being audited: running a command it chose is exactly what this audit
never does. `rev-parse` and `diff --name-only` do not consult textconv and do not run
hooks.
"""
import re
import subprocess
from pathlib import Path

TIMEOUT = 30


def _git(path, *args):
    """Run one read-only git query. Returns None when it is not a repo, or git is absent."""
    try:
        done = subprocess.run(('git', '-C', str(path)) + args,
                              capture_output=True, text=True, timeout=TIMEOUT,
                              check=False)
    except (OSError, subprocess.SubprocessError):
        return None
    if done.returncode != 0:
        return None
    # Trailing only: `status --porcelain` encodes staged-vs-worktree in the two leading
    # columns, so stripping the whole output shifts the first line and eats a character
    # off its path.
    return done.stdout.rstrip()


def revision(path):
    """The target's current commit, or None when it is not a git repository.

    None is not "unchanged": a target with no revision cannot be compared at all, and the
    callers treat that as "every recorded pattern needs re-verification".
    """
    root = Path(path)
    if not root.is_dir():
        return None
    if _git(root, 'rev-parse', '--is-inside-work-tree') != 'true':
        return None
    return _git(root, 'rev-parse', 'HEAD') or None


def dirty(path):
    """Whether the work tree carries uncommitted changes, or None when not a repo.

    A dirty tree means the commit id does not describe what was actually read, so a
    knowledge base derived from it cannot be version-stamped honestly.
    """
    if revision(path) is None:
        return None
    return bool(_git(path, 'status', '--porcelain') or '')


def work_tree_root(path):
    """The git work tree this path sits in, or None. Read-only.

    Used to notice that the records are being written **into somebody's repository** —
    which is legal and sometimes deliberate, so it is reported rather than refused. It is
    how 15 MB of audit records once landed in the framework repo's `git status`.
    """
    root = Path(path)
    for candidate in [root] + list(root.parents):
        if candidate.is_dir():
            if _git(candidate, 'rev-parse', '--is-inside-work-tree') != 'true':
                continue
            top = _git(candidate, 'rev-parse', '--show-toplevel')
            return top or None
    return None


def changed_paths(path, since):
    """Repo-relative paths that differ between `since` and the current HEAD.

    Returns None when the comparison cannot be made (not a repo, unknown commit, git
    absent). None means "unknown", never "nothing changed".
    """
    if not since or revision(path) is None:
        return None
    if _git(path, 'cat-file', '-e', since + '^{commit}') is None:
        return None                       # the recorded commit is not in this clone
    names = _git(path, 'diff', '--name-only', '--no-textconv', since, 'HEAD')
    if names is None:
        return None
    moved = [line.strip() for line in names.splitlines() if line.strip()]
    # Uncommitted work is part of what will be read, so it counts as changed too.
    pending = _git(path, 'status', '--porcelain') or ''
    for line in pending.splitlines():
        match = re.match(r'^.{2}\s+(.*)$', line)
        if not match:
            continue
        name = match.group(1).strip()
        if ' -> ' in name:                # a rename shows both sides
            moved.extend(part.strip() for part in name.split(' -> '))
        elif name:
            moved.append(name)
    return sorted(set(moved))
