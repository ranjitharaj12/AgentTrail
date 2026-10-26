"""Enrichment: derive paths, path_class, net_dest, action_type, trust_level, intent.

Pure functions over Events, no database. Running it twice gives the same result.
"""
from __future__ import annotations

import posixpath
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

import yaml

from agenttrail.schema import Event, EventType, PathClass, ToolSource, TrustLevel

# ---------- config ----------


@dataclass
class ProjectConfig:
    root: str
    vendored_dirs: list[str]


@dataclass
class Config:
    home: str
    projects: dict[str, ProjectConfig]

    @classmethod
    def load(cls, path: Path) -> "Config":
        raw = yaml.safe_load(Path(path).read_text())
        projects = {n: ProjectConfig(p["root"], p.get("vendored_dirs", []))
                    for n, p in raw["projects"].items()}
        return cls(home=raw["home"], projects=projects)


# ---------- paths ----------

SENSITIVE = [re.compile(p) for p in [
    r"/\.ssh(/|$)", r"/\.aws(/|$)", r"/\.gnupg(/|$)", r"/\.kube(/|$)",
    r"(^|/)\.env(\.(?!example$|sample$)[^/]*)?$",   # .env, .env.local; not .env.example
    r"\.(pem|key|p12|pfx)$", r"(^|/)id_(rsa|ed25519|ecdsa)",
    r"/Library/Keychains", r"/\.config/(google-chrome|chromium|BraveSoftware)",
    r"/Library/Application Support/(Google/Chrome|Firefox)",
    r"(^|/)\.(bash|zsh)_history$", r"(^|/)\.netrc$", r"(^|/)\.git-credentials$",
    # Credential stores of common command-line tools (an auth token lives in each)
    r"/\.config/(gh|hub|gcloud|op|rclone|heroku)(/|$)", r"/\.docker/config\.json$",
    r"/\.(azure|oci)(/|$)", r"/\.terraform\.d/credentials", r"/\.m2/settings\.xml$",
    r"(^|/)\.(pypirc|npmrc|vault-token|s3cfg|terraformrc)$",
]]
# Outside the project, a data file whose name says it holds a secret is treated as one.
# (Inside the project the name alone is too weak: `token_utils.json` is probably just code data.)
SECRET_NAME = re.compile(r"(?i)(^|/)[^/]*(credential|secret|token|api[-_]?key|passwd|password)[^/]*"
                         r"\.(json|ya?ml|toml|ini|cfg|conf|env|txt|key)$")

PATH_ARG_KEYS = ("file_path", "path", "notebook_path")
SEVERITY = {PathClass.project: 0, PathClass.home: 1, PathClass.system: 2, PathClass.sensitive: 3}


def _normalize(p: str, root: str, home: str) -> str:
    if p == "~" or p.startswith("~/"):
        p = home + p[1:]
    elif not p.startswith("/"):
        p = posixpath.join(root, p)
    return posixpath.normpath(p)


def _looks_like_path(tok: str) -> bool:
    if tok.startswith("-") or "://" in tok:
        return False
    return "/" in tok or tok.startswith(".") or tok == "~" or any(s.search(tok) for s in SENSITIVE)


def extract_paths(ev: Event, root: str, home: str) -> list[str]:
    raw: list[str] = []
    for k in PATH_ARG_KEYS:
        if isinstance(ev.args.get(k), str):
            raw.append(ev.args[k])
    cmd = ev.args.get("command")
    if isinstance(cmd, str):
        try:
            toks = shlex.split(cmd)
        except ValueError:
            toks = cmd.split()
        raw += [t for t in _drop_sed_scripts(toks) if _looks_like_path(t)]
    return list(dict.fromkeys(_normalize(p, root, home) for p in raw))  # dedupe, keep order


def _drop_sed_scripts(toks: list[str]) -> list[str]:
    """`sed -i '/foo/d' file`: the script '/foo/d' looks like a path but isn't one."""
    out, i = [], 0
    while i < len(toks):
        out.append(toks[i])
        if posixpath.basename(toks[i]) == "sed":
            j = i + 1
            while j < len(toks) and toks[j].startswith("-"):   # skip flags
                out.append(toks[j])
                j += 1
            i = j + 1                                          # skip the script itself
            continue
        i += 1
    return out


def classify_path(p: str, root: str, home: str) -> PathClass:
    inside = p == root or p.startswith(root + "/")
    if any(s.search(p) for s in SENSITIVE) or (not inside and SECRET_NAME.search(p)):
        return PathClass.sensitive
    if inside:
        return PathClass.project
    if p == home or p.startswith(home + "/"):
        return PathClass.home
    return PathClass.system


# ---------- network ----------

URL_RE = re.compile(r"https?://[^\s'\"<>]+")
NET_BINARIES = {"curl", "wget", "nc", "ncat", "netcat", "socat", "telnet", "ftp", "sftp", "scp", "rsync", "ssh",
                "gh", "hub", "aws", "gcloud", "az", "kubectl", "twine", "http", "https", "xh", "aria2c"}
# Programs that are local for most subcommands and remote for a few.
NET_SUBCOMMANDS = {"git": {"push", "fetch", "pull", "clone", "ls-remote"},
                   "docker": {"push", "pull", "login"}, "npm": {"publish", "login", "adduser"}}
# Commands that only print or filter text: a URL inside them is just text, not a request.
TEXT_BINARIES = {"echo", "printf", "cat", "grep", "rg", "sed", "awk", "head", "tail", "less", "wc", "tee"}


def extract_net_dest(ev: Event) -> str | None:
    url = ev.args.get("url")
    if isinstance(url, str) and url:
        return urlparse(url).hostname
    cmd = ev.args.get("command")
    if isinstance(cmd, str):
        m = URL_RE.search(cmd)
        if m:
            return urlparse(m.group(0)).hostname
    return None


# ---------- action type ----------

READ_TOOLS = {"Read", "Grep", "Glob", "LS"}
WRITE_TOOLS = {"Edit", "Write", "MultiEdit", "NotebookEdit"}
NET_TOOLS = {"WebFetch", "WebSearch"}


SEPARATORS = {"&&", "||", ";", "|", "&", "(", ")"}
PREFIXES = {"sudo", "env", "nohup", "time", "command", "exec"}


def command_segments(cmd: str) -> list[list[str]]:
    """Split a shell command into simple commands at &&, ||, ;, | and subshell parentheses."""
    try:
        lex = shlex.shlex(cmd, posix=True, punctuation_chars=True)
        lex.whitespace_split = True
        toks = list(lex)
    except ValueError:
        toks = cmd.split()
    segs, cur = [], []
    for t in toks:
        if t in SEPARATORS:
            if cur:
                segs.append(cur)
            cur = []
        else:
            cur.append(t)
    if cur:
        segs.append(cur)
    return segs


def _program(seg: list[str]) -> tuple[str | None, list[str]]:
    """The program a simple command runs, and its arguments, past VAR=value and sudo-style prefixes."""
    for i, t in enumerate(seg):
        if ("=" in t and not t.startswith("-")) or t in PREFIXES:
            continue
        return posixpath.basename(t), seg[i + 1:]
    return None, []


def command_programs(cmd: str) -> list[tuple[str, list[str]]]:
    return [(b, a) for b, a in map(_program, command_segments(cmd)) if b]


def command_binary(cmd: str) -> str | None:
    """The first program a command runs."""
    progs = command_programs(cmd)
    return progs[0][0] if progs else None


def _is_network(prog: str, args: list[str]) -> bool:
    return prog in NET_BINARIES or bool(set(args[:4]) & NET_SUBCOMMANDS.get(prog, set()))


DELETE_BINARIES = {"rm", "rmdir", "shred", "unlink", "dd", "mkfs"}
FIND_DELETE = re.compile(r"\bfind\b.*\s(-delete\b|-exec\s+(rm|shred)\b)")


def action_type(ev: Event, net_dest: str | None) -> str | None:
    if ev.event_type == EventType.user_prompt:
        return "prompt"
    if ev.event_type not in (EventType.tool_decision, EventType.tool_result):
        return None
    if ev.tool_source == ToolSource.mcp:
        return "mcp_call"
    if ev.tool in READ_TOOLS:
        return "read"
    if ev.tool in WRITE_TOOLS:
        return "write"
    if ev.tool in NET_TOOLS:
        return "network"
    if ev.tool == "Bash":
        cmd = str(ev.args.get("command", ""))
        progs = command_programs(cmd)
        names = [b for b, _ in progs]
        if any(_is_network(b, a) for b, a in progs) or (net_dest and any(b not in TEXT_BINARIES for b in names)):
            return "network"
        if any(b in DELETE_BINARIES for b in names) or FIND_DELETE.search(cmd):
            return "delete"
        return "exec"
    return "other"


# ---------- trust ----------


def trust_level(ev: Event, paths: list[str], proj: ProjectConfig, action: str | None) -> TrustLevel | None:
    """Trust of the content this call brings into the agent's context."""
    if ev.event_type not in (EventType.tool_decision, EventType.tool_result):
        return None
    if ev.tool_source == ToolSource.mcp:
        return TrustLevel.mcp_result
    if ev.tool in NET_TOOLS:
        return TrustLevel.web
    if ev.tool in READ_TOOLS and paths:
        if any(f"/{d}/" in p for p in paths for d in proj.vendored_dirs):
            return TrustLevel.third_party
        return TrustLevel.user_authored
    if ev.tool == "Bash" and action == "network":      # only a real fetch brings web content in
        return TrustLevel.web
    return None


# ---------- the main entry point ----------


def enrich_session(events: list[Event], cfg: Config) -> list[Event]:
    events = sorted(events, key=lambda e: e.seq)
    prompts: list[str] = []
    by_tool_use: dict[str, dict] = {}   # tool_use_id -> derived fields from the decision
    out: list[Event] = []

    for ev in events:
        if ev.project not in cfg.projects:
            raise KeyError(f"project {ev.project!r} not in config/projects.yaml")
        proj = cfg.projects[ev.project]

        if ev.event_type == EventType.user_prompt and ev.prompt_text:
            prompts.append(ev.prompt_text)
        intent = " ".join(prompts[-3:]) or None   # latest prompt + the two before

        paths = extract_paths(ev, proj.root, cfg.home)
        classes = [classify_path(p, proj.root, cfg.home) for p in paths]
        path_class = max(classes, key=SEVERITY.get) if classes else None
        net = extract_net_dest(ev)
        action = action_type(ev, net)
        derived = dict(paths=paths, path_class=path_class, net_dest=net, action_type=action,
                       trust_level=trust_level(ev, paths, proj, action))

        # A tool_result carries no arguments; inherit from its tool_decision.
        if ev.event_type == EventType.tool_decision and ev.tool_use_id:
            by_tool_use[ev.tool_use_id] = derived
        elif ev.event_type == EventType.tool_result and ev.tool_use_id in by_tool_use:
            derived = by_tool_use[ev.tool_use_id]

        out.append(ev.model_copy(update={**derived, "intent": intent}))
    return out
