"""``pocketsec-chat``: ask questions about PocketSec alerts from a terminal.

What this module is FOR: the presentation layer of the alert explainer, and the only
module in the package allowed to write to stdout.

    pocketsec-chat demo                          scripted walk-through of the demo alerts
    pocketsec-chat chat                          interactive REPL (the default)
    pocketsec-chat --ask "why?" --alert 1        one question, one answer
    pocketsec-chat --ask "why?" --alert 1 --json the same, as JSON with provenance
    pocketsec-chat --ask "why?" --sources        the same, with full source ids and digests
    pocketsec-chat --bundle alert.json ...       explain alert handoff files instead

Alerts come from the synthetic demo corpus unless ``--bundle`` names handoff files
(``pocketsec.assistant.alert_handoff.v1``). Every demo alert is labelled SYNTHETIC in
every answer header.

Every text answer is checked twice: each sentence by ``guard.check_sentence`` when it
is built, and the rendered text a person reads by ``guard.verify_rendered`` just
before it is printed. If the second check fails, a fixed note is printed instead of
the answer.

What it never does: run, build or forward a command. Questions go to the classifier
and the templates, and nothing else. Exit codes: 0 answered, 2 bad input (unknown
alert, unreadable bundle).
"""

from __future__ import annotations

import argparse
import json
import os
import stat
import sys
import time
from collections.abc import Sequence
from typing import TextIO

from pocketsec.assistant.answers import Answer
from pocketsec.assistant.demo import build_demo_alerts
from pocketsec.assistant.facts import AlertFacts
from pocketsec.assistant.guard import quote_number, verify_rendered
from pocketsec.assistant.handoff import HandoffError, facts_from_handoff
from pocketsec.assistant.phrasing import dimension_phrase, horizon_phrase, level_phrase
from pocketsec.assistant.session import Session
from pocketsec.assistant.wording import NOTES

__all__ = ["DEMO_SCRIPT", "main"]

#: The questions ``demo`` asks, in order, on the first two alerts. Casual phrasings on
#: purpose: the demo shows the classifier as well as the answers.
DEMO_SCRIPT: tuple[str, ...] = (
    "y did u flag this",
    "what happened?",
    "which process did this?",
    "hw sure r u",
    "what don't you know?",
    "is this a false alarm?",
    "what did pocketsec do about it?",
    "can u undo",
    "kill it",
    "how sure are you that this is a false alarm",
)
_MAX_BUNDLE_BYTES = 8 * 1024 * 1024
#: Printed in place of an answer whose rendered text failed ``verify_rendered``.
RENDER_REFUSED = (
    "This answer failed the final grounding check on its rendered text and was not shown."
)
#: Load failures in plain words. The path and the payload are never quoted.
_LOAD_ERRORS: tuple[tuple[type[BaseException], str], ...] = (
    (FileNotFoundError, "the file does not exist"),
    (IsADirectoryError, "that path is a directory, not a file"),
    (PermissionError, "permission to read the file was denied"),
    (json.JSONDecodeError, "the file is not valid JSON"),
    (UnicodeDecodeError, "the file is not UTF-8 text"),
    (RecursionError, "the JSON is nested too deeply"),
    (ArithmeticError, "the file holds a number out of range"),
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pocketsec-chat",
        description="Explain PocketSec alerts from their recorded facts. No language model.",
    )
    parser.add_argument("mode", nargs="?", choices=("demo", "chat"), default=None)
    parser.add_argument("--ask", metavar="QUESTION", help="answer one question and exit")
    parser.add_argument("--alert", metavar="ID", default="1", help="alert number or incident id")
    parser.add_argument("--json", action="store_true", help="print the answer as JSON")
    parser.add_argument(
        "--sources", action="store_true", help="show full source ids and evidence digests"
    )
    parser.add_argument(
        "--bundle", metavar="FILE", action="append", default=[], help="alert handoff JSON file"
    )
    return parser


def _read_bounded(path: str) -> str:
    """At most ``_MAX_BUNDLE_BYTES`` of a regular file.

    ``stat().st_size`` alone is not a bound: ``/dev/zero``, a FIFO and ``/dev/stdin``
    report size 0 and then stream without end. So only regular files are read, and the
    read itself is capped. The type is checked before opening (opening a FIFO blocks
    until a writer appears) and again on the open descriptor, in case the path was
    swapped in between; ``O_NONBLOCK`` keeps that open from blocking either way.
    """
    if not stat.S_ISREG(os.stat(path).st_mode):
        raise HandoffError("bundle must be a regular file")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0))
    with os.fdopen(descriptor, "rb") as handle:
        if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
            raise HandoffError("bundle must be a regular file")
        data = handle.read(_MAX_BUNDLE_BYTES + 1)
    if len(data) > _MAX_BUNDLE_BYTES:
        raise HandoffError("bundle file is larger than the 8 MiB limit")
    return data.decode("utf-8")


def _load_bundles(paths: Sequence[str]) -> tuple[AlertFacts, ...]:
    alerts: list[AlertFacts] = []
    for raw in paths:
        payload = json.loads(_read_bounded(raw))
        items = payload.get("alerts", [payload]) if isinstance(payload, dict) else payload
        if not isinstance(items, list):
            raise HandoffError("bundle must be a handoff object, a list, or {'alerts': [...]}")
        alerts.extend(facts_from_handoff(item) for item in items)
    return tuple(alerts)


def _emit(
    out: TextIO, session: Session, reply: Answer, *, as_json: bool, full: bool = False
) -> None:
    short = session.short_id(reply.alert)
    if as_json:
        print(json.dumps(reply.to_dict(short_id=short), indent=2), file=out)
        return
    rendered = reply.render(short_id=short, full_sources=full)
    if reply.alert is not None and verify_rendered(rendered, reply.alert):
        header = rendered.splitlines()[:2]
        print("\n".join([*header, f"Note: {RENDER_REFUSED}"]), file=out)
        return
    print(rendered, file=out)


def _summary(facts: AlertFacts) -> str:
    """One /alerts row's description: the hand-off, then the top lineage's state."""
    a = facts.assessment
    parts = [horizon_phrase(a.horizon)] if a.horizon else [f"verdict {a.verdict}"]
    top = facts.lineages[0] if facts.lineages else None
    if top is not None and top.state:
        state = ", ".join(f"{dimension_phrase(d)} {level_phrase(v)}" for d, v in top.state[:3])
        parts.append(f"highest process state: {state} (score {quote_number(top.phi)})")
    return "; ".join(parts)


def _list_alerts(out: TextIO, session: Session) -> None:
    print("Alerts (* marks the open one):", file=out)
    for index, facts in enumerate(session.alerts, start=1):
        origin = "SYNTHETIC" if facts.synthetic else "recorded"
        marker = "*" if session.current is facts else " "
        print(
            f"{marker} {index}. {facts.alert_id} [{origin}], {facts.ledger.total} events: "
            f"{_summary(facts)}",
            file=out,
        )


def _unknown_alert(out: TextIO, session: Session) -> None:
    count = len(session.alerts)
    if not count:
        print("There are no alerts loaded.", file=out)
        return
    print(
        f"There is no alert with that number or id. Use --alert with a number from 1 to "
        f"{count}, or one of these incident ids:",
        file=out,
    )
    for facts in session.alerts:
        print(f"  {facts.alert_id}", file=out)


def _one_shot(out: TextIO, session: Session, args: argparse.Namespace) -> int:
    if session.open(args.alert) is None:
        _unknown_alert(out, session)
        return 2
    _emit(out, session, session.ask(args.ask), as_json=args.json, full=args.sources)
    return 0


def _demo(out: TextIO, session: Session, loaded_in: float) -> int:
    print(
        f"PocketSec alert explainer: {len(session.alerts)} alerts loaded in {loaded_in:.2f} s.",
        file=out,
    )
    print(NOTES["SYNTHETIC"], file=out)
    _list_alerts(out, session)
    for ref in ("1", "2")[: len(session.alerts)]:
        session.open(ref)
        for question in DEMO_SCRIPT:
            print(f"\n>>> {question}", file=out)
            _emit(out, session, session.ask(question), as_json=False)
    return 0


def _open(out: TextIO, session: Session, argument: str) -> None:
    if not argument.strip():
        print("Usage: /open <number or incident id>. Type /alerts to list them.", file=out)
        return
    found = session.open(argument)
    print(
        NOTES["UNKNOWN_ALERT"] if found is None else f"Opened alert {session.short_id(found)}.",
        file=out,
    )


def _command(out: TextIO, session: Session, line: str, last: Answer | None) -> bool:
    """Handle a /command. Returns False when the session should end."""
    name, _, argument = line.partition(" ")
    if name in {"/quit", "/exit"}:
        return False
    if name == "/alerts":
        _list_alerts(out, session)
    elif name == "/open":
        _open(out, session, argument)
    elif name == "/sources":
        if last is None:
            print("There is no answer yet to show sources for.", file=out)
        else:
            _emit(out, session, last, as_json=False, full=True)
    elif name == "/help":
        for key in ("HELP_ASK", "HELP_COMMANDS", "HELP_TAGS"):
            print(NOTES[key], file=out)
    else:
        print("Unknown command. Type /help to see the commands.", file=out)
    return True


def _repl(stdin: TextIO, out: TextIO, session: Session) -> int:
    print("PocketSec alert explainer. Type /help for help, /quit to leave.", file=out)
    _list_alerts(out, session)
    last: Answer | None = None
    for raw in stdin:
        line = raw.strip()
        if not line:
            continue
        if line.startswith("/"):
            if not _command(out, session, line, last):
                break
            continue
        last = session.ask(line)
        _emit(out, session, last, as_json=False)
    return 0


def _load_error(exc: BaseException) -> str:
    if isinstance(exc, HandoffError):
        return str(exc)
    return next(
        (text for kind, text in _LOAD_ERRORS if isinstance(exc, kind)),
        f"the file could not be read ({type(exc).__name__})",
    )


def main(
    argv: Sequence[str] | None = None, *, stdin: TextIO | None = None, stdout: TextIO | None = None
) -> int:
    args = _parser().parse_args(argv)
    out = stdout if stdout is not None else sys.stdout
    started = time.perf_counter()
    try:
        alerts = _load_bundles(args.bundle) if args.bundle else build_demo_alerts()
    except (OSError, ValueError, HandoffError, RecursionError, ArithmeticError) as exc:
        print(f"Could not load the alerts: {_load_error(exc)}.", file=out)
        return 2
    if not alerts:
        print("Warning: the bundle holds no alerts.", file=out)
    session = Session(alerts)
    loaded_in = time.perf_counter() - started
    if args.ask is not None:
        return _one_shot(out, session, args)
    if args.mode == "demo":
        return _demo(out, session, loaded_in)
    return _repl(stdin if stdin is not None else sys.stdin, out, session)


if __name__ == "__main__":
    raise SystemExit(main())
