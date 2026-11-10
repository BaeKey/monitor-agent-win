#!/usr/bin/env python3
"""Stream Cargo JSON diagnostics to readable logs and GitHub annotations.

Cargo's exit status belongs to the caller: invoke this filter with bash pipefail.
This script never suppresses or downgrades a compiler error.
"""

import json
import sys


def escape_data(value: str) -> str:
    """Escape workflow-command data, in the required order."""
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def escape_property(value: str) -> str:
    return escape_data(value).replace(":", "%3A").replace(",", "%2C")


def log(text: str) -> None:
    # Source excerpts and non-JSON Cargo output are not workflow commands.
    # Prefix EVERY line so even an excerpt containing ::error cannot inject one.
    for line in text.splitlines():
        print(f"  {line}", flush=True)


def diagnostic(message: dict) -> None:
    rendered = message.get("rendered") or message.get("message", "Rust diagnostic")
    log(rendered)
    level = message.get("level")
    if level not in ("error", "warning"):
        return

    code = message.get("code") or {}
    title = code.get("code") or f"Rust {level}"
    properties = []
    spans = message.get("spans") or []
    primary = next((span for span in spans if span.get("is_primary")), None)
    if primary is not None:
        filename = primary.get("file_name")
        line = primary.get("line_start")
        if filename:
            properties.append(f"file={escape_property(filename)}")
        if isinstance(line, int) and line > 0:
            properties.append(f"line={line}")
    properties.append(f"title={escape_property(title)}")
    # Include rendered notes/help, not just the headline, in the public API data.
    print(f"::{level} {','.join(properties)}::{escape_data(rendered)}", flush=True)


def main() -> None:
    for raw in sys.stdin:
        try:
            event = json.loads(raw)
        except json.JSONDecodeError:
            # cargo progress messages and tool startup failures are plain text.
            log(raw)
            continue
        if not isinstance(event, dict):
            log(raw)
            continue
        if event.get("reason") == "compiler-message":
            diagnostic(event["message"])
        elif event.get("reason") == "build-finished" and not event.get("success"):
            print("::error title=Cargo::Clippy compilation failed; see compiler diagnostics above.", flush=True)
        # Successful artifact/build-script records carry no diagnostic.


if __name__ == "__main__":
    main()
