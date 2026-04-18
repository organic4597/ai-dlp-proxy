#!/usr/bin/env python3
"""프로세스 감시/버튼 e2e 검증용 더미 장기 실행 서비스."""

from __future__ import annotations

import argparse
import json
import os
import signal
import time
from pathlib import Path


RUNNING = True


def _stop(_sig, _frame) -> None:
    global RUNNING
    RUNNING = False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--name", required=True)
    parser.add_argument("--events-file", required=True)
    parser.add_argument("-p", "--listen-port")
    args, _extras = parser.parse_known_args()

    signal.signal(signal.SIGTERM, _stop)
    signal.signal(signal.SIGINT, _stop)

    events_path = Path(args.events_file)
    events_path.parent.mkdir(parents=True, exist_ok=True)

    def write_event(kind: str) -> None:
        payload = {
            "event": kind,
            "name": args.name,
            "pid": os.getpid(),
            "ts": time.time(),
            "listen_port": args.listen_port,
        }
        with events_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(payload, ensure_ascii=False) + "\n")

    write_event("start")
    while RUNNING:
        time.sleep(0.1)
    write_event("stop")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())