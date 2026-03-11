from __future__ import annotations

import logging

from utils.agent_runner import OpencodeRunner

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")

# Example model; override as needed
MODEL = "rchat/gpt-oss-120b"


def main() -> None:
    runner = OpencodeRunner()

    start = runner.create_session(
        first_message="Reply with exactly: SESSION_OK",
        model=MODEL,
        capture_output=True,
    )
    logging.info("Created session: %s", start.session_id)
    logging.info("First reply: %r", (start.output or "").strip())

    follow_up = runner.continue_session(
        session_id=start.session_id,
        message="Reply with exactly: CONTINUE_OK",
        model=MODEL,
        capture_output=True,
    )
    logging.info("Continue reply: %r", (follow_up or "").strip())


if __name__ == "__main__":
    main()
