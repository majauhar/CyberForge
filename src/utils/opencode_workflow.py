from typing import List, Optional

from .opencode_run import (
    DEFAULT_MODEL,
    DEFAULT_OUTPUT_FILE,
    continue_opencode_session,
    get_latest_session_id,
    get_session_id_by_name,
    initiate_opencode_session,
)


def run_opencode_workflow(
    directory: str,
    session_title: str,
    prompts: List[str],
    model: Optional[str] = DEFAULT_MODEL,
    output_file: str = DEFAULT_OUTPUT_FILE,
) -> Optional[str]:
    """Run a sequence of prompts in one opencode session.
    Starts a new session with the first prompt, then continues the same session
    with each remaining prompt in order.

    Args:
        directory: Working directory to run opencode in (--dir).
        session_title: Title for the new session.
        prompts: List of prompts; the first starts the session, the rest continue it.
        model: Model to use. If None, opencode_run.DEFAULT_MODEL is used.
        output_file: File to write opencode stdout/stderr to for each run.

    Returns:
        The session id after the workflow completes, or None if the session could
        not be resolved after the first run.

    Raises:
        ValueError: If prompts is empty.
    """
    if not prompts:
        raise ValueError("No prompts provided")

    def _log(msg: str) -> None:
        with open(output_file, "a") as f:
            f.write(msg)

    # Start session with first prompt
    _log("Starting session: " + session_title + "\n")
    _log("📄 Prompt 0: " + prompts[0] + "\n")
    initiate_opencode_session(
        prompt=prompts[0],
        title=session_title,
        model=model,
        directory=directory,
        output_file=output_file,
    )

    # Resolve session id (most recent with this title = the one we just created)
    session_id = get_session_id_by_name(session_title, directory=directory)
    if session_id is None:
        raise ValueError(f"No session found for title: {session_title}")

    # Run remaining prompts in the same session
    for i, prompt in enumerate(prompts[1:], start=1):
        _log("📄 Prompt " + str(i) + ": " + prompt + "\n")
        continue_opencode_session(
            prompt=prompt,
            session_id=session_id,
            model=model,
            directory=directory,
            output_file=output_file,
        )

    return session_id
