import json
import os
import subprocess
import sys
import warnings
from typing import Optional

DEFAULT_MODEL = "rchat/gpt-oss-120b"
DEFAULT_OUTPUT_FILE = os.path.join(sys.path[0], "output.txt")


def get_latest_session_id(directory: Optional[str] = None) -> Optional[str]:
    """Return the most recently updated session id, or None if there are no sessions.

    Args:
        directory: If set, run opencode session list in this directory (cwd) so
            sessions are scoped to this project.
    """
    result = subprocess.run(
        ['opencode', 'session', 'list', '--format', 'json', '--max-count', '1'],
        capture_output=True,
        text=True,
        cwd=directory if directory else None,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return None
    sessions = json.loads(result.stdout)
    return sessions[0]['id'] if sessions else None


def get_session_id_by_name(
    name: str,
    most_recent_if_duplicates: bool = True,
    directory: Optional[str] = None,
) -> Optional[str]:
    """Return the session id for sessions whose title equals name (exact match).

    Sessions are ordered by most recent first.
    - If most_recent_if_duplicates is True (default): return the most recent match
      when multiple sessions share the same name.
    - If most_recent_if_duplicates is False: return a session id only when exactly
      one session has that name; if multiple match, emit a warning and return None.

    Args:
        name: Exact session title to search for.
        most_recent_if_duplicates: If True, return the most recent match when
            multiple sessions share the name; if False, return None and warn on duplicates.
        directory: If set, run opencode session list in this directory (cwd) so
            sessions are scoped to this project.

    Returns:
        The session id string, or None if no match or multiple matches (strict mode).
    """
    result = subprocess.run(
        ['opencode', 'session', 'list', '--format', 'json'],
        capture_output=True,
        text=True,
        cwd=directory if directory else None,
    )
    if result.returncode != 0 or not result.stdout.strip():
        return None
    sessions = json.loads(result.stdout)
    matches = [s for s in sessions if s.get('title') == name]
    if not matches:
        return None
    if most_recent_if_duplicates:
        return matches[0]['id']
    if len(matches) > 1:
        warnings.warn(
            f"Multiple sessions found with title {name!r} ({len(matches)} matches); returning None.",
            UserWarning,
            stacklevel=2,
        )
        return None
    return matches[0]['id']


def continue_opencode_session(
    prompt: str,
    session_id: str,
    model: str = DEFAULT_MODEL,
    directory: Optional[str] = None,
    output_file: str = DEFAULT_OUTPUT_FILE,
):
    """Run opencode with the given prompt in an existing session.

    Args:
        prompt: Initial message or instruction to send.
        session_id: Id of the session to continue.
        model: Model to use (default: DEFAULT_MODEL).
        directory: Working directory to run opencode in (passed as --dir). If None, default is used.
        output_file: File to write output to (default: DEFAULT_OUTPUT_FILE).

    Returns:
        None (output is written to output.txt).
    """
    kwargs = {"session": session_id}
    if directory is not None:
        kwargs["dir"] = directory
    return run_opencode(prompt, model=model, output_file=output_file, kwargs=kwargs)


def initiate_opencode_session(
    prompt: str,
    title: str,
    model: str = DEFAULT_MODEL,
    directory: Optional[str] = None,
    output_file: str = DEFAULT_OUTPUT_FILE,
):
    """Start a new opencode session with the given prompt and title.

    Args:
        prompt: Initial message or instruction to send.
        title: Title for the new session.
        model: Model to use (default: DEFAULT_MODEL).
        directory: Working directory to run opencode in (passed as --dir). If None, default is used.
        output_file: File to write output to (default: DEFAULT_OUTPUT_FILE).

    Returns:
        None (output is written to output.txt).
    """
    kwargs = {"title": title}
    if directory is not None:
        kwargs["dir"] = directory
    return run_opencode(prompt, model=model, output_file=output_file, kwargs=kwargs)


def run_opencode(
    prompt: str,
    model: str = DEFAULT_MODEL,
    output_file: str = DEFAULT_OUTPUT_FILE,
    kwargs: dict = {},
):
    """Run opencode with the given prompt; optional kwargs become CLI flags (e.g. session, title).

    Args:
        prompt: Message or instruction to send.
        model: Model to use (default: DEFAULT_MODEL).
        output_file: File to write output to (default: DEFAULT_OUTPUT_FILE).
        kwargs: Optional CLI options as key-value pairs (e.g. session, title).

    Returns:
        None (stdout/stderr are written to output.txt).
    """
    args = ['opencode', 'run', prompt, '-m', model]
    for key, value in kwargs.items():
        args.extend([f'--{key}', value])
    with open(output_file, 'a') as f:
        process = subprocess.Popen(
            args,
            text=True,
            stdout=f,
            stderr=f
        )
        process.wait()