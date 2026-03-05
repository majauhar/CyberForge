import json
import logging
import subprocess
import warnings
from typing import Optional, Tuple

DEFAULT_MODEL = "rchat/gpt-oss-120b"

logger = logging.getLogger(__name__)


def get_latest_session_id(
    directory: Optional[str] = None
) -> Optional[str]:
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
    capture_output: bool = False,
) -> Optional[str]:
    """Run opencode with the given prompt in an existing session. Streams output to logging.
    If capture_output is True, returns full stdout as str.
    """
    kwargs = {"session": session_id}
    if directory is not None:
        kwargs["dir"] = directory
    return run_opencode(prompt, model=model, kwargs=kwargs, capture_output=capture_output)


def initiate_opencode_session(
    prompt: str,
    title: str,
    model: str = DEFAULT_MODEL,
    directory: Optional[str] = None,
    capture_output: bool = False,
) -> Optional[str]:
    """Start a new opencode session with the given prompt and title. Streams output to logging.
    If capture_output is True, returns full stdout as str.
    """
    kwargs = {"title": title}
    if directory is not None:
        kwargs["dir"] = directory
    return run_opencode(prompt, model=model, kwargs=kwargs, capture_output=capture_output)


def run_opencode(
    prompt: str,
    model: str = DEFAULT_MODEL,
    kwargs: dict = {},
    capture_output: bool = False,
) -> Optional[str]:
    """Run opencode with the given prompt; optional kwargs become CLI flags (e.g. session, title).
    Streams stdout/stderr to logging. If capture_output is True, returns full stdout as str.
    """
    args = ['opencode', 'run', prompt, '-m', model]
    for key, value in kwargs.items():
        args.extend([f'--{key}', value])
    cwd = kwargs.get("dir")
    process = subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        cwd=cwd,
    )
    lines: list[str] = []
    if process.stdout:
        for line in process.stdout:
            logger.info(line.strip())
            if capture_output:
                lines.append(line)
    process.wait()
    return "\n".join(lines) if capture_output else None
