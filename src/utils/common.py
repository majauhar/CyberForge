from typing import Optional, Sequence, Set


def is_valid_id(valid_ids: Set[str], choice: Optional[str]) -> bool:
    """Return True iff choice is a non-empty string and is in valid_ids."""
    return bool(choice and choice in valid_ids)


_DEFAULT_LLM_REFUSAL_MARKERS: Sequence[str] = ("I can't assist", "I can’t assist")


def raise_if_LLM_refusal(
    stdout: Optional[str],
    refusal_markers: Sequence[str] = _DEFAULT_LLM_REFUSAL_MARKERS,
) -> None:
    """Raise ValueError if the model response contains a refusal marker."""
    text = (stdout or "").strip()
    for marker in refusal_markers:
        if marker in text:
            raise ValueError("Model refused to assist; retrying node.")

