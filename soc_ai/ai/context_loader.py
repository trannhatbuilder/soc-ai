"""Context loader for the AI Log Analysis module.

Loads the Markdown context files under ``soc_ai/ai/context/`` and
exposes them as a single string that can be embedded in the system
prompt sent to the Groq model.

The six files follow the original evvolabs naming convention:

  - ``01_environment.md``         — platform, assets, baseline traffic
  - ``02_detection_policy.md``    — alert / ignore / low-signal rules
  - ``03_asset_criticality.md``   — asset inventory and port criticality
  - ``04_known_benign_patterns.md``— patterns that must NOT alert
  - ``05_response_playbooks.md``  — per-category response actions
  - ``06_output_schema.md``       — JSON contract the model must obey

If a file is missing or unreadable, the loader emits a clear
placeholder so the prompt still makes sense and the failure is
visible in the model output.
"""

from pathlib import Path
from typing import Dict, List, Optional


# ── Public constants ────────────────────────────────────────────────────

# Default location of the context directory, relative to the project
# root. Tests can override this by passing a different path to
# :class:`ContextLoader`.
DEFAULT_CONTEXT_DIR: str = "soc_ai/ai/context"

# Ordered list of context files. The order here determines the order
# in which they are concatenated into the system prompt — keep it
# stable so the model sees a consistent structure.
CONTEXT_FILES: List[str] = [
    "01_environment.md",
    "02_detection_policy.md",
    "03_asset_criticality.md",
    "04_known_benign_patterns.md",
    "05_response_playbooks.md",
    "06_output_schema.md",
]


# ── Context loader ──────────────────────────────────────────────────────

class ContextLoader:
    """
    Loads Markdown context files and concatenates them into a single
    prompt-ready string.

    Usage
    -----
    >>> loader = ContextLoader()              # uses DEFAULT_CONTEXT_DIR
    >>> context_text = loader.load()          # full concatenated context
    >>> files = loader.load_files()           # dict of {filename: content}

    The loader is intentionally simple — no caching, no templating.
    Context files are read fresh on every call so that edits during
    SOC tuning take effect on the next analysis run without restart.
    """

    def __init__(self, context_dir: Optional[str] = None) -> None:
        """
        Parameters
        ----------
        context_dir : str, optional
            Path to the directory containing the Markdown context
            files. When ``None``, defaults to :data:`DEFAULT_CONTEXT_DIR`
            resolved relative to the current working directory.
        """
        self.context_dir = Path(context_dir or DEFAULT_CONTEXT_DIR)

    def load(self) -> str:
        """
        Load and concatenate every context file into a single string.

        Each file is wrapped in a Markdown heading showing its
        filename, so the model can reference which file a rule came
        from. Missing or unreadable files produce a visible placeholder
        block so the prompt remains coherent.

        Returns
        -------
        str
            Concatenated context, ready to embed in the system prompt.
        """
        files = self.load_files()
        parts: List[str] = []

        for filename in CONTEXT_FILES:
            content = files.get(filename)
            if content is None:
                parts.append(
                    f"\n\n## [Context file missing: {filename}]\n\n"
                    f"This context file could not be loaded. Rules from it "
                    f"are unavailable for this analysis.\n"
                )
            else:
                parts.append(
                    f"\n\n## Context file: {filename}\n\n{content}\n"
                )

        return "".join(parts).strip()

    def load_files(self) -> Dict[str, str]:
        """
        Load every context file into a dict keyed by filename.

        Missing or unreadable files are silently omitted from the
        returned dict; callers can detect their absence by checking
        whether the expected key is present.

        Returns
        -------
        dict[str, str]
            Mapping ``{filename: file_content}`` for every file that
            was successfully read.
        """
        result: Dict[str, str] = {}

        for filename in CONTEXT_FILES:
            path = self.context_dir / filename
            try:
                content = path.read_text(encoding="utf-8")
                result[filename] = content
            except (OSError, UnicodeDecodeError):
                # Silently skip — :meth:`load` will emit a placeholder.
                continue

        return result

    def files_present(self) -> List[str]:
        """
        Return the list of context files actually present on disk.

        Useful for diagnostics and tests.
        """
        present: List[str] = []
        for filename in CONTEXT_FILES:
            if (self.context_dir / filename).is_file():
                present.append(filename)
        return present