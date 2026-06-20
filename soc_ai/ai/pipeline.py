"""AI Analysis pipeline — reads aggregated windows, sends each one to
an LLM for analysis, and writes AnalyzedLog JSONL output.

Flow:

    AggregatedLog JSONL  ->  LLMAnalyzer  ->  AnalyzedLog JSONL

Pipeline position (per the original evvolabs architecture):

    Raw Logs
      -> Normalize Logs
      -> Deduplicate Logs
      -> Data Enrichment
      -> Log Aggregation (5-min window)
      -> AI Log Analysis (LLMAnalyzer)   <-- this pipeline
      -> Alert Detection
      -> Send Alert to Telegram

Provider selection
------------------
The LLM provider is selected by the ``LLM_PROVIDER`` environment
variable (see ``.env``). Any OpenAI-compatible provider is supported:
Groq, DeepSeek, OpenRouter, Together, OpenAI, or a custom endpoint.

To switch providers, edit ``.env``::

    LLM_PROVIDER=deepseek
    DEEPSEEK_API_KEY=sk-xxxxxxxxxxxx
    DEEPSEEK_MODEL=deepseek-chat

No code changes are required.

Input contract
--------------
The standard input is the output of ``soc_ai.aggregation.pipeline`` —
a JSONL file where each line is one :class:`AggregatedLog` (a single
5-minute window of enriched logs). Each window is sent to the LLM
independently and produces one :class:`AIVerdict`.

Reading the aggregated input correctly requires reconstructing:
  - The nested :class:`IPEnrichment` objects inside each log's
    ``enrichments`` dict.
  - The :class:`EnrichedLog` objects inside the window's ``logs``
    list (with their dedup metadata and enrichments).
  - The :class:`AggregatedLog` container itself.

This is handled by :func:`read_aggregated_jsonl` below. Plain
``json.loads`` would produce dicts-of-dicts which would crash the
analyzer when it accesses typed attributes like
``enrichment.is_malicious``.

Robustness
----------
A single LLM failure (rate limit, timeout, malformed JSON) produces
a :class:`AIVerdict.fallback` for that window — the pipeline
continues with the next window and never aborts mid-run. The number
of fallback verdicts is reported in the summary.

Usage (CLI):
    python -m soc_ai.ai.pipeline <input_jsonl> <output_jsonl>

Usage (API):
    from soc_ai.ai.pipeline import analyze_pipeline

    analyze_pipeline(
        input_file="output/aggregated_fortigate.jsonl",
        output_file="output/analyzed_fortigate.jsonl",
    )
"""

import argparse
import json
from pathlib import Path
from typing import Any, Dict, List

from dotenv import load_dotenv

load_dotenv()

from soc_ai.aggregation.schemas import AggregatedLog
from soc_ai.ai.analyzer import LLMAnalyzer
from soc_ai.ai.schemas import AIVerdict, AnalyzedLog
from soc_ai.enrichment.schemas import EnrichedLog, IPEnrichment


# ── IO helpers ──────────────────────────────────────────────────────────

def read_aggregated_jsonl(input_file: str) -> List[AggregatedLog]:
    """
    Read a JSONL file of aggregated windows and return AggregatedLog objects.

    Each line is one :class:`AggregatedLog`. The function reconstructs
    the nested object graph properly:

      1. For each log in ``logs``: convert ``enrichments`` from a
         dict-of-dicts to a dict-of-:class:`IPEnrichment`.
      2. Build each :class:`EnrichedLog` with its dedup metadata and
         reconstructed enrichments.
      3. Build the :class:`AggregatedLog` via
         :meth:`AggregatedLog.from_logs`, which recomputes the
         summary counts (``event_count``, ``unique_log_count``,
         ``malicious_ip_count``) automatically.

    Malformed lines are skipped silently with a warning count
    (aggregated windows that fail to parse are not actionable and
    would crash the analyzer; better to skip and report).

    Parameters
    ----------
    input_file : str
        Path to the aggregated JSONL file (typically the output of
        ``soc_ai.aggregation.pipeline``).

    Returns
    -------
    list[AggregatedLog]
        Parsed aggregated windows, in file order.
    """
    windows: List[AggregatedLog] = []

    with open(input_file, "r", encoding="utf-8") as fh:
        for line_number, line in enumerate(fh, start=1):
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
                window = _reconstruct_aggregated_log(data)
                windows.append(window)
            except (json.JSONDecodeError, TypeError, ValueError, KeyError) as exc:
                # Skip malformed windows — they would crash the analyzer.
                # Print to stderr so the user sees the skip.
                print(
                    f"[!] Skipping malformed aggregated line {line_number}: {exc}"
                )

    return windows


def _reconstruct_aggregated_log(data: Dict[str, Any]) -> AggregatedLog:
    """
    Reconstruct an :class:`AggregatedLog` from a plain dict.

    Performs the reverse of :meth:`AggregatedLog.to_dict`:

      1. Extract window metadata (``window_start``, ``window_end``,
         ``log_source``).
      2. For each log in ``logs``: reconstruct nested
         :class:`IPEnrichment` objects, then build an
         :class:`EnrichedLog`.
      3. Call :meth:`AggregatedLog.from_logs` to rebuild summary
         counts from the reconstructed logs (rather than trusting
         the stored counts — this guarantees consistency).
    """
    window_start = data["window_start"]
    window_end = data["window_end"]
    raw_logs = data.get("logs", [])

    logs: List[EnrichedLog] = []
    for raw_log in raw_logs:
        # Reconstruct enrichments dict-of-IPEnrichment
        raw_enrichments = raw_log.get("enrichments") or {}
        raw_log["enrichments"] = {
            ip: IPEnrichment(**ip_data)
            for ip, ip_data in raw_enrichments.items()
        }
        logs.append(EnrichedLog(**raw_log))

    if not logs:
        raise ValueError("Aggregated window has no logs")

    return AggregatedLog.from_logs(
        window_start=window_start,
        window_end=window_end,
        logs=logs,
    )


def write_analyzed_jsonl(
    output_file: str,
    analyzed_logs: List[AnalyzedLog],
) -> None:
    """
    Write a list of :class:`AnalyzedLog` objects to a JSONL file.

    Each line is the JSON serialisation of :meth:`AnalyzedLog.to_dict`,
    which preserves the original aggregated window under the
    ``"aggregated"`` key and the AI verdict under the ``"verdict"``
    key.

    Parameters
    ----------
    output_file : str
        Path for the output JSONL file. Parent directories are
        created automatically.
    analyzed_logs : list[AnalyzedLog]
        Analyzed log entries to write.
    """
    output_path = Path(output_file)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w", encoding="utf-8") as fh:
        for log in analyzed_logs:
            fh.write(json.dumps(log.to_dict(), ensure_ascii=False) + "\n")


# ── Pipeline entry point ────────────────────────────────────────────────

def analyze_pipeline(
    input_file: str,
    output_file: str,
    analyzer: LLMAnalyzer = None,
) -> List[AnalyzedLog]:
    """
    Full AI analysis pipeline: read aggregated JSONL -> analyze each
    window with the LLM -> write JSONL.

    Parameters
    ----------
    input_file : str
        Path to the aggregated JSONL file (output of the aggregation
        pipeline).
    output_file : str
        Path for the analyzed JSONL output.
    analyzer : LLMAnalyzer, optional
        Pre-built analyzer instance. When ``None``, a new one is
        constructed using the ``LLM_PROVIDER`` environment variable
        (and the corresponding ``<PROVIDER>_API_KEY`` /
        ``<PROVIDER>_BASE_URL`` / ``<PROVIDER>_MODEL`` vars).
        Pass a pre-built instance when you want to share an analyzer
        across multiple pipeline runs (saves context-loading time).

    Returns
    -------
    list[AnalyzedLog]
        One analyzed entry per input window, in file order.
    """
    aggregated_windows = read_aggregated_jsonl(input_file)
    print(f"[+] Read {len(aggregated_windows)} aggregated windows from: {input_file}")

    if analyzer is None:
        analyzer = LLMAnalyzer()
        config = analyzer.describe()
        print(
            f"[+] Initialized LLMAnalyzer "
            f"(provider={config['provider']}, "
            f"model={config['model']}, "
            f"base_url={config['base_url']})"
        )
    else:
        print(f"[+] Using provided analyzer (model={analyzer.model})")

    # Analyze each window sequentially.
    # A failure on one window produces a fallback verdict — the loop
    # never aborts.
    analyzed_logs: List[AnalyzedLog] = []
    alert_count = 0
    fallback_count = 0
    total_tokens = 0

    for i, window in enumerate(aggregated_windows, start=1):
        print(
            f"[~] Analyzing window {i}/{len(aggregated_windows)}: "
            f"{window.window_start} -> {window.window_end} "
            f"({window.unique_log_count} logs, {window.event_count} events)"
        )

        verdict = analyzer.analyze(window)
        analyzed_logs.append(AnalyzedLog(aggregated=window, verdict=verdict))

        # Track stats
        if verdict.should_alert:
            alert_count += 1
        if verdict.category == "analysis_failed":
            fallback_count += 1
        if verdict.tokens_used is not None:
            total_tokens += verdict.tokens_used

        # Print per-window verdict summary
        verdict_marker = "ALERT" if verdict.should_alert else "ok   "
        fallback_marker = " [FALLBACK]" if verdict.category == "analysis_failed" else ""
        print(
            f"    [{verdict_marker}] severity={verdict.severity:8s} "
            f"confidence={verdict.confidence:3d}  "
            f"category={verdict.category}{fallback_marker}"
        )
        if verdict.tokens_used is not None:
            print(f"    tokens={verdict.tokens_used}")

    # Summary
    print()
    print(
        f"[+] Analysis summary: "
        f"windows={len(analyzed_logs)}, "
        f"alerts={alert_count}, "
        f"fallbacks={fallback_count}, "
        f"total_tokens={total_tokens}"
    )

    write_analyzed_jsonl(output_file, analyzed_logs)
    print(f"[+] Output saved to: {output_file}")

    return analyzed_logs


# ── CLI ─────────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="Analyze aggregated log windows with an LLM",
    )
    parser.add_argument(
        "input_file",
        help="Path to the aggregated JSONL file",
    )
    parser.add_argument(
        "output_file",
        help="Path for the analyzed JSONL output",
    )

    args = parser.parse_args()

    analyze_pipeline(
        input_file=args.input_file,
        output_file=args.output_file,
    )


if __name__ == "__main__":
    main()