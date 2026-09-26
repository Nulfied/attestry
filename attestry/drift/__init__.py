"""Pillar one: notice when a model stops behaving the way it used to.

Providers update models behind stable names. Nothing in your code changes,
nothing errors, and the pipeline quietly starts doing something slightly
different. The only defence is to have written down what the old behaviour was,
in a form a machine can re-check tonight.

::

    from attestry.drift import Suite, run_suite, get_provider

    suite = Suite.load(".attestry/drift/suites/support.suite.json")
    run = run_suite(suite, get_provider("ollama", "llama3"))
    print(run.format())
    raise SystemExit(run.exit_code)

Exit codes are the interface for CI: 0 stable, 1 drifted, 2 an expectation
broke, 3 the provider could not be reached.
"""

from .compare import (
    MODES,
    Verdict,
    check,
    drift_between,
    normalize,
    output_digest,
    similarity,
    unified_diff,
)
from .providers import PROVIDERS, Provider, ProviderError, Response, get_provider
from .runner import (
    EXIT_CODES,
    STATUSES,
    Outcome,
    Run,
    case_timeline,
    history,
    load_baseline,
    record_baseline,
    record_run,
    run_suite,
    save_baseline,
    save_run,
)
from .suite import SUITE_SUFFIX, Case, Suite, example_suite

__all__ = [
    "Suite",
    "Case",
    "SUITE_SUFFIX",
    "example_suite",
    "run_suite",
    "Run",
    "Outcome",
    "STATUSES",
    "EXIT_CODES",
    "load_baseline",
    "save_baseline",
    "save_run",
    "record_run",
    "record_baseline",
    "history",
    "case_timeline",
    "Provider",
    "Response",
    "PROVIDERS",
    "ProviderError",
    "get_provider",
    "check",
    "drift_between",
    "similarity",
    "normalize",
    "unified_diff",
    "output_digest",
    "Verdict",
    "MODES",
]
