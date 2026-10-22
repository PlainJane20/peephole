"""LIVE evaluation of Peephole's backends. NEEDS KEYS IN THE ENVIRONMENT AND MAKES REAL, PAID CALLS. NOT RUN YET.

STATUS: built and offline-tested with stub backends only. Nothing here has been run against Jev or Claude Haiku.

    python scripts/run_live_eval.py --dry-run                        # exact call counts per backend; calls nothing
    export TYPESAFE_API_KEY=...                                      # Jev; environment only (no key flag exists)
    export ANTHROPIC_API_KEY=...                                     # Haiku, optional
    python scripts/run_live_eval.py --live --limit 10 --repeats 1    # a cheap first run, prints the plan, needs --yes
    python scripts/run_live_eval.py --live --yes                     # everything: all datasets, 3 repeats
    python scripts/run_live_eval.py --live --yes --resume <run_id>   # continue a stopped run

Stop early: `touch PEEPHOLE_KILL` or set PEEPHOLE_KILL_SWITCH=1. Exit codes: 0 done, 2 refused or bad usage,
3 --max-calls reached, 4 kill switch, 5 model/API error or retry cap (state is saved in every case).
Set a provider spend limit first: the caps count calls, not money. Results go to evals/results/live/<run_id>/.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from peephole.live import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
