"""Background job process: `python -m app.worker`.

Runs Dependency-Track pull-sync, the stale-SBOM check and the exception sweep in one
process, separate from the multi-worker API, so each job runs exactly once per interval.
The sweep also runs once at start-up, so exceptions that expired while the worker was
down are handled without waiting a full interval.
"""

import logging

from app.core.scheduler import run_blocking, run_exception_sweep


def main() -> None:
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    run_exception_sweep()
    run_blocking()


if __name__ == "__main__":
    main()
