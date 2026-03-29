"""
Worker entry point.
Runs the connector scheduler as a separate process.
"""
import asyncio
import logging
import signal

from app.workers.scheduler import setup_scheduler, scheduler

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)

logger = logging.getLogger(__name__)


async def main():
    logger.info("SOCINT Worker starting...")
    setup_scheduler()

    stop_event = asyncio.Event()

    def _shutdown(signum, frame):
        logger.info("Shutdown signal received")
        stop_event.set()

    signal.signal(signal.SIGTERM, _shutdown)
    signal.signal(signal.SIGINT, _shutdown)

    await stop_event.wait()

    scheduler.shutdown()
    logger.info("Worker stopped")


if __name__ == "__main__":
    asyncio.run(main())
