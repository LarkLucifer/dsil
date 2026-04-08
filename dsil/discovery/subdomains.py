import asyncio
import logging
from pathlib import Path

logger = logging.getLogger("dsil.discovery.subdomains")

class SubfinderSource:
    """
    Integrasi Subfinder untuk penemuan subdomain secara pasif.
    """

    def __init__(self, target: str):
        self.target = target

    async def fetch_subdomains(self) -> list[str]:
        """
        Fetch subdomains using subfinder.
        """
        # subfinder -d {target} -silent
        cmd = ["subfinder", "-d", self.target, "-silent"]

        logger.info("SubfinderSource: starting subdomain discovery for %s", self.target)
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()

            if process.returncode != 0:
                err_msg = stderr.decode().strip()
                logger.warning("Subfinder failed (code %d): %s", process.returncode, err_msg)
                return []

            subdomains = []
            for line in stdout.decode().splitlines():
                sub = line.strip()
                if sub:
                    subdomains.append(sub)

            logger.info("SubfinderSource: discovered %d subdomains", len(subdomains))
            return list(set(subdomains))
        except FileNotFoundError:
            logger.error("Subfinder binary not found in PATH.")
            return []
        except Exception as e:
            logger.exception("SubfinderSource unexpected error: %s", e)
            return []
