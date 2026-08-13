"""Asynchronous HTTP client for network operations.

This module provides an asynchronous HTTP client for making network requests
with robust error handling, retries, and caching.
"""

import asyncio
import logging
from typing import Any, Coroutine, Dict, List, Optional, Union

import aiohttp
import httpx
from aiohttp import ClientError, ClientResponseError, ClientTimeout
from httpx import HTTPError, RequestError

logger = logging.getLogger(__name__)

# Cap how long a server-supplied Retry-After can stall one request.
MAX_RETRY_AFTER_SECONDS = 60.0


def _parse_retry_after(headers: Any) -> Optional[float]:
    """Return the Retry-After delay in seconds, if the server sent a numeric one.

    OSV/NVD/GitHub send Retry-After on 429; honoring it avoids retrying too soon
    and exhausting attempts. The HTTP-date form falls back to exponential backoff.
    """
    if not headers:
        return None
    value = headers.get("Retry-After")
    if not value:
        return None
    try:
        return min(float(value), MAX_RETRY_AFTER_SECONDS)
    except (TypeError, ValueError):
        return None


class AsyncHTTPClient:
    """Asynchronous HTTP client with error handling and retries."""

    def __init__(
        self,
        timeout: float = 30,
        max_retries: int = 3,
        backoff_factor: float = 0.5,
        concurrent_requests: int = 10,
    ):
        """Initialize the async HTTP client.

        Args:
            timeout: Request timeout in seconds
            max_retries: Maximum number of retry attempts
            backoff_factor: Backoff factor for retries
            concurrent_requests: Maximum number of concurrent requests
        """
        self.timeout = timeout
        self.max_retries = max_retries
        self.backoff_factor = backoff_factor
        self.concurrent_requests = concurrent_requests
        self._session: Optional[aiohttp.ClientSession] = None
        self._semaphore: Optional[asyncio.Semaphore] = None

    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create an aiohttp session.

        Returns:
            aiohttp ClientSession
        """
        if self._session is None or self._session.closed:
            timeout = ClientTimeout(total=self.timeout)
            session = aiohttp.ClientSession(timeout=timeout)
            self._session = session
            self._semaphore = asyncio.Semaphore(self.concurrent_requests)
        if self._session is None:
            raise RuntimeError("HTTP session is not initialized")  # pragma: no cover
        return self._session

    async def close(self) -> None:
        """Close the aiohttp session."""
        if self._session is not None and not self._session.closed:
            await self._session.close()
            self._session = None

    def _retry_delay(self, retry: int, retry_after: Optional[float]) -> float:
        """Delay before a retry: honor Retry-After, else exponential backoff."""
        if retry_after is not None:
            return retry_after
        return float(self.backoff_factor * (2 ** (retry - 1)))

    async def get(
        self,
        url: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Make an asynchronous GET request with retries.

        Args:
            url: URL to request
            params: Query parameters
            headers: HTTP headers

        Returns:
            JSON response as a dictionary, or None if the request failed
        """
        session = await self._get_session()
        headers = headers or {
            "User-Agent": "dependency-risk-profiler/0.2.0",
            "Accept": "application/json",
        }

        semaphore = self._semaphore
        if semaphore is None:
            raise RuntimeError("Semaphore is not initialized")  # pragma: no cover
        async with semaphore:
            retry_after: Optional[float] = None
            for retry in range(self.max_retries + 1):
                try:
                    if retry > 0:
                        delay = self._retry_delay(retry, retry_after)
                        retry_after = None
                        logger.debug(
                            (
                                f"Retry {retry}/{self.max_retries} for {url} "
                                f"after {delay:.2f}s delay"
                            )
                        )
                        await asyncio.sleep(delay)

                    # Ensure we have a valid session
                    if session is None:
                        raise RuntimeError(
                            "HTTP session is not initialized"
                        )  # pragma: no cover
                    async with session.get(
                        url, params=params, headers=headers
                    ) as response:
                        response.raise_for_status()
                        response_json = await response.json()
                        result: Dict[str, Any] = response_json
                        return result

                except ClientResponseError as e:
                    # Don't retry on 4xx client errors (except 429 Too Many Requests)
                    if e.status >= 400 and e.status < 500 and e.status != 429:
                        logger.debug(
                            f"Client error ({e.status}) fetching data from {url}: {e}"
                        )
                        return None

                    if e.status == 429:
                        retry_after = _parse_retry_after(e.headers)

                    if retry == self.max_retries:
                        logger.debug(f"Max retries reached for {url}: {e}")
                        return None

                    logger.debug(
                        (
                            f"HTTP error fetching data from {url} "
                            f"(attempt {retry+1}/{self.max_retries+1}): {e}"
                        )
                    )

                except (ClientError, asyncio.TimeoutError) as e:
                    if retry == self.max_retries:
                        logger.debug(f"Max retries reached for {url}: {e}")
                        return None

                    logger.debug(
                        (
                            f"Connection error fetching data from {url} "
                            f"(attempt {retry+1}/{self.max_retries+1}): {e}"
                        )
                    )

                except Exception as e:
                    logger.debug(f"Unexpected error fetching data from {url}: {e}")
                    return None

        return None

    async def post(
        self,
        url: str,
        json_data: Dict[str, Any],
        headers: Optional[Dict[str, str]] = None,
    ) -> Optional[Dict[str, Any]]:
        """Make an asynchronous POST request with retries.

        Args:
            url: URL to request
            json_data: JSON data to send
            headers: HTTP headers

        Returns:
            JSON response as a dictionary, or None if the request failed
        """
        session = await self._get_session()
        headers = headers or {
            "User-Agent": "dependency-risk-profiler/0.2.0",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        semaphore = self._semaphore
        if semaphore is None:
            raise RuntimeError("Semaphore is not initialized")  # pragma: no cover
        async with semaphore:
            retry_after: Optional[float] = None
            for retry in range(self.max_retries + 1):
                try:
                    if retry > 0:
                        delay = self._retry_delay(retry, retry_after)
                        retry_after = None
                        logger.debug(
                            (
                                f"Retry {retry}/{self.max_retries} for {url} "
                                f"after {delay:.2f}s delay"
                            )
                        )
                        await asyncio.sleep(delay)

                    # Ensure we have a valid session
                    if session is None:
                        raise RuntimeError(
                            "HTTP session is not initialized"
                        )  # pragma: no cover
                    async with session.post(
                        url, json=json_data, headers=headers
                    ) as response:
                        response.raise_for_status()
                        response_json = await response.json()
                        result: Dict[str, Any] = response_json
                        return result

                except ClientResponseError as e:
                    # Don't retry on 4xx client errors (except 429 Too Many Requests)
                    if e.status >= 400 and e.status < 500 and e.status != 429:
                        logger.debug(
                            f"Client error ({e.status}) fetching data from {url}: {e}"
                        )
                        return None

                    if e.status == 429:
                        retry_after = _parse_retry_after(e.headers)

                    if retry == self.max_retries:
                        logger.debug(f"Max retries reached for {url}: {e}")
                        return None

                    logger.debug(
                        (
                            f"HTTP error fetching data from {url} "
                            f"(attempt {retry+1}/{self.max_retries+1}): {e}"
                        )
                    )

                except (ClientError, asyncio.TimeoutError) as e:
                    if retry == self.max_retries:
                        logger.debug(f"Max retries reached for {url}: {e}")
                        return None

                    logger.debug(
                        (
                            f"Connection error fetching data from {url} "
                            f"(attempt {retry+1}/{self.max_retries+1}): {e}"
                        )
                    )

                except Exception as e:
                    logger.debug(f"Unexpected error fetching data from {url}: {e}")
                    return None

        return None


async def fetch_url_async(url: str, timeout: int = 10) -> Optional[str]:
    """Fetch content from a URL asynchronously.

    Args:
        url: URL to fetch
        timeout: Request timeout in seconds

    Returns:
        The content as a string, or None if the request failed
    """
    try:
        headers = {
            "User-Agent": "dependency-risk-profiler/0.2.0",
        }

        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(url, headers=headers, follow_redirects=True)
            response.raise_for_status()
            text = str(response.text)
            return text
    except (HTTPError, RequestError) as e:
        logger.debug(f"Error fetching {url}: {e}")
        return None
    except Exception as e:
        logger.debug(f"Unexpected error fetching {url}: {e}")
        return None


async def fetch_json_async(url: str, timeout: int = 10) -> Optional[Dict[str, Any]]:
    """Fetch JSON from a URL asynchronously.

    Args:
        url: URL to fetch
        timeout: Request timeout in seconds

    Returns:
        The parsed JSON as a dictionary, or None if the request failed
    """
    try:
        headers = {
            "User-Agent": "dependency-risk-profiler/0.2.0",
            "Accept": "application/json",
        }

        async with httpx.AsyncClient(timeout=timeout) as client:
            response = await client.get(url, headers=headers, follow_redirects=True)
            response.raise_for_status()
            json_data: Dict[str, Any] = response.json()
            return json_data
    except (HTTPError, RequestError) as e:
        logger.debug(f"Error fetching JSON from {url}: {e}")
        return None
    except ValueError as e:
        logger.debug(f"Error parsing JSON from {url}: {e}")
        return None
    except Exception as e:
        logger.debug(f"Unexpected error fetching JSON from {url}: {e}")
        return None
