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


class AsyncHTTPClient:
    """Asynchronous HTTP client with error handling and retries."""

    def __init__(
        self,
        timeout: float = 10,
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
            for retry in range(self.max_retries + 1):
                try:
                    if retry > 0:
                        # Calculate delay with exponential backoff
                        delay = self.backoff_factor * (2 ** (retry - 1))
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
            for retry in range(self.max_retries + 1):
                try:
                    if retry > 0:
                        # Calculate delay with exponential backoff
                        delay = self.backoff_factor * (2 ** (retry - 1))
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


class AsyncHTTPBatchClient:
    """Client for making batched asynchronous HTTP requests."""

    def __init__(
        self,
        timeout: float = 10,
        max_retries: int = 3,
        backoff_factor: float = 0.5,
        concurrent_requests: int = 10,
    ):
        """Initialize the batch HTTP client.

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
        self.client = AsyncHTTPClient(
            timeout=timeout,
            max_retries=max_retries,
            backoff_factor=backoff_factor,
            concurrent_requests=concurrent_requests,
        )

    async def close(self) -> None:
        """Close the underlying HTTP client."""
        await self.client.close()

    async def batch_get(
        self,
        urls: List[str],
        params: Optional[List[Dict[str, Any]]] = None,
        headers: Optional[Dict[str, str]] = None,
    ) -> List[Optional[Dict[str, Any]]]:
        """Make multiple GET requests in parallel.

        Args:
            urls: List of URLs to request
            params: List of query parameters for each URL (or None for all)
            headers: HTTP headers to use for all requests

        Returns:
            List of JSON responses in the same order as the URLs.
            Each element can be None if the corresponding request failed.
        """
        if params is None:
            # params will contain None values which is expected
            params = [None] * len(urls)  # type: ignore
        elif len(params) != len(urls):
            raise ValueError("params must be the same length as urls")

        # Create a list of tasks
        # Any result could be an Optional[Dict[str, Any]]
        tasks: List[Coroutine[Any, Any, Any]] = [
            self.client.get(url, param, headers) for url, param in zip(urls, params)
        ]

        # Execute all tasks in parallel
        results_raw = await asyncio.gather(*tasks, return_exceptions=True)
        # Type check for mypy - ensure we handle all possible result types
        results: List[Union[Optional[Dict[str, Any]], BaseException]] = results_raw

        # Process results, converting exceptions to None
        processed_results: List[Optional[Dict[str, Any]]] = []
        for result in results:
            if isinstance(result, BaseException):
                logger.debug(f"Request failed with error: {result}")
                processed_results.append(None)
            elif result is None:
                # Already None, just append
                processed_results.append(None)
            else:
                # Cast to appropriate type for mypy
                typed_result: Optional[Dict[str, Any]] = result
                processed_results.append(typed_result)

        return processed_results

    async def batch_post(
        self,
        urls: List[str],
        json_data_list: List[Dict[str, Any]],
        headers: Optional[Dict[str, str]] = None,
    ) -> List[Optional[Dict[str, Any]]]:
        """Make multiple POST requests in parallel.

        Args:
            urls: List of URLs to request
            json_data_list: List of JSON data to send for each URL
            headers: HTTP headers to use for all requests

        Returns:
            List of JSON responses in the same order as the URLs
        """
        if len(json_data_list) != len(urls):
            raise ValueError("json_data_list must be the same length as urls")

        # Create a list of tasks
        tasks = [
            self.client.post(url, json_data, headers)
            for url, json_data in zip(urls, json_data_list)
        ]

        # Execute all tasks in parallel
        results_raw = await asyncio.gather(*tasks, return_exceptions=True)
        # Type check for mypy - ensure we handle all possible result types
        results: List[Union[Optional[Dict[str, Any]], BaseException]] = results_raw

        # Process results, converting exceptions to None
        processed_results: List[Optional[Dict[str, Any]]] = []
        for result in results:
            if isinstance(result, BaseException):
                logger.debug(f"Request failed with error: {result}")
                processed_results.append(None)
            elif result is None:
                # Already None, just append
                processed_results.append(None)
            else:
                # Cast to appropriate type for mypy
                typed_result: Optional[Dict[str, Any]] = result
                processed_results.append(typed_result)

        return processed_results


# Create a global client instance for convenience
http_client = AsyncHTTPClient()
batch_client = AsyncHTTPBatchClient()


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
            text = response.text
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
