"""
Generic HTTP Client for External API Integrations

Reusable HTTP client with:
- Automatic retries with exponential backoff
- Rate limiting
- Caching
- Timeout handling
- Error handling
- Request/response logging
"""

import requests
import time
from typing import Dict, Optional, Any, Callable
from functools import wraps, lru_cache
from datetime import datetime, timedelta
import json


class RateLimiter:
    """Simple rate limiter for API calls"""

    def __init__(self, calls_per_minute: int = 60):
        self.calls_per_minute = calls_per_minute
        self.calls = []

    def wait_if_needed(self):
        """Wait if rate limit would be exceeded"""
        now = datetime.now()

        # Remove calls older than 1 minute
        self.calls = [call_time for call_time in self.calls
                     if now - call_time < timedelta(minutes=1)]

        # If we've hit the limit, wait
        if len(self.calls) >= self.calls_per_minute:
            oldest_call = min(self.calls)
            wait_time = 60 - (now - oldest_call).total_seconds()
            if wait_time > 0:
                print(f"  [RateLimiter] Waiting {wait_time:.1f}s to avoid rate limit...")
                time.sleep(wait_time)
                self.calls = []

        self.calls.append(now)


class HTTPClient:
    """
    Generic HTTP client for external API integrations

    Features:
    - Automatic retries with exponential backoff
    - Rate limiting
    - Timeout handling
    - Error handling
    - Request/response logging
    """

    def __init__(
        self,
        base_url: str,
        default_headers: Optional[Dict[str, str]] = None,
        timeout: int = 10,
        max_retries: int = 3,
        retry_delay: float = 1.0,
        rate_limit: Optional[int] = None,
        verbose: bool = False
    ):
        """
        Initialize HTTP client

        Args:
            base_url: Base URL for API (e.g., "https://www.virustotal.com/api/v3")
            default_headers: Default headers for all requests
            timeout: Request timeout in seconds
            max_retries: Maximum number of retries on failure
            retry_delay: Initial delay between retries (exponential backoff)
            rate_limit: Max requests per minute (None = no limit)
            verbose: Enable verbose logging
        """
        self.base_url = base_url.rstrip('/')
        self.default_headers = default_headers or {}
        self.timeout = timeout
        self.max_retries = max_retries
        self.retry_delay = retry_delay
        self.verbose = verbose

        # Rate limiter
        self.rate_limiter = RateLimiter(rate_limit) if rate_limit else None

        # Session for connection pooling
        self.session = requests.Session()
        self.session.headers.update(self.default_headers)

    def _log(self, message: str):
        """Log message if verbose mode is enabled"""
        if self.verbose:
            print(f"  [HTTPClient] {message}")

    def _build_url(self, endpoint: str) -> str:
        """Build full URL from endpoint"""
        endpoint = endpoint.lstrip('/')
        return f"{self.base_url}/{endpoint}"

    def _handle_response(self, response: requests.Response, endpoint: str) -> Dict[str, Any]:
        """
        Handle API response and errors

        Args:
            response: Response object
            endpoint: API endpoint (for logging)

        Returns:
            Parsed JSON response or error dict
        """
        # Log response
        self._log(f"{response.request.method} {endpoint} -> {response.status_code}")

        # Success (2xx)
        if 200 <= response.status_code < 300:
            try:
                return response.json()
            except json.JSONDecodeError:
                return {
                    "success": True,
                    "status_code": response.status_code,
                    "text": response.text
                }

        # Client errors (4xx)
        elif 400 <= response.status_code < 500:
            error_data = {
                "error": True,
                "status_code": response.status_code,
                "endpoint": endpoint
            }

            if response.status_code == 400:
                error_data["message"] = "Bad request - check parameters"
            elif response.status_code == 401:
                error_data["message"] = "Unauthorized - check API key"
            elif response.status_code == 403:
                error_data["message"] = "Forbidden - invalid API key or permissions"
            elif response.status_code == 404:
                error_data["message"] = "Not found - resource doesn't exist"
            elif response.status_code == 429:
                error_data["message"] = "Rate limit exceeded"
                error_data["rate_limit_exceeded"] = True
            else:
                error_data["message"] = f"Client error {response.status_code}"

            try:
                error_data["details"] = response.json()
            except:
                error_data["details"] = response.text

            return error_data

        # Server errors (5xx)
        elif 500 <= response.status_code < 600:
            return {
                "error": True,
                "status_code": response.status_code,
                "message": f"Server error {response.status_code} - API may be down",
                "endpoint": endpoint,
                "retryable": True
            }

        # Unknown
        else:
            return {
                "error": True,
                "status_code": response.status_code,
                "message": f"Unexpected status code {response.status_code}",
                "endpoint": endpoint
            }

    def request(
        self,
        method: str,
        endpoint: str,
        params: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        json_data: Optional[Dict[str, Any]] = None,
        data: Optional[Any] = None,
        retry_on_rate_limit: bool = True
    ) -> Dict[str, Any]:
        """
        Make HTTP request with retries and error handling

        Args:
            method: HTTP method (GET, POST, PUT, DELETE, etc.)
            endpoint: API endpoint (e.g., "/ip_addresses/1.2.3.4")
            params: URL query parameters
            headers: Additional headers (merged with defaults)
            json_data: JSON body data
            data: Raw body data
            retry_on_rate_limit: Retry if rate limit is hit

        Returns:
            API response as dict
        """
        url = self._build_url(endpoint)

        # Merge headers
        request_headers = {**self.default_headers, **(headers or {})}

        # Rate limiting
        if self.rate_limiter:
            self.rate_limiter.wait_if_needed()

        # Retry loop
        last_error = None
        for attempt in range(self.max_retries):
            try:
                self._log(f"{method} {endpoint} (attempt {attempt + 1}/{self.max_retries})")

                response = self.session.request(
                    method=method,
                    url=url,
                    params=params,
                    headers=request_headers,
                    json=json_data,
                    data=data,
                    timeout=self.timeout
                )

                result = self._handle_response(response, endpoint)

                # Success
                if not result.get("error"):
                    return result

                # Rate limit - retry if enabled
                if result.get("rate_limit_exceeded") and retry_on_rate_limit:
                    wait_time = self.retry_delay * (2 ** attempt)
                    self._log(f"Rate limit hit, waiting {wait_time}s before retry...")
                    time.sleep(wait_time)
                    continue

                # Retryable server error
                if result.get("retryable"):
                    wait_time = self.retry_delay * (2 ** attempt)
                    self._log(f"Server error, waiting {wait_time}s before retry...")
                    time.sleep(wait_time)
                    continue

                # Non-retryable error
                return result

            except requests.exceptions.Timeout:
                last_error = {
                    "error": True,
                    "message": f"Request timeout after {self.timeout}s",
                    "endpoint": endpoint,
                    "exception": "Timeout"
                }
                self._log(f"Timeout on attempt {attempt + 1}")

            except requests.exceptions.ConnectionError as e:
                last_error = {
                    "error": True,
                    "message": "Connection error - check network/API availability",
                    "endpoint": endpoint,
                    "exception": str(e)
                }
                self._log(f"Connection error on attempt {attempt + 1}: {e}")

            except requests.exceptions.RequestException as e:
                last_error = {
                    "error": True,
                    "message": f"Request failed: {str(e)}",
                    "endpoint": endpoint,
                    "exception": str(e)
                }
                self._log(f"Request exception on attempt {attempt + 1}: {e}")

            # Exponential backoff before retry
            if attempt < self.max_retries - 1:
                wait_time = self.retry_delay * (2 ** attempt)
                time.sleep(wait_time)

        # All retries failed
        return last_error or {
            "error": True,
            "message": "All retry attempts failed",
            "endpoint": endpoint
        }

    def get(self, endpoint: str, params: Optional[Dict[str, Any]] = None, **kwargs) -> Dict[str, Any]:
        """GET request"""
        return self.request("GET", endpoint, params=params, **kwargs)

    def post(self, endpoint: str, json_data: Optional[Dict[str, Any]] = None, **kwargs) -> Dict[str, Any]:
        """POST request"""
        return self.request("POST", endpoint, json_data=json_data, **kwargs)

    def put(self, endpoint: str, json_data: Optional[Dict[str, Any]] = None, **kwargs) -> Dict[str, Any]:
        """PUT request"""
        return self.request("PUT", endpoint, json_data=json_data, **kwargs)

    def delete(self, endpoint: str, **kwargs) -> Dict[str, Any]:
        """DELETE request"""
        return self.request("DELETE", endpoint, **kwargs)

    def close(self):
        """Close session"""
        self.session.close()


# ===== Caching Decorator =====

def cache_response(ttl_seconds: int = 3600):
    """
    Cache decorator for API responses

    Args:
        ttl_seconds: Time to live in seconds (default: 1 hour)

    Usage:
        @cache_response(ttl_seconds=300)
        def get_ip_reputation(ip: str):
            return client.get(f"/ip/{ip}")
    """
    cache = {}

    def decorator(func: Callable) -> Callable:
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Create cache key from function name and arguments
            cache_key = f"{func.__name__}:{args}:{sorted(kwargs.items())}"

            # Check cache
            if cache_key in cache:
                result, timestamp = cache[cache_key]
                age = time.time() - timestamp

                if age < ttl_seconds:
                    print(f"  [Cache] Hit for {func.__name__} (age: {age:.1f}s)")
                    return result
                else:
                    print(f"  [Cache] Expired for {func.__name__} (age: {age:.1f}s)")
                    del cache[cache_key]

            # Call function and cache result
            result = func(*args, **kwargs)
            cache[cache_key] = (result, time.time())
            print(f"  [Cache] Stored for {func.__name__}")

            return result

        return wrapper
    return decorator


# ===== Testing =====

if __name__ == "__main__":
    print("=" * 60)
    print("HTTP CLIENT TEST")
    print("=" * 60)

    # Test with JSONPlaceholder (public test API)
    client = HTTPClient(
        base_url="https://jsonplaceholder.typicode.com",
        timeout=5,
        verbose=True
    )

    # Test GET
    print("\n1. Test GET request:")
    result = client.get("/posts/1")
    print(f"   Result: {result.get('title', 'ERROR')}")

    # Test GET with params
    print("\n2. Test GET with params:")
    result = client.get("/posts", params={"userId": 1})
    print(f"   Found {len(result)} posts" if isinstance(result, list) else "ERROR")

    # Test 404
    print("\n3. Test 404 error:")
    result = client.get("/posts/9999999")
    print(f"   Error: {result.get('message', 'NO ERROR')}")

    # Test timeout
    print("\n4. Test timeout:")
    slow_client = HTTPClient(
        base_url="https://httpbin.org",
        timeout=1,
        verbose=True
    )
    result = slow_client.get("/delay/5")
    print(f"   Error: {result.get('message', 'NO ERROR')}")

    client.close()
    slow_client.close()

    print("\n" + "=" * 60)
    print("✅ HTTP Client tests completed")
    print("=" * 60)
