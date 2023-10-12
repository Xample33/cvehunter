import httpx
from httpx._exceptions import ConnectError, ConnectTimeout, ProxyError


class Connect:
    def __init__(self, proxy: dict = None) -> None:
        self.proxy = proxy
        self.timeout = 10
        self.client = None  # Initialize the client as None

    async def get_client(self) -> httpx.AsyncClient:
        if self.client is None or self.client.is_closed:
            # Create a new client or recreate it if it's closed
            self.client = httpx.AsyncClient(
                timeout=self.timeout,
                proxies=self.proxy,
            )
        return self.client

    async def make_request(self, api_url: str) -> str:
        status_unauthorized = 401
        stuatus_notfound = 404

        client = await self.get_client()
        try:
            response = await client.get(api_url)
        except ConnectTimeout:
            raise ConnectTimeout("Connection timed out")
        except ProxyError as proxy_err:
            raise ProxyError(proxy_err)
        except ConnectError as conn_err:
            raise ConnectError(conn_err)

        if response.status_code == status_unauthorized:
            raise ValueError("Invalid credentials")

        if response.status_code == stuatus_notfound and 'NVD Web Services Endpoint' not in response.text:
            raise ValueError("Invalid data provided")

        if '"totalResults": 0' in response.text:
            return None

        await self.close_connection()
        return response.text

    async def close_connection(self) -> None:
        if self.client and not self.client.is_closed:
            await self.client.aclose()
