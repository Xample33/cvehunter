import httpx
from httpx import ConnectTimeout, HTTPStatusError

class Auth:
    def __init__(self, username: str, password: str, proxy: dict = None):
        self.username = username
        self.password = password
        self.proxy = proxy
        self.timeout = 10
        self.client = None  # Initialize the client as None

    async def get_client(self):
        if self.client is None or self.client.is_closed:
            # Create a new client or recreate it if it's closed
            self.client = httpx.AsyncClient(
                auth=(self.username, self.password),
                verify=False,
                timeout=self.timeout,
                proxies=self.proxy
            )
        return self.client

    async def check_connection(self):
        api_url = "https://www.opencve.io/api/account/subscriptions/vendors"
        client = await self.get_client()
        try:
            response = await client.get(api_url)
        except ConnectTimeout:
            raise ConnectTimeout("Connection timed out")

        if response.status_code == 200:
            return
        elif response.status_code == 401:
            raise ValueError("Invalid credentials")
        else:
            raise HTTPStatusError(f"Error {response.status_code} while retrieving data from {api_url}")

    async def make_request(self, api_url: str) -> str:
        client = await self.get_client()
        try:
            response = await client.get(api_url)
        except ConnectTimeout:
            raise ConnectTimeout("Connection timed out")

        if response.status_code == 401:
            raise ValueError("Invalid credentials")

        if '{"message": "Not found."}' in response.text:
            return None
        
        await self.close_connection()
        return response.text

    async def close_connection(self):
        if self.client and not self.client.is_closed:
            await self.client.aclose()