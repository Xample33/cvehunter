from .Cve import Cve
from .Cvss import Cvss
from .Cwe import Cwe

from urllib3.exceptions import InsecureRequestWarning
from urllib3 import disable_warnings
import json
from cvehunter import utils as u
import httpx
from httpx import HTTPStatusError, ConnectTimeout
from datetime import datetime, timezone
#disable warnings
disable_warnings(InsecureRequestWarning)

class Auth:
    def __init__(self, username: str, password: str, proxy: dict = None):
        
        self.username = username
        self.password = password
        self.proxy = proxy
        
        self.timeout = 10
        self.client = httpx.AsyncClient(auth=(self.username, self.password), verify=False, timeout=self.timeout, proxies=self.proxy)

    async def check_connection(self):
        api_url = "https://www.opencve.io/api/account/subscriptions/vendors"
        response = await self.client.get(api_url)

        if response.status_code == 200:
            return
        elif response.status_code == 401:
            raise ValueError("Invalid credentials")
        else:
            raise HTTPStatusError(f"Error {response.status_code} while retrieving data from {api_url}")

    async def make_request(self, api_url: str):
        try:
            response = await self.client.get(api_url)
        except ConnectTimeout:
            raise ConnectTimeout(f"Connection timed out")	
        
        if response.status_code == 401:
            raise ValueError("Invalid credentials")
        
        if '{"message": "Not found."}' in response.text:
            return None
        
        return response.text
    
    async def close_connection(self):
        await self.client.aclose()
