from .Cve import Cve
from .Cvss import Cvss
from .Cwe import Cwe

from urllib3.exceptions import InsecureRequestWarning
from urllib3 import disable_warnings
import json
from cvehunter import utils as u
import httpx
from httpx import HTTPStatusError
from datetime import datetime, timezone
#disable warnings
disable_warnings(InsecureRequestWarning)

class Auth:
    def __init__(self, username: str, password: str, proxy: dict = None):
        
        self.username = username
        self.password = password
        
        self.timeout = 10
        self.client = httpx.AsyncClient(auth=(self.username, self.password), verify=False, timeout=self.timeout)

    async def check_connection(self):
        api_url = "https://www.opencve.io/api/account/subscriptions/vendors"
        response = await self.make_request(api_url)

        if response.status_code == 200:
            return
        elif response.status_code == 401:
            raise ValueError("Invalid credentials")
        else:
            raise httpx.HTTPStatusError(f"Error {response.status_code} while retrieving data from {api_url}")

    async def make_request(self, api_url: str):
        response = await self.client.get(api_url)
        print('\n', response.elapsed.total_seconds())
        
        if response.status_code == 401:
            raise ValueError("Invalid credentials")
        
        if '{"message": "Not found."}' in response.text:
            return None
        
        return response.text

    async def search_cve(self, cve_id: str):
        u.check_cve_integrity(cve_id)
        
        api_url = f"https://www.opencve.io/api/cve/{cve_id}"
        raw_data = await self.make_request(api_url)
    
        if not raw_data:
            return None

        json_data = json.loads(raw_data)

        cve = Cve()
        cve.cve_id = json_data.get("id")
        cve.cwe_id = json_data.get("cwes")


        if json_data.get("raw_nvd_data") is not None:
            #check if impact exists
            
            if json_data["raw_nvd_data"]["impact"]:
                #check if cvss v2 exists
                
                if json_data["raw_nvd_data"]["impact"].get("baseMetricV2") is not None:
                    cve.cvss_v2 = Cvss()
                    cve.cvss_v2.version = json_data["raw_nvd_data"]["impact"]["baseMetricV2"]["cvssV2"].get("version")
                    cve.cvss_v2.score = json_data["raw_nvd_data"]["impact"]["baseMetricV2"]["cvssV2"].get("baseScore")
                    cve.cvss_v2.vector = json_data["raw_nvd_data"]["impact"]["baseMetricV2"]["cvssV2"].get("vectorString")
                    cve.cvss_v2.severity = json_data["raw_nvd_data"]["impact"]["baseMetricV2"]["cvssV2"].get("baseSeverity")
                    
                    cve.cvss_v2.impact = json_data["raw_nvd_data"]["impact"]["baseMetricV2"].get("impactScore")
                    cve.cvss_v2.exploitability = json_data["raw_nvd_data"]["impact"]["baseMetricV2"].get("exploitabilityScore")
                
                #check if cvss v3 exists
                if json_data["raw_nvd_data"]["impact"].get("baseMetricV3") is not None:
                    cve.cvss_v3 = Cvss()
                    cve.cvss_v3.version = json_data["raw_nvd_data"]["impact"]["baseMetricV3"]["cvssV3"].get("version")
                    cve.cvss_v3.score = json_data["raw_nvd_data"]["impact"]["baseMetricV3"]["cvssV3"].get("baseScore")
                    cve.cvss_v3.vector = json_data["raw_nvd_data"]["impact"]["baseMetricV3"]["cvssV3"].get("vectorString")
                    cve.cvss_v3.severity = json_data["raw_nvd_data"]["impact"]["baseMetricV3"]["cvssV3"].get("baseSeverity")
                    
                    cve.cvss_v3.impact = json_data["raw_nvd_data"]["impact"]["baseMetricV3"].get("impactScore")
                    cve.cvss_v3.exploitability = json_data["raw_nvd_data"]["impact"]["baseMetricV3"].get("exploitabilityScore")
        
        cve.published_date = json_data.get("created_at")
        cve.updated_date = json_data.get("updated_at")
        
        return cve
    
    async def search_cwe(self, cwe_id: str):
        u.check_cwe_integrity(cwe_id)
        
        api_url = f"https://www.opencve.io/api/cwe/{cwe_id}"
        raw_data = await self.make_request(api_url)
        
        if raw_data is None:
            return None
        
        json_data = json.loads(raw_data)
        
        cwe = Cwe()
        
        cwe.cwe_id = json_data.get("id")
        cwe.name = json_data.get("name")
        cwe.description = json_data.get("description")
        
        return cwe
    
    async def close_connection(self):
        await self.client.aclose()
