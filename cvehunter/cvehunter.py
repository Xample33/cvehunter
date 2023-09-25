# cvehunter.py

from .Auth import Auth  # Import the Auth class here
from .Cve import Cve
from .Cvss import Cvss
from .Cwe import Cwe
from . import utils as u
import json

async def connect(username, password, proxy: dict = None):
    print(proxy)
    auth = Auth(username, password, proxy)
    return CveHunter(auth)

class CveHunter:
    def __init__(self, auth):
        self.auth = auth

    async def search_cve(self, cve_id: str):
        u.check_cve_integrity(cve_id)
        api_url = f"https://www.opencve.io/api/cve/{cve_id}"
        raw_data = await self.auth.make_request(api_url)
        
        if not raw_data:
            return None
        
        json_data = json.loads(raw_data)
        
        cve = Cve()
        cve.cve_id = json_data.get("id")
        cve.cwe_id = json_data.get("cwes")

        if json_data.get("raw_nvd_data") is not None:
            # Check if impact exists
            if json_data["raw_nvd_data"]["impact"]:
                # Check if cvss v2 exists
                if json_data["raw_nvd_data"]["impact"].get("baseMetricV2") is not None:
                    cve.cvss_v2 = Cvss()
                    cve.cvss_v2.version = json_data["raw_nvd_data"]["impact"]["baseMetricV2"]["cvssV2"].get("version")
                    cve.cvss_v2.score = json_data["raw_nvd_data"]["impact"]["baseMetricV2"]["cvssV2"].get("baseScore")
                    # ... (continue setting Cvss attributes)
                    
                # Check if cvss v3 exists
                if json_data["raw_nvd_data"]["impact"].get("baseMetricV3") is not None:
                    cve.cvss_v3 = Cvss()
                    cve.cvss_v3.version = json_data["raw_nvd_data"]["impact"]["baseMetricV3"]["cvssV3"].get("version")
                    cve.cvss_v3.score = json_data["raw_nvd_data"]["impact"]["baseMetricV3"]["cvssV3"].get("baseScore")
                    # ... (continue setting Cvss attributes)
        
        cve.published_date = json_data.get("created_at")
        cve.updated_date = json_data.get("updated_at")
        
        return cve
    
    async def search_cwe(self, cwe_id: str):
        u.check_cwe_integrity(cwe_id)
        
        api_url = f"https://www.opencve.io/api/cwe/{cwe_id}"
        raw_data = await self.auth.make_request(api_url)
        
        if raw_data is None:
            return None
        
        json_data = json.loads(raw_data)
        
        cwe = Cwe()
        
        cwe.cwe_id = json_data.get("id")
        cwe.name = json_data.get("name")
        cwe.description = json_data.get("description")
        
        return cwe
