from .Auth import Auth 
from .Cve import Cve
from .Cvss import Cvss
from .Cwe import Cwe
from . import utils as u
import json

async def connect(username, password, proxy: dict = None):
    auth = Auth(username, password, proxy)
    await auth.check_connection()  # Check if the connection is successful
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
        cve.raw = raw_data
        cve.cve_id = json_data.get("id")
        cve.cwe_id = json_data.get("cwes")
        cve.summary = json_data.get("summary")

        if json_data.get("raw_nvd_data") is not None:
            references = json_data["raw_nvd_data"]["cve"]["references"].get("reference_data")

            cve.references = [reference["url"] for reference in references]
            
            # Check if impact exists
            
            
            if json_data["raw_nvd_data"]["impact"]:
                # Check if cvss v2 exists
                if json_data["raw_nvd_data"]["impact"].get("baseMetricV2") is not None:
                    cve.cvss_v2 = Cvss()
                    cve.cvss_v2.version = float(json_data["raw_nvd_data"]["impact"]["baseMetricV2"]["cvssV2"].get("version"))
                    cve.cvss_v2.score = json_data["raw_nvd_data"]["impact"]["baseMetricV2"]["cvssV2"].get("baseScore")
                    cve.cvss_v2.vector = json_data["raw_nvd_data"]["impact"]["baseMetricV2"]["cvssV2"].get("vectorString")
                    cve.cvss_v2.severity = json_data["raw_nvd_data"]["impact"]["baseMetricV2"]["cvssV2"].get("baseSeverity")
                    
                    cve.cvss_v2.impact = json_data["raw_nvd_data"]["impact"]["baseMetricV2"].get("impactScore")
                    cve.cvss_v2.exploitability = json_data["raw_nvd_data"]["impact"]["baseMetricV2"].get("exploitabilityScore")
                   
                    
                # Check if cvss v3 exists
                if json_data["raw_nvd_data"]["impact"].get("baseMetricV3") is not None:
                    cve.cvss_v3 = Cvss()
                    cve.cvss_v3.version = float(json_data["raw_nvd_data"]["impact"]["baseMetricV3"]["cvssV3"].get("version"))
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
        raw_data = await self.auth.make_request(api_url)
        
        if raw_data is None:
            return None
        
        json_data = json.loads(raw_data)
        
        cwe = Cwe()
        
        cwe.cwe_id = json_data.get("id")
        cwe.name = json_data.get("name")
        cwe.description = json_data.get("description")
        
        return cwe
    
    async def get_latest_cves(self, page: int = 1) -> list[Cve]:
        """
        Get the latest CVEs, 20 per page
        
        page: The page number to get the CVEs from
        """
        
        u.check_latest_cves_integrity(page)
        
        api_url = f"https://www.opencve.io/api/cve?page={page}"
        raw_data = await self.auth.make_request(api_url)
        
        if raw_data is None:
            return None
        
        json_data = json.loads(raw_data)
        
        cves = []
        
        for element in json_data:
            single_cve = Cve()
            single_cve.cve_id = element["id"]
            single_cve.summary = element["summary"]
            single_cve.published_date = element["created_at"]
            single_cve.updated_date = element["updated_at"]
            
            cves.append(single_cve)
            
        return cves