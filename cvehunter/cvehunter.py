from .Connect import Connect 
from .Cve import Cve
from .Cvss import Cvss
from . import utils as u
import json

class CveHunter:
    #init method to pass proxy to Connect class:
    def __init__(self, proxy: dict = None) -> None:
        self.proxy = proxy
        
    async def check_connection(self) -> bool:
        api_url = "https://services.nvd.nist.gov/rest/json/cves/"
        raw_data = await Connect(self.proxy).make_request(api_url)
        
        if raw_data is None:
            return False
        
        return True
    
    async def search_by_cve(self, cve_id: str) -> Cve:
        u.check_cve_integrity(cve_id)
        
        api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        raw_data = await Connect(self.proxy).make_request(api_url)

        if not raw_data:
            return None
        
        json_data = json.loads(raw_data)
        json_root = json_data['vulnerabilities'][0]['cve']
        cve = Cve()
        cve.raw = raw_data
        
        cve.cve_id = json_root.get("id")
        cve.description = json_root['descriptions'][0].get("value")
        cve.source = json_root.get("sourceIdentifier")
        
        temp_cwe = json_root['weaknesses'][0]['description'][0].get("value")
        if temp_cwe == "NVD-CWE-Other":
            cve.cwe_id = json_root['weaknesses'][1]['description'][0].get("value")
            
        elif temp_cwe == "NVD-CWE-noinfo":
            cve.cwe_id = None
        
        else:
            cve.cwe_id = temp_cwe

        references = json_root["references"]
        cve.references = [reference["url"] for reference in references]
        
        # Check if cvss v2 exists
        if json_root["metrics"].get("cvssMetricV2") is not None:
            cve.cvss_v2 = Cvss()
            
            cve.cvss_v2.version = float(json_data['vulnerabilities'][0]['cve']["metrics"]["cvssMetricV2"][0]["cvssData"].get("version"))
            cve.cvss_v2.score = json_root["metrics"]["cvssMetricV2"][0]["cvssData"].get("baseScore")
            cve.cvss_v2.vector = json_root["metrics"]["cvssMetricV2"][0]["cvssData"].get("vectorString")
            
            cve.cvss_v2.severity = json_root["metrics"]["cvssMetricV2"][0].get("baseSeverity")
            
            cve.cvss_v2.impact = json_root["metrics"]["cvssMetricV2"][0].get("impactScore")
            cve.cvss_v2.exploitability = json_root["metrics"]["cvssMetricV2"][0].get("exploitabilityScore")
            
            
        # Check if cvss v3.0 exists
        if json_root["metrics"].get("cvssMetricV30") is not None:
            cve.cvss_v3 = Cvss()
            
            cve.cvss_v3.version = float(json_data['vulnerabilities'][0]['cve']["metrics"]["cvssMetricV30"][0]["cvssData"].get("version"))
            cve.cvss_v3.score = json_root["metrics"]["cvssMetricV30"][0]["cvssData"].get("baseScore")
            cve.cvss_v3.vector = json_root["metrics"]["cvssMetricV30"][0]["cvssData"].get("vectorString")
            
            cve.cvss_v3.severity = json_root["metrics"]["cvssMetricV30"][0]["cvssData"].get("baseSeverity")
            
            cve.cvss_v3.impact = json_root["metrics"]["cvssMetricV30"][0].get("impactScore")
            cve.cvss_v3.exploitability = json_root["metrics"]["cvssMetricV30"][0].get("exploitabilityScore")
        
        # Check if cvss v3.1 exists
        if json_root["metrics"].get("cvssMetricV31") is not None:
            cve.cvss_v3 = Cvss()
            
            cve.cvss_v3.version = float(json_data['vulnerabilities'][0]['cve']["metrics"]["cvssMetricV31"][0]["cvssData"].get("version"))
            cve.cvss_v3.score = json_root["metrics"]["cvssMetricV31"][0]["cvssData"].get("baseScore")
            cve.cvss_v3.vector = json_root["metrics"]["cvssMetricV31"][0]["cvssData"].get("vectorString")
            
            cve.cvss_v3.severity = json_root["metrics"]["cvssMetricV31"][0]["cvssData"].get("baseSeverity")
            
            cve.cvss_v3.impact = json_root["metrics"]["cvssMetricV31"][0].get("impactScore")
            cve.cvss_v3.exploitability = json_root["metrics"]["cvssMetricV31"][0].get("exploitabilityScore")
                   
        
        cve.published_date = json_root.get("published")
        cve.updated_date = json_root.get("lastModified")
        
        return cve
    
    async def search_by_cpe(self, cpe_id: str, limit: int = None, only_vulnerable: bool = None, start_date: str = None, end_date: str = None) -> list:
        """
        Search for CVEs based on a CPE ID (partial or full).

        Args:
            cpe_id: The CPE ID to search for CVEs.
            limit (optional): Maximum number of results to return. Default is None (no limit).
            only_vulnerable (optional): Limit results to only include the vulnerable one.
            start_date (optional): Start date for filtering CVEs based on publication date.
            end_date (optional): End date for filtering CVEs based on publication date.

        Returns:
            list: A list of CVE IDs matching the search criteria.
            
        Example:
            >>> cve_ids = await search_by_cpe('cpe:2.3:o:microsoft:windows_10:1607:*:*:*:*:*:*:*')
            >>> cve_ids = await search_by_cpe('cpe:2.3:o:microsoft:windows_10:1607')
        """
        u.check_cpe_integrity(cpe_id)
        u.check_limit_integrity(limit) if limit is not None else None
        u.check_vulnerable_integrity(only_vulnerable) if only_vulnerable is not None else None
        u.check_date_integrity(start_date) if start_date is not None else None
        u.check_date_integrity(end_date) if end_date is not None else None
        
        api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName={cpe_id}"
        if limit is not None:
            api_url += f"&resultsPerPage={limit}"
            
        if start_date is not None:
            api_url += f"&pubStartDate={start_date}"
            
        if end_date is not None:
            api_url += f"&pubEndDate={end_date}"
            
        if only_vulnerable is not None:
            api_url += f"&isVulnerable"
            
        raw_data = await Connect(self.proxy).make_request(api_url)
        
        if raw_data is None:
            return None
        
        json_data = json.loads(raw_data)
        
        cpe = []
        for single_cve in json_data['vulnerabilities']:
            cpe.append(single_cve['cve'].get("id"))
 
        return cpe
    
    async def search_by_vector(self, cvss_version: int, vector: str, limit: int = None, start_date: str = None, end_date: str = None) -> list:
        """
        Search for CVEs based on a CVSS vector and version.

        Args:
            cvss_version: The CVSS version (2 or 3) to use for the search.
            vector: The CVSS vector representing the vulnerabilities.
            limit (optional): Maximum number of results to return. Default is None (no limit).
            start_date (optional): Start date for filtering CVEs based on publication date.
            end_date (optional): End date for filtering CVEs based on publication date.

        Returns:
            list: A list of CVE IDs matching the search criteria.
            
        Example:
            >>> cve_ids = await search_by_vector(3, 'AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H')
        """
        u.check_cvssversion_integrity(cvss_version)
        u.check_vector_integrity(vector)
        u.check_limit_integrity(limit) if limit is not None else None
        u.check_date_integrity(start_date) if start_date is not None else None
        u.check_date_integrity(end_date) if end_date is not None else None
        
        api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cvssV{cvss_version}Metrics={vector}"
        if limit is not None:
            api_url += f"&resultsPerPage={limit}"
            
        if start_date is not None:
            api_url += f"&pubStartDate={start_date}"
            
        if end_date is not None:
            api_url += f"&pubEndDate={end_date}"
            
        raw_data = await Connect(self.proxy).make_request(api_url)
        
        if raw_data is None:
            return None
        
        json_data = json.loads(raw_data)
        
        cve = []
        for single_cve in json_data['vulnerabilities']:
            cve.append(single_cve['cve'].get("id"))
 
        return cve
    
    async def search_by_cwe(self, cwe_id: str, limit: int = None, start_date: str = None, end_date: str = None) -> list:
        """
        Search for CVEs based on a CWE ID.

        Args:
            cwe_id: The CWE ID to search for CVEs.
            limit (optional): Maximum number of results to return. Default is None (no limit).
            start_date (optional): Start date for filtering CVEs based on publication date.
            end_date (optional): End date for filtering CVEs based on publication date.

        Returns:
            list: A list of CVE IDs matching the search criteria.

        Example:
            >>> cve_ids = await search_by_cwe("CWE-78")
        """
        u.check_cwe_integrity(cwe_id)
        u.check_limit_integrity(limit) if limit is not None else None
        u.check_date_integrity(start_date) if start_date is not None else None
        u.check_date_integrity(end_date) if end_date is not None else None
        
        api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cweId={cwe_id}"
        if limit is not None:
            api_url += f"&resultsPerPage={limit}"
            
        if start_date is not None:
            api_url += f"&pubStartDate={start_date}"
            
        if end_date is not None:
            api_url += f"&pubEndDate={end_date}"
            
        raw_data = await Connect(self.proxy).make_request(api_url)

        if raw_data is None:
            return None
        
        json_data = json.loads(raw_data)
        
        cve = []
        for single_cve in json_data['vulnerabilities']:
            cve.append(single_cve['cve'].get("id"))
 
        return cve