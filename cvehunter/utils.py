from datetime import datetime

def check_cve_integrity(cve_id: str) -> None:
    if not cve_id:
        raise ValueError("CVE ID is required")
    
    if not isinstance(cve_id, str):
        raise TypeError("CVE ID must be a string")
    
    if not cve_id.startswith("CVE-"):
        raise ValueError("CVE ID must start with CVE-")
    
    if not cve_id[4:8].isdigit():
        raise ValueError("CVE ID must be in the format CVE-YYYY-NNNN")
    
    #check if the first part of the cve is only charters and a date
    if not cve_id[9:].isdigit():
        raise ValueError("CVE ID must be in the format CVE-YYYY-NNNN")
    
    #check cve year
    cve_year = int(cve_id.split("-")[1])
    current_year = int(datetime.now().year)
    if cve_year > current_year:
        raise ValueError("CVE ID year cannot be greater than current year")
    
def check_cpe_integrity(cpe_id: str) -> None:
    if not cpe_id:
        raise ValueError("CPE ID is required")
    
    if not isinstance(cpe_id, str):
        raise TypeError("CPE ID must be a string")
    
    if not cpe_id.startswith("cpe:"):
        raise ValueError("CPE ID must start with cpe:")    
    
def check_credentials_integrity(username: str, password: str) -> None:
    if not username:
        raise ValueError("Username is required")
    
    if not password:
        raise ValueError("Password is required")
    
    if not isinstance(username, str):
        raise TypeError("Username must be a string")
    
    if not isinstance(password, str):
        raise TypeError("Password must be a string")
    
def check_latest_cves_integrity(page: int) -> None:
    if not isinstance(page, int):
        raise TypeError("Page must be an integer")
    
    if page < 1:
        raise ValueError("Page must be greater than 0")
    
def check_limit_integrity(limit: int) -> None:
    if not isinstance(limit, int):
        raise TypeError("Limit must be an integer")
    
    if limit < 1:
        raise ValueError("Limit must be greater than 0")
    
def check_vulnerable_integrity(only_vulnerable: bool) -> None:
    if not isinstance(only_vulnerable, bool):
        raise TypeError("Only vulnerable must be a True or False")
    
def check_cvssversion_integrity(cvss_version: int) -> None:
    if not isinstance(cvss_version, int):
        raise TypeError("CVSS version must be an integer")
    
    if cvss_version not in [2, 3]:
        raise ValueError("CVSS version must be 2 or 3")
    
def check_vector_integrity(vector: str) -> None:
    if not isinstance(vector, str):
        raise TypeError("Vector must be a string")
    
def check_cwe_integrity(cwe_id: str) -> None:
    if not isinstance(cwe_id, str):
        raise TypeError("CWE ID must be a string")
    
    if not cwe_id.startswith("CWE-"):
        raise ValueError("CWE ID must start with CWE-")
    
    if not cwe_id[4:].isdigit():
        raise ValueError("CWE ID must be in the format CWE-NNN")
    
    if len(cwe_id) > 7:
        raise ValueError("CWE ID must be in the format CWE-NNN")
    
def check_date_integrity(date: str) -> None:
    if not isinstance(date, str):
        raise TypeError("Date must be a string")
    
    # the two format are 2021-08-04T00:00:00 or 2020-01-01T00:00:00-05:00, try to parse the first one
    # if it fails try the second one
    try:
        datetime.strptime(date, "%Y-%m-%dT%H:%M:%S")
    except ValueError:
        raise ValueError("Date must be in the format YYYY-MM-DDTHH:MM:SS or YYYY-MM-DDTHH:MM:SS+HH:MM")
    else:
        return
    
    try:
        datetime.strptime(date, "%Y-%m-%dT%H:%M:%S%z")
    except ValueError:
        raise ValueError("Date must be in the format YYYY-MM-DDTHH:MM:SS or YYYY-MM-DDTHH:MM:SS+HH:MM")
    else:
        return