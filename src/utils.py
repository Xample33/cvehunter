from datetime import datetime

def check_cve_integrity(cve_id: str):
    if not cve_id:
        raise ValueError("CVE ID is required")
    
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
    
def check_cwe_integrity(cwe_id: str):
    if not cwe_id:
        raise ValueError("CWE ID is required")
    
    if not cwe_id.startswith("CWE-"):
        raise ValueError("CWE ID must start with CWE-")
    
    if not cwe_id[4:].isdigit():
        raise ValueError("CWE ID must be in the format CWE-NNNN")
    
def check_credentials_integrity(username: str, password: str):
    if not username:
        raise ValueError("Username is required")
    
    if not password:
        raise ValueError("Password is required")
    
    if not isinstance(username, str):
        raise TypeError("Username must be a string")
    
    if not isinstance(password, str):
        raise TypeError("Password must be a string")