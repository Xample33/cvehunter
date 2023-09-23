import asyncio
import cvehunter
import os


username = os.environ.get("OPENCVE_USERNAME")
password = os.environ.get("OPENCVE_PASSWORD")

async def sample_cwe():
    auth = cvehunter.Auth(username, password)
    
    cve = await auth.search_cve("CVE-2023-41991")
    print(cve)
    
    cwe = await auth.search_cwe("CWE-99999")
    print(cwe)
    
asyncio.run(sample_cwe())