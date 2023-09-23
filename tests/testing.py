import asyncio
import cvehunter
    
async def sample_cwe():
    auth = cvehunter.Auth("EMAIL", "PASSWORD")
    
    cve = await auth.search_cve("CVE-2023-41991")
    print(cve)
    
    cwe = await auth.search_cwe("CWE-79")
    print(cwe)
    
asyncio.run(sample_cwe())