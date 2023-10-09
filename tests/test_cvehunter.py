import pytest
import os
from cvehunter import CveHunter

@pytest.mark.asyncio
async def test_cve_correct():
    ch = CveHunter()
    
    cve = await ch.search_by_cve("CVE-2023-41991")
    print(str(cve)[:200])
    assert cve is not None
    
@pytest.mark.asyncio
async def test_cve_cvss30():
    ch = CveHunter()
    
    cve = await ch.search_by_cve("CVE-2017-0144")
    print(str(cve)[:200])
    assert (cve.cvss_v3 == {
        'score': 8.1,
        'vector': 'CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H',
        'severity': 'HIGH',
        'version': 3.0,
        'exploitability': 2.2,
        'impact': 5.9
    })	

@pytest.mark.asyncio
async def test_cve_wrong_year():
    ch = CveHunter()
    
    with pytest.raises(ValueError) as exc_info:
        print(await ch.search_by_cve("CVE-2024-41991"))
    
    print(str(exc_info.value))
    assert str(exc_info.value) == "CVE ID year cannot be greater than current year"
    
@pytest.mark.asyncio
async def test_cve_wrong_id():
    ch = CveHunter()
    
    with pytest.raises(ValueError) as exc_info:
        print(await ch.search_by_cve("CVE-ssss-41991"))
    
    print(str(exc_info.value))    
    assert str(exc_info.value) == ("CVE ID must be in the format CVE-YYYY-NNNN")

@pytest.mark.asyncio
async def test_cwe_correct():
    ch = CveHunter()
    
    cwe = await ch.search_by_cwe("CWE-79", limit=10)
    print(str(cwe)[:200])
    assert cwe is not None

@pytest.mark.asyncio
async def test_cwe_wrong():
    ch = CveHunter()
    
    with pytest.raises(ValueError) as exc_info:
        print(await ch.search_by_cwe("CWE-9999"))
    
    print(str(exc_info.value))    
    assert str(exc_info.value) == ("CWE ID must be in the format CWE-NNN")