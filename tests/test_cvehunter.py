import pytest
import os
import cvehunter.cvehunter as cvehunter

@pytest.mark.asyncio
async def test_auth_correct():
    username = os.environ.get("OPENCVE_USERNAME")
    password = os.environ.get("OPENCVE_PASSWORD")
    ch = await cvehunter.connect(username, password)
    return ch

@pytest.mark.asyncio
async def test_auth_wrong():
    ch = await cvehunter.connect('wrong', 'wrong')
    assert ch is not None

@pytest.mark.asyncio
async def test_cve_correct():
    username = os.environ.get("OPENCVE_USERNAME")
    password = os.environ.get("OPENCVE_PASSWORD")
    ch = await cvehunter.connect(username, password)
    
    cve = await ch.search_cve("CVE-2023-41991")
    assert cve is not None

@pytest.mark.asyncio
async def test_cve_wrong_year():
    username = os.environ.get("OPENCVE_USERNAME")
    password = os.environ.get("OPENCVE_PASSWORD")
    ch = await cvehunter.connect(username, password)
    
    with pytest.raises(ValueError) as exc_info:
        await ch.search_cve("CVE-2024-41991")

    assert str(exc_info.value) == "CVE ID year cannot be greater than current year"
    
@pytest.mark.asyncio
async def test_cve_wrong_id():
    username = os.environ.get("OPENCVE_USERNAME")
    password = os.environ.get("OPENCVE_PASSWORD")
    ch = await cvehunter.connect(username, password)
    
    with pytest.raises(ValueError) as exc_info:
        await ch.search_cve("CVE-ssss-41991")
        
    assert str(exc_info.value) ==("CVE ID must be in the format CVE-YYYY-NNNN")

@pytest.mark.asyncio
async def test_cwe_correct():
    username = os.environ.get("OPENCVE_USERNAME")
    password = os.environ.get("OPENCVE_PASSWORD")
    ch = await cvehunter.connect(username, password)
    
    cwe = await ch.search_cwe("CWE-79")
    assert cwe is not None

@pytest.mark.asyncio
async def test_cwe_wrong():
    username = os.environ.get("OPENCVE_USERNAME")
    password = os.environ.get("OPENCVE_PASSWORD")
    ch = await cvehunter.connect(username, password)
    
    cwe = await ch.search_cwe("CWE-99989")
    assert cwe is None
