import pytest
import os
import asyncio
from cvehunter.Auth import Auth

@pytest.mark.asyncio
async def test_auth_correct():
    username = os.environ.get("OPENCVE_USERNAME")
    password = os.environ.get("OPENCVE_PASSWORD")
    auth = Auth(username, password)
    return auth

@pytest.mark.asyncio
async def test_auth_wrong():
    auth = Auth('wrong', 'wrong')
    assert auth is not None

@pytest.mark.asyncio
async def test_cve_correct():
    username = os.environ.get("OPENCVE_USERNAME")
    password = os.environ.get("OPENCVE_PASSWORD")
    auth = Auth(username, password)
    
    cve = await auth.search_cve("CVE-2023-41991")
    assert cve is not None

@pytest.mark.asyncio
async def test_cve_wrong_year():
    username = os.environ.get("OPENCVE_USERNAME")
    password = os.environ.get("OPENCVE_PASSWORD")
    auth = Auth(username, password)
    
    with pytest.raises(ValueError) as exc_info:
        await auth.search_cve("CVE-2024-41991")

    assert str(exc_info.value) == "CVE ID year cannot be greater than current year"
    
@pytest.mark.asyncio
async def test_cve_wrong_id():
    username = os.environ.get("OPENCVE_USERNAME")
    password = os.environ.get("OPENCVE_PASSWORD")
    auth = Auth(username, password)
    
    with pytest.raises(ValueError) as exc_info:
        await auth.search_cve("CVE-ssss-41991")
        
    assert str(exc_info.value) ==("CVE ID must be in the format CVE-YYYY-NNNN")

@pytest.mark.asyncio
async def test_cwe_correct():
    username = os.environ.get("OPENCVE_USERNAME")
    password = os.environ.get("OPENCVE_PASSWORD")
    auth = Auth(username, password)
    
    cwe = await auth.search_cwe("CWE-79")
    assert cwe is not None

@pytest.mark.asyncio
async def test_cwe_wrong():
    username = os.environ.get("OPENCVE_USERNAME")
    password = os.environ.get("OPENCVE_PASSWORD")
    auth = Auth(username, password)
    
    cwe = await auth.search_cwe("CWE-99999")
    assert cwe is None
