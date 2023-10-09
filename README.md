<p align="center">
  <img height=300 src="https://raw.githubusercontent.com/Xample33/cvehunter/development/images/cvehunter_logo.png" alt='cvehunter_logo'></a>
</p>

<h1 align="center"> CVEHunter - Async python wrapper for CVE/CPE data</h1>

<p align="center">  
  <a href="https://pypi.org/project/cvehunter"> <img alt="PyPI - Version" src="https://badgen.net/pypi/v/cvehunter"> </a>
  <a href="https://pypi.org/project/cvehunter"> <img alt="PyPI - Python Version" src="https://badgen.net/pypi/python/cvehunter"> </a>
  <a href="https://pypi.org/project/cvehunter"> <img alt="PyPI - Downloads" src="https://badgen.net/pypi/dm/cvehunter"> </a>
  <img src="https://hits.seeyoufarm.com/api/count/incr/badge.svg?url=https%3A%2F%2Fgithub.com%2FXample33%2Fcvehunter&count_bg=%2379C83D&title_bg=%23555555&icon=&icon_color=%23E7E7E7&title=hits&edge_flat=false">
</p>

CVEHunter is a Python asynchronous library designed to simplify the retrieval of CVE (Common Vulnerabilities and Exposures) and CPE (Common Platform Enumeration) information using the NVD API. It streamlines the process of searching for and accessing valuable security data for vulnerability assessment and management.

## Installation

```
pip3 install cvehunter
```

## Example
Code:
```python
import asyncio
from cvehunter import CveHunter

async def test() -> None:
    ch = CveHunter()
    
    cve = await ch.search_by_cve("CVE-2023-41991")
    
    print(cve.cve_id)
    print(cve.cwe_id)
    print(cve.description)
    print(cve.cvss_v3)
    print(cve.references)
    
asyncio.run(test())
```

Output:
```
CVE-2023-41991
CWE-295
A certificate validation issue was addressed. This issue is fixed in macOS Ventura 13.6, iOS 16.7 and iPadOS 16.7. A malicious app [...]
{'score': 5.5, 'vector': 'CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N', 'severity': 'MEDIUM', 'version': 3.1, 'exploitability': 1.8, 'impact': 3.6}
['http://seclists.org/fulldisclosure/2023/Oct/5', 'https://support.apple.com/en-us/HT213927', 'https://support.apple.com/en-us/HT213931']
```

## TODO
- [ ] Change history
- [ ] Better filters

## Contributing
Contributions are welcome! If you'd like to contribute to CVEHunter, please follow the guidelines outlined in the Contributing Guide.


## License
This project is licensed under the MIT License.

