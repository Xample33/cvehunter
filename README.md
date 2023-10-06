<p align="center">
  <img height=300 src="https://github.com/Xample33/cve-hunter/assets/54323615/f8654f5c-d7ce-4929-b5f7-3d9bd3c78c94" alt='cvehunter'></a>
</p>

<h1 align="center"> CVEHunter - Async python package for CVE/CWE data</h1>

<p align="center"> 
  <a href="https://badge.fury.io/py/cvehunter"><img src="https://badge.fury.io/py/cvehunter.svg" alt="PyPI"></a>
  <img alt="PyPI - Python Version" src="https://img.shields.io/pypi/pyversions/cvehunter">
  <a href="https://github.com/psf/black"><img alt="Code style: black" src="https://img.shields.io/badge/code%20style-black-000000.svg"></a>
</p>

CVEHunter is a Python asynchronous library designed to simplify the retrieval of CVE (Common Vulnerabilities and Exposures) and CWE (Common Weakness Enumeration) information using the OpenCVE API. It streamlines the process of searching for and accessing valuable security data for vulnerability assessment and management.

## Installation

```
pip3 install cvehunter
```

## Example
Code:
```python
import asyncio
from cvehunter import cvehunter
    
async def sample():
    ch = await cvehunter.connect(username, password)

    cve = await ch.search_cve("CVE-2023-41991")
    print(cve)
    
    cwe = await ch.search_cwe("CWE-79")
    print(cwe)
    
asyncio.run(sample())
```

Output:
```
{'cve_id': 'CVE-2023-41991', 'cwe_id': [], 'cvss_v2': None, 'cvss_v3': None, 'published_date': '2023-09-21T19:15:00Z', 'last_modified_date': '2023-09-23T03:15:00Z'}

{'cwe_id': 'CWE-79', 'name': "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')", 'description': 'The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.'}
```

## Contributing
Contributions are welcome! If you'd like to contribute to CVEHunter, please follow the guidelines outlined in the Contributing Guide.

## License
This project is licensed under the MIT License.

