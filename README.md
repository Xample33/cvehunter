<p align="center">
  <img height=300 src="https://github.com/Xample33/cve-hunter/assets/54323615/f8654f5c-d7ce-4929-b5f7-3d9bd3c78c94" alt='cvehunter'></a>
</p>

<h1 align="center"> CVEHunter - Asynchronous python package for CVE/CWE </h1>

CVEHunter is a Python asynchronous library designed to simplify the retrieval of CVE (Common Vulnerabilities and Exposures) and CWE (Common Weakness Enumeration) information using the OpenCVE API. It streamlines the process of searching for and accessing valuable security data for vulnerability assessment and management.

## Installation

```
pip3 install cvehunter
```

## Example
Code:
```python
import asyncio
import cvehunter
    
async def sample_cwe():
    auth = cvehunter.Auth("USERNAME", "PASSWORD")
    
    cve = await auth.search_cve("CVE-2023-41991")
    print(cve)
    
    cwe = await auth.search_cwe("CWE-79")
    print(cwe)
    
asyncio.run(sample_cwe())
```

Output:
```
{'cve_id': 'CVE-2023-41991', 'cwe_id': [], 'cvss_v2': None, 'cvss_v3': None, 'published_date': '2023-09-21T19:15:00Z', 'last_modified_date': '2023-09-23T03:15:00Z'}

{'cwe_id': 'CWE-79', 'name': "Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')", 'description': 'The software does not neutralize or incorrectly neutralizes user-controllable input before it is placed in output that is used as a web page that is served to other users.'}
```

## Contributing
Contributions are welcome! If you'd like to contribute to CVEHunter, please follow the guidelines outlined in our Contributing Guide.

## License
This project is licensed under the MIT License.

