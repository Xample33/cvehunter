from os import path
from setuptools import setup

def read(fname):
    return open(path.join(path.dirname(__file__), fname), encoding='utf-8').read()

setup(
    name="cvehunter",
    version="1.0.6",
    packages=["cvehunter"],
    author="Xample33",
    maintainer="Xample33",
    license="MIT",
    url="https://github.com/Xample33/cvehunter",
    description="Asynchronous python wrapper for the NVD API",
    long_description=read('README.md'),
    long_description_content_type='text/markdown',
    install_requires=[
        "httpx",
        "urllib3",
    ],
    python_requires='>=3.9',
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        'Programming Language :: Python :: 3.9',
        'Programming Language :: Python :: 3.10',
        'Programming Language :: Python :: 3.11',
        'Operating System :: OS Independent',
    ],
    keywords="cve nist nvd cpe cwe cvss vulnerability api",
)
