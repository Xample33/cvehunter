from os import path
from setuptools import setup

def read(fname):
    return open(path.join(path.dirname(__file__), fname), encoding='utf-8').read()

setup(
    name="cvehunter",
    version="1.0.0",
    author="Xample33",
    license="MIT",
    url="https://github.com/Xample33/cvehunter",
    long_description=read('README.md'),
    long_description_content_type='text/markdown',  # Specify the content type as Markdown
    install_requires=[
        "httpx",
        "urllib3",
    ],
)
