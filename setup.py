from os import path
from setuptools import setup

def read(fname):
    return open(path.join(path.dirname(__file__), fname)).read()

setup(
    name = "cvehunter",
    version = "0.0.1",
    author = "Xample33",
    license = "MIT",
    url = "https://github.com/Xample33/cvehunter",
    long_description=read('README.md')
)