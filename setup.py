# -*- coding: utf-8 -*-
# import sys
from os.path import join, dirname, exists
from setuptools import setup
from setuptools import find_packages

long_description = open(join(dirname(__file__), 'README.md')).read().strip() if exists('README.md') else ''
install_requires = [
    "requests",
]

setup(
    name="PyCriminalIP",
    description="Python library for CriminalIP(https://www.criminalip.io/)",
    license="MIT License",
    url="https://github.com/haginara/PyCriminalIP",
    long_description=long_description,
    long_description_content_type='text/markdown',
    version='0.2.0',
    author="Jonghak Choi",
    author_email="haginara@gmail.com",
    install_requires=install_requires,
    packages=find_packages(),
    package_data={
        '': ['README.md', 'LICENSE'],
    },
    include_package_data=True,
    classifiers=[
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
    ],
)