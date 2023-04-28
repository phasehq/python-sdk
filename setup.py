from setuptools import setup, find_packages

setup(
    name='phase-sdk',
    version='0.0.1',
    description='Python SDK for Phase',
    url="https://phase.dev",
    author='Phase',
    packages=find_packages(),
    install_requires=[
        'PyNaCl',
        'requests',
    ],
)
