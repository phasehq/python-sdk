from setuptools import setup, find_packages

from src.version import __version__

setup(
    name='phase_dev',
    version=__version__,
    description='Python SDK for Phase',
    url="https://phase.dev",
    author='Phase',
    packages=find_packages(),
    install_requires=[
        'PyNaCl',
        'requests',
    ],
)
