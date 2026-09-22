from setuptools import setup, find_packages

setup(
    name="tristrike",
    version="1.0.0",
    description="Unified Autonomous Multi-Agent Web Security & Bug Bounty Platform",
    author="TriStrike AI Community",
    packages=find_packages(),
    py_modules=["tristrike"],
    install_requires=[
        "requests>=2.28.0",
        "urllib3>=1.26.0",
    ],
    entry_points={
        "console_scripts": [
            "tristrike=tristrike:main",
        ],
    },
    python_requires=">=3.8",
)
