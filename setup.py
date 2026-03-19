from setuptools import setup, find_packages

setup(
    name="secopsai",
    version="0.0.0",
    description="SecOps AI toolkit",
    packages=find_packages(exclude=("tests", "docs")),
    include_package_data=True,
    entry_points={
        "console_scripts": [
            "secopsai=secopsai.cli:main",
        ],
    },
)
