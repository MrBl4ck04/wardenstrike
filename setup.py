from setuptools import setup, find_packages

setup(
    name="wardenstrike",
    version="1.0.0",
    description="AI-Powered Pentesting Framework with Burp Suite & ZAP Integration",
    author="mrbl4ck",
    packages=find_packages(),
    python_requires=">=3.10",
    install_requires=[
        "click>=8.1.0",
        "rich>=13.0.0",
        "pyyaml>=6.0",
        "jinja2>=3.1.0",
        "aiohttp>=3.9.0",
        "anthropic>=0.40.0",
        "python-dotenv>=1.0.0",
        "sqlalchemy>=2.0.0",
        "requests>=2.31.0",
        "beautifulsoup4>=4.12.0",
        "tabulate>=0.9.0",
        "prompt_toolkit>=3.0.0",
        "xmltodict>=0.13.0",
    ],
    entry_points={
        "console_scripts": [
            "wardenstrike=wardenstrike.cli:main",
        ],
    },
    classifiers=[
        "Programming Language :: Python :: 3",
        "Topic :: Security",
    ],
)
