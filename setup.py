from setuptools import setup, find_packages

setup(
    name="umaycrypt",
    version="1.0.0",
    description="UmayCrypt - Göktürk (Orhun-Yenisey) Motifli AES-256-GCM CLI Şifreleme Aracı",
    long_description=open("README.md", "r", encoding="utf-8").read(),
    long_description_content_type="text/markdown",
    author="UmayCrypt",
    url="https://github.com/umaycrypt/umaycrypt",
    packages=find_packages(),
    install_requires=[
        "cryptography>=49.0.0",
    ],
    extras_require={
        "dev": ["pytest>=8.0.0"],
    },
    entry_points={
        "console_scripts": [
            "umay=umay.cli:main",
        ],
    },
    python_requires=">=3.10",
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Topic :: Security :: Cryptography",
    ],
)
