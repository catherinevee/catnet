"""
CatNet Setup Configuration

Installation script for CatNet CLI and library
"""

from setuptools import setup, find_packages
from pathlib import Path

# Read README
README = Path("README.md")
long_description = README.read_text() if README.exists() else ""

# Read requirements
requirements = []
requirements_file = Path("requirements.txt")
if requirements_file.exists():
    requirements = [
        line.strip()
        for line in requirements_file.read_text().splitlines()
        if line.strip() and not line.startswith('#')
    ]

# CLI requirements (subset of main requirements)
cli_requirements = [
    'click>=8.0.0',
    'httpx>=0.24.0',
    'rich>=13.0.0',
    'tabulate>=0.9.0',
    'pyyaml>=6.0',
    'configparser>=5.0.0'
]

setup(
    name='catnet',
    version='1.0.0',
    author='CatNet Team',
    author_email='admin@catnet.local',
    description='Enterprise-grade GitOps-enabled network configuration deployment system',
    long_description=long_description,
    long_description_content_type='text/markdown',
    url='https://github.com/catnet/catnet',
    packages=find_packages(exclude=['tests*', 'docs*']),
    include_package_data=True,
    python_requires='>=3.11',

    # Dependencies
    install_requires=cli_requirements,

    # Full dependencies for server installation
    extras_require={
        'server': requirements,
        'dev': [
            'pytest>=7.0.0',
            'pytest-asyncio>=0.21.0',
            'pytest-cov>=4.0.0',
            'black>=23.0.0',
            'isort>=5.0.0',
            'mypy>=1.0.0',
            'bandit>=1.7.0',
            'safety>=2.0.0',
            'pre-commit>=3.0.0'
        ],
        'docs': [
            'sphinx>=6.0.0',
            'sphinx-rtd-theme>=1.0.0',
            'sphinx-autodoc-typehints>=1.0.0',
            'myst-parser>=1.0.0'
        ]
    },

    # CLI entry points
    entry_points={
        'console_scripts': [
            'catnet=cli.catnet:cli',
            'catnet-server=src.main:main'
        ]
    },

    # Package data
    package_data={
        'catnet': [
            'configs/*.yaml',
            'configs/*.ini',
            'templates/*',
            'static/*'
        ]
    },

    # Classifiers
    classifiers=[
        'Development Status :: 4 - Beta',
        'Intended Audience :: System Administrators',
        'Intended Audience :: Information Technology',
        'Topic :: System :: Networking',
        'Topic :: System :: Systems Administration',
        'License :: OSI Approved :: MIT License',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.11',
        'Programming Language :: Python :: 3.12',
        'Operating System :: OS Independent',
        'Framework :: FastAPI',
        'Environment :: Console',
        'Environment :: Web Environment'
    ],

    # Keywords
    keywords='network automation gitops configuration management cisco juniper',

    # Project URLs
    project_urls={
        'Documentation': 'https://catnet.readthedocs.io',
        'Bug Reports': 'https://github.com/catnet/catnet/issues',
        'Source': 'https://github.com/catnet/catnet',
        'Changelog': 'https://github.com/catnet/catnet/blob/main/CHANGELOG.md'
    }
)