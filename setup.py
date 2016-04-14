import os
from setuptools import setup

with open("ukti/datahub/mystique.py") as f:
    exec([l.strip() for l in f.readlines() if "__version__ = " in l][0])

# Allow setup.py to be run from any path
os.chdir(os.path.normpath(os.path.join(os.path.abspath(__file__), os.pardir)))

readme_path = os.path.join(os.path.dirname(__file__), "README.md")

# Get the long description from README.md
with open(readme_path) as readme:
    setup(
        name="ukti.datahub.mystique",
        version=".".join([str(_) for _ in __version__]),
        packages=["ukti", "ukti.datahub"],
        namespace_packages=["ukti.datahub", "ukti.datahub"],
        include_package_data=True,
        license="GPLv3",
        description="UKTI integration with Microsoft Azure AD",
        long_description=readme.read(),
        url="https://github.com/UKTradeInvestment/mystique",
        download_url="https://github.com/UKTradeInvestment/mystique",
        install_requires=[
            "PyJWT",
            "flask",
            "python-dotenv",
            "requests",
        ],
        tests_require=[
            "nose",
            "responses"
        ],
        test_suite="nose.collector",
        classifiers=[
            "Operating System :: POSIX",
            "Operating System :: Unix",
            "Programming Language :: Python",
            "Programming Language :: Python :: 3.3",
            "Programming Language :: Python :: 3.4",
            "Programming Language :: Python :: 3.5",
            "Topic :: Internet :: WWW/HTTP",
        ],
    )
