import setuptools

setuptools.setup(
    name="avd_etl_logging",
    version="0.0.1",
    author="Team Google 2024 - MSU CSE Captone - Brendan Wieferich, email: wiefer20@msu.edu",
    description="A simple library that helps with the logging of etl actions within the android vulnerability database backend",
    packages=["avd_etl_logging"],
    python_requires=">=3.11",
    install_requires=['sqlalchemy', 'google-cloud-secret-manager', 
                      'google-cloud-storage', 'cloud-sql-python-connector']
)