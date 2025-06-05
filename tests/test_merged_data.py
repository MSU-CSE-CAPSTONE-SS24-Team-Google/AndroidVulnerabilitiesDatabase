"""
Test integrity of data from the merged data set stored in SQL database. The purpose of this is to reveal any 
areas where data may need to be examined or patched. It is not necessarily indicative of process failures.

Author: Brendan Wieferich
"""

from google.cloud.sql.connector import Connector
import sqlalchemy
from google.cloud import secretmanager_v1
import os

PROJECT_ID = "solid-gamma-411111"
SECRET_ID = "wiefer20SQL"
VERSION_ID = "1"

# append credentials to path to test in local environment 
# gerate credentials json file via Google CLI, add to .config
# PATH = os.path.join(os.getcwd(), '.config\file_name.json')
# os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = PATH

PATH = os.path.join(os.getcwd(), '.config\solid-gamma-411111-52e009325882.json')
os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = PATH

connector = Connector()
# count of all records
select_all = "SELECT count(*) FROM android_vulnerability_data"

# test the merged data set for data integrity
# failed tests do not necessarily indicate a process failure
# tests are intended to notify if there are records that may need to be cleaned or patched
class Test_merged():
    def get_connection(self):
        # Create client to access SQL password
        secret_client = secretmanager_v1.SecretManagerServiceClient()
        name = f"projects/{PROJECT_ID}/secrets/{SECRET_ID}/versions/{VERSION_ID}"
        response = secret_client.access_secret_version(name=name) 
        connection = connector.connect(
            "solid-gamma-411111:us-central1:ss24-teamgoogle",
            "pymysql",
            user="wiefer20",
            password=response.payload.data.decode('UTF-8'),
            db='vulnerabilities'
        )
        return connection
    
    # check to ensure all CVE id's are of the correct format
    def test_check_cve_format(self):
        pool = sqlalchemy.create_engine(
            "mysql+pymysql://",
            creator=self.get_connection,
        )
        with pool.connect() as db_conn:
            # count of all records with correct formating
            select_all_correct = 'SELECT count(*) FROM android_vulnerability_data WHERE cve LIKE "CVE%%"'
            total = db_conn.execute(select_all).fetchall()
            correct = db_conn.execute(select_all_correct).fetchall()
            # check
            assert total == correct

    # check that all base scores are within the correct range
    def test_check_base_score_range(self):
        pool = sqlalchemy.create_engine(
            "mysql+pymysql://",
            creator=self.get_connection,
        )
        with pool.connect() as db_conn:
            # count of all records with correct range
            select_all_range = "SELECT count(*) FROM android_vulnerability_data WHERE base_score BETWEEN 0 AND 10"
            total = db_conn.execute(select_all).fetchall()
            correct = db_conn.execute(select_all_range).fetchall()
            # check
            assert total == correct
    
    # check metric version
    def test_check_metric_version(self):
        pool = sqlalchemy.create_engine(
            "mysql+pymysql://",
            creator=self.get_connection,
        )
        with pool.connect() as db_conn:
            # count of all records with correct range
            select_all_not_null = "SELECT count(*) FROM android_vulnerability_data WHERE metric_version IS NOT NULL"
            total = db_conn.execute(select_all).fetchall()
            correct = db_conn.execute(select_all_not_null).fetchall()
            # check
            assert total == correct

    # check patch_level
    def test_check_patch_level(self):
        pool = sqlalchemy.create_engine(
            "mysql+pymysql://",
            creator=self.get_connection,
        )
        with pool.connect() as db_conn:
            # count of all records with correct formating
            select_all_correct = "SELECT count(*) FROM android_vulnerability_data WHERE patch_level = 'patch_level' \
                 OR patch_level BETWEEN 01 AND 06"
            total = db_conn.execute(select_all).fetchall()
            correct = db_conn.execute(select_all_correct).fetchall()
            # check
            assert total == correct

    # check component
    def test_check_component(self):
        pool = sqlalchemy.create_engine(
            "mysql+pymysql://",
            creator=self.get_connection,
        )
        with pool.connect() as db_conn:
            # count of all records with correct formating
            select_all_correct = "SELECT count(*) FROM android_vulnerability_data WHERE component IS NOT NULL"
            total = db_conn.execute(select_all).fetchall()
            correct = db_conn.execute(select_all_correct).fetchall()
            # check
            assert total == correct

    # check date
    def test_check_date(self):
        pool = sqlalchemy.create_engine(
            "mysql+pymysql://",
            creator=self.get_connection,
        )
        with pool.connect() as db_conn:
            # count of all records with correct formating
            select_all_correct = "SELECT count(*) FROM android_vulnerability_data WHERE date IS NOT NULL"
            total = db_conn.execute(select_all).fetchall()
            correct = db_conn.execute(select_all_correct).fetchall()
            # check
            assert total == correct

    # check asb_url
    def test_check_asb_url(self):
        pool = sqlalchemy.create_engine(
            "mysql+pymysql://",
            creator=self.get_connection,
        )
        with pool.connect() as db_conn:
            # count of all records with correct formating
            select_all_correct = "SELECT count(*) FROM android_vulnerability_data WHERE asb_url IS NOT NULL"
            total = db_conn.execute(select_all).fetchall()
            correct = db_conn.execute(select_all_correct).fetchall()
            # check
            assert total == correct

    # check impact_score
    def test_check_impact_range(self):
        pool = sqlalchemy.create_engine(
            "mysql+pymysql://",
            creator=self.get_connection,
        )
        with pool.connect() as db_conn:
            # count of all records with correct range
            select_all_impact_range = "SELECT count(*) FROM android_vulnerability_data WHERE impact_score BETWEEN 0 AND 10"
            total = db_conn.execute(select_all).fetchall()
            correct = db_conn.execute(select_all_impact_range).fetchall()
            # check
            assert total == correct

    # check vuln_status
    def test_vuln_status(self):
        pool = sqlalchemy.create_engine(
            "mysql+pymysql://",
            creator=self.get_connection,
        )
        with pool.connect() as db_conn:
            # count of all records with correct range
            select_all_not_null = "SELECT count(*) FROM android_vulnerability_data WHERE vuln_status IS NOT NULL"
            total = db_conn.execute(select_all).fetchall()
            correct = db_conn.execute(select_all_not_null).fetchall()
            # check
            assert total == correct
    
    # check exploitability_score
    def test_exploit_score_range(self):
        pool = sqlalchemy.create_engine(
            "mysql+pymysql://",
            creator=self.get_connection,
        )
        with pool.connect() as db_conn:
            # count of all records with correct range
            select_all_exploit_range = "SELECT count(*) FROM android_vulnerability_data WHERE exploitability_score BETWEEN 0 AND 10"
            total = db_conn.execute(select_all).fetchall()
            correct = db_conn.execute(select_all_exploit_range).fetchall()
            # check
            assert total == correct