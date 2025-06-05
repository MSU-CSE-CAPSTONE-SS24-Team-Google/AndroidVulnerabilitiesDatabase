"""
Library for the data set merge process

Authors: Brendan Wieferich, Seth Darling
"""

from google.cloud.sql.connector import Connector
from google.cloud import secretmanager
import sqlalchemy
import json

PROJECT_ID = "solid-gamma-411111"
SECRET_ID = "wiefer20SQL"
VERSION_ID = "1"

# A class that merges the nvd and asb datasets together
class Merger:
    # in: connector object for sql db
    def __init__(self, connector):
        self.connector = connector
        self.pool = None
        # Create table SQL
        self.create_table_stmt = sqlalchemy.text(
            "CREATE TABLE IF NOT EXISTS android_vulnerability_data (patch_level TEXT, \
            cve VARCHAR(255), \
            references_ VARCHAR(255), \
            reference_links TEXT, \
            type TEXT, \
            severity TEXT, \
            updated_aosp_versions TEXT, \
            component TEXT, \
            subcomponent TEXT, \
            android_launch_version TEXT, \
            kernel_launch_version TEXT, \
            minimum_launch_version TEXT, \
            minimum_kernel_version TEXT, \
            date_reported TEXT, \
            updated_google_devices TEXT, \
            updated_nexus_devices TEXT, \
            updated_versions TEXT, \
            affected_versions TEXT, \
            publicly_available TEXT, \
            bulletin_type TEXT, \
            component_code TEXT, \
            component_code_link TEXT, \
            date TEXT, \
            asb_url TEXT, \
            notes TEXT, \
            vuln_status varchar(255), \
            metric_version varchar(255), \
            base_score FLOAT, \
            exploitability_score FLOAT, \
            impact_score FLOAT, PRIMARY KEY (cve, references_));"
        )
        # Join SQL
        # takes all data from the asb table and does a left outer join on nvd data and gets specific columns
        self.join_stmt = sqlalchemy.text("\
            REPLACE INTO android_vulnerability_data SELECT asb.*, nvd_transformed_data.vuln_status, nvd_transformed_data.metric_version,\
            nvd_transformed_data.base_score, nvd_transformed_data.exploitability_score,\
            nvd_transformed_data.impact_score FROM asb LEFT OUTER JOIN nvd_transformed_data\
            ON asb.cve = nvd_transformed_data.cve_id"
            )
        self.check = sqlalchemy.text("SELECT cve, references_, base_score, date FROM android_vulnerability_data ORDER BY date DESC LIMIT 10;")
        self.count = sqlalchemy.text("SELECT count(*) FROM android_vulnerability_data;")

    # Get connection to google cloud sql db
    def get_connection(self):
        # Create client to access SQL password
        secret_client = secretmanager.SecretManagerServiceClient()
        name = f"projects/{PROJECT_ID}/secrets/{SECRET_ID}/versions/{VERSION_ID}"
        response = secret_client.access_secret_version(name=name)        
        
        connection = self.connector.connect(
            "solid-gamma-411111:us-central1:ss24-teamgoogle",
            "pymysql",
            user="wiefer20",
            password=response.payload.data.decode('UTF-8'),
            db='vulnerabilities'
        )
        return connection


    # create resource pool for sql queries
    def create_pool(self):
        self.pool = sqlalchemy.create_engine(
            "mysql+pymysql://",
            creator=self.get_connection,
        )

    # merge the two datasets
    def merge(self):
        with self.pool.connect() as db_conn:
            db_conn.execute(self.create_table_stmt)
            before_count = db_conn.execute(self.count).fetchall()[0][0]
            db_conn.execute(self.join_stmt)
            # return to notify of success
            answer = db_conn.execute(self.check).fetchall()
            after_count = db_conn.execute(self.count).fetchall()[0][0]
            print("Number of rows: ", after_count)
            print("Rows added: ", after_count - before_count)
        return answer
    
# a class that logs the completion of the process
# note: this code can be packaged as an importable library for use in the cloud, see the README file for more
class logger:
    def __init__(self, connector, bucket):
        self.connector = connector
        self.bucket = bucket
        self.pool = None
        self.cycle_year = None
        self.cycle_month = None

    # get the cycle data from logs
    def get_log_data(self):
        sel_cycle = sqlalchemy.text("SELECT MAX(start_date), MAX(end_date) FROM cycle WHERE active = 1")
        with self.pool.connect() as db_conn:
            get_cycle = db_conn.execute(sel_cycle).fetchall()
            self.cycle_year = get_cycle[0][1].year
            self.cycle_month = get_cycle[0][1].month
    
    # add new trigger file to activate logging fucntion
    def add_trigger_file(self, file_list, status):
        # write API response directly to G Cloud bucket
        filename = 'trigger_file.json'
        blob = self.bucket.blob(filename)
        with blob.open(mode = "w") as datafile:
            j = {"files":file_list,
                 "status":"{}".format(status),
                 "process":"asb-nvd-merge",
                 "cycle":"{}-{}".format(self.cycle_year, self.cycle_month)}
            json.dump(j, datafile)
    
    # Get connection to google cloud sql db
    def get_connection(self):
        secret_client = secretmanager.SecretManagerServiceClient()
        name = f"projects/{PROJECT_ID}/secrets/{SECRET_ID}/versions/{VERSION_ID}"
        response = secret_client.access_secret_version(name=name)   
        connection = self.connector.connect(
            "solid-gamma-411111:us-central1:ss24-teamgoogle",
            "pymysql",
            user="wiefer20",
            password=response.payload.data.decode('UTF-8'),
            db="etl-logs"
        )
        return connection


    # create resource pool for sql queries
    def create_pool(self):
        self.pool = sqlalchemy.create_engine(
            "mysql+pymysql://",
            creator=self.get_connection,
        )