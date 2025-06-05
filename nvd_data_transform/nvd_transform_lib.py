"""
Library containing classes used to perform the load and transform process for NVD data.

Authors: Brendan Wieferich, Seth Darling
"""

import json
from google.cloud.sql.connector import Connector
from google.cloud import secretmanager_v1
import sqlalchemy

PROJECT_ID = "solid-gamma-411111"
SECRET_ID = "wiefer20SQL"
VERSION_ID = "1"

"""
class that transforms json formatted data from json files
and then uploads them to cloud sql server
"""
class nvd_transformer:
    """
    Initialize the class
    in:
        bucket: google cloud storage bucket
        connector: connector for google cloud sql db
    """
    def __init__(self, bucket, connector):
        self.bucket = bucket
        self.connector = connector
        self.connection = None
        self.pool = None
        self.insert_statement = sqlalchemy.text(
            "REPLACE INTO nvd_transformed_data (\
                cve_id,\
                vuln_status,\
                metric_version,\
                base_score,\
                base_severity,\
                exploitability_score,\
                impact_score\
                ) VALUES (\
                    :cve_id,\
                    :vuln_status,\
                    :metric_version,\
                    :base_score,\
                    :base_severity,\
                    :exploitability_score,\
                    :impact_score\
                    );"
        )
        self.create_table_stmt = sqlalchemy.text(
            "CREATE TABLE IF NOT EXISTS nvd_transformed_data (\
                cve_id varchar(255) NOT NULL,\
                vuln_status varchar(255),\
                metric_version varchar(255),\
                base_score FLOAT,\
                base_severity varchar(255),\
                exploitability_score FLOAT,\
                impact_score FLOAT,\
                PRIMARY KEY (cve_id)\
                )"
        )

    # drop table if needed
    def drop_tab(self):
        with self.pool.connect() as db_conn:
            # create table if not exists
            db_conn.execute("DROP TABLE IF EXISTS nvd_transformed_data")

    """
    Load file from cloud bucket, reformat, then load into sql db
    in:
        filename: name of the file in cloud bucket
    """
    def upload_nvd_data(self, filename):

        # open file in cloud storage
        blob = self.bucket.blob(filename)
        with blob.open(mode = "r") as infile:
            vulnerabilities = json.load(infile)

        # list of rows of data 
        report_data = []
        
        # for each report, pull and store as dict
        for report in vulnerabilities['vulnerabilities']:
            if report['cve']['vulnStatus'] != "Rejected":
                data = {
                    'cve_id': report["cve"]["id"],
                    'vuln_status': report['cve']['vulnStatus']
                    }
                if 'cvssMetricV2' in report["cve"]["metrics"]:
                    data['metric_version'] = '2.0'
                    data['base_score'] = report["cve"]["metrics"]['cvssMetricV2'][0]['cvssData']['baseScore']
                    data['base_severity'] = report["cve"]["metrics"]['cvssMetricV2'][0]['baseSeverity']
                    data['exploitability_score'] = report["cve"]["metrics"]['cvssMetricV2'][0]['exploitabilityScore']
                    data['impact_score'] = report["cve"]["metrics"]['cvssMetricV2'][0]['impactScore']
                if 'cvssMetricV30' in report["cve"]["metrics"]:
                    data['metric_version'] = '3.0'
                    data['base_score'] = report["cve"]["metrics"]['cvssMetricV30'][0]['cvssData']['baseScore']
                    data['base_severity'] = report["cve"]["metrics"]['cvssMetricV30'][0]['cvssData']['baseSeverity']
                    data['exploitability_score'] = report["cve"]["metrics"]['cvssMetricV30'][0]['exploitabilityScore']
                    data['impact_score'] = report["cve"]["metrics"]['cvssMetricV30'][0]['impactScore']
                if 'cvssMetricV31' in report["cve"]["metrics"]:
                    data['metric_version'] = '3.1'
                    data['base_score'] = report["cve"]["metrics"]['cvssMetricV31'][0]['cvssData']['baseScore']
                    data['base_severity'] = report["cve"]["metrics"]['cvssMetricV31'][0]['cvssData']['baseSeverity']
                    data['exploitability_score'] = report["cve"]["metrics"]['cvssMetricV31'][0]['exploitabilityScore']
                    data['impact_score'] = report["cve"]["metrics"]['cvssMetricV31'][0]['impactScore']
                # store dict as row in list
                report_data.append(data)

        # connect to sql db then
        with self.pool.connect() as db_conn:
            # create table if not exists
            db_conn.execute(self.create_table_stmt)
            # insert rows into table
            for row in report_data:
                if 'metric_version' in row:
                    db_conn.execute(self.insert_statement, [{
                        'cve_id':row['cve_id'],
                        'vuln_status':row['vuln_status'],
                        'metric_version':row['metric_version'],
                        'base_score':row['base_score'],
                        'base_severity':row['base_severity'],
                        'exploitability_score':row['exploitability_score'],
                        'impact_score':row['impact_score']
                        }])
                
    # Get connection to google cloud sql db
    def get_connection(self):
        # Create client to access SQL password
        secret_client = secretmanager_v1.SecretManagerServiceClient()
        name = f"projects/{PROJECT_ID}/secrets/{SECRET_ID}/versions/{VERSION_ID}"
        response = secret_client.access_secret_version(name=name)         
        connection = self.connector.connect(
            "solid-gamma-411111:us-central1:ss24-teamgoogle",
            "pymysql",
            user="wiefer20",
            password=response.payload.data.decode('UTF-8'),
            db="vulnerabilities"
        )
        return connection


    # create resource pool for sql queries
    def create_pool(self):
        self.pool = sqlalchemy.create_engine(
            "mysql+pymysql://",
            creator=self.get_connection,
        )

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
                 "process":"nvd-transform",
                 "cycle":"{}-{}".format(self.cycle_year, self.cycle_month)}
            json.dump(j, datafile)
    
    # Get connection to google cloud sql db
    def get_connection(self):
        secret_client = secretmanager_v1.SecretManagerServiceClient()
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