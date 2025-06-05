"""
Library for the data patching process

Author: Brendan Wieferich, Seth Darling
"""

import json
from google.cloud.sql.connector import Connector
import sqlalchemy
import json
import requests
import time
from google.cloud import secretmanager_v1

PROJECT_ID = "solid-gamma-411111"
API_KEY = "nvd-api-key"
VERSION_ID = "1"

"""
class that transforms json formatted data from json files
and then uploads them to cloud sql server
"""
class nvd_patcher:
    """
    Initialize the class
    in:
        bucket: google cloud storage bucket
        connector: connector for google cloud sql db
    """
    def __init__(self, connector):
        self.connector = connector
        self.connection = None
        self.pool = None
        self.select_null_base_score = sqlalchemy.text(
            "SELECT cve FROM android_vuln_data WHERE base_score IS NULL;"
        )
        self.select_cve_from_nvd_data = sqlalchemy.text(
            "SELECT cve_id FROM nvd_transformed_data where cve_id = :cve"
        )
        self.cves = []
        self.nvd_data_cves = []
        self.nvd_data = {}
        self.nvd_data['vulnerabilities'] = []
        self.iterations = 0
        self.valid_nvd_data = {}
        self.valid_nvd_data['vulnerabilities'] = []
        self.invalid_nvd_data = {}
        self.invalid_nvd_data['vulnerabilities'] = []
        self.insert_valid_statement = sqlalchemy.text(
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
                    ) ON DUPLICATE KEY UPDATE cve_id = CONCAT(:cve_id, '-duplicate');")
        self.create_table_invalid = sqlalchemy.text(
            "CREATE TABLE IF NOT EXISTS bad_cves (cve_id varchar(255) NOT NULL, vuln_status varchar(255), PRIMARY KEY (cve_id));"
        )
        self.insert_invalid_statement = sqlalchemy.text(
            "REPLACE INTO bad_cves (cve_id, vuln_status) VALUES (:cve_id, :vuln_status);"
        )
                
    # Get connection to google cloud sql db
    def get_connection(self):
        connection = self.connector.connect(
            "solid-gamma-411111:us-central1:ss24-teamgoogle",
            "pymysql",
            user="wiefer20",
            password="]r_2~|3G^LblcM_'",
            db="vulnerabilities"
        )
        return connection


    # create resource pool for sql queries
    def create_pool(self):
        self.pool = sqlalchemy.create_engine(
            "mysql+pymysql://",
            creator=self.get_connection,
        )

    # get all cves that have a base score of NULL
    def fetch_cves(self):
        with self.pool.connect() as db_conn:
            # run query
            self.cves = db_conn.execute(self.select_null_base_score).fetchall()
    
    # retrieve missing cve data from nvd data base
    def extract_cve_data(self):
        for cve in self.cves:
            self.iterations += 1
            if self.iterations % 49 == 0:
                print("Records parsed: ", self.iterations, "/", len(self.cves))
                print("Paused to avoid API reject")
                time.sleep(45)
                print("Resumed")
            secret_client = secretmanager_v1.SecretManagerServiceClient()
            # get API key
            name = f"projects/{PROJECT_ID}/secrets/{API_KEY}/versions/{VERSION_ID}"
            response = secret_client.access_secret_version(name=name)
            response = response.payload.data.decode('UTF-8')
            HEADER = {'Authorization':f'apiKey:{response}'}
            # make request
            api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0/?cveID={cve[0]}"
            response = requests.get(url=api_url, headers=HEADER)
            if response:
                self.nvd_data['vulnerabilities'] = self.nvd_data['vulnerabilities'] + response.json()['vulnerabilities']

    # write the nvd_data to a local json file
    # FOR TESTING PURPOSES
    def write_nvd_json(self):
        with open("nvd_data.json", "w") as outfile:
            json.dump(self.nvd_data, outfile)

    # read the nvd_data to a local file
    # FOR TESTING PURPOSES
    def read_nvd_json(self):
        with open("nvd_data.json", "r") as infile:
            self.nvd_data = json.load(infile)

    # get extracted nvd data
    def get_nvd_data(self):
        return self.nvd_data
    
    # parse the extracted data and sort it
    def parse_nvd_data(self):
        for record in self.nvd_data['vulnerabilities']:
            if record['cve']['vulnStatus'] == 'Analyzed':
                self.valid_nvd_data['vulnerabilities'].append(record)
            else:
                self.invalid_nvd_data['vulnerabilities'].append(record)

    def patch_nvd_data(self):
        # patch the data for valid CVEs
        valid_record_data = []
        invalid_record_data = []
        # parse valid records for relevent values
        for record in self.valid_nvd_data['vulnerabilities']:
            if record['cve']['vulnStatus'] == "Analyzed":
                data = {
                    'cve_id': record['cve']["id"],
                    'vuln_status': record['cve']['vulnStatus']
                    }
                if 'cvssMetricV2' in record['cve']["metrics"]:
                    data['metric_version'] = '2.0'
                    data['base_score'] = record['cve']["metrics"]['cvssMetricV2'][0]['cvssData']['baseScore']
                    data['base_severity'] = record['cve']["metrics"]['cvssMetricV2'][0]['baseSeverity']
                    data['exploitability_score'] = record['cve']["metrics"]['cvssMetricV2'][0]['exploitabilityScore']
                    data['impact_score'] = record['cve']["metrics"]['cvssMetricV2'][0]['impactScore']
                if 'cvssMetricV30' in record['cve']["metrics"]:
                    data['metric_version'] = '3.0'
                    data['base_score'] = record['cve']["metrics"]['cvssMetricV30'][0]['cvssData']['baseScore']
                    data['base_severity'] = record['cve']["metrics"]['cvssMetricV30'][0]['cvssData']['baseSeverity']
                    data['exploitability_score'] = record['cve']["metrics"]['cvssMetricV30'][0]['exploitabilityScore']
                    data['impact_score'] = record['cve']["metrics"]['cvssMetricV30'][0]['impactScore']
                if 'cvssMetricV31' in record['cve']["metrics"]:
                    data['metric_version'] = '3.1'
                    data['base_score'] = record['cve']["metrics"]['cvssMetricV31'][0]['cvssData']['baseScore']
                    data['base_severity'] = record['cve']["metrics"]['cvssMetricV31'][0]['cvssData']['baseSeverity']
                    data['exploitability_score'] = record['cve']["metrics"]['cvssMetricV31'][0]['exploitabilityScore']
                    data['impact_score'] = record['cve']["metrics"]['cvssMetricV31'][0]['impactScore']
                # store dict as row in list
                valid_record_data.append(data)
        # parse the invalid data
        for record in self.invalid_nvd_data['vulnerabilities']:
            if record['cve']['vulnStatus'] == 'Rejected' or record['cve']['vulnStatus'] == 'Awaiting Analysis':
                data = {}
                data['cve_id'] = record['cve']['id']
                data['vuln_status'] = record['cve']['vulnStatus']
                invalid_record_data.append(data)

        with self.pool.connect() as db_conn:
            # create table
            db_conn.execute("DROP TABLE IF EXISTS bad_cves")
            db_conn.execute(self.create_table_invalid)
            # insert valid records into nvd_data
            for row in valid_record_data:
                if 'metric_version' in row:
                    db_conn.execute(self.insert_valid_statement, [{
                        'cve_id':row['cve_id'],
                        'vuln_status':row['vuln_status'],
                        'metric_version':row['metric_version'],
                        'base_score':row['base_score'],
                        'base_severity':row['base_severity'],
                        'exploitability_score':row['exploitability_score'],
                        'impact_score':row['impact_score']
                        }])
            # insert invalid records
            for row in invalid_record_data:
                db_conn.execute(self.insert_invalid_statement, [{
                    'cve_id':row['cve_id'], 
                    'vuln_status':row['vuln_status']
                    }])

    # get parsed nvd data
    def get_parsed_data(self):
        return self.valid_nvd_data, self.invalid_nvd_data