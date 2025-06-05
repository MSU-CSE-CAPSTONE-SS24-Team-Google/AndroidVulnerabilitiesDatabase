"""
Library for the NVD data extract process.

Authors: Brendan Wieferich, Frederick Fan
"""

import json
import requests
import copy
from datetime import datetime, timedelta
import time
import sqlalchemy
from google.cloud import secretmanager_v1

PROJECT_ID = "solid-gamma-411111"
SECRET_ID = "wiefer20SQL"
API_KEY = "nvd-api-key"
VERSION_ID = "1"

# this function handles getting NVD data and putting it in json file
def nvd_to_json(api_url, bucket, year, month):
    secret_client = secretmanager_v1.SecretManagerServiceClient()
    name = f"projects/{PROJECT_ID}/secrets/{API_KEY}/versions/{VERSION_ID}"
    response = secret_client.access_secret_version(name=name)
    response = response.payload.data.decode('UTF-8')
    
    # store count of cve records
    HEADER = {'Authorization':f'apiKey:{response}'}
    count = requests.get(url=api_url, headers=HEADER).json()['totalResults']
    
    # if count > 2000 then figure out how many times to iterate
    if count > 2000:
        count_down = count
        count_i = 0
        while count_down > 0 and count_i < 100:
            count_down = count_down - 2000
            count_i = count_i + 1
    elif count < 0:
        raise ValueError("negative number")
    else:
        count_i = 0
    
    # set start index, empty list of responses
    start_index = 0
    responses = []
    
    # perform iterations if needed otherwise pull data
    if count_i > 0:
        for i in range(count_i):
            # time.sleep(10)
            # create copy to not alter original api_url
            url_copy = copy.copy(api_url)
            HEADER = {'Authorization':'apiKey:cb2c4927-7014-446a-b923-4b8a278e6781'}
            url_copy += "&startIndex={}".format(str(start_index))
            responses.append(requests.get(url=url_copy, headers=HEADER))
            start_index = start_index + 2000
    else:
        # time.sleep(15)
        api_url += "&startIndex=0"
        HEADER = {'Authorization':'apiKey:cb2c4927-7014-446a-b923-4b8a278e6781'}
        responses.append(requests.get(url=api_url, headers=HEADER))
    
    # consolidate responses in format that can be written to JSON file
    response_full = {}
    response_full['vulnerabilities'] = []
    for response in responses:
        # time.sleep(4)
        response_full['vulnerabilities'] = response_full['vulnerabilities'] + response.json()['vulnerabilities']
    
    # write API response directly to G Cloud bucket
    filename = '{}-{}.json'.format(year, month)
    blob = bucket.blob(filename)
    with blob.open(mode = "w") as datafile:
        json.dump(response_full, datafile)

"""""
using the NVD api with date parameters has a max date range of 120 days, this function makes it so that you can
have two dates greater than 120 days by using a sliding window to make api calls with a date range of 120 until
you reach the end date

It is currently not fully function which i believe is due to limitations of the api, however you can test it and see
that it should always generate valid api urls assuming you enter two valid dates
"""""
def nvd_data_extract(start_date, end_date, bucket, year, month):
    curr_start = start_date

    while curr_start < end_date:

        curr_end = curr_start +timedelta(days=119)
        if curr_end > end_date:
            curr_end = end_date

        # generate URL for API call
        end_string = curr_end.strftime("%Y-%m-%d")
        start_string = curr_start.strftime("%Y-%m-%d")
        api_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0/?lastModStartDate={start_string}T13:00:00.000%2B01:00&lastModEndDate={end_string}T13:36:00.000%2B01:00" 
        nvd_to_json(api_url, bucket, year, month)

        curr_start = curr_start + timedelta(days=120)

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
        sel_cycle = sqlalchemy.text("SELECT start_date, end_date FROM cycle WHERE active = 1")
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