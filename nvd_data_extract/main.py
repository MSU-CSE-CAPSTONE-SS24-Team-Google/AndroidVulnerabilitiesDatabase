"""
Main file for the execution of the NVD data extract process

Authors: Brendan Wieferich, Frederick Fan
"""

import functions_framework
from datetime import datetime
from google.cloud import storage
import os
import json
import sqlalchemy
from google.cloud.sql.connector import Connector
from google.cloud import secretmanager_v1
from nvd_extract_lib import nvd_data_extract, logger

PROJECT_ID = "solid-gamma-411111"
SECRET_ID = "wiefer20SQL"
VERSION_ID = "1"

# execute the processes for extracting and storing the nvd data
@functions_framework.http
def main(request):
    # connect to GCP bucket
    client = storage.Client(project="solid-gamma-411111")
    bucket = client.get_bucket('nvd-extract-data')

    # connect to sql database to get cycle data
    connector = Connector()
    def get_connection():
        # Create client to access SQL password
        secret_client = secretmanager_v1.SecretManagerServiceClient()
        name = f"projects/{PROJECT_ID}/secrets/{SECRET_ID}/versions/{VERSION_ID}"
        response = secret_client.access_secret_version(name=name)
        
        connection = connector.connect(
            "solid-gamma-411111:us-central1:ss24-teamgoogle",
            "pymysql",
            user="wiefer20",
            password=response.payload.data.decode('UTF-8'),
            db="etl-logs"
        )
        return connection
    
    pool = sqlalchemy.create_engine(
            "mysql+pymysql://",
            creator=get_connection,
        )
    
    try:
        # get dates for cycle
        sel_cycle = sqlalchemy.text("SELECT start_date, end_date FROM cycle WHERE active = 1")
        with pool.connect() as db_conn:
            get_cycle = db_conn.execute(sel_cycle).fetchall()
            start = [get_cycle[0][0].year, get_cycle[0][0].month, get_cycle[0][0].day]
            end = [get_cycle[0][1].year, get_cycle[0][1].month, get_cycle[0][1].day]

        stop = [start[0], start[1] + 1, start[2]]
        start_date = datetime(start[0], start[1], start[2])
        stop_date = datetime(stop[0], stop[1], stop[2])
        end_date = datetime(end[0], end[1], end[2])

        file_list = []
    except Exception as e:
        print("Failure getting data from etl-logs: ", e)

    try:
        # loop until start date reaches end date
        while start_date < end_date:
            # run extract
            nvd_data_extract(start_date, stop_date, bucket, str(start[0]), str(start[1]))
            file_list.append("{}-{}.json".format(start[0], start[1]))
            print("Uploaded: ", str(start[0]), "-", str(start[1]),".json")
            # if end of year: start date at Jan 1 of the next year, else increment month
            if start[1] >= 12:
                start[0] = start[0] + 1
                start[1] = 1
            else:
                start[1] = start[1] + 1
            # if end of year: stop date at Jan 1 of the next year, else increment month
            if stop[1] >= 12:
                stop[0] = stop[0] + 1
                stop[1] = 1
            else:
                stop[1] = stop[1] + 1
            # generate new start and stop date
            start_date = datetime(start[0], start[1], start[2])
            stop_date = datetime(stop[0], stop[1], stop[2])
        # drop a file in trigger bucket
        bucket = client.get_bucket('nvd-trigger')

        try:
            # invoke logger
            log = logger(connector, bucket)
            log.get_connection()
            log.create_pool()
            log.get_log_data()
            log.add_trigger_file(file_list, 'success')
        except Exception as e:
            print("Failure during logging process: ", e)

        # close client
        client.close()
        connector.close()
    except Exception as e:
        # drop a file in trigger bucket
        bucket = client.get_bucket('nvd-trigger')

        # invoke logger
        log = logger(connector, bucket)
        log.get_connection()
        log.create_pool()
        log.get_log_data()
        log.add_trigger_file("None", "failed")
        # close client
        client.close()
        connector.close()
        print("Failure during extract process: ", e)

    return "Success"
