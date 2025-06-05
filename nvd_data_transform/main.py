"""
Main file for execution of the transform and load processes for NVD data. 

Author: Brendan Wieferich
"""

import functions_framework
from google.cloud import storage
from google.cloud.sql.connector import Connector
from nvd_transform_lib import nvd_transformer, logger
import os
import sqlalchemy
import json

# execute the process of reformatting data and uploading to sql db
@functions_framework.http
def main(request):
    # connect to GCP bucket
    client = storage.Client(project="solid-gamma-411111")

    # get file names from bucket
    trigger_bucket = client.get_bucket('nvd-trigger')
    blob = trigger_bucket.blob("trigger_file.json")
    with blob.open(mode = "r") as infile:
        extract_data = json.load(infile)

    # if extract was successful run processes
    if extract_data['status'] == 'success':
        try:
            file_names = extract_data['files']

            # Create Connector for sql db
            connector = Connector()
            # get nvd bucket
            bucket = client.get_bucket('nvd-extract-data')
            transformer = nvd_transformer(bucket, connector)

            # get all file names in bucket
            #blobs = client.list_blobs('nvd-extract-data')

            # get connection and create pool
            transformer.get_connection()
            transformer.create_pool()

            # for each file in cloud bucket
            for file in file_names:
                # reformat and insert into sql table
                transformer.upload_nvd_data(file)
                print("Uploaded: ", file)

            log = logger(connector, trigger_bucket)
            log.get_connection()
            log.create_pool()
            log.get_log_data()
            log.add_trigger_file(file_names, 'success')

            # close connections
            client.close()
            connector.close()
            print("end")
            return "Success"
        except Exception as e:
            file_names = extract_data['files']

            # Create Connector for sql db
            connector = Connector()
            # set up logger
            log = logger(connector, trigger_bucket)
            log.get_connection()
            log.create_pool()
            log.get_log_data()
            log.add_trigger_file(file_names, 'failed')
            print("Failure during load process: ", e)
    else:
        file_names = extract_data['files']

        # Create Connector for sql db
        connector = Connector()
        # set up logger
        log = logger(connector, trigger_bucket)
        log.get_connection()
        log.create_pool()
        log.get_log_data()
        log.add_trigger_file(file_names, 'failed: upstream failure')
        return "Failed"
