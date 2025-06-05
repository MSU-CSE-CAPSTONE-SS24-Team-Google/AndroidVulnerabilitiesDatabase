"""
Main file for the execution of the merge process

Author: Brendan Wieferich
"""

import functions_framework
from google.cloud.sql.connector import Connector
import os
import sqlalchemy
from merge_lib import Merger, logger
from google.cloud import storage
import json

# perform setup and execute the merge processes
@functions_framework.http
def main(request):
    # Create Connector for sql db
    connector = Connector()

    try:
        # init merger
        merger = Merger(connector)
        merger.get_connection()
        merger.create_pool()

        # perform merge
        x = merger.merge()

        client = storage.Client(project="solid-gamma-411111")
        bucket = client.get_bucket('nvd-trigger')

        # invoke logger
        log = logger(connector, bucket)
        log.get_connection()
        log.create_pool()
        log.get_log_data()
        log.add_trigger_file("SQL table merge", 'success')

        client.close()
        connector.close()
        print(x)
    except Exception as e:
        client = storage.Client(project="solid-gamma-411111")
        bucket = client.get_bucket('nvd-trigger')

        # invoke logger
        log = logger(connector, bucket)
        log.get_connection()
        log.create_pool()
        log.get_log_data()
        log.add_trigger_file("SQL table merge", 'success')
        client.close()
        connector.close()
        print("Failure during marge process: ", e)
    return "Success"