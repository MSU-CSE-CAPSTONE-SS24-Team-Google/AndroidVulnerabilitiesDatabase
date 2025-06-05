"""
Main file for the execution of the data patching process. 

Author: Brendan Wieferich
"""

import functions_framework
from datetime import datetime
from google.cloud import storage
import os
import json
import sqlalchemy
from google.cloud.sql.connector import Connector
from data_patch_lib import nvd_patcher

# execute the process of patching the data tables for cves that are missing
@functions_framework.http
def main(request):
    # instantiate connector
    connector = Connector()
    #instantiate patcher
    patcher = nvd_patcher(connector)
    patcher.get_connection()
    patcher.create_pool()
    # get the list of cves with null base_scores
    patcher.fetch_cves()
    patcher.extract_cve_data()
    #patcher.write_nvd_json()
    #patcher.read_nvd_json()
    patcher.parse_nvd_data()
    valid_data, invalid_data = patcher.get_parsed_data()
    print(len(patcher.nvd_data['vulnerabilities']))
    print(len(valid_data['vulnerabilities']), "\n", len(invalid_data['vulnerabilities']))
    patcher.patch_nvd_data()
    print("DONE")