import functions_framework
from google.cloud.sql.connector import Connector
from google.cloud import storage
import json
from logger_lib import connect, update_logs

# perform processes to update logs for etl services
@functions_framework.cloud_event
def main(cloud_event):
    # connect to bucket
    client = storage.Client(project="solid-gamma-411111")
    bucket = client.get_bucket('nvd-trigger')

    # get data from file
    blob = bucket.blob("trigger_file.json")
    with blob.open(mode = "r") as infile:
        extract_data = json.load(infile)

    # update logs
    if extract_data["status"] == "success":
        return_str = update_logs(extract_data, "success") 
    else:
        return_str = update_logs(extract_data, "failed")
    client.close()
    
    return return_str

    



