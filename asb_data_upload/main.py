"""
File for the execution of the load process for scraped ASB data.

Author: Seth Darling, Brendan Wieferich
"""

from google.cloud import storage
from google.cloud.sql.connector import Connector, IPTypes
from google.cloud import secretmanager
import csv
import os
import sqlalchemy
import functions_framework
import json

BUCKET_NAME = 'test-abs-data'
PROJECT_ID = "solid-gamma-411111"
SECRET_ID = "darlin98SQL"
VERSION_ID = "1"

@functions_framework.http
def main(request):
    # Establish connections to bucket and database
    client = storage.Client(project="solid-gamma-411111")
    bucket = client.get_bucket(BUCKET_NAME)
    files = client.list_blobs(BUCKET_NAME)

    ## Access JSON file containing files to upload
    json_bucket = client.get_bucket("asb-update-log")
    json_file_name = client.list_blobs("asb-update-log")
    files_to_read = []
    for file in json_file_name:
        print(file)
        json_blob = json_bucket.blob(file.name)
        with json_blob.open(mode='r') as json_file:
            file = json.load(json_file)
            files_to_read += file["files"]

    print(files_to_read)
    ## Sort file_to_read so latest cves are read last
    files_to_read.sort()

    ip_type = IPTypes.PRIVATE if os.environ.get("PRIVATE_IP") else IPTypes.PUBLIC

    connector = Connector(ip_type)

    # Create client to access 
    secret_client = secretmanager.SecretManagerServiceClient()
    name = f"projects/{PROJECT_ID}/secrets/{SECRET_ID}/versions/{VERSION_ID}"
    response = secret_client.access_secret_version(name=name)

    def get_conn():
        connection = connector.connect(
                "solid-gamma-411111:us-central1:ss24-teamgoogle",
                "pymysql",
                user="darlin98",
                password=response.payload.data.decode('UTF-8'),
                db="vulnerabilities"
            )
        return connection
    
    def create_pool():
        pool = sqlalchemy.create_engine(
                "mysql+pymysql://",
                creator=get_conn,
            )
        return pool
        
    get_conn()
    pool = create_pool()    
    
    # SQL statement for asb table
    create_table_statement = sqlalchemy.text("CREATE TABLE IF NOT EXISTS asb(patch_level TEXT, cve VARCHAR(255), references_ VARCHAR(255), reference_links TEXT, type TEXT, severity TEXT, updated_aosp_versions TEXT, component TEXT, subcomponent TEXT, android_launch_version TEXT, kernel_launch_version TEXT, minimum_launch_version TEXT, minimum_kernel_version TEXT, date_reported TEXT, updated_google_devices TEXT, updated_nexus_devices TEXT, updated_versions TEXT, affected_versions TEXT, publicly_available TEXT, bulletin_type TEXT, component_code TEXT, component_code_link TEXT, date DATE, asb_url TEXT, notes TEXT, PRIMARY KEY (cve, references_));")

    # SQL statement for inserting data from csv files into database
    insert_statement = sqlalchemy.text(
            "REPLACE INTO asb (\
                patch_level,\
                cve,\
                references_,\
                reference_links,\
                type,\
                severity,\
                updated_aosp_versions,\
                component,\
                subcomponent,\
                android_launch_version,\
                kernel_launch_version,\
                minimum_launch_version,\
                minimum_kernel_version,\
                date_reported,\
                updated_google_devices,\
                updated_nexus_devices,\
                updated_versions,\
                affected_versions,\
                publicly_available,\
                bulletin_type,\
                component_code,\
                component_code_link,\
                date,\
                asb_url,\
                notes\
                ) VALUES (\
                :patch_level,\
                :cve,\
                :references_,\
                :reference_links,\
                :type,\
                :severity,\
                :updated_aosp_versions,\
                :component,\
                :subcomponent,\
                :android_launch_version,\
                :kernel_launch_version,\
                :minimum_launch_version,\
                :minimum_kernel_version,\
                :date_reported,\
                :updated_google_devices,\
                :updated_nexus_devices,\
                :updated_versions,\
                :affected_versions,\
                :publicly_available,\
                :bulletin_type,\
                :component_code,\
                :component_code_link,\
                :date,\
                :asb_url,\
                :notes\
                    )"
        )

    # List of dictionaries 
    cves = []
    field_names = ['patch_level', 'cve', 'references_', 'reference_links', 'type', 'severity', 'updated_aosp_versions', 'component', 'subcomponent', 'android_launch_version', 'kernel_launch_version', 'minimum_launch_version', 'minimum_kernel_version', 'date_reported', 'updated_google_devices', 'updated_nexus_devices', 'updated_versions', 'affected_versions', 'publicly_available', 'bulletin_type', 'component_code', 'component_code_link', 'date', 'asb_url', 'notes']
    # Iterate over all csv files in cleaned_asb_data and create dictionary with field names as keys for each csv
    for file in files_to_read:
        blob = bucket.blob(file)
        with blob.open(mode='r') as csvfile:
            reader = csv.DictReader(csvfile, fieldnames=field_names)
            for row in reader:
                row['patch_level'] = row['date'] + '-' + row['patch_level']

                row['date'] = row['date'] + '-01'
                
                if row['date'] != 'date' and (row['cve'][0:3] == 'CVE'):
                    cves.append(row)    
                if 'pixel' in file:
                    row['bulletin_type'] = "Pixel"  
                else:
                    row['bulletin_type'] = "Android"               
    
    # Connect to MySQL database using SQLAlchemy
    # For each dictionary insert it into asb table
    with pool.connect() as db_conn:
        db_conn.execute(create_table_statement)
        for row in cves:   
            print("Uploading: ", row['cve'])
            # Delete row if it already exists in asb
            db_conn.execute(sqlalchemy.text("DELETE FROM asb WHERE cve = '"+ row['cve'] + "'"))
            db_conn.execute(insert_statement, [{
                'patch_level':row['patch_level'],
                'cve':row['cve'],
                'references_':row['references_'],
                'reference_links':row['reference_links'], 
                'type':row['type'], 
                'severity':row['severity'], 
                'updated_aosp_versions':row['updated_aosp_versions'], 
                'component':row['component'], 
                'subcomponent':row['subcomponent'], 
                'android_launch_version':row['android_launch_version'], 
                'kernel_launch_version':row['kernel_launch_version'], 
                'minimum_launch_version':row['minimum_launch_version'], 
                'minimum_kernel_version':row['minimum_kernel_version'], 
                'date_reported':row['date_reported'], 
                'updated_google_devices':row['updated_google_devices'], 
                'updated_nexus_devices':row['updated_nexus_devices'], 
                'updated_versions':row['updated_versions'], 
                'affected_versions':row['affected_versions'], 
                'publicly_available':row['publicly_available'], 
                'bulletin_type':row['bulletin_type'], 
                'component_code':row['component_code'], 
                'component_code_link':row['component_code_link'], 
                'date':row['date'], 
                'asb_url':row['asb_url'],
                'notes':row['notes']
            }])

    # Close connections to database and Google Cloud
    connector.close()
    client.close()     
    return "Success"


if __name__ == "__main__":
    i = 1
    main(i)