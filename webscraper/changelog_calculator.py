"""
Enters log of changes into database and uploads JSON file to cloud

Authors: Omay Dogan, Seth Darling
"""

import os
import sqlalchemy
from google.cloud.sql.connector import Connector, IPTypes
from google.cloud import secretmanager
from google.cloud import storage
from datetime import datetime
import json

PROJECT_ID = "solid-gamma-411111"
SECRET_ID = "darlin98SQL"
VERSION_ID = "1"

## Enters log of changes into database
def calculate_changelog(files, patch_levels_scraped, blob_names_scraped, bulletin_type="Android"):
    client = storage.Client(project="solid-gamma-411111")
    bucket = client.bucket("asb-update-log")

    ip_type = IPTypes.PRIVATE if os.environ.get("PRIVATE_IP") else IPTypes.PUBLIC

    connector = Connector(ip_type)

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

    cves_per_date = {}
    new_cves_per_date = {}

    for index, patch_level in enumerate(patch_levels_scraped):
        date = patch_level
        cve_list = []
        for k, row in enumerate(files.files[index]):
            if k == 0:
                continue
            cve_list.append(row[1])
        cves_per_date[date] = cve_list

        with pool.connect() as db_conn:
            results = db_conn.execute(sqlalchemy.text("SELECT cve FROM android_vuln_data WHERE date='" + date + "';"))
        
        set1 = set(cve_list)
        set2 = set([row[0] for row in results])

        new_cves = set1 ^ set2

        added_cves = list(new_cves)
        print('new cve for date ' + date + ': ' + str(added_cves))

        new_cves_per_date[date] = added_cves

    scrape_date = datetime.today().strftime('%Y-%m-%d')

    filename = scrape_date
    if (bulletin_type == "Pixel"):
        blob = bucket.blob('pixel-log.json')
    else:
        blob = bucket.blob('log.json')
    with blob.open(mode = "w") as datafile:
        j = {"files":blob_names_scraped,
                "process":"web_scrape",
                "new_cves":new_cves_per_date}
        
        json.dump(j, datafile)

    with pool.connect() as db_conn:
        db_conn.execute(sqlalchemy.text("INSERT INTO asb_update_log (date) VALUES ('" + scrape_date + "');"))

    