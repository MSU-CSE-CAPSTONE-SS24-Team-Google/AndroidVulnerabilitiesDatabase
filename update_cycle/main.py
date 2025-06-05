"""
main file for the update_cycle process. Updates the SQL table that stores information on start and end dates
for processes.

Author: Brendan Wieferich
"""
import functions_framework
from google.cloud import storage
from google.cloud.sql.connector import Connector
import os
import sqlalchemy
from datetime import date
from google.cloud import secretmanager_v1

PROJECT_ID = "solid-gamma-411111"
SECRET_ID = "wiefer20SQL"
VERSION_ID = "1"

# update the cycle dates in the database for date tracking
@functions_framework.http
def main(request):
    connector = Connector()
    # setup for connection to SQL db
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
    
    # get the most recent end date
    get_last_end_date = sqlalchemy.text("SELECT end_date FROM cycle WHERE active = 1")
    
    with pool.connect() as conn:
        last_end_date = conn.execute(get_last_end_date).fetchall()

    if last_end_date:
        # set up insert statement
        last_end_date = last_end_date[0][0]
        current_date = date.today()
        str_date = current_date.isoformat()

        ins_cycle = sqlalchemy.text("INSERT INTO cycle VALUES (\
        0,\
        DATE('{}'),\
        DATE('{}'),\
        1)".format(last_end_date, str_date)
        )
    else:
        ins_cycle = None

    # statement to set old cycles to inactive
    update_cycle = sqlalchemy.text("UPDATE cycle SET active = 0")

    with pool.connect() as conn:
        # execute update
        conn.execute(get_last_end_date)
        conn.execute(update_cycle)
        conn.execute(ins_cycle)
        result = conn.execute("SELECT * FROM cycle").fetchall()
        print(result)

    # print verification
    #print(get_last_end_date, "\n", ins_cycle, "\n", update_cycle)

    connector.close()