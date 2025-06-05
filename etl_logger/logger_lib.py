from google.cloud.sql.connector import Connector
import sqlalchemy

def connect(connector):
    def get_connection():
        connection = connector.connect(
            "solid-gamma-411111:us-central1:ss24-teamgoogle",
            "pymysql",
            user="wiefer20",
            password="]r_2~|3G^LblcM_'",
            db="etl-logs"
        )
        return connection
    
    pool = sqlalchemy.create_engine(
            "mysql+pymysql://",
            creator=get_connection,
        )
    
    return pool

# update the etl log table "jobs"
# in: extract_data, the data from the file
# in: status, the status of the last run
# out: a string indicating successful update
def update_logs(extract_data, status):
    process = extract_data["process"]

    ins_jobs = sqlalchemy.text("INSERT INTO jobs VALUES (\
        0,\
        '{}',\
        '{}',\
        CURRENT_TIMESTAMP(),\
        (SELECT id FROM cycle WHERE active = 1)\
        )".format(process, status)
    )
    conn = Connector()
    pool = connect(conn)
    with pool.connect() as db_conn:
        db_conn.execute(ins_jobs)
    conn.close()
    return "Updated with status: {}".format(status)