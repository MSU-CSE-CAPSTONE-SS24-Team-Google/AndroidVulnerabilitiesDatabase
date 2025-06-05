import sqlalchemy
from google.cloud.sql.connector import Connector
import json
from google.cloud import storage
from google.cloud import secretmanager_v1

# Classes that executes code that etl processes use for logging across processes
class logger:
    def __init__(self, connector=Connector, bucket=storage.Client.bucket, 
                 instance_connection_string=str, driver=str, db_name=str,
                 project_id=str, sec_id=str, user=str):
        self.connector = connector
        self.bucket = bucket
        self.pool = None
        self.cycle_year = None
        self.cycle_month = None
        self.instance_connection_string = instance_connection_string
        self.driver = driver
        self.db_name = db_name
        self.password = None
        self.project_id = project_id
        self.sec_id = sec_id
        self.version_id = "1"
        self.user = user

    # get the cycle data from logs
    def get_log_data(self):
        sel_cycle = sqlalchemy.text("SELECT MAX(start_date), MAX(end_date) FROM cycle WHERE active = 1;")
        with self.pool.connect() as db_conn:
            get_cycle = db_conn.execute(sel_cycle).fetchall()
            self.cycle_year = get_cycle[0][1].year
            self.cycle_month = get_cycle[0][1].month
    
    # add new trigger file to activate logging fucntion
    def add_trigger_file(self, file_list, status, process_name):
        # write API response directly to G Cloud bucket
        filename = 'trigger_file.json'
        blob = self.bucket.blob(filename)
        with blob.open(mode = "w") as datafile:
            j = {"files":file_list,
                 "status":"{}",
                 "process":"{}".format(process_name),
                 "cycle":"{}-{}".format(status, self.cycle_year, self.cycle_month)}
            json.dump(j, datafile)

    # get and store the credentials for the service
    def get_credentials(self):
        secret_client = secretmanager_v1.SecretManagerServiceClient()
        name = f"projects/{self.project_id}/secrets/{self.sec_id}/versions/{self.version_id}"
        response = secret_client.access_secret_version(name=name)
        self.password = response.payload.data.decode('UTF-8')
    
    # Get connection to google cloud sql db
    def get_connection(self):
        connection = self.connector.connect(
            self.instance_connection_string,
            self.driver,
            user=self.user,
            password=self.password,
            db=self.db_name
        )
        return connection


    # create resource pool for sql queries
    def create_pool(self):
        self.pool = sqlalchemy.create_engine(
            "mysql+pymysql://",
            creator=self.get_connection,
        )