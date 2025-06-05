# Author: Alessandro Bocchi <bocchial@msu.edu> and Trey Cosnowski <cosnows4@msu.edu>
from flask import current_app as app
from flask import render_template, redirect, request, jsonify
from flask_cors import CORS
import csv
from werkzeug.datastructures import ImmutableMultiDict
from pprint import pprint
import json
import random
import mysql.connector
import sqlalchemy
import logging
import os
from dataclasses import dataclass
from google.analytics.data_v1beta import BetaAnalyticsDataClient
from google.analytics.data_v1beta.types import (
    DateRange,
    Dimension,
    Metric,
    Filter,
    FilterExpression,
    MetricType,
    RunReportRequest,
)

CORS(app)
CORS(app, resources={r"/api/*": {"origins": "https://web-app-tg6ur4q5ua-uc.a.run.app"}})

# MySQL configuration [change]
db_config = {
	'host': '34.41.151.234',
	'user': 'bocchial',
	'password': 'password',
	'database': 'nvd-data'
}

db_config_asb = {
	'host': '34.41.151.234',
	'user': 'cosnows4',
	'password': 'pass',
	'database': 'vulnerabilities'
 
}


db_user = "bocchial"  
db_pass = "password"  
db_name = "vulnerabilities"
instance_connection_name = "/cloudsql/solid-gamma-411111:us-central1:ss24-teamgoogle"

db = sqlalchemy.create_engine(
    # Equivalent URL:
    # mysql+pymysql://<db_user>:<db_pass>@/<db_name>?unix_socket=<socket_path>/<cloud_sql_instance_name>
    sqlalchemy.engine.url.URL.create(
        drivername="mysql+pymysql",
        username=db_user,
        password=db_pass,
        database=db_name,
        query={"unix_socket": instance_connection_name},
    ),
)




custom_query_cols = ["baseScoreMax", "baseScoreMin", "start_date", "end_date", "severity", "exploitabilityScoreMin", "exploitabilityScoreMax", "impactScoreMin", "impactScoreMax", "patchLevel"]




@app.route('/')
def root():
	return redirect('/home')

@app.route('/home')
def home():
	# users = User.query.all()
	return render_template('home.html')

@app.route('/vulnerability')
def vulnerability():
	return render_template('vulnerabilityIndex.html')


@app.route('/vulnerabilityPage')
def vulnerabilityPage():
	return render_template('vulnerabilityPage.html')


@app.route('/api/baseurl', methods=['GET'])
def get_base_url():
    base_url = request.base_url
    return jsonify({'base_url': base_url})

## CVE-2022-47421
@app.route('/api/nvd_data/<string:cve_id>', methods=['GET'])
def get_nvd_data(cve_id: str):
    # Fetch data from the MySQL database 
    cve_id = sanitize_sql_string(cve_id)
    with db.connect() as db_conn:
        results = db_conn.execute(sqlalchemy.text(f"SELECT * FROM nvd_data WHERE cve_id = '{cve_id}'")).fetchall()
        sqlalchemy.union_all()
        return jsonify({'results': [dict(row) for row in results]})

@app.route('/api/vulnerabilities/<string:cve>', methods=['GET'])
def get_asb_data(cve: str):
    # CVE-2021-31345 works
    # CVE-2020-29374 does not work
    #  gcloud sql connect ss24-teamgoogle --user=<user> to connect to db
    # connection = mysql.connector.connect(**db_config_asb)
    # cursor = connection.cursor()
    # sql_statement = f"SELECT * FROM asb WHERE cve = '{cve}'"
    
    # cursor.execute(sql_statement)
    # data = cursor.fetchall()
    cve = sanitize_sql_string(cve)
    with db.connect() as db_conn:
        results = db_conn.execute(sqlalchemy.text(f"SELECT * FROM android_vulnerability_data WHERE cve = '{cve}'")).fetchall()
        return jsonify({'results': [dict(row) for row in results]})

@app.route('/api/data')
def get_data():
    # connection = mysql.connector.connect(**db_config_asb)
    # cursor = connection.cursor(dictionary=True)
    # sql_statement = f"SELECT * FROM vulnerabilities_data"
    
    # cursor.execute(sql_statement)
    # data = cursor.fetchall()
    
    with db.connect() as db_conn:
        results = db_conn.execute(sqlalchemy.text("SELECT * FROM android_vulnerability_data")).fetchall()
        return jsonify({'results': [dict(row) for row in results]})

@app.route('/api/vulnerabilities/merged_data/<string:cve>')
def get_merged_data_by_cve(cve):
    # connection = mysql.connector.connect(**db_config_asb)
    # cursor = connection.cursor(dictionary=True)
    # sql_statement = f"SELECT * FROM vulnerabilities_data WHERE cve = '{cve}'"
    
    # cursor.execute(sql_statement)
    # data = cursor.fetchall()
    cve = sanitize_sql_string(cve)
    with db.connect() as db_conn:
        results = db_conn.execute(sqlalchemy.text(f"SELECT * FROM android_vulnerability_data WHERE cve = '{cve}'")).fetchall()
        notes_result = db_conn.execute(sqlalchemy.text(f"SELECT * FROM asb WHERE cve = '{cve}'")).fetchall()

        result_list = [dict(row) for row in results]
        if notes_result[0]['notes'] != None:
            result_list[0]['note'] = notes_result[0]['notes']

        return jsonify({'results': [dict(row) for row in result_list]})

@app.route('/api/vulnerabilities/merged_data/<string:start_date>&<string:end_date>', methods=['GET'])
def get_merged_data_based_on_date_range(start_date: str, end_date: str):
    # connection = mysql.connector.connect(**db_config_asb)
    # cursor = connection.cursor(dictionary=True)
    # sql_statement = f"SELECT * FROM vulnerabilities_data WHERE date between '{start_date}' AND '{end_date}'"
    
    # cursor.execute(sql_statement)
    # data = cursor.fetchall()
    start_date = sanitize_sql_string(start_date)
    end_date = sanitize_sql_string(end_date)
    with db.connect() as db_conn:
        results = db_conn.execute(sqlalchemy.text(f"SELECT * FROM android_vulnerability_data WHERE date between '{start_date}' AND '{end_date}'")).fetchall()
        return jsonify({'results': [dict(row) for row in results]})

# @app.route('/api/vulnerabilities/<string:start_date>&<string:end_date>', methods=['GET'])
# def get_cves_based_on_date_range(start_date: str, end_date: str):
#     # connection = mysql.connector.connect(**db_config_asb)
#     # cursor = connection.cursor()
#     # sql_statement = f"SELECT * FROM asb WHERE date between '{start_date}' AND '{end_date}'"
    
#     # cursor.execute(sql_statement)
#     # data = cursor.fetchall()
    
#     with db.connect() as db_conn:
#         results = db_conn.execute(sqlalchemy.text(f"SELECT * FROM asb WHERE date between '{start_date}' AND '{end_date}'")).fetchall()
#         return jsonify({'results': [dict(row) for row in results]})

@app.route('/api/vulnerabilities/<string:start_date>/<string:end_date>/<string:field>', methods=['GET'], endpoint='filteredData')
def get_cves_based_on_date(start_date: str, end_date: str, field: str):
    # connection = mysql.connector.connect(**db_config_asb)
    # cursor = connection.cursor()
    # if field == "none":
    #     sql_statement = f"SELECT * FROM vulnerabilities_data WHERE date between '{start_date}' AND '{end_date}'"
    # else:
    #     sql_statement = f"SELECT * FROM vulnerabilities_data WHERE date between '{start_date}' AND '{end_date}' AND "
    
    # cursor.execute(sql_statement)
    # data = cursor.fetchall()
    start_date = sanitize_sql_string(start_date)
    end_date = sanitize_sql_string(end_date)
    with db.connect() as db_conn:
        results = db_conn.execute(sqlalchemy.text(f"SELECT * FROM android_vulnerability_data WHERE date between '{start_date}' AND '{end_date}'")).fetchall()
        return jsonify({'results': [dict(row) for row in results]})
    
@app.route('/api/vulnerabilities/<string:baseScoreMin>/<string:baseScoreMax>', methods=['GET'])
def get_cves_based_on_base_score(baseScoreMin: str, baseScoreMax: str):   
    baseScoreMin = float(baseScoreMin)
    baseScoreMax = float(baseScoreMax)
    with db.connect() as db_conn:
        results = db_conn.execute(sqlalchemy.text(f"SELECT * FROM android_vulnerability_data WHERE base_score between {baseScoreMin} AND {baseScoreMax}")).fetchall()
        return jsonify({'results': [dict(row) for row in results]})
    
@app.route('/api/vulnerabilities/custom/<string:param>', methods=['GET'])
def get_cves_based_on_customQuery(param: str): 
    
    param: dict = json.loads(param)
    query = f"SELECT * FROM android_vulnerability_data"
    where = False
    
    bulletin_types = []

    patchLevels = []

    sanitized_dict = {key: sanitize_sql_string(value) for key, value in param.items()}
    orderString = f""

    for key, value in sanitized_dict.items():
        if value is not None:  
            if key == "baseScoreMax":
                if where:
                    query += f" AND base_score between {float(param[key])} AND {float(param['baseScoreMax'])}"
                else:
                    where = True
                    query += f" WHERE base_score between {float(param['baseScoreMin'])} AND {float(param['baseScoreMax'])}"
            
            elif key == "start_date":
                if param["start_date"] == param["end_date"]:
                    if where:
                        query += f" AND date = '{param['start_date']}-01'"                                                
                    else:
                        where = True
                        query += f" WHERE date = '{param['start_date']}-01'"
                else:
                    if where:
                        query += f" AND date between '{param['start_date']}' AND '{param['end_date']}'"                                                
                    else:
                        where = True
                        query += f" WHERE date between '{param['start_date']}' AND '{param['end_date']}'"
            
            elif key == "severity":
                if where:
                    query += f" AND severity = '{param['severity']}'"
                else:
                    where = True
                    query += f" WHERE severity = '{param['severity']}'"

            elif key == "exploitabilityScoreMax":
                if where:
                    query += f" AND exploitability_score between '{param['exploitabilityScoreMin']}' AND '{param['exploitabilityScoreMax']}'"                                                
                else:
                    where = True
                    query += f" WHERE exploitability_score between '{param['exploitabilityScoreMin']}' AND '{param['exploitabilityScoreMax']}'"

            elif key == "impactScoreMax":
                if where:
                    query += f" AND impact_score between '{param['impactScoreMin']}' AND '{param['impactScoreMax']}'"                                                
                else:
                    where = True
                    query += f" WHERE impact_score between '{param['impactScoreMin']}' AND '{param['impactScoreMax']}'"

            elif key == "patchLevel01" or key == "patchLevel02" or key == "patchLevel05" or key == "patchLevel06":
                patchLevels.append(value)

            elif key == "component":
                if where:
                    query += f" AND component = '{param['component']}'"                                                
                else:
                    where = True
                    query += f" WHERE component = '{param['component']}'" 

            elif key == "androidOS":
                bulletin_types.append('Android OS')

            elif key == "pixel":
                bulletin_types.append('Pixel')


  

    if patchLevels:
        patchLevelString = f"("
        for i, patchLevel in enumerate(patchLevels):
            if i == len(patchLevels)-1:
                patchLevelString += f"'{patchLevel}')"
            else:
                patchLevelString += f"'{patchLevel}',"
        if where:
            query += f" AND SUBSTRING(patch_level,9,2) IN {patchLevelString}"
        else:
            where = True
            query += f" WHERE SUBSTRING(patch_level,9,2) IN {patchLevelString}"
    
    if bulletin_types:
        bulletinTypesString = f"("
        for i, bulletinType in enumerate(bulletin_types):
            if i == len(bulletin_types)-1:
                bulletinTypesString += f"'{bulletinType}')"
            else:
                bulletinTypesString += f"'{bulletinType}',"
        if where:
            query += f" AND bulletin_type IN {bulletinTypesString}"
        else:
            query += f" WHERE bulletin_type IN {bulletinTypesString}"

    if "order" in sanitized_dict:
        if sanitized_dict["orderDirection"] == "ascending":
            query += f"ORDER BY {sanitized_dict['order']}"
        else:
            query += f"ORDER BY {sanitized_dict['order']} DESC"


    with db.connect() as db_conn:
        results = db_conn.execute(sqlalchemy.text(query)).fetchall()
        return jsonify({'results': [dict(row) for row in results]})
    

@app.route('/api/vulnerabilities/multiple_cves', methods=['GET'])
def get_multiple_cves():
    cves = request.args.getlist('cve')
    results = []
    with db.connect() as db_conn:
        for cve in cves:
            query = sqlalchemy.text(f"SELECT * FROM android_vulnerability_data WHERE cve = '{cve}'")
            result = db_conn.execute(query).fetchall()
            for row in result:
                results.append(dict(row))           
    return jsonify({'results': results})

def sanitize_sql_string(value):
    # replace single quotes with double single quotes to break harmful sql code
    # for example '; DROP TABLE vulnerabilities_data;
    value.replace("'", "''")
    return value

@app.route('/api/vulnerabilities/components', methods=['GET'])
def get_components(): 
    with db.connect() as db_conn:
        query = "SELECT DISTINCT component FROM android_vulnerability_data"
        results = db_conn.execute(sqlalchemy.text(query)).fetchall()
        return jsonify({'results': [dict(row) for row in results]})
    


@app.route('/api/analytic_data/trendingCVEs', methods=['GET'])
def get_trending_pages():
    """Runs a simple report on a Google Analytics 4 property."""
    
    
    client = BetaAnalyticsDataClient()

    request = RunReportRequest(
        property=f"properties/431979354",
        dimensions=[Dimension(name="fullPageUrl")],
        metrics=[Metric(name="screenPageViews")],
        date_ranges=[DateRange(start_date="2020-03-31", end_date="today")],
    )
    
    response = client.run_report(request)
    
    json_data = {
        "row_count": response.row_count,
        "dimension_headers": [],
        "metric_headers": [],
        "rows": []
    }
    
    for dimensionHeader in response.dimension_headers:
        json_data["dimension_headers"].append({"name": dimensionHeader.name})

    for metricHeader in response.metric_headers:
        metric_type = MetricType(metricHeader.type_).name
        json_data["metric_headers"].append({"name": metricHeader.name, "type": metric_type})

    for rowIdx, row in enumerate(response.rows):
        row_data = {"dimensions": {}, "metrics": {}}

        for i, dimension_value in enumerate(row.dimension_values):
            dimension_name = response.dimension_headers[i].name
            row_data["dimensions"][dimension_name] = dimension_value.value

        for i, metric_value in enumerate(row.metric_values):
            metric_name = response.metric_headers[i].name
            row_data["metrics"][metric_name] = metric_value.value

        json_data["rows"].append(row_data)
        
    
    json_response = json.dumps(json_data, indent=4)
    
    return json_response
    
@app.route('/api/vulnerabilities/noBaseScore/<string:cve>', methods=['GET'])
def get_bad_cves(cve: str):
    with db.connect() as db_conn:
        query = f"SELECT vuln_status FROM bad_cves WHERE cve_id = '{cve}'"
        results = db_conn.execute(sqlalchemy.text(query)).fetchall()
        return jsonify({'results': [dict(row) for row in results]})


@app.route('/api/analytic_data/asb_update_log', methods=['GET'])
def get_asb_update_log():
    with db.connect() as db_conn:
        query = f"SELECT * from asb_update_log"
        results = db_conn.execute(sqlalchemy.text(query)).fetchall()
        return jsonify({'results': [dict(row) for row in results][0]})

    
                   
    


    


