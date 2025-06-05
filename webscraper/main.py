from datetime import datetime
from bs4 import BeautifulSoup
import requests
import csv
import android_bulletin_scraper
import os
from google.cloud import storage
import csv_to_cloud
import functions_framework
import json
from datetime import datetime
import sqlalchemy
from google.cloud.sql.connector import Connector, IPTypes
from google.cloud import secretmanager
from pixel_bulletin_scraper import PixelScraper
import changelog_calculator

PROJECT_ID = "solid-gamma-411111"
SECRET_ID = "darlin98SQL"
VERSION_ID = "1"

# main function to scrape asb on a periodic basis
@functions_framework.http
def main(request):
    client = storage.Client(project="solid-gamma-411111")
    bucket = client.bucket("asb-update-log")

    url_list = android_bulletin_scraper.generate_bulletin_urls()
    available_file_names_in_asb = []
    url_list_patch_level = []

    for url in url_list:
        available_file_names_in_asb.append(url[-10:-3] + "-data")
        url_list_patch_level.append(url[-10:])
    
    blob_names = []

    blobs = client.list_blobs("test-abs-data")
    for blob in blobs:
        blob_names.append(blob.name)

    # print(str(available_file_names_in_asb))
    # print(str(blob_names))

    blobs_to_be_uploaded =[]

    for elem in available_file_names_in_asb:
        if elem not in blob_names:
            blobs_to_be_uploaded.append(elem)
    #print(blobs_to_be_uploaded)

    # scrape the last 12 months of bulletins to update them
    for elem in available_file_names_in_asb[slice(12)]:
        if elem not in blobs_to_be_uploaded:
            blobs_to_be_uploaded.append(elem)
    
    urls_to_be_scraped = []
    for elem in blobs_to_be_uploaded:
        for url in url_list_patch_level:
            if url[:-3] == elem[:-5]:
                urls_to_be_scraped.append(url)

    print(blobs_to_be_uploaded)
    

    file_container = android_bulletin_scraper.get_bulletin_pages(urls_to_be_scraped)

    print("uploading to bucket")
    csv_to_cloud.upload_file_to_cloud("test-abs-data", file_container)

    # scrape_date = datetime.today().strftime('%Y-%m-%d')

    # filename = scrape_date
    # blob = bucket.blob('log.json')
    # with blob.open(mode = "w") as datafile:
    #     j = {"files":blobs_to_be_uploaded,
    #             "process":"web_scrape"}
        
    #     json.dump(j, datafile)

    changelog_calculator.calculate_changelog(file_container, urls_to_be_scraped, blobs_to_be_uploaded)

    ## Handle Pixel Bulletins
    pixel_scraper = PixelScraper()
    PixelScraper.scrape()

    return blobs_to_be_uploaded



if __name__ == "__main__":
    i=1
    main(i)