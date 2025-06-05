"""
Webscraper class for Pixel Security Bulletins

Authors: Seth Darling, Omay Dogan
"""

from bs4 import BeautifulSoup
import requests
import csv
import io
import android_bulletin_scraper
import changelog_calculator
from google.cloud import storage


MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November",
          "December"]

csv_column_headers = ["patch_level", "cve", "references", "reference_links", "type", "severity",
                              "updated aosp versions", "component", "subcomponent", "android launch version",
                              "kernel launch version", "minimum launch version", "minimum kernel version",
                              "date reported", 
                              "updated google devices", "updated nexus devices",
                              "updated versions", "affected versions", "not publicly available", "bulletin type","component code", "component code link", "date", "asb_url", "notes"]

class PixelScraper:
    def scrape(self):
        ## Get list of pixel bulletin urls
        url_list = self.generate_pixel_bulletin_urls()


        client = storage.Client(project="solid-gamma-411111")
        bucket = client.get_bucket('test-abs-data')

        available_file_names_in_asb = []
        url_list_patch_level = []

        for url in url_list:
            available_file_names_in_asb.append(url[-10:-3] + "-data-pixel")
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
                if url[:-3] == elem[:-11]:
                    urls_to_be_scraped.append(url)

        #print(urls_to_be_scraped)
        
        file_container = android_bulletin_scraper.CSVFiles()
        for url in urls_to_be_scraped:
            url = "/docs/security/bulletin/pixel/" + url
            ## For each url use BeuatifulSoup to parse html
            targetPage = requests.get("https://source.android.com" + url)
            soup = BeautifulSoup(targetPage.text, "html.parser")
            patch_id = url[-10:-3]
            print(patch_id)

            ## Add file for patch
            file_container.add_file(patch_id + "-data-pixel", targetPage.text)
            ## Headers that CVE table could be under
            possible_header_ids_1 = ["patches", "security-patches", "Security-patches"]
            patch = ""
            ## Ensures bulletin has patches as some do not
            for header in possible_header_ids_1:
                patch = soup.find("h2", attrs={"id": header})
                if patch is not None:
                    print(patch)
                    break
            if patch is None:
                print("No patches")    

            ## Writes csv file from table of CVE patches
            if patch is not None:
                android_bulletin_scraper.write_patch_level_tables("01", patch, file_container, csv_column_headers, patch_id, url, soup)

        ## Connect to Google Cloud Bucket and clean and upload csv files
        client = storage.Client(project="solid-gamma-411111")
        bucket = client.get_bucket('test-abs-data')
        for csv_file, file_name in zip(file_container.get_csv_files(),file_container.get_file_names()):
            
            blob = bucket.blob(file_name)
            blob.upload_from_string(csv_file) 
        changelog_calculator.calculate_changelog(file_container, urls_to_be_scraped, blobs_to_be_uploaded, "Pixel") 

    ## Generates python list of urls for all Pixel Security Bulletins
    def generate_pixel_bulletin_urls(self):
        website = "https://source.android.com/docs/security/bulletin"
        result = requests.get(website)
        content = result.text  # Gets the content of the website

        soup = BeautifulSoup(content, 'html.parser')
        box = soup.find("span", class_="devsite-nav-text", string="Bulletins Home").parent.parent.parent.find_all \
            ("a", class_="devsite-nav-title gc-analytics-event")
        url_list = []
        ## Narrow down list of all bulletin urls to those for Pixel
        for url in box:
            if url.get_text() == "Pixel":
                break
            if url.get_text() in MONTHS:
                href = url.get("href")
                if "pixel" in href and "watch" not in href:
                    url_list.append(href)
        return url_list              

def main():
    scraper = PixelScraper()
    scraper.scrape()


if __name__ == "__main__":
    main()