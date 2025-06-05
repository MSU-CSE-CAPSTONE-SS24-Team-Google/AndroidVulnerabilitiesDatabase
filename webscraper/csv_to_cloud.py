from google.cloud import storage
import os
import android_bulletin_scraper

# os.environ[
#     "GOOGLE_APPLICATION_CREDENTIALS"] = "/Users/treycosnowskidev/.config/gcloud/application_default_credentials.json"

def upload_file_to_cloud(bucket, file_container):
    client = storage.Client(project="solid-gamma-411111")
    bucket = client.bucket(bucket)

    file_container.clean_files()
    
    for csv_file, file_name in zip(file_container.get_csv_files(),file_container.get_file_names()):
        blob = bucket.blob(file_name)
        blob.upload_from_string(csv_file)


def main_test():
    # client = storage.Client(project="solid-gamma-411111")
    #bucket = client.bucket('android-vulnerabilities-data')
    # bucket = client.bucket('test-abs-data')
    # bucket = client.bucket('cleaned_asb_data')
    
    # use this to scrape every bulletin
    # file_container = android_bulletin_scraper.main_test()
    
    # use this to scrape and upload a specific bulletin
    file_container = android_bulletin_scraper.get_bulletin_page("https://source.android.com/docs/security/bulletin/2018-06-01", "2018-06")

    file_container.clean_files()
    #file_container.write_to_local()

    file_container.validate()
    
    return
    for csv_file, file_name in zip(file_container.get_csv_files(),file_container.get_file_names()):
        
        blob = bucket.blob(file_name)
        blob.upload_from_string(csv_file)

    

if __name__ == "__main__":
    main_test()
    

