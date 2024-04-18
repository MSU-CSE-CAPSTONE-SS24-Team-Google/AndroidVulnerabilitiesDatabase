# CSE498-TeamGoogle-SS24

NOTICE: This product uses the NVD API but is not endorsed or certified by the NVD.

## Getting started

To make it easy for you to get started with GitLab, here's a list of recommended next steps.

## Deploying flask website locally
Use docker-compose to host the web application locally by executing the following command from a terminal:
This is the Flask API website. Deploy locally with a docker-compose to use the API locally.

```
docker-compose -f docker-compose.yml -p teamgoogle-android-vulnerability-database up
```
## Deploying website to GCLOUD
Deploy your Dockerized App to Google Cloud by running the commands below
```
gcloud builds submit --tag gcr.io/solid-gamma-411111/web-app

gcloud run deploy --image gcr.io/solid-gamma-411111/web-app --platform managed

gcloud app deploy --project=solid-gamma-411111
```
When prompted for service name, press enter.
When prompted for the region choose us-central1
When prompted regarding unauthenticated invocations choose  y


## Add your files

- [ ] [Create](https://docs.gitlab.com/ee/user/project/repository/web_editor.html#create-a-file) or [upload](https://docs.gitlab.com/ee/user/project/repository/web_editor.html#upload-a-file) files
- [ ] [Add files using the command line](https://docs.gitlab.com/ee/gitlab-basics/add-file.html#add-a-file-using-the-command-line) or push an existing Git repository with the following command:

```
cd existing_repo
git remote add origin https://gitlab.msu.edu/wiefer20/cse498-teamgoogle-ss24.git
git branch -M main
git push -uf origin main
```

## Integrate with your tools

- [ ] [Set up project integrations](https://gitlab.msu.edu/wiefer20/cse498-teamgoogle-ss24/-/settings/integrations)

## Collaborate with your team

- [ ] [Invite team members and collaborators](https://docs.gitlab.com/ee/user/project/members/)
- [ ] [Create a new merge request](https://docs.gitlab.com/ee/user/project/merge_requests/creating_merge_requests.html)
- [ ] [Automatically close issues from merge requests](https://docs.gitlab.com/ee/user/project/issues/managing_issues.html#closing-issues-automatically)
- [ ] [Enable merge request approvals](https://docs.gitlab.com/ee/user/project/merge_requests/approvals/)
- [ ] [Set auto-merge](https://docs.gitlab.com/ee/user/project/merge_requests/merge_when_pipeline_succeeds.html)

## Test and Deploy

Use the built-in continuous integration in GitLab.

- [ ] [Get started with GitLab CI/CD](https://docs.gitlab.com/ee/ci/quick_start/index.html)
- [ ] [Analyze your code for known vulnerabilities with Static Application Security Testing (SAST)](https://docs.gitlab.com/ee/user/application_security/sast/)
- [ ] [Deploy to Kubernetes, Amazon EC2, or Amazon ECS using Auto Deploy](https://docs.gitlab.com/ee/topics/autodevops/requirements.html)
- [ ] [Use pull-based deployments for improved Kubernetes management](https://docs.gitlab.com/ee/user/clusters/agent/)
- [ ] [Set up protected environments](https://docs.gitlab.com/ee/ci/environments/protected_environments.html)

***




## Name
Android Vulnerability Database

## Description
Compile Android Security Bulletin and National Vulnerability Database vulnerabilities into one place​

Enable OEMs to identify high priority security vulnerabilities​

Easy to use web-application utilizing our API to allow users to query vulnerabilities​


## Installation
Angular Frontend App:
    This project uses Angular to power the frontend of our web application
    Use this links to follow the instructions on how to set up Angular: https://angular.io/guide/setup-local
    Build the Angular App: Change your directory to the one that has the Angular App and type into the console ng build
    Start Agnualr App: Change your directory to the one that has the Angular App and type into the console ng serve

Flask Backend:
    This project uses Flask to power the backend of our web application
    Pyhton Download: https://www.python.org/downloads/
    Our app uses local host and cloud to run the backend

        Cloud Deploy: Please see the Google Cloud section for how to deploy
        Local Deploy: Use Docker locally deploy the backend

## Usage
Use Case 1: A OEM of Android need to upgrade to patch level 2020-01-01 from patch level 2020-04-01. What are the patches we need to incorporate in between those patch levels? 

Use Case 2: A company's Android devices run the latest security patch, but we need to check for vulnerabilities with a CVSS score above 9 introduced after this patch.

Use Case 3: Researchers can access a press release about a specific vulnerability by typing its CVE number into a search bar. This allows them to learn more about the vulnerability. 



## Authors and acknowledgment
Alex Bocchi : bocchial@msu.edu
Trey Cosnowski : cosnows4@msu.edu
Seth Darling : darlin98@msu.edu
Omay Dogan : doganoma@msu.edu
Frederick Fan : fanfrede@msu.edu
Brendan Wieferich : wiefer20@msu.edu

## Project status
This project was completed the MSU Capstone Team Google

## ETL Processes

All ETL processes are designed to be run with a serverless architechture utilizing Google Cloud Functions. Serverless architechture was chosen because of it's cost-effectiveness for low frequency scripts such as these, plus the ability to work on each component in isolation.

As such each part of the process is deployed individually using Google Cloud Build, and are contained within their own subdirectories within the codebase. They are setup such that external dependencies are minimal. The intent of this design is to make the processes easy to refactor for use on other platforms. 

IMPORTANT: The SQL processes within this project are built using MySQL dialect. If you wish to use a different SQL dialect you may need to adjust SQL syntax.

Note on requirements.txt files:
The serverless architechture requires a requirements.txt file for each directory that is deployed as a function in Google Cloud Functions. Removal of these files or failure to update them upon adding a new library will cause a failure during deployment. All libraries used in that process and all dependencies that are not built in must be included.

The processes requires a working SQL database such as a Google Cloud hosted SQL server, and a Cloud storage solution such as Google Cloud Storage. Our solution utilizes Google Cloud Platform. You need only to change the names to your own, or set them up such that the names line up.

Primary ETL processes are contained in the following directories:
- nvd_data_extract: extracts and stores data from the NVD database and stores it as dated json files in a google storage bucket.
- nvd_data_transform: transforms the json formatted NVD data in the stored files and stores the data in a MYSQL database hosted on Google Cloud.
- webscraper: scrapes the Android Security Bulletins webpage and stores the data in csv files to a Google Cloud Storage bucket.
- asb_data_upload: transforms the csv formatted Android Security Bulletins data in the stored files and stores the data in a MYSQL database hosted on Google Cloud.
- data_merge: performs left outer join on the Android Security Bulletins data table and the NVD data table, with the left table being the Android Security Bulletins table. All data from the Android Security Bulletins will be included in the final dataset. This way all available information for the Android Security Bulletins will be present regardless if the NVD has analysed the data at that point.

Supporting processes:
- update_cycle: updates a table in the SQL database which stores information on the date ranges for ETL processes
- asb_data_patching: goes through the merged data set after completion of the merge and cross checks the records with the data in the NVD. The tables are then patched where appropriate.
- etl_logger: Listens for a Pub/Sub event and reads the files that are dropped by the logger class in ETL processes. Records the status of ETL process runs to track successes and failures. This functionality currently only applies to NVD processes and the merge process.

The functions are set to be invoked by http request, and are managed by a combination of cloud scheduler and the pulling and pushing of specfic data to specific sources. This is handled by the logger class, which is present in each of the primary ETL processes. There is also supporting infrastructure that helps the scripts communicate with each other. This is one limitation that comes with the serverless architechture that requires some workarounds. 

Below is an a description of how the processes should be run.

NVD processes:
1. Run update_cycle process. Updates the cycle table so that downstream processes know the date ranges we are extracting.
2. Run nvd_data_extract. Reads the cycle table and executes. Upon completion drops a file in a designatated storage bucket that contains a success or failure message, and a list of files that down stream process need to read.
3. Run nvd_data_transform. Reads the aforementioned file to determine if the precceding process was successful and if so, reads the file list and then executes on those files.

ASB processes:
1. Run webscraper. Scrapes the Android Seccurity Bulletins for the past year's data. Upon completion drops a file in a designatated storage bucket that contains a success or failure message, and a list of files that down stream process need to read.
2. Run nvd_data_transform. Reads the aforementioned file to determine if the precceding process was successful and if so, reads the file list and then executes on those files.

Merge processes:
1. Run only after NVD processes and ASB processes have been run through to completion
2. Run the merge process.
3. Run asb_data_patching.

Notes on the API key:
Request your own API key here: https://nvd.nist.gov/developers/request-an-api-key
It is recommended that you aquire an API key and store it using a secret manager. The project uses Google Cloud's Secret Manager by default. You will need to set this up for your project.

Notes on connecting to SQL databases:
We also use Google Cloud's Secret Manager to store the passwords for the project's connections. 

Notes on credentials:
The scripts are meant to be run within Google Cloud, and uses the default credentials for the project environment. If you want to test the files locally for testing purposes you will need to aquire a credentials json file and append it to the PATH. As such, no access is available without this file if run locally. You will not be able to run the scripts out of the box.
Example:
PATH = os.path.join(os.getcwd(), 'path\to\your\credentials.json')
os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = PATH

Deployment:
Create a Google cloud function named as desired. It is recommended that you use an http request to invoke the function because the Pub/Sub option imposes strict time limits on functions. You will need to set up Cloud build and connect it to you repository. You will need a cloudbuild.yml file.
Example of what to put in the cloudbuild.yml file to deploy:
  # deploy merge
  - name: "gcr.io/cloud-builders/gcloud"
    args: 
      - functions
      - deploy
      - asb-nvd-data-merge
      - --source=./data_merge/

How to execute:
Our solution utilizes Google Cloud Scheduler to orchestrate the execution of processes. They are invoked using http requests.

Notes on logger class:
Due to the limits of serverless architechture, this class is seen in several places in ETL processes. However, it is also present in it's own directory and there is a setup.py file in the outermost directory that can be used to package the logger class. You can add this package to to an appropriate private location such as Google Artifacts Registry for example. This will allow you to use the package as an importable library, and update that code in isolation. The packagable version has been abstracted out to be as generic as possible.