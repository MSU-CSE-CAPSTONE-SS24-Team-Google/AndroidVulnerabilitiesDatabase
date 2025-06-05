#!/bin/bash

#Iterates over all files in bucket and imports them to sql database
#Author: Seth Darling
for bulletin in $(gcloud storage ls --recursive gs://cleaned_asb_data/**)
do
    gcloud sql import csv ss24-teamgoogle $bulletin --database=vulnerabilities --table=asb
done     
