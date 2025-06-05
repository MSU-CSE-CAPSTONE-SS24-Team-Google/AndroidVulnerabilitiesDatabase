'''
    Cleans the csv files data so that each row's values are formatted correctly and error fixes some columns
    @return
        Cleaned list of all of the vulnerabilities for that date
    
    Author: Trey Cosnowski and Omay Dogan
'''

import csv
import copy
import io

def clean_csv(csv_file):
    #csv_list_temp = csv_file.split("\r\n")

    csv_rows = copy.deepcopy(csv_file)   
       
    
    # Fix data errors for multiple cves
    # Will need this in revised csv cleaner version
    for j, row in enumerate(csv_rows):
        saved_cve = ""
        try:    
            if len(row[1].split(",")) > 1:
                for i, cve in enumerate(row[1].split(",")):
                    cve = cve.strip(" ")
                    if "CVE" in cve:
                        if i == 0:
                            saved_cve = cve
                            
                        else:
                            next_row = copy.deepcopy(row)
                            next_row[1] = cve
                            csv_rows.append(next_row)
                        
                row[1] = saved_cve
                
            csv_rows[j][1] = row[1].strip()
            
        except IndexError:
            continue
        
    # Fix data errors with multiple Bugs with AOSP links
    # The error that we talking about in class, delete the row if the CVE column has ANDROID-####
    # Delete the cols that dont hace CVE-##### as the 1 index
    saved_cve_row = {}
    for i,row in enumerate(csv_rows):
        if row[1][:3] == "CVE":
            saved_cve_row.clear()
            for j, val in enumerate(row):
                if val != 'None':
                    saved_cve_row[j] = val
        elif row[1] == "None" and row[7] == saved_cve_row[7]:
            saved_ref = row[1]
            for j, val in enumerate(row):
                if val == 'None' and j in saved_cve_row:
                    csv_rows[i][j] = saved_cve_row[j]
                                     
    # Fix data so that there is only 1 reference per cve
    for i, row in enumerate(csv_rows):
        if len(row[2]) >= 1 and i != 0 and row[2] != "None":
            new_ref = ""
            extra_ref = []
            for j, val in enumerate(row[2][0].split()):
                if val[:1] != "A":
                    if val:
                        val = val.replace("[","").replace(']','').replace(",",'')
                        extra_ref.append(val)
                else:
                    new_ref = val
            csv_rows[i][2] = new_ref
            if extra_ref:
                csv_rows[i][-5] = extra_ref
            
            new_ref_links = {}
            for key, val in row[3].items():
                if key[:1] != "A":
                    if val:
                        if isinstance(csv_rows[i][-4], str):
                            temp_dict = {}
                            temp_dict[key] = val
                            csv_rows[i][-4] = temp_dict
                            
                        elif isinstance(csv_rows[i][-4], dict):
                            csv_rows[i][-4][key] = val
                else:
                    new_ref_links[key] = val
                        
            csv_rows[i][3] = new_ref_links
            
        elif len(row[2]) == 1:
            csv_rows[i][2] = row[2][0]
            
            
    
     # Remove a row if there is not a cve or reference
    temp_rows = []
    for i, row in enumerate(csv_rows):
        if not row[1] and not row[2]:
            continue
        elif row[1][:3] != "CVE" and not row[2]:
            continue
        else:
            temp_rows.append(row)
            
    csv_rows.clear()
    csv_rows = copy.deepcopy(temp_rows)
    
    final_csv_rows = []
    # Clean Data (Strips all of the unwanted characters)    
    for j, row in enumerate(csv_rows):
        
        for i, value in enumerate(row):
            if i == 3 and not value:
                csv_rows[j][i] = "None"

            elif i == 7:
                csv_rows[j][i] = value.replace("\n", " ")
                
            else:
                try:
                    csv_rows[j][i] = value.replace("'\'","").replace('"',"").replace("'","").replace("\n","").replace("\t","").strip()
                except AttributeError:
                    if isinstance(value, list):
                        for k, ele in enumerate(value):
                            csv_rows[j][i][k] = ele.replace("'\'","").replace('"',"").replace("'","").replace("\n","").replace("\t","").strip() 
                            
                    elif isinstance(value, dict):
                        cleaned_dict = {}
                        for key, val in value.items():
                            key_new = key.replace("'\'","").replace('"',"").replace("'","").replace("\n","").replace("\t","").strip()
                            val_new = val.replace("'\'","").replace('"',"").replace("'","").replace("\n","").replace("\t","").strip()
                            cleaned_dict[key_new] = val_new
                        
                        csv_rows[j][i] = cleaned_dict
        if csv_rows[j][1] != "None":
            final_csv_rows.append(copy.deepcopy(csv_rows[j]))
                        
   
       

    return final_csv_rows      
        