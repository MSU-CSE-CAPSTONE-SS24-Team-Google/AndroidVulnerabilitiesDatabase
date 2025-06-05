from bs4 import BeautifulSoup
import android_bulletin_scraper
import re
import copy

def vaildate(file_container):
    column_names = android_bulletin_scraper.csv_column_headers

    for idx, file in enumerate(file_container.get_files()):
        rows = copy.deepcopy(file) 
        soup = BeautifulSoup(file_container.get_requested_pages()[idx], "html.parser")
        current_file_name = file_container.get_file_names()[idx]

        print("---Validating " + current_file_name + "---")

        # every column must have values in these columns
        # "patch_level", "cve", "component", "date", "asb_url"
        column_must_have_value = [0, 1, 7, 22, 23]

        for i, row in enumerate(rows):
            for col in column_must_have_value:
                if row[col] == None:
                    print("row " + str(i + 2) + ": " + str(column_names[col]) + " column should not have None value!")
        #------------------------

        # check if every cve column is in format 'CVE-dddd'        
        pattern = re.compile('CVE-\d{4}-')

        for i, row in enumerate(rows):
            if re.match(pattern, row[1]) == None:
                print("row " + str(i + 2) + ": doesnt have cve number!")
        #------------------------
                
        # check if every cve number found in the page is included in a row
        pattern = re.compile(r'CVE-\d{4}-\d{2,7}')

        # remove every element that is after the changelog
        versions_h2 = soup.find('h2', attrs={"id": "versions"})
        if versions_h2 != None:
            for elem in versions_h2.find_next_siblings():
                elem.decompose()
        
        versions_h2 = soup.find('h2', attrs={"id": "revisions"})
        if versions_h2 != None:
            for elem in versions_h2.find_next_siblings():
                elem.decompose()
        
        # remove ackowledgements list
        ack_h2 = soup.find('h2', attrs={"id": "acknowledgements"})
        if ack_h2:
            ack_h2.find_next("ul").decompose()
        
        if soup.find('h2', attrs={"id": "announcements"}):
            soup.find('h2', attrs={"id": "announcements"}).find_next("ul").decompose()
        elif soup.find('h3', attrs={"id": "acknowledgements"}):
            soup.find('h3', attrs={"id": "acknowledgements"}).find_next("ul").decompose()
        
        # remove every paragraph
        for elem in soup.find_all("p"):
            elem.decompose()
        
        # remove every element that is a note
        for elem in soup.find_all("aside", attrs={"class": "note"}):
            elem.decompose()

        #for cve_num in re.findall(pattern, file_container.get_requested_pages()[idx]):
        for cve_num in re.findall(pattern, str(soup)):
            cve_found = False
            for i, row in enumerate(rows):
                if row[1] == cve_num:
                    cve_found = True
                    break
            if not cve_found:
                print(cve_num + " was not found in file!")
        #--------------------------
            
        
            
