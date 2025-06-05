'''
    Goes through all of the dates from the Android Securtiy Bulletin and scrapes all of the data from each vulnerability

    Author: Trey Cosnowski and Omay Dogan
'''

from bs4 import BeautifulSoup
import requests
import csv
import io
from csv_cleaner import clean_csv
import data_validation

MONTHS = ["January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November",
          "December"]


class CSVFiles:
    def __init__(self):
        self.file_names = []
        # structure of self.files -> self.files[file][row][row_elements]
        self.files = []
        self.requested_page_names = []
        self.requested_pages = []
        return

    def add_file(self, file_name, requested_page=None):
        self.file_names.append(file_name)
        self.files.append([])
        if requested_page is not None:
            self.requested_page_names.append(file_name)
            self.requested_pages.append(requested_page)
    
    # returns the files in list format
    def get_files(self):
        return self.files
    
    def get_requested_pages(self):
        return self.requested_pages
    
    def get_file_names(self):
        return self.file_names
    
    def writerow(self, csv_row):
        self.files[-1].append(csv_row)
    
    # returns the files in csv format 
    def get_csv_files(self):
        result = []
        for file in self.files:
            csvfile = io.StringIO()
            csvwriter = csv.writer(csvfile)
            for row in file:
                csvwriter.writerow(row)
            result.append(csvfile.getvalue())
        
        return result
    
    def write_to_local(self):
        files = self.get_csv_files()
        for idx, file in enumerate(files):
            #print(idx)
            
            with open("webscraper/scraped_data_requests/" + self.file_names[idx], "w") as local_file:
                local_file.write(file)
    
    def clean_files(self):
        cleaned_files = []
        #print(self.files)
        for file in self.files:
            cleaned_files.append(clean_csv(file))
            #print(clean_csv(file))
            #print(file)
            #cleaned_files.append(file)
        self.files = cleaned_files

    def validate(self):
        data_validation.vaildate(self)

# Need to hear back from client about updated kernel versions
csv_column_headers_lookup = {"android os launch version": "android launch version",
                             "kernel version": "kernel launch version",
                             "minimum update version": "minimum launch version",
                             "severity*": "severity",
                             "android bug": "references",
                             "updated kernel versions" : "kernel launch version", #!!!!!!!!!!!!!!!!!!
                             "bug(s) with aosp links": "references",
                             "bug with aosp links": "references",
                             "bug with aosp link": "references",
                             "bugs with aosp link": "references",
                             "bugs with aosp links" : "references",
                             "bug(s)" : "references",
                             "bug(s) ": "references",
                             "bugs": "references",
                             "bug": "references",
                             "android bugs": "references",
                             "bug(s) with aosp link": "references"}

csv_column_headers = ["patch_level", "cve", "references", "reference_links", "type", "severity",
                              "updated aosp versions", "component", "subcomponent", "android launch version",
                              "kernel launch version", "minimum launch version", "minimum kernel version",
                              "date reported", 
                              "updated google devices", "updated nexus devices",
                              "updated versions", "affected versions", "not publicly available", "bulletin type","component code", "component code link", "date", "asb_url", "notes"]


def get_bulletin_pages(urls):

    file_container = CSVFiles()

    for url in urls:
        targetPage = requests.get("https://source.android.com/docs/security/bulletin/" + url)
        soup = BeautifulSoup(targetPage.text, "html.parser")
        patch_id = url[-10:-3]

        html_file = open("requested_page.html", "w")
        html_file.write(targetPage.text)
        html_file.close()

        print("reading: " + patch_id)

        # TODO: saved csv file name should reflect the date
        #csvfile = open("scraped_datas/" + patch_id + "-data", "w")
        file_container.add_file(patch_id + "-data", targetPage.text)

        file_container.writerow(csv_column_headers)

        known_patch_levels = get_patch_level_header_nodes(soup, patch_id)

        for patch_level in known_patch_levels:
            write_patch_level_tables(patch_level[0], patch_level[1], file_container, csv_column_headers, patch_id, url, soup)
    
    return file_container

def get_bulletin_page(url,patch_id):
    targetPage = requests.get(url)
    soup = BeautifulSoup(targetPage.text, "html.parser")

    # save html for debugging
    html_file = open("requested_page.html", "w")
    html_file.write(targetPage.text)
    html_file.close()

    print("reading: " + patch_id)

    # TODO: saved csv file name should reflect the date
    #csvfile = open("scraped_data_requests/" + patch_id + "-data", "w")
    # csvfile = io.StringIO()
    # csvwriter = csv.writer(csvfile)

    file_container = CSVFiles()
    file_container.add_file(patch_id + "-data", targetPage.text)

    file_container.writerow(csv_column_headers)

    known_patch_levels = get_patch_level_header_nodes(soup, patch_id)

    for patch_level in known_patch_levels:
        print(patch_level)
        write_patch_level_tables(patch_level[0], patch_level[1], file_container, csv_column_headers, patch_id, url, soup)

    #print(file_container.files)
    return file_container

# scrapes every bulletin page
def main_test():
    url_list = generate_bulletin_urls()
    
    file_container = CSVFiles()

    for url in url_list:
        targetPage = requests.get("https://source.android.com" + url)
        soup = BeautifulSoup(targetPage.text, "html.parser")
        patch_id = url[-10:-3]

        html_file = open("requested_page.html", "w")
        html_file.write(targetPage.text)
        html_file.close()

        print("reading: " + patch_id)

        # TODO: saved csv file name should reflect the date
        #csvfile = open("scraped_datas/" + patch_id + "-data", "w")
        file_container.add_file(patch_id + "-data", targetPage.text)

        file_container.writerow(csv_column_headers)

        known_patch_levels = get_patch_level_header_nodes(soup, patch_id)

        for patch_level in known_patch_levels:
            write_patch_level_tables(patch_level[0], patch_level[1], file_container, csv_column_headers, patch_id, url, soup)
    
    return file_container


'''
Generates the urls for all of the bulletins 
'''


def generate_bulletin_urls():
    website = "https://source.android.com/docs/security/bulletin"
    result = requests.get(website)
    content = result.text  # Gets the content of the website

    soup = BeautifulSoup(content, 'html.parser')

    box = soup.find("span", class_="devsite-nav-text", string="Bulletins Home").parent.parent.parent.find_all \
        ("a", class_="devsite-nav-title gc-analytics-event")

    url_list = []
    for url in box:
        if url.get_text() == "Overview":
            break
        if url.get_text() in MONTHS:
            href = url.get("href")
            url_list.append(href)
    return url_list


# finds the html table nodes and calls the function that reads the table and writes the data to csv file
def write_patch_level_tables(name, level, writer, header, month, url, soup):
    #print("writing patch level tables")
    current_component_name = getNextComponentName(level)
    while current_component_name:
        table_component_name = current_component_name.text
        # Find all tables in each of the "boxes" for -01 and -05 patch levels
        table = current_component_name.find_next('table')

        if table is None:
            print("couldnt find the table for " + current_component_name.text)
            break

        if check_parent_component(table, table_component_name):
            write_table(writer, header, name, table_component_name, table, month, url, soup)
        else:
            print("skipping table-less component: " + current_component_name.text)
        current_component_name = getNextComponentName(current_component_name)


'''
Checks to make sure that the component matches the correct table
'''


def check_parent_component(table, table_component_name):
    next_component = table.find_previous()
    while True:
        if next_component.name == "h3":
            if next_component.text == table_component_name:
                return True
            else:
                return False
        next_component = next_component.find_previous()


# writes the data in the table to csv
def  write_table(writer, csv_header, patch_level, component_name, table, month, url, soup):
    #print("reading table: " + component_name)
    table_body = table.findChild("tbody")
    # some tables dont have tbody so we skip that
    if table_body is None:
        table_body = table

    thead_found = False
    
    possible_table_header = table.findChild("thead")

    if possible_table_header is not None:
        thead_found = True
        table_header = possible_table_header.findChild("tr").findChildren("th")
        #print("table header found")
    else:
        table_header = table_body.findChild("tr").findChildren("th")

    skipping_header = False
    if not table_header:
        skipping_header = True
        table_header = table_body.findChildren("th")
    # reads the header of the table to make sure the data is placed in the correct spot in csv file
    column_names = []
    for header in table_header:
        if header.text:
            #print(header.text)
            column_names.append(header.text.lower())

    column_correct_order = []
    for elem in column_names:
        if elem == "component":
            column_correct_order.append(csv_header.index("subcomponent"))
        elif elem in csv_header:
            column_correct_order.append(csv_header.index(elem))
        elif elem == "cves":
            column_correct_order.append(csv_header.index("cve"))
        else:
            column_correct_order.append(csv_header.index(csv_column_headers_lookup[elem]))

    # get the table rows while skipping the header row
    
    if thead_found or skipping_header:
        table_rows = table_body.findChildren("tr")
    else:
        table_rows = table_body.findChild("tr").find_next_siblings("tr")

    for row in table_rows:
        row_data = []
        for data in row.findChildren("td"):
            if data:
                if len(row_data) == 0 and data.text[:1] == "A" and column_correct_order[0] == 1:
                    row_data.append(None)
                    row_data.append(data)
                
                else:
                    row_data.append(data)

        # iterate the row data and generate the what we are going to insert into the csv file
        csv_row = ["None"] * len(csv_header)
        for data, order in zip(row_data, column_correct_order):
            if csv_header[order] == "references":
                
                ref_dic = {}

                cleaned_data = []
                # remove things like new line and spaces
               
                clean_data = data.text.strip().splitlines()
                for i, elem in enumerate(clean_data[:]):
                    clean_data[i] = elem.replace("*","")
                    if not clean_data[i].isspace():
                        cleaned_data.append(clean_data[i])
                for i in range(len(cleaned_data)):
                    cleaned_data[i] = cleaned_data[i].strip()

                # insert into the references column as list
                csv_row[order] = cleaned_data
                for ref in data.findChildren("a"):
                    if ref.text != "*":
                        ref_dic[ref.text] = ref["href"]
                    else:
                        csv_row[-7] = "True"

                # insert into the reference_links column as dict
                csv_row[order + 1] = ref_dic
            elif data is None:
                continue
            else:
                csv_row[order] = data.text

        # add the component name to csv row
        csv_row[csv_header.index("component")] = component_name
        # add the patch level (01 or 05) to csv row
        csv_row[0] = patch_level
        csv_row[-3] = month
        csv_row[-2] = url
        csv_row[-6] = "Android OS"
        if csv_row[-7] == "None":
            csv_row[-7] = "False"
        #print("writing row")
        #print(csv_row)
            
        csv_number = csv_row[1]
        notes = []
        for elem in soup.find_all("aside", attrs={"class": "note"}):
            notes.append(elem.text)
        for note in notes:
            if csv_number in note:
                csv_row[csv_header.index("notes")] = note
                print("note added: " + note)
                break
        writer.writerow(csv_row)


# finds the component name which is written in h3. It stops if it gets to an h2 element which contains the next patch level
def getNextComponentName(component_name):
    current_elem = component_name.find_next_sibling()
    while current_elem.name != "h2":
        next_elem = current_elem.find_next_sibling()
        if next_elem is None:
            return None
        current_elem = next_elem
        if next_elem.name == "h3":
            return next_elem
    return None


# find the headers for patch levels
# sources: https://www.geeksforgeeks.org/beautifulsoup-search-by-text-inside-a-tag/#

def get_patch_level_header_nodes(soup, patch_id):
    possible_header_ids_1 = [patch_id + "-01-security-patch-level-vulnerability-details", "vuln-details-01",
                             "details-01", "spl-details-01", "patech-details",
                             "detsild-01", "01-details", patch_id + "-01-details", patch_id + "-01-spl-details",
                             patch_id + "-01-security-patch-level—vulnerability-details", "security_vulnerability_details"]

    possible_header_ids_5 = [patch_id + "-05-security-patch-level-vulnerability-details", "vuln-details-05",
                             "details-05", "spl-details-05", "details-05",
                             "05-details", patch_id + "-05-details", "05spl", patch_id + "-05-security-patch-level—vulnerability-details"]
    
    possible_header_ids_6 = [patch_id + "-06-security-patch-level-vulnerability-details", patch_id + "-06-details"]
    
    known_patch_levels = [patch_id+"-01", patch_id+"-02", patch_id+"-05", patch_id+"-06"]
    for id in possible_header_ids_1:
        patch_01 = soup.find("h2", attrs={"id": id})
        if patch_01 is not None:
            break
    if patch_01 is None:
        patch_01 = soup.find(
            lambda node: node.name == "h2" and patch_id + "-01 security patch level vulnerability details" in node.text)

    for id in possible_header_ids_5:
        patch_05 = soup.find("h2", attrs={"id": id})
        if patch_05 is not None:
            break
    if patch_05 is None:
        patch_05 = soup.find(
            lambda node: node.name == "h2" and patch_id + "-05 security patch level vulnerability details" in node.text)
        
    for id in possible_header_ids_6:
        patch_06 = soup.find("h2", attrs={"id": id})
        if patch_06 is not None:
            break
    if patch_06 is None:
        patch_06 = soup.find(
            lambda node: node.name == "h2" and patch_id + "-06 security patch level vulnerability details" in node.text)

    patch_levels = []
    if patch_01 is not None:
        patch_levels.append([known_patch_levels[0][-2:], patch_01])

    if patch_05 is not None:
        patch_levels.append([known_patch_levels[2][-2:], patch_05])
        
    if patch_06 is not None:
        patch_levels.append([known_patch_levels[3][-2:], patch_06])

    if patch_01 is None and patch_05 is None and patch_06 is None:
        unknown_patch_level = soup.find("h2", attrs={"id": "security_vulnerability_details"})
        if unknown_patch_level is not None:
            paragraph = unknown_patch_level.find_next("p").text
            for patch_level in known_patch_levels:
                if paragraph.find(patch_level) != -1:
                    patch_levels.append([patch_level[-2:], unknown_patch_level])
        else:
            # Gets into this else statement if there is no id that is in an html tag
            patch_levels.append(["01", soup.find("h2", attrs={"id": "acknowledgements"})])
            return patch_levels

    #print(patch_levels)
    return patch_levels


if __name__ == "__main__":
    main_test()
