from bs4 import BeautifulSoup
import requests

# request a specific page to debug it
targetPage = requests.get("https://source.android.com/docs/security/bulletin/2016-04-01")
soup = BeautifulSoup(targetPage.text, "html.parser")

html_file = open("requested_page_debug.html", "w")
html_file.write(targetPage.text)
html_file.close()