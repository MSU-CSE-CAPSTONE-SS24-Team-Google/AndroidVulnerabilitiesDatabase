import json

yearList = ["2024", "2023", "2022"]
monthList = ["December", "November", "October"]
patchLevelList = ["01", "05"]

jsonDict = {}

for year in yearList:
    jsonDict[year] = {}
    for month in monthList:
        jsonDict[year][month] = {}
        for patchLevel in patchLevelList:
            jsonDict[year][month][patchLevel] = []

with open('test.json', 'w') as f:
    f.write(json.dumps(jsonDict))
