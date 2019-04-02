import os
import json

with open("../src/report.json", "r") as f:
    report = json.load(f)

for filename in report:
    if len(report[filename]["success"]) > 0:
        print(filename)