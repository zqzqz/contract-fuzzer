import os
import json

def select_success(filepath):
    with open(filepath, "r") as f:
        report = json.load(f)

    for filename in report:
        if len(report[filename]["success"]) > 5:
            print(filename)

def compare_reports(filepath0, filepath1):
    with open(filepath0, "r") as f:
        report0 = json.load(f)

    with open(filepath1, "r") as f:
        report1 = json.load(f)

    total, a, b = 0, 0, 0
    for filename in report0:
        try:
            success_rate_dif = report0[filename]["success_rate"] - report1[filename]["success_rate"]
            attempt_rate_def = report0[filename]["attempt_rate"] - report1[filename]["attempt_rate"]
            if success_rate_dif == 0 and attempt_rate_def == 0:
                continue
            total += 1
            if success_rate_dif > 0:
                a += 1
            if attempt_rate_def < 0:
                b += 1
            print(filename, success_rate_dif, attempt_rate_def)
        except:
            pass
    print("total", a / total, b / total)

compare_reports("report0.json", "report1.json")