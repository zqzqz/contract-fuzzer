import os
import json

def list_all_contracts(datapath):
    source = []
    for filename in os.listdir(datapath):
        try:
            with open(os.path.join(datapath, filename), "r", encoding="utf-8") as f:
                source.append(f.read())
        except Exception as e:
            print("error", e, filename)


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

list_all_contracts("/home/zqz/teether_contract")