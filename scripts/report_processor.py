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
    total, select, BalanceIncrement, Selfdestruct, CodeInjection = 0, 0, 0, 0, 0

    for filename in report:
        total += 1
        if str(report[filename]).count("exploit") > 0:
            print(filename)
            select += 1
            if str(report[filename]).count("BalanceIncrement") > 0:
                BalanceIncrement += 1
            if str(report[filename]).count("Selfdestruct") > 0:
                Selfdestruct += 1
            if str(report[filename]).count("CodeInjection") > 0:
                CodeInjection += 1
    print(select, BalanceIncrement, Selfdestruct, CodeInjection, total)

def compare_reports(filepath0, filepath1):
    with open(filepath0, "r") as f:
        report0 = json.load(f)

    with open(filepath1, "r") as f:
        report1 = json.load(f)

    total, a, b, success_total = 0, 0, 0, 0
    for filename in report0:
        try:
            success0, success1 = str(report0[filename]).count("exploit"), str(report1[filename]).count("exploit")
            if success0 or success1:
                success_total += 1
            attempt0, attempt1 = 0, 0

            success_rate_dif = success0 - success1
            attempt_rate_dif = 0

            if success0 and success1:
                count0, count1 = 0, 0
                for repeat in report0[filename]:
                    for report in report0[filename][repeat]["reports"]:
                        attempt0 += report["attempt"]
                        count0 += 1
                for repeat in report1[filename]:
                    for report in report1[filename][repeat]["reports"]:
                        attempt1 += report["attempt"]
                        count1 += 1
                attempt0, attempt1 = attempt0 / count0, attempt1 / count1

            attempt_rate_dif = attempt0 - attempt1

            if success_rate_dif == 0 and attempt_rate_dif == 0:
                continue
            total += 1
            if success_rate_dif > 0:
                a += 1
            if attempt_rate_dif < 0:
                b += 1
            print(filename, success_rate_dif, attempt_rate_def)
        except:
            pass
    print("total", a / total, b / total)

# list_all_contracts("/home/zqz/teether_contract")
select_success("report.model.exploit.json")
# compare_reports("report.model.exploit.json", "report.random.exploit.json")