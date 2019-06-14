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


def select_success(filepath, name_map):
    filename_list = []
    with open(filepath, "r") as f:
        report = json.load(f)
    total, select = 0, 0 
    BalanceIncrement, Selfdestruct, CodeInjection = 0, 0, 0 
    Reentrancy, TimestampDependency, BlockNumberDependency, UnhandledException = 0, 0, 0, 0

    name_visited = {}
    for filename in report:
        total += 1
        # if str(report[filename]).count("exploit") > 0:
        if str(report[filename]).count("pc") > 0:
            name = filename.split('#')[1].split('.')[0]
            if name in name_visited:
                continue
            else:
                name_visited[name] = 1
            # print(filename)
            filename_list.append(filename)

            if name not in name_map:
                weight = 1
            else:
                weight = 1 # name_map[name]

            select += 1
            if str(report[filename]).count("Selfdestruct") > 0:
                Selfdestruct += weight
            elif str(report[filename]).count("CodeInjection") > 0:
                CodeInjection += weight
            elif str(report[filename]).count("BalanceIncrement") > 0:
                BalanceIncrement += weight
            if str(report[filename]).count("Reentrancy") > 0:
                Reentrancy += weight
            if str(report[filename]).count("TimestampDependency") > 0:
                TimestampDependency += weight
            if str(report[filename]).count("BlockNumberDependency") > 0:
                BlockNumberDependency += weight
            if str(report[filename]).count("UnhandledException") > 0:
                UnhandledException += weight
    # print(select/total, BalanceIncrement, Selfdestruct, CodeInjection)
    print(select/total, Reentrancy, TimestampDependency, BlockNumberDependency, UnhandledException)
    return filename_list

def unique(filepath):
    with open(filepath, "r") as f:
        contracts = f.read().split("\n")
    contracts = list(set(contracts))
    contracts = "\n".join(contracts)
    with open(filepath, "w") as f:
        f.write(contracts)

def compare_reports(filepath0, filepath1):
    with open(filepath0, "r") as f:
        report0 = json.load(f)

    with open(filepath1, "r") as f:
        report1 = json.load(f)

    total, a, b, success_total = 0, 0, 0, 0
    attempt_dif_total = 0
    for filename in report0:
        try:
            success0, success1 = str(report0[filename]).count("pc"), str(report1[filename]).count("pc")
            if success0 or success1:
                success_total += 1
            attempt0, attempt1 = 0, 0

            success_rate_dif = success0 - success1
            attempt_rate_dif = 0

            if success0 and success1:
                count0, count1 = 0, 0
                for repeat in report0[filename]:
                    for report in report0[filename][repeat]["reports"]:
                        if report["attempt"] > 350:
                            continue
                        attempt0 += report["attempt"]
                        count0 += 1
                for repeat in report1[filename]:
                    for report in report1[filename][repeat]["reports"]:
                        attempt1 += report["attempt"]
                        count1 += 1
                attempt0, attempt1 = attempt0 / count0, attempt1 / count1

            attempt_rate_dif = attempt0 - attempt1
            attempt_dif_total += attempt_rate_dif

            if success_rate_dif == 0 and attempt_rate_dif == 0:
                continue
            total += 1
            if success_rate_dif > 0:
                a += 1
            if attempt_rate_dif < 0:
                b += 1
            print(filename, success_rate_dif, attempt_rate_dif)
        except:
            pass
    print(total, a / total, b / total, attempt_dif_total)

with open("map.json", "r") as f:
    name_map = json.load(f)
# list_all_contracts("/home/zqz/teether_contract")
filename_list = select_success("report.model.vulnerability.json", name_map)
# with open("exploit_list.txt", "w") as f:
#     for filename in filename_list:
#         f.write(filename + "\n")

# compare_reports("test.report.model.vulnerability.json", "test.report.random.vulnerability.json")
# unique("vulnerability_list.txt")