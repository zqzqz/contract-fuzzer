from pyfuzz.fuzzer.fuzzer import Fuzzer
from pyfuzz.config import DIR_CONFIG, FUZZ_CONFIG
from pyfuzz.utils.utils import experimentDirectory
from pyfuzz.utils.timeout import Timeout
from pyfuzz.fuzzer.detector.exploit import Exploit
from pyfuzz.fuzzer.detector.vulnerability import Vulnerability
import numpy as np
import argparse
import logging
import sys, os
import json
import random
import traceback
import time

logging.basicConfig()
logger = logging.getLogger("pyfuzz")
logger.setLevel(logging.INFO)

def fuzz(datadir, output, repeat_num, set_timeout, opts):
    # Where we save our checkpoints and graphs
    experiment_dir = experimentDirectory(DIR_CONFIG["experiment_dir"], opts)

    # initialize fuzzer framework
    env = Fuzzer(evmEndPoint=None, opts=opts)

    report = {}
    if os.path.isfile(output):
        with open(output, "r") as f:
            report = json.load(f)

    contract_files = os.listdir(datadir)
    for filename in contract_files:
        logger.info("start fuzzing {}".format(filename))
        full_filename = os.path.join(datadir, filename)
        contract_name = filename.split('.')[0].split("#")[-1]

        if filename not in report:
            tmp_report = {}
        else:
            continue

        if not env.loadContract(full_filename, contract_name):
            # wait for recovery
            time.sleep(5)
            continue
        
        write_flag = False
        for i in range(repeat_num):
            try:
                with Timeout(set_timeout):
                    tmp_report[i] = {
                        "reports": [],
                        "coverage": 0,
                        "attempt": 0
                    }
                    timeout = 0
                    done = 0
                    state = env.reset()
                    report_num = 0
                    while True:
                        if timeout:
                            break
                        try:
                            state, done, timeout = env.step()
                            # env.printTxList()

                            for r in range(report_num, len(env.report)):
                                # logger.info("Found:", repr(env.report[r]))
                                tmp_report[i]["reports"].append({"report": repr(env.report[r]), "attempt": env.counter})
                            report_num = len(env.report)

                            if timeout:
                                logger.info("contract {} finished with counter {}".format(
                                    filename, env.counter))
                                break

                            if "exploit" in opts and opts["exploit"] == True and report_num > 0:
                                logger.info("exploit found")
                                env.printTxList()
                                logger.info("contract {} finished with counter {}".format(
                                    filename, env.counter))
                                tmp_report[i]["coverage"] = env.coverage()
                                tmp_report[i]["attempt"] = env.counter
                                write_flag = True
                                break

                        except Exception as e:
                            if isinstance(e, Timeout.Timeout):
                                logger.error("Time is out for contract {} at test {}".format(filename, repeat_num))
                            else:
                                logger.error("Error {} {}".format(str(e), traceback.format_exc()))
                                # wait for recovery
                                time.sleep(5)
                            done, timeout = 0, 0, 0
                            break
            except Exception as e:
                logger.error("Error {} {}".format(str(e), traceback.format_exc()))
                # wait for recovery
                time.sleep(5)
    
        if write_flag:
            report[filename] = tmp_report
            with open(output, "w") as f:
                json.dump(report, f, indent=4)
                logger.info("Result written")


def main():
    parser = argparse.ArgumentParser(description='Contract fuzzer')
    parser.add_argument('cmd', metavar='CMD', type=str,
                        help='command from [fuzz, train]')
    parser.add_argument(
        "--datadir", help="directory containing contract source files")
    parser.add_argument("--output", type=str,
                        help="output report", default="report.json")
    parser.add_argument("--exploit", action='store_const',
                        default=False, const=True, help="find exploitations")
    parser.add_argument("--vulnerability", action='store_const',
                        default=False, const=True, help="find vulnerabilities")
    parser.add_argument("--repeat", type=int,
                        help="repeated number of testing", default=1)
    parser.add_argument("--timeout", type=int,
                        help="timeout", default=120)    

    args = parser.parse_args()
    if not os.path.isdir(args.datadir):
        logger.exception("wrong datadir")
        exit(1)
    opts = {
        "exploit": args.exploit,
        "vulnerability": args.vulnerability
    }
    if args.cmd == "fuzz":
        fuzz(args.datadir, args.output, args.repeat, args.timeout, opts)
    else:
        logger.exception("command {} is not found".format(args.cmd))


if __name__ == '__main__':
    main()
