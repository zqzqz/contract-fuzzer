from pyfuzz.fuzzer.fuzzer import Fuzzer
from pyfuzz.trainer.model import *
from pyfuzz.config import TRAIN_CONFIG, DIR_CONFIG, FUZZ_CONFIG
from pyfuzz.trainer.train import train
from pyfuzz.utils.utils import experimentDirectory
from pyfuzz.utils.timeout import Timeout
from pyfuzz.fuzzer.detector.exploit import Exploit
from pyfuzz.fuzzer.detector.vulnerability import Vulnerability
import numpy as np
import argparse
import logging
import sys
import json
import random

logging.basicConfig()
logger = logging.getLogger("pyfuzz")
logger.setLevel(logging.INFO)

def fuzz(datadir, output, repeat_num, rand_prob, set_timeout, opts):
    # Where we save our checkpoints and graphs
    experiment_dir = experimentDirectory(DIR_CONFIG["experiment_dir"], opts)

    # initialize fuzzer framework
    env = Fuzzer(evmEndPoint=None, opts=opts)

    # Create estimators
    actionProcessor = ActionProcessor()
    stateProcessor = StateProcessor()
    # q_estimator = Estimator(scope="q_estimator", summaries_dir=experiment_dir, action_num=actionProcessor.actionNum)
    # target_estimator = Estimator(scope="target_q")

    if rand_prob < 1.0:
        # Create directories for checkpoints and summaries
        checkpoint_dir = os.path.join(experiment_dir, "checkpoints")
        checkpoint_path = os.path.join(checkpoint_dir, "model.meta")

    report = {}
    if os.path.isfile(output):
        with open(output, "r") as f:
            report = json.load(f)

    with tf.Session() as sess:
        if rand_prob < 1.0:
            # First let's load meta graph and restore weights
            saver = tf.train.import_meta_graph(checkpoint_path)
            saver.restore(sess, tf.train.latest_checkpoint(checkpoint_dir))

            graph = tf.get_default_graph()
            predictions = graph.get_tensor_by_name(
                "target_q/CNN/predictions:0")
            X = graph.get_tensor_by_name("target_q/X:0")
            real_seq_length = graph.get_tensor_by_name(
                "target_q/real_seq_length:0")

        contract_files = os.listdir(datadir)
        for filename in contract_files:
            # env.refreshEvm()
            logger.info(filename)
            full_filename = os.path.join(datadir, filename)
            contract_name = filename.split('.')[0].split("#")[-1]
            # print("filename", filename)

            if filename not in report:
                report[filename] = {}
            else:
                continue

            if not env.loadContract(full_filename, contract_name):
                continue

            # if env.contract["opcodes"].count("CALL ") == 0:
                # continue
            
            for i in range(repeat_num):
                try:
                    with Timeout(set_timeout):
                        report[filename][i] = {
                            "reports": [],
                            "coverage": 0,
                            "attempt": 0
                        }
                        timeout = 0
                        done = 0
                        state, seq_len = env.reset()
                        report_num = 0
                        while True:
                            # test
                            env.printTxList()
                            if opts["exploit"] and done:
                                break
                            if timeout:
                                break
                            try:
                                if rand_prob < 1.0:
                                    feed_dict = {X: np.expand_dims(
                                        state, 0), real_seq_length: np.expand_dims(seq_len, 0)}
                                    q_values = sess.run(predictions, feed_dict)[0]
                                    action_probs = np.ones(
                                        actionProcessor.actionNum, dtype=float) * rand_prob / actionProcessor.actionNum
                                    best_action = np.argmax(q_values)
                                    action_probs[best_action] += (1.0 - rand_prob)
                                    action = np.random.choice(
                                        np.arange(len(action_probs)), p=action_probs)
                                else:
                                    action = random.randint(0, TRAIN_CONFIG["action_num"]-1)
                                state, seq_len, reward, done, timeout = env.step(action)

                                for r in range(report_num, len(env.report)):
                                    # logger.info("Found:", repr(env.report[r]))
                                    report[filename][i]["reports"].append({"report": repr(env.report[r]), "attempt": env.counter})
                                report_num = len(env.report)

                            except Exception as e:
                                if isinstance(e, Timeout.Timeout):
                                    logger.error("Time is out for contract {} at test {}".format(filename, repeat_num))
                                logger.error("__main__.baseline: {}".format(str(e)))
                                reward, done, timeout = 0, 0, 0
                                break
                            # print("reward", reward)
                except:
                    pass

                logger.info("contract {} finished with counter {}".format(
                    filename, env.counter))
                report[filename][i]["coverage"] = env.coverage()
                report[filename][i]["attempt"] = env.counter

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
    parser.add_argument("--episode", type=int,
                        help="number of episode", default=100)
    parser.add_argument("--exploit", action='store_const',
                        default=False, const=True, help="find exploitations")
    parser.add_argument("--random", action='store_const',
                        default=False, const=True, help="omit model and use random actions")
    parser.add_argument("--vulnerability", action='store_const',
                        default=False, const=True, help="find vulnerabilities")
    parser.add_argument("--repeat", type=int,
                        help="repeated number of testing", default=10)
    parser.add_argument("--timeout", type=int,
                        help="timeout", default=120)    

    args = parser.parse_args()
    if not os.path.isdir(args.datadir):
        logger.exception("wrong datadir")
        exit(1)
    if args.random:
        rand_prob = 1.0
    else:
        rand_prob = FUZZ_CONFIG["random_action_prob"]
    opts = {
        "exploit": args.exploit,
        "vulnerability": args.vulnerability
    }
    if args.cmd == "train":
        train(args.datadir, args.episode, opts)
    elif args.cmd == "fuzz":
        fuzz(args.datadir, args.output, args.repeat, rand_prob, args.timeout, opts)
    else:
        logger.exception("command {} is not found".format(args.cmd))


if __name__ == '__main__':
    main()
