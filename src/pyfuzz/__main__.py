from pyfuzz.fuzzer.fuzzer import Fuzzer
from pyfuzz.trainer.model import *
from pyfuzz.config import TRAIN_CONFIG, DIR_CONFIG, FUZZ_CONFIG
from pyfuzz.trainer.train import train
import numpy as np
import argparse
import logging
import sys
import json
import random

logging.basicConfig()
logger = logging.getLogger("pyfuzz")
logger.setLevel(logging.INFO)


def fuzz(datadir, rand_prob, opts):
    logger.info("fuzzing the contracts")

    # Where we save our checkpoints and graphs
    experiment_dir = DIR_CONFIG["experiment_dir"]

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
            full_filename = os.path.join(datadir, filename)
            contract_name = filename.split('.')[0].split("#")[-1]
            
            if not env.loadContract(full_filename, contract_name):
                continue

            state, seq_len = env.reset()
            while True:
                logger.info(env.state.txList)

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
                    state, seq_len, reward, done = env.step(action)
                except Exception as e:
                    logger.error("__main__.fuzz: {}".format(str(e)))
                    reward, done = 0, 0

                if done:
                    logger.info("contract {} finished".format(filename))
                    for rep in env.report:
                        logger.info(repr(rep))
                    break


def baseline(datadir, output, repeat_num, rand_prob, opts):
    # Where we save our checkpoints and graphs
    experiment_dir = DIR_CONFIG["experiment_dir"]

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
            logger.info(filename)
            full_filename = os.path.join(datadir, filename)
            contract_name = filename.split('.')[0].split("#")[-1]

            if filename not in report:
                report[filename] = {
                    "success": [],
                    "failure": []
                }
            else:
                continue

            if not env.loadContract(full_filename, contract_name):
                continue

            for i in range(repeat_num):
                state, seq_len = env.reset()
                while True:
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
                        state, seq_len, reward, done = env.step(action)

                    except Exception as e:
                        logger.error("__main__.baseline: {}".format(str(e)))
                        reward, done = 0, 0

                    if done:
                        logger.info("contract {} finished with counter {}".format(
                            filename, env.counter))
                        if env.counter == FUZZ_CONFIG["max_attempt"]:
                            report[filename]["failure"].append(
                                {"attempt": env.counter, "coverage": env.coverage()})
                        else:
                            report[filename]["success"].append(
                                {"attempt": env.counter, "coverage": env.coverage()})
                        break

            if len(report[filename]["success"]) + len(report[filename]["failure"]) != 0:
                report[filename]["success_rate"] = len(report[filename]["success"]) / (
                    len(report[filename]["success"]) + len(report[filename]["failure"]))
            else:
                report[filename]["success_rate"] = 0
            if len(report[filename]["success"]) != 0:
                report[filename]["attempt_rate"] = sum(
                    [i["attempt"] for i in report[filename]["success"]]) / len(report[filename]["success"])
                report[filename]["success_coverage"] = sum(
                    [i["coverage"] for i in report[filename]["success"]]) / len(report[filename]["success"])
            else:
                report[filename]["attempt_rate"] = FUZZ_CONFIG["max_attempt"]
                report[filename]["success_coverage"] = 0
            if len(report[filename]["failure"]) != 0:
                report[filename]["failure_coverage"] = sum(
                    [i["coverage"] for i in report[filename]["failure"]]) / len(report[filename]["failure"])
            else:
                report[filename]["failure_coverage"] = 0

            with open(output, "w") as f:
                json.dump(report, f, indent=4)
                logger.info("Result written")


def main():
    parser = argparse.ArgumentParser(description='Contract fuzzer')
    parser.add_argument('cmd', metavar='CMD', type=str,
                        help='command from [fuzz, train, baseline]')
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
                        help="repeated number of testing", default=100)

    args = parser.parse_args()
    if not os.path.isdir(args.datadir):
        logger.error("wrong datadir")
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
        fuzz(args.datadir, rand_prob, opts)
    elif args.cmd == "baseline":
        baseline(args.datadir, args.output, args.repeat, rand_prob, opts)
    else:
        logger.error("command {} is not found".format(args.cmd))


if __name__ == '__main__':
    main()
