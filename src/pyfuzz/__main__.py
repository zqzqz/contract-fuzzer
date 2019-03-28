from pyfuzz.fuzzer.fuzzer import Fuzzer
from pyfuzz.trainer.model import *
from pyfuzz.config import TRAIN_CONFIG, DIR_CONFIG, FUZZ_CONFIG
from pyfuzz.trainer.train import train
import numpy as np
import argparse
import logging
import sys

logging.basicConfig()
logger = logging.getLogger("pyfuzz")
logger.setLevel(logging.INFO)

def fuzz(datadir, opts):
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

    # Create directories for checkpoints and summaries
    checkpoint_dir = os.path.join(experiment_dir, "checkpoints")
    checkpoint_path = os.path.join(checkpoint_dir, "model.meta")

    rand_prob = FUZZ_CONFIG["random_action_prob"]

    with tf.Session() as sess:
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
            contract_name = filename.split('.')[0].split("#")[1]
            env.loadContract(full_filename, contract_name)

            state, seq_len = env.reset()
            while True:
                logger.info(env.state.txList)

                feed_dict = {X: np.expand_dims(
                    state, 0), real_seq_length: np.expand_dims(seq_len, 0)}
                q_values = sess.run(predictions, feed_dict)[0]
                action_probs = np.ones(
                    actionProcessor.actionNum, dtype=float) * rand_prob / actionProcessor.actionNum
                best_action = np.argmax(q_values)
                action_probs[best_action] += (1.0 - rand_prob)
                action = np.random.choice(
                    np.arange(len(action_probs)), p=action_probs)
                state, seq_len, reward, done = env.step(action)

                if done:
                    logger.info("contract {} finished".format(filename))
                    for rep in env.report:
                        logger.info(repr(rep))
                    break


def main():
    parser = argparse.ArgumentParser(description='Contract fuzzer')
    parser.add_argument('--train', action='store_const', const=True, default=False, help='train q estimator for DQN in the fuzzer')
    parser.add_argument("--datadir", help="directory containing contract source files")
    parser.add_argument("--episode", type=int, help="number of episode", default=100)
    parser.add_argument("--exploit", action='store_const', default=False, const=True, help="find exploitations")
    parser.add_argument("--vulnerability", action='store_const', default=False, const=True, help="find vulnerabilities")

    args = parser.parse_args()
    if not os.path.isdir(args.datadir):
        logger.error("wrong datadir")
        exit(1)
    opts = {
        "exploit": args.exploit,
        "vulnerability": args.vulnerability
    }
    if args.train:
        train(args.datadir, args.episode, opts)
    else:
        fuzz(args.datadir, opts)

if __name__ == '__main__':
    main()