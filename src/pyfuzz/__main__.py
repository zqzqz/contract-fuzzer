from pyfuzz.fuzzer.fuzzer import Fuzzer
from pyfuzz.trainer.model import *
from pyfuzz.config import TRAIN_CONFIG, DIR_CONFIG
from pyfuzz.trainer.train import train
import numpy as np
import argparse

def fuzz():
    print("fuzzing the contracts")

    # Where we save our checkpoints and graphs
    experiment_dir = DIR_CONFIG["experiment_dir"]

    # initialize fuzzer framework
    env = Fuzzer(evmEndPoint=None)
    filename = os.path.join(DIR_CONFIG["test_contract_dir"], 'Test.sol')
    env.loadContract(filename, "Test")

    # Create estimators
    actionProcessor = ActionProcessor(env.maxFuncNum, env.maxCallNum)
    stateProcessor = StateProcessor(env.maxFuncNum, env.maxCallNum)
    # q_estimator = Estimator(scope="q_estimator", summaries_dir=experiment_dir, action_num=actionProcessor.actionNum)
    # target_estimator = Estimator(scope="target_q")

    # Create directories for checkpoints and summaries
    checkpoint_dir = os.path.join(experiment_dir, "checkpoints")
    checkpoint_path = os.path.join(checkpoint_dir, "model.meta")

    with tf.Session() as sess:
        # First let's load meta graph and restore weights
        saver = tf.train.import_meta_graph(checkpoint_path)
        saver.restore(sess, tf.train.latest_checkpoint(checkpoint_dir))

        state, seq_len = env.reset()

        graph = tf.get_default_graph()
        predictions = graph.get_tensor_by_name(
            "q_estimator/linear/predictions:0")
        X = graph.get_tensor_by_name("q_estimator/X:0")
        real_seq_length = graph.get_tensor_by_name(
            "q_estimator/real_seq_length:0")

        epsilon = 0.5
        while True:
            feed_dict = {X: np.expand_dims(
                state, 0), real_seq_length: np.expand_dims(seq_len, 0)}
            q_values = sess.run(predictions, feed_dict)[0]
            action_probs = np.ones(
                actionProcessor.actionNum, dtype=float) * epsilon / actionProcessor.actionNum
            best_action = np.argmax(q_values)
            action_probs[best_action] += (1.0 - epsilon)
            action = np.random.choice(
                np.arange(len(action_probs)), p=action_probs)
            state, seq_len, reward, done = env.step(action)

            if done:
                break


def main():
    parser = argparse.ArgumentParser(description='Contract fuzzer')
    parser.add_argument('--train', dest='train_mode', action='store_const',
                        const=1, default=0,
                        help='train q estimator for DQN in the fuzzer')

    args = parser.parse_args()
    if args.train_mode:
        train()
    else:
        fuzz()

if __name__ == '__main__':
    main()