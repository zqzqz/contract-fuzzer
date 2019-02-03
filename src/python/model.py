import logging
import itertools
import numpy as np
import tensorflow as tf
from utils import hexToUint8

actionList = ["insertFirst", "insertLast", "removeFirst",
              "removeLast", "modifyArgs", "modifySender", "modifyValue"]


class Action:
    def __init__(self, actionId, actionArg):
        self.actionId = actionId
        self.actionArg = actionArg


class ActionProcessor:
    """
        map actions to integers
    """

    def __init__(self, maxFuncNum, maxCallNum):
        self.maxFuncNum = maxFuncNum
        self.maxCallNum = maxCallNum
        self.actionNum = maxFuncNum * 4 + maxCallNum * 2

    def encodeAction(self, actionObj):
        actionId = actionObj.actionId
        actionArg = actionObj.actionArg
        assert(actionId >= 0 and actionId < len(actionList))
        if actionId < 2:
            assert(actionArg and actionArg >=
                   0 and actionArg < self.maxFuncNum)
            return actionId * self.maxFuncNum + actionArg
        elif actionId < 4:
            return 2 * self.maxFuncNum + (actionId - 2)
        else:
            assert(actionArg and actionArg >=
                   0 and actionArg < self.maxCallNum)
            return 2 * self.maxFuncNum + 2 + (actionId - 4) * self.maxCallNum + actionArg

    def decodeAction(self, action):
        assert(action >= 0 and action <
               self.maxFuncNum * 2 + self.maxCallNum * 2)
        if action < 2 * self.maxFuncNum:
            return Action(action // self.maxFuncNum, action % self.maxFuncNum)
        elif action < 2 * self.maxFuncNum + 2:
            return Action(action - 2 * self.maxFuncNum + 2, 0)
        else:
            action -= (2 * self.maxFuncNum + 2)
            return Action(action // self.maxCallNum + 4, action % self.maxCallNum)


class State:
    def __init__(self, staticAnalysis, txList):
        self.staticAnalysis = staticAnalysis
        self.txList = txList


class StateProcessor:
    """
        map states to tensors
    """

    def __init__(self, maxFuncNum, maxCallNum, tokenSize=256):
        self.maxFuncNum = maxFuncNum
        self.maxCallNum = maxCallNum
        self.tokenSize = tokenSize

    def encodeState(self, stateObj):
        staticAnalysis = stateObj.staticAnalysis
        txList = stateObj.txList
        # encoding of staticAnalysis: todo
        sequence = np.array([[0 for _ in range(self.tokenSize)]], dtype=np.uint8)
        for tx in txList:
            sequence = np.append(sequence, np.expand_dims(hexToUint8(tx.hash, self.tokenSize), axis=0), axis=0)
            for arg in tx.args:
                sequence = np.append(sequence, np.expand_dims(hexToUint8(arg, self.tokenSize), axis=0), axis=0)
            sequence = np.append(sequence, np.expand_dims(hexToUint8(tx.value, self.tokenSize), axis=0), axis=0)
            sequence = np.append(sequence, np.expand_dims(hexToUint8(tx.sender, self.tokenSize), axis=0), axis=0)
        return sequence[1:]

    def decodeState(self, state):
        pass


class Estimator():
    """
        Q-value estimator neural network
    """

    def __init__(self, scope="estimator", summaries_dir=None):
        self.scope = scope
        # Writes Tensorboard summaries to disk
        self.summary_writer = None
        with tf.variable_scope(scope):
            # Build the graph
            self._build_model(256, len(actionList), 128)
            if summaries_dir:
                summary_dir = os.path.join(
                    summaries_dir, "summaries_{}".format(scope))
                if not os.path.exists(summary_dir):
                    os.makedirs(summary_dir)
                self.summary_writer = tf.summary.FileWriter(summary_dir)

    def _build_model(self, sequence_length, action_num, lstm_size, token_size=256):
        # Placeholders for our input
        self.X = tf.placeholder(
            shape=[None, sequence_length, token_size], dtype=tf.uint8, name="X")
        # The TD target value
        self.y = tf.placeholder(
            shape=[None, action_num], dtype=tf.float32, name="y")
        # Integer id of which action was selected
        self.actions = tf.placeholder(
            shape=[None], dtype=tf.int32, name="actions")
        # self.keep_prob = tf.placeholder(tf.float32, name='keep_prob')
        self.real_seq_length = tf.placeholder(
            tf.float32, [None], name='real_seq_length')

        # RNN
        with tf.name_scope('RNN'):
            self.cell = tf.nn.rnn_cell.LSTMCell(lstm_size)
            self.cell = tf.contrib.rnn.DropoutWrapper(
                self.cell, output_keep_prob=0.5)
            self.outputs, self.status = tf.nn.dynamic_rnn(
                self.cell, self.X, sequence_length=self.real_seq_length, dtype=tf.float32)

        # linear transformation
        with tf.name_scope("linear"):
            output_wrapper = tf.get_variable(
                'output_wrapper', shape=[lstm_size, action_num])
            output_bias = tf.Variable(initial_value=tf.constant(
                [0.1] * action_num), name='output_bias')
            self.predictions = tf.nn.xw_plus_b(
                self.status[-1], output_wrapper, output_bias, name='predictions')
            self.outputs = tf.argmax(self.predictions, axis=1, name='outputs')

        # loss and accuracy
        with tf.name_scope('loss_accuracy'):
            self.losses = tf.nn.softmax_cross_entropy_with_logits(
                logits=self.predictions, labels=self.y)
            self.loss = tf.reduce_mean(losses)
            self.accuracy = tf.reduce_mean(
                tf.cast(tf.equal(self.outputs, tf.argmax(self.y, axis=1)), "float"))

        self.optimizer = tf.train.AdamOptimizer(0.001)
        self.train_op = self.optimizer.minimize(
            self.loss, global_step=tf.contrib.framework.get_global_step())

        self.summaries = tf.summary.merge([
            tf.summary.scalar("loss", self.loss),
            tf.summary.histogram("loss_hist", self.losses),
            tf.summary.histogram("q_value_hist", self.predictions),
            tf.summary.scalar("max_q_value", tf.reduce_max(self.predictions))
        ])

    def predict(self, sess, s, seq_len):
        """
        Predict action values
        """
        return sess.run(self.predictions, {self.X: s, self.real_seq_length: seq_len})

    def update(self, sess, s, a, y, seq_len):
        """
        Update estimator towards given targets
        """
        feed_dict = {self.X: s, self.y: y,
                     self.actions: a, self.real_seq_length: seq_len}
        summaries, global_step, _, loss = sess.run(
            [self.summaries, tf.contrib.framework.get_global_step(),
             self.train_op, self.loss],
            feed_dict
        )
        if self.summary_writer:
            self.summary_writer.add_summary(summaries, global_step)
        return loss


class ModelParametersCopier():
    """
    Copy model parameters of one estimator to another.
    """

    def __init__(self, estimator1, estimator2):
        """
        Defines copy-work operation graph.  
        Args:
          estimator1: Estimator to copy the paramters from
          estimator2: Estimator to copy the parameters to
        """
        e1_params = [t for t in tf.trainable_variables(
        ) if t.name.startswith(estimator1.scope)]
        e1_params = sorted(e1_params, key=lambda v: v.name)
        e2_params = [t for t in tf.trainable_variables(
        ) if t.name.startswith(estimator2.scope)]
        e2_params = sorted(e2_params, key=lambda v: v.name)

        self.update_ops = []
        for e1_v, e2_v in zip(e1_params, e2_params):
            op = e2_v.assign(e1_v)
            self.update_ops.append(op)

    def make(self, sess):
        """
        Makes copy.
        Args:
            sess: Tensorflow session instance
        """
        sess.run(self.update_ops)


def make_epsilon_greedy_policy(estimator, nA):
    """
    Creates an epsilon-greedy policy based on a given Q-function approximator and epsilon.

    Args:
        estimator: An estimator that returns q values for a given state
        nA: Number of actions in the environment.

    Returns:
        A function that takes the (sess, observation, epsilon) as an argument and returns
        the probabilities for each action in the form of a numpy array of length nA.

    """
    def policy_fn(sess, observation, epsilon):
        A = np.ones(nA, dtype=float) * epsilon / nA
        q_values = estimator.predict(sess, np.expand_dims(observation, 0))[0]
        best_action = np.argmax(q_values)
        A[best_action] += (1.0 - epsilon)
        return A
    return policy_fn
