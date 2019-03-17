import logging
import itertools
import numpy as np
import tensorflow as tf
from pyfuzz.utils.utils import *
from pyfuzz.config import TRAIN_CONFIG
import os

actionList = ["insertFirst", "insertLast", "removeFirst",
              "removeLast", "modifyArgs", "modifySender", "modifyValue"]


class Action:
    def __init__(self, actionId, actionArg):
        self.actionId = actionId
        self.actionArg = actionArg


class ActionProcessor:
    """
        map actions to integers
        from 1 to maxFuncNum * 2 + maxCallNum * 3 + 2
    """

    def __init__(self):
        self.maxFuncNum = TRAIN_CONFIG["max_func_num"]
        self.maxCallNum = TRAIN_CONFIG["max_call_num"]
        self.actionNum = TRAIN_CONFIG["action_num"]

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
               self.maxFuncNum * 2 + self.maxCallNum * 3 + 2)
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
        map states to tensors (maxFuncNum, maxLineLength)
        [[static analysis of func x, transaction on func x (or zeros)],
        ...
         [static analysis of func y, transaction or zeros]]
    """

    def __init__(self):
        self.maxFuncNum = TRAIN_CONFIG["max_func_num"]
        self.maxCallNum = TRAIN_CONFIG["max_call_num"]
        self.maxFuncArg = TRAIN_CONFIG["max_func_arg"]
        self.sequence = None
        self.txNum = None
        self.seqLen = TRAIN_CONFIG["max_line_length"]

    def encodeState(self, stateObj):
        staticAnalysis = stateObj.staticAnalysis
        txList = stateObj.txList
        self.txNum = len(txList)
        funcHashes = list(staticAnalysis.encoded_report.keys())

        # encoding
        self.sequence = np.array([[0 for _ in range(self.seqLen)]], dtype=np.uint8)

        for tx in txList:
            if tx.hash in funcHashes:
                funcHashes.remove(tx.hash)
            
            txLine = np.array([], dtype=np.uint8)
            if tx.hash not in staticAnalysis.encoded_report:
                txStatic = "0"
            else:
                txStatic = intListToHexString(staticAnalysis.encoded_report[tx.hash], staticAnalysis.token_size)
            txStatic = hexToBinary(txStatic, size=self.seqLen)
            txLine = np.append(txLine, txStatic)
            # txLine = np.append(txLine, hexToBinary(tx.hash, 32))
            txLine = np.append(txLine, hexToBinary(valueToHex32(tx.sender), 32))
            txLine = np.append(txLine, hexToBinary(valueToHex32(tx.value), 32))

            arg_1d_list = eval('[%s]'%repr(tx.args).replace('[', '').replace(']', ''))
            for arg in arg_1d_list:
                txLine = np.append(txLine, hexToBinary(valueToHex32(arg), 32))

            if txLine.shape[0] < self.sequence.shape[1]:
                txLine = np.append(txLine, hexToBinary(
                    "0x0", self.sequence.shape[1] - txLine.shape[0]))
            elif txLine.shape[0] > self.sequence.shape[1]:
                txLine = txLine[:self.sequence.shape[1]]
            # print(self.sequence.shape, np.expand_dims(txLine, axis=0).shape, txLine.shape)
            self.sequence = np.append(self.sequence, np.expand_dims(txLine, axis=0), axis=0)

        while self.sequence.shape[0] < self.maxFuncNum + 1:
            txLine = np.array([], dtype=np.uint8)
            if len(funcHashes) > 0:
                funcHash = funcHashes[0]
                funcHashes.remove(funcHash)
                txStatic = intListToHexString(staticAnalysis.encoded_report[funcHash], staticAnalysis.token_size)
                txStatic = hexToBinary(txStatic, size=self.seqLen)
                txLine = np.append(txLine, txStatic)
            if txLine.shape[0] < self.sequence.shape[1]:
                txLine = np.append(txLine, hexToBinary(
                    "0x00", self.sequence.shape[1] - txLine.shape[0]))
            self.sequence = np.append(self.sequence, np.expand_dims(txLine, axis=0), axis=0)
        
        self.sequence = self.sequence[1:]
        self.sequence = np.expand_dims(self.sequence, axis=2)
        return self.sequence, self.txNum

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
            line_num = TRAIN_CONFIG["max_func_num"]
            line_len = TRAIN_CONFIG["max_line_length"]
            action_num = TRAIN_CONFIG["action_num"]
            self._build_model(line_num, line_len, action_num)
            if summaries_dir:
                summary_dir = os.path.join(
                    summaries_dir, "summaries_{}".format(scope))
                if not os.path.exists(summary_dir):
                    os.makedirs(summary_dir)
                self.summary_writer = tf.summary.FileWriter(summary_dir)

    def _build_model(self, line_num, line_len, action_num):
        # Placeholders for our input
        self.X = tf.placeholder(
            shape=[None, line_num, line_len, 1], dtype=tf.uint8, name="X")
        # The TD target value
        self.y = tf.placeholder(
            shape=[None], dtype=tf.float32, name="y")
        # Integer id of which action was selected
        self.actions = tf.placeholder(
            shape=[None], dtype=tf.int32, name="actions")
        # self.keep_prob = tf.placeholder(tf.float32, name='keep_prob')
        self.real_seq_length = tf.placeholder(
            tf.float32, [None], name='real_seq_length')

        X = tf.to_float(self.X)
        batch_size = tf.shape(self.X)[0]

        # CNN
        with tf.name_scope('CNN'):
            # Three convolutional layers
            conv1 = tf.contrib.layers.conv2d(
                inputs=X, num_outputs=32, kernel_size=[2, 32], activation_fn=tf.nn.relu)
            conv2 = tf.contrib.layers.conv2d(
                inputs=conv1, num_outputs=64, kernel_size=[2, 16], activation_fn=tf.nn.relu)
            conv3 = tf.contrib.layers.conv2d(
                inputs=conv2, num_outputs=64, kernel_size=[2, 8], activation_fn=tf.nn.relu)

            pool3 = tf.layers.max_pooling2d(inputs=conv3, pool_size=[2, 2], strides=2)

            # Fully connected layers
            flattened = tf.contrib.layers.flatten(pool3)
            fc1 = tf.contrib.layers.fully_connected(flattened, 512)
            self.predictions = tf.contrib.layers.fully_connected(fc1, action_num)

        # linear transformation
        with tf.name_scope("linear"):
            # Get the predictions for the chosen actions only
            gather_indices = tf.range(
                batch_size) * tf.shape(self.predictions)[1] + self.actions
            self.outputs = tf.gather(tf.reshape(
                self.predictions, [-1]), gather_indices)

        # loss and accuracy
        with tf.name_scope('loss_accuracy'):
            # self.losses = tf.nn.softmax_cross_entropy_with_logits(
            #    logits=self.outputs, labels=self.y)
            self.losses = tf.squared_difference(self.y, self.outputs)
            self.loss = tf.reduce_mean(self.losses)
            self.accuracy = tf.reduce_mean(
                tf.cast(tf.equal(self.outputs, self.y), "float"))

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
    def policy_fn(sess, observation, epsilon, seq_len):
        A = np.ones(nA, dtype=float) * epsilon / nA
        q_values = estimator.predict(sess, np.expand_dims(observation, 0), np.expand_dims(seq_len, 0))[0]
        best_action = np.argmax(q_values)
        A[best_action] += (1.0 - epsilon)
        return A
    return policy_fn
