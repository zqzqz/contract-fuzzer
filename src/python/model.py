import logging
import itertools
import numpy as np
import os
import random
import sys
import psutil
import tensorflow as tf
from lib import plotting
from collections import deque, namedtuple

actionList = ["insertFirst", "insertLast", "removeFirst",
              "removeLast", "modifyArgs", "modifySender", "modifyValue"]


class ActionProcessor:
    """
        map actions to integers
    """

    def __init__(self, maxFuncNum, maxCallNum):
        self.maxFuncNum = maxFuncNum
        self.maxCallNum = maxCallNum
        self.actionNum = maxFuncNum * 4 + maxCallNum * 2

    def encodeAction(self, actionId, actionArg):
        assert(actionId >= 0 and actionId < len(actionList))
        if actionId < 4:
            assert(actionArg and actionArg >=
                   0 and actionArg < self.self.maxFuncNum)
            return actionId * self.maxFuncNum + actionArg
        else:
            assert(actionArg and actionArg >=
                   0 and actionArg < self.self.maxCallNum)
            return 4 * self.maxFuncNum + (actionId - 4) * self.maxCallNum + aFuncctionArg

    def decodeAction(self, action):
        assert(action >= 0 and action < self.maxFuncNum * 4 + self.maxCallNum * 2)
        if action < 4 * self.maxFuncNum:
            return action // self.maxFuncNum, action % self.maxFuncNum
        else:
            action -= 4 * self.maxFuncNum
            return action // self.maxCallNum + 4, action % self.maxCallNum

    @property
    def actionNum(self):
        return self.actionNum


class StateProcessor:
    """
        map states to tensors
    """

    def __init__(self, maxFuncNum, maxCallNum):
        self.maxFuncNum = maxFuncNum
        self.maxCallNum = maxCallNum

    def encodeState(self, staticAnalysis, txList):
        return None

    def decodeState(self, state):
        return None


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
            self._build_model()
            if summaries_dir:
                summary_dir = os.path.join(summaries_dir, "summaries_{}".format(scope))
                if not os.path.exists(summary_dir):
                    os.makedirs(summary_dir)
                self.summary_writer = tf.summary.FileWriter(summary_dir)

    def _build_model(self, sequence_length, action_num, lstm_size, token_size=256):
        # Placeholders for our input
        self.X = tf.placeholder(shape=[None, sequence_length, token_size], dtype=tf.uint8, name="X")
        # The TD target value
        self.y = tf.placeholder(shape=[None, action_num], dtype=tf.float32, name="y")
        # Integer id of which action was selected
        self.actions = tf.placeholder(shape=[None], dtype=tf.int32, name="actions")
        self.keep_prob = tf.placeholder(tf.float32, name='keep_prob')
        self.real_seq_length = tf.placeholder(tf.float32, [None], name='name_seq_length')

        # RNN
        with tf.name_scope('RNN'):
            self.cell = tf.contrib.rnn.BasicLSTMCell(lstm_size)
            self.cell = tf.contrib.rnn.DropoutWrapper(self.cell, output_keep_prob=self.keep_prob)
            self.outputs, self.status = tf.nn.dynamic_rnn(self.cell, self.X, sequence_length=self.real_seq_length, dtype=tf.float32)

        # linear transformation
        with tf.name_scope("linear"):
            output_wrapper = tf.get_variable('output_wrapper', shape=[lstm_size, action_num])
            output_bias = tf.Variable(initial_value=tf.constant([0.1] * action_num), name='output_bias')
            self.predictions = tf.nn.xw_plus_b(self.status[-1], output_wrapper, output_bias, name='predictions')
            self.outputs = tf.argmax(self.predictions, axis=1, name='outputs')
        
        # loss and accuracy
        with tf.name_scope('loss_accuracy'):
            self.losses = tf.nn.softmax_cross_entropy_with_logits(logits=self.predictions, labels=self.y)
            self.loss = tf.reduce_mean(losses)
            self.accuracy = tf.reduce_mean(tf.cast(tf.equal(self.outputs, tf.argmax(self.y, axis=1)), "float"))

        self.optimizer = tf.train.AdamOptimizer(0.001)
        self.train_op = self.optimizer.minimize(self.loss, global_step=tf.contrib.framework.get_global_step())

        self.summaries = tf.summary.merge([
            tf.summary.scalar("loss", self.loss),
            tf.summary.histogram("loss_hist", self.losses),
            tf.summary.histogram("q_value_hist", self.predictions),
            tf.summary.scalar("max_q_value", tf.reduce_max(self.predictions))
        ])

    def predict(self, sess, s):
        """
        Predict action values
        """
        return sess.run(self.predictions, {self.X: s})

    def update(self, sess, s, a, y):
        """
        Update estimator towards given targets
        """
        feed_dict = { self.X: s, self.y: y, self.actions: a}
        summaries, global_step, _, loss = sess.run(
            [self.summaries, tf.contrib.framework.get_global_step(), self.train_op, self.loss],
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
        e1_params = [t for t in tf.trainable_variables() if t.name.startswith(estimator1.scope)]
        e1_params = sorted(e1_params, key=lambda v: v.name)
        e2_params = [t for t in tf.trainable_variables() if t.name.startswith(estimator2.scope)]
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

def deep_q_learning(sess,
                    env,
                    q_estimator,
                    target_estimator,
                    state_processor,
                    num_episodes,
                    experiment_dir,
                    replay_memory_size=500000,
                    replay_memory_init_size=50000,
                    update_target_estimator_every=10000,
                    discount_factor=0.99,
                    epsilon_start=1.0,
                    epsilon_end=0.1,
                    epsilon_decay_steps=500000,
                    batch_size=32,
                    record_video_every=50):
    """
    Q-Learning algorithm for off-policy TD control using Function Approximation.
    Finds the optimal greedy policy while following an epsilon-greedy policy.

    Args:
        sess: Tensorflow Session object
        env: fuzzer environment
        q_estimator: Estimator object used for the q values
        target_estimator: Estimator object used for the targets
        state_processor: A StateProcessor object
        num_episodes: Number of episodes to run for
        experiment_dir: Directory to save Tensorflow summaries in
        replay_memory_size: Size of the replay memory
        replay_memory_init_size: Number of random experiences to sampel when initializing 
          the reply memory.
        update_target_estimator_every: Copy parameters from the Q estimator to the 
          target estimator every N steps
        discount_factor: Gamma discount factor
        epsilon_start: Chance to sample a random action when taking an action.
          Epsilon is decayed over time and this is the start value
        epsilon_end: The final minimum value of epsilon after decaying is done
        epsilon_decay_steps: Number of steps to decay epsilon over
        batch_size: Size of batches to sample from the replay memory
        record_video_every: Record a video every N episodes

    Returns:
        An EpisodeStats object with two numpy arrays for episode_lengths and episode_rewards.
    """
    Transition = namedtuple("Transition", ["state", "action", "reward", "next_state", "done"])
    actionProcessor = ActionProcessor()

    # The replay memory
    replay_memory = []
    
    # Make model copier object
    estimator_copy = ModelParametersCopier(q_estimator, target_estimator)

    # Keeps track of useful statistics
    stats = plotting.EpisodeStats(
        episode_lengths=np.zeros(num_episodes),
        episode_rewards=np.zeros(num_episodes))
    
    # For 'system/' summaries, useful to check if currrent process looks healthy
    current_process = psutil.Process()

    # Create directories for checkpoints and summaries
    checkpoint_dir = os.path.join(experiment_dir, "checkpoints")
    checkpoint_path = os.path.join(checkpoint_dir, "model")
    monitor_path = os.path.join(experiment_dir, "monitor")
    
    if not os.path.exists(checkpoint_dir):
        os.makedirs(checkpoint_dir)
    if not os.path.exists(monitor_path):
        os.makedirs(monitor_path)

    saver = tf.train.Saver()
    # Load a previous checkpoint if we find one
    latest_checkpoint = tf.train.latest_checkpoint(checkpoint_dir)
    if latest_checkpoint:
        print("Loading model checkpoint {}...\n".format(latest_checkpoint))
        saver.restore(sess, latest_checkpoint)
    
    # Get the current time step
    total_t = sess.run(tf.contrib.framework.get_global_step())

    # The epsilon decay schedule
    epsilons = np.linspace(epsilon_start, epsilon_end, epsilon_decay_steps)

    # The policy we're following
    policy = make_epsilon_greedy_policy(
        q_estimator,
        len(actionList))

    # Populate the replay memory with initial experience
    print("Populating replay memory...")
    state = env.reset()
    state = state_processor.process(sess, state)
    state = np.stack([state] * 4, axis=2)
    for i in range(replay_memory_init_size):
        action_probs = policy(sess, state, epsilons[min(total_t, epsilon_decay_steps-1)])
        action = np.random.choice(np.arange(len(action_probs)), p=action_probs)
        next_state, reward, done, _ = env.step(actionList[action])
        next_state = state_processor.process(sess, next_state)
        next_state = np.append(state[:,:,1:], np.expand_dims(next_state, 2), axis=2)
        replay_memory.append(Transition(state, action, reward, next_state, done))
        if done:
            state = env.reset()
            state = state_processor.process(sess, state)
            state = np.stack([state] * 4, axis=2)
        else:
            state = next_state


    # Record videos
    # Add env Monitor wrapper
    env = Monitor(env, directory=monitor_path, video_callable=lambda count: count % record_video_every == 0, resume=True)

    for i_episode in range(num_episodes):

        # Save the current checkpoint
        saver.save(tf.get_default_session(), checkpoint_path)

        # Reset the environment
        state = env.reset()
        state = state_processor.process(sess, state)
        state = np.stack([state] * 4, axis=2)
        loss = None

        # One step in the environment
        for t in itertools.count():

            # Epsilon for this time step
            epsilon = epsilons[min(total_t, epsilon_decay_steps-1)]

            # Maybe update the target estimator
            if total_t % update_target_estimator_every == 0:
                estimator_copy.make(sess)
                print("\nCopied model parameters to target network.")

            # Print out which step we're on, useful for debugging.
            print("\rStep {} ({}) @ Episode {}/{}, loss: {}".format(
                    t, total_t, i_episode + 1, num_episodes, loss), end="")
            sys.stdout.flush()

            # Take a step
            action_probs = policy(sess, state, epsilon)
            action = np.random.choice(np.arange(len(action_probs)), p=action_probs)
            next_state, reward, done, _ = env.step(actionList[action])
            next_state = state_processor.process(sess, next_state)
            next_state = np.append(state[:,:,1:], np.expand_dims(next_state, 2), axis=2)

            # If our replay memory is full, pop the first element
            if len(replay_memory) == replay_memory_size:
                replay_memory.pop(0)

            # Save transition to replay memory
            replay_memory.append(Transition(state, action, reward, next_state, done))   

            # Update statistics
            stats.episode_rewards[i_episode] += reward
            stats.episode_lengths[i_episode] = t

            # Sample a minibatch from the replay memory
            samples = random.sample(replay_memory, batch_size)
            states_batch, action_batch, reward_batch, next_states_batch, done_batch = map(np.array, zip(*samples))

            # Calculate q values and targets
            q_values_next = target_estimator.predict(sess, next_states_batch)
            targets_batch = reward_batch + np.invert(done_batch).astype(np.float32) * discount_factor * np.amax(q_values_next, axis=1)

            # Perform gradient descent update
            states_batch = np.array(states_batch)
            loss = q_estimator.update(sess, states_batch, action_batch, targets_batch)

            if done:
                break

            state = next_state
            total_t += 1

        # Add summaries to tensorboard
        episode_summary = tf.Summary()
        episode_summary.value.add(simple_value=epsilon, tag="episode/epsilon")
        episode_summary.value.add(simple_value=stats.episode_rewards[i_episode], tag="episode/reward")
        episode_summary.value.add(simple_value=stats.episode_lengths[i_episode], tag="episode/length")
        episode_summary.value.add(simple_value=current_process.cpu_percent(), tag="system/cpu_usage_percent")
        episode_summary.value.add(simple_value=current_process.memory_percent(memtype="vms"), tag="system/v_memeory_usage_percent")
        q_estimator.summary_writer.add_summary(episode_summary, i_episode)
        q_estimator.summary_writer.flush()
        
        yield total_t, plotting.EpisodeStats(
            episode_lengths=stats.episode_lengths[:i_episode+1],
            episode_rewards=stats.episode_rewards[:i_episode+1])

    return stats