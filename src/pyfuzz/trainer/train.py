import itertools
import numpy as np
import os
import random
import sys
import psutil
import tensorflow as tf
from collections import deque, namedtuple

from pyfuzz.fuzzer.fuzzer import Fuzzer
from pyfuzz.utils.utils import experimentDirectory
from pyfuzz.trainer.model import *
from pyfuzz.config import *


def deep_q_learning(sess,
                    env,
                    datadir,
                    q_estimator,
                    target_estimator,
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
    Transition = namedtuple(
        "Transition", ["state", "seq_len", "action", "reward", "next_state", "next_seq_len", "contract_file", "done"])
    actionProcessor = ActionProcessor()
    stateProcessor = StateProcessor()

    # The replay memory
    replay_memory = []

    # Make model copier object
    estimator_copy = ModelParametersCopier(q_estimator, target_estimator)

    # # Keeps track of useful statistics
    # stats = plotting.EpisodeStats(
    #     episode_lengths=np.zeros(num_episodes),
    #     episode_rewards=np.zeros(num_episodes))

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
        actionProcessor.actionNum)

    # test
    filenames = os.listdir(datadir)
    filename_len = len(filenames)
    counter = 0

    # Populate the replay memory with initial experience
    print("Populating replay memory...")
    # state, seq_len, filename = env.random_reset(datadir)
    filename = filenames[counter % filename_len]
    state, seq_len = env.contract_reset(datadir, filename)
    counter += 1
    for i in range(replay_memory_init_size):
        action_probs, q_values = policy(
            sess, state, epsilons[min(total_t, epsilon_decay_steps-1)], seq_len)
        action = np.random.choice(np.arange(len(action_probs)), p=action_probs)
        next_state, next_seq_len, reward, done, timeout = env.step(action)
        replay_memory.append(Transition(
            state, seq_len, action, reward, next_state, next_seq_len, filename, done))
        if timeout:
            # env.refreshEvm()
            # state, seq_len, filename = env.random_reset(datadir)
            filename = filenames[counter % filename_len]
            state, seq_len = env.contract_reset(datadir, filename)
            counter += 1
        else:
            state = next_state
            seq_len = next_seq_len
    
    # test
    test_memory = replay_memory[:100]

    # Add env Monitor wrapper
    # todo

    for i_episode in range(num_episodes):

        episode_reward = 0
        episode_q = 0

        # Save the current checkpoint
        saver.save(tf.get_default_session(), checkpoint_path)

        # Reset the environment
        # state, seq_len, filename = env.random_reset(datadir)
        state, seq_len = env.contract_reset(datadir, filenames[i_episode % filename_len])
        loss = None

        # env.refreshEvm()

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
            action_probs, q_values = policy(sess, state, epsilon, seq_len)
            action = np.random.choice(
                np.arange(len(action_probs)), p=action_probs)
            next_state, next_seq_len, reward, done, timeout = env.step(action)

            # test
            episode_reward += reward

            # If our replay memory is full, pop the first element
            if len(replay_memory) == replay_memory_size:
                replay_memory.pop(0)

            # Save transition to replay memory
            replay_memory.append(Transition(
                state, seq_len, action, reward, next_state, next_seq_len, filename, done))

            # # Update statistics
            # stats.episode_rewards[i_episode] += reward
            # stats.episode_lengths[i_episode] = t

            # Sample a minibatch from the replay memory
            samples = random.sample(replay_memory, batch_size)
            states_batch, seq_len_batch, action_batch, reward_batch, next_states_batch, next_seq_len_batch, contract_file_batch, done_batch = map(
                np.array, zip(*samples))

            # Calculate q values and targets
            q_values_next = target_estimator.predict(
                sess, next_states_batch, next_seq_len_batch)
            targets_batch = reward_batch.astype(np.float32) + np.subtract(np.ones(len(
                done_batch)), done_batch).astype(np.float32) * discount_factor * np.amax(q_values_next, axis=1)

            # Perform gradient descent update
            states_batch = np.array(states_batch)
            seq_len_batch = np.array(seq_len_batch)
            loss = q_estimator.update(
                sess, states_batch, action_batch, targets_batch, seq_len_batch)

            # test
            states_batch, seq_len_batch, action_batch, reward_batch, next_states_batch, next_seq_len_batch, contract_file_batch, done_batch = map(
                np.array, zip(*test_memory))
            q_values = target_estimator.predict(
                sess, states_batch, seq_len_batch)
            episode_q += float(np.amax(q_values))

            if timeout:
                break

            state = next_state
            seq_len = next_seq_len
            total_t += 1

        episode_reward /= t
        episode_q /= t
        with open("train_plot.csv", "a") as f:
            f.write("{}, {}\n".format(str(episode_reward), str(episode_q)))
        # Add summaries to tensorboard
        # episode_summary = tf.Summary()
        # episode_summary.value.add(simple_value=epsilon, tag="episode/epsilon")
        # episode_summary.value.add(
        #     simple_value=stats.episode_rewards[i_episode], tag="episode/reward")
        # episode_summary.value.add(
        #     simple_value=stats.episode_lengths[i_episode], tag="episode/length")
        # episode_summary.value.add(
        #     simple_value=current_process.cpu_percent(), tag="system/cpu_usage_percent")
        # episode_summary.value.add(simple_value=current_process.memory_percent(
        #     memtype="vms"), tag="system/v_memeory_usage_percent")
        # q_estimator.summary_writer.add_summary(episode_summary, i_episode)
        # q_estimator.summary_writer.flush()

        # yield total_t, plotting.EpisodeStats(
        #     episode_lengths=stats.episode_lengths[:i_episode+1],
        #     episode_rewards=stats.episode_rewards[:i_episode+1])

    return


def train(datadir, episode_num=100, opts={}):
    print("training the DQN")

    # Where we save our checkpoints and graphs
    experiment_dir = experimentDirectory(DIR_CONFIG["experiment_dir"], opts)

    # Create a glboal step variable
    global_step = tf.Variable(0, name='global_step', trainable=False)

    # Create estimators
    ap = ActionProcessor()
    q_estimator = Estimator(scope="q_estimator", summaries_dir=experiment_dir)
    target_estimator = Estimator(scope="target_q")

    env = Fuzzer(evmEndPoint=None, opts=opts)

    with tf.Session() as sess:
        sess.run(tf.global_variables_initializer())
        deep_q_learning(sess,
                        env,
                        datadir,
                        q_estimator=q_estimator,
                        target_estimator=target_estimator,
                        experiment_dir=experiment_dir,
                        num_episodes=episode_num,
                        replay_memory_size=10000,
                        replay_memory_init_size=2500,
                        update_target_estimator_every=2500,
                        epsilon_start=1.0,
                        epsilon_end=0.4,
                        epsilon_decay_steps=250000,
                        discount_factor=0.6,
                        batch_size=32)
