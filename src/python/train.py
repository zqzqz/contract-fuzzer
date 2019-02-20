import logging
import itertools
import numpy as np
import os
import random
import sys
import psutil
import tensorflow as tf
from collections import deque, namedtuple

from fuzzer import *
from model import *


def deep_q_learning(sess,
                    env,
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
        "Transition", ["state", "seq_len", "action", "reward", "next_state", "next_seq_len", "done"])
    actionProcessor = ActionProcessor(env.maxFuncNum, env.maxCallNum)
    stateProcessor = StateProcessor(env.maxFuncNum, env.maxCallNum)

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

    # Populate the replay memory with initial experience
    print("Populating replay memory...")
    state, seq_len = env.reset()
    for i in range(replay_memory_init_size):
        action_probs = policy(
            sess, state, epsilons[min(total_t, epsilon_decay_steps-1)], seq_len)
        action = np.random.choice(np.arange(len(action_probs)), p=action_probs)
        next_state, next_seq_len, reward, done = env.step(action)
        replay_memory.append(Transition(
            state, seq_len, action, reward, next_state, next_seq_len, done))
        if done:
            state, seq_len = env.reset()
        else:
            state = next_state
            seq_len = next_seq_len

    # Add env Monitor wrapper
    # todo

    for i_episode in range(num_episodes):

        # Save the current checkpoint
        saver.save(tf.get_default_session(), checkpoint_path)

        # Reset the environment
        state , seq_len = env.reset()
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
            action_probs = policy(sess, state, epsilon, seq_len)
            action = np.random.choice(
                np.arange(len(action_probs)), p=action_probs)
            next_state, next_seq_len, reward, done = env.step(action)

            # If our replay memory is full, pop the first element
            if len(replay_memory) == replay_memory_size:
                replay_memory.pop(0)

            # Save transition to replay memory
            replay_memory.append(Transition(
                state, seq_len, action, reward, next_state, next_seq_len, done))

            # # Update statistics
            # stats.episode_rewards[i_episode] += reward
            # stats.episode_lengths[i_episode] = t

            # Sample a minibatch from the replay memory
            samples = random.sample(replay_memory, batch_size)
            states_batch, seq_len_batch, action_batch, reward_batch, next_states_batch, next_seq_len_batch, done_batch = map(
                np.array, zip(*samples))

            # Calculate q values and targets
            q_values_next = target_estimator.predict(sess, next_states_batch, next_seq_len_batch)
            targets_batch = reward_batch.astype(np.float32) + np.invert(done_batch).astype(
                np.float32) * discount_factor * np.amax(q_values_next, axis=1)

            # Perform gradient descent update
            states_batch = np.array(states_batch)
            seq_len_batch = np.array(seq_len_batch)
            loss = q_estimator.update(
                sess, states_batch, action_batch, targets_batch, seq_len_batch)

            if done:
                break

            state = next_state
            seq_len = next_seq_len
            total_t += 1

        # Add summaries to tensorboard
        episode_summary = tf.Summary()
        episode_summary.value.add(simple_value=epsilon, tag="episode/epsilon")
        # episode_summary.value.add(
        #     simple_value=stats.episode_rewards[i_episode], tag="episode/reward")
        # episode_summary.value.add(
        #     simple_value=stats.episode_lengths[i_episode], tag="episode/length")
        episode_summary.value.add(
            simple_value=current_process.cpu_percent(), tag="system/cpu_usage_percent")
        episode_summary.value.add(simple_value=current_process.memory_percent(
            memtype="vms"), tag="system/v_memeory_usage_percent")
        q_estimator.summary_writer.add_summary(episode_summary, i_episode)
        q_estimator.summary_writer.flush()

        # yield total_t, plotting.EpisodeStats(
        #     episode_lengths=stats.episode_lengths[:i_episode+1],
        #     episode_rewards=stats.episode_rewards[:i_episode+1])

    return


def train():
    # config
    maxFuncNum = 3
    maxCallNum = 3

    # Where we save our checkpoints and graphs
    experiment_dir = os.path.abspath("./experiments")

    # Create a glboal step variable
    global_step = tf.Variable(0, name='global_step', trainable=False)

    # Create estimators
    ap = ActionProcessor(maxFuncNum=maxFuncNum, maxCallNum=maxCallNum)
    q_estimator = Estimator(scope="q_estimator", summaries_dir=experiment_dir, action_num=ap.actionNum)
    target_estimator = Estimator(scope="target_q")

    env = Fuzzer(maxFuncNum=maxFuncNum, maxCallNum=maxCallNum, evmEndPoint=None)
    with open(os.path.join(os.getcwd(), '../static/Test.sol'), 'r') as f:
        text = f.read()
    env.loadContract(text, "Test")

    with tf.Session() as sess:
        sess.run(tf.global_variables_initializer())
        for t, stats in deep_q_learning(sess,
                                        env,
                                        q_estimator=q_estimator,
                                        target_estimator=target_estimator,
                                        experiment_dir=experiment_dir,
                                        num_episodes=100,
                                        replay_memory_size=1000,
                                        replay_memory_init_size=100,
                                        update_target_estimator_every=100,
                                        epsilon_start=1.0,
                                        epsilon_end=0.1,
                                        epsilon_decay_steps=5000,
                                        discount_factor=0.99,
                                        batch_size=16):

            print("\nEpisode Reward: {}".format(stats.episode_rewards[-1]))


if __name__ == '__main__':
    train()
