import os

TRAIN_CONFIG = {
    "max_call_num": 3,
    "max_func_num": 10,
    "max_func_arg": 4,
    "token_size": 32,
    "feature_size": 8
}

TRAIN_CONFIG["action_num"] = TRAIN_CONFIG["max_call_num"] * 4

ANALYSIS_CONFIG = {
    "token_size": 5,
    "max_line_num": 4,
    "max_dep_num": 3,
    "feature_num": 5
}

ANALYSIS_CONFIG["max_length"] = ANALYSIS_CONFIG["max_line_num"] * (ANALYSIS_CONFIG["max_dep_num"] + 2)

TRAIN_CONFIG["max_line_length"] = TRAIN_CONFIG["token_size"] * (ANALYSIS_CONFIG["max_length"] + 2) + TRAIN_CONFIG["feature_size"] * ANALYSIS_CONFIG["feature_num"]

FUZZ_CONFIG = {
    "seed_prob": 0.6,
    "random_action_prob": 0.6,
    "account_balance": "0xffffffffffffffffffffffffffffffff",
    "max_attempt": 100,
    "valid_mutation_reward": 1,
    "vulnerability_reward": 1,
    "exploit_reward": 2,
    "path_variaty_reward": 0.5,
    "path_discovery_reward": 0.2
}

DIR_CONFIG = {}
DIR_CONFIG["experiment_dir"] = os.path.join(os.path.dirname(__file__), "experiments")
DIR_CONFIG["seed_dir"] = os.path.join(os.path.dirname(__file__), "evm_types/seed")
DIR_CONFIG["test_contract_dir"] = os.path.join(os.path.dirname(__file__), "test/contracts")