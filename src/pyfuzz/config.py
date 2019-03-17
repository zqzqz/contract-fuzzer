import os

TRAIN_CONFIG = {
    "max_call_num": 2,
    "max_func_num": 4,
    "max_func_arg": 6,
}

TRAIN_CONFIG["action_num"] = TRAIN_CONFIG["max_func_num"] * 2 + TRAIN_CONFIG["max_call_num"] * 3 + 2

ANALYSIS_CONFIG = {
    "token_size": 8,
    "max_line_num": 6,
    "max_dep_num": 4,
}

ANALYSIS_CONFIG["max_length"] = ANALYSIS_CONFIG["max_line_num"] * (ANALYSIS_CONFIG["max_dep_num"] + 3)

TRAIN_CONFIG["max_line_length"] = ANALYSIS_CONFIG["token_size"] * ANALYSIS_CONFIG["max_length"] + 32 * TRAIN_CONFIG["max_func_arg"] + 32 * 2

FUZZ_CONFIG = {
    "seed_prob": 0.4,
    "random_action_prob": 0.4
}

DIR_CONFIG = {}
DIR_CONFIG["experiment_dir"] = os.path.join(os.path.dirname(__file__), "experiments")
DIR_CONFIG["seed_dir"] = os.path.join(os.path.dirname(__file__), "evm_types/seed")
DIR_CONFIG["test_contract_dir"] = os.path.join(os.path.dirname(__file__), "test/contracts")