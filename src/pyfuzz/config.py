TRAIN_CONFIG = {
    "max_call_num": 3,
    "max_func_num": 3,
    "max_func_arg": 6
}

TRAIN_CONFIG["action_num"] = TRAIN_CONFIG["max_func_num"] * 2 + TRAIN_CONFIG["max_call_num"] * 3 + 2

ANALYSIS_CONFIG = {
    "token_size": 8,
    "max_line_num": 6,
    "max_dep_num": 4,
}

ANALYSIS_CONFIG["max_length"] = ANALYSIS_CONFIG["max_line_num"] * (ANALYSIS_CONFIG["max_dep_num"] + 3)

TRAIN_CONFIG["max_line_length"] = ANALYSIS_CONFIG["token_size"] * ANALYSIS_CONFIG["max_length"] + 32 * TRAIN_CONFIG["max_func_arg"] + 32 * 2 + 8