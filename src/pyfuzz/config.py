import os

FUZZ_CONFIG = {
    "max_call_num": 3,
    "seed_prob": 0.4,
    "account_balance": "0xffffffffffffffffffffffffffffffff",
    "max_attempt": 100
}

DIR_CONFIG = {}
DIR_CONFIG["experiment_dir"] = os.path.join(os.path.dirname(__file__), "experiments")
DIR_CONFIG["seed_dir"] = os.path.join(os.path.dirname(__file__), "evm_types/seed")
DIR_CONFIG["test_contract_dir"] = os.path.join(os.path.dirname(__file__), "test/contracts")