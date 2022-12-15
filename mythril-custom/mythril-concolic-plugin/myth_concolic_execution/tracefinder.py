from mythril.laser.plugin.signals import PluginSkipWorldState
from mythril.laser.plugin.interface import LaserPlugin
from mythril.plugin.loader import MythrilLaserPlugin
from mythril.laser.plugin.plugins.plugin_annotations import MutationAnnotation
from mythril.laser.ethereum.state.global_state import GlobalState
from mythril.laser.ethereum.svm import LaserEVM
from mythril.laser.smt import UGT, symbol_factory, simplify, Bool
from mythril.laser.ethereum.transaction.transaction_models import (
    ContractCreationTransaction,
)
from mythril.analysis import solver
from mythril.exceptions import UnsatError
from typing import List, Tuple


class TraceFinderBuilder(MythrilLaserPlugin):
    name = "trace-finder"
    plugin_default_enabled = True
    enabled = True

    author = "MythX Development Team"
    name = "MythX Trace Finder"
    plugin_license = "All rights reserved."
    plugin_type = "Laser Plugin"
    plugin_version = "0.0.1 "
    plugin_description = "This plugin merges states after the end of a transaction"

    def __call__(self, *args, **kwargs):
        return TraceFinder()


class TraceFinder(LaserPlugin):
    def init(self):
        self._reset()

    def _reset(self):
        self.tx_trace: List[List[Tuple[int, str]]] = []

    def initialize(self, symbolic_vm: LaserEVM):
        """Initializes Trace Finder

        Introduces hooks during the start of the execution and each execution state
        :param symbolic_vm:
        :return:
        """
        self._reset()

        @symbolic_vm.laser_hook("start_exec")
        def start_sym_trans_hook():
            self.tx_trace.append([])

        @symbolic_vm.laser_hook("execute_state")
        def trace_jumpi_hook(global_state: GlobalState):
            self.tx_trace[-1].append(
                (global_state.mstate.pc, global_state.current_transaction.id)
            )