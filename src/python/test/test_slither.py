from slither.slither import Slither
from slither.printers.summary.slithir import PrinterSlithIR
import os
import logging

logger = logging.getLogger("Slither")

filename = os.path.join(os.path.dirname(__file__), '../../static/test/Test.sol')

slither = Slither(filename)
printer = PrinterSlithIR(slither, logger)
contracts = slither._contracts_by_id.values()

for contract in contracts:
    printer.output(contract)
    # see https://github.com/trailofbits/slither/blob/master/slither/printers/summary/slithir.py
    # get contracts, functions, nodes, expressions from contract object