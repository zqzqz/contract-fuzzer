import os
import logging
from abc import abstractmethod
import random
import argparse

from pyfuzz.fuzzer.fuzzer import Fuzzer
from pyfuzz.trainer.model import *
from pyfuzz.config import TRAIN_CONFIG, DIR_CONFIG, FUZZ_CONFIG
from pyfuzz.trainer.train import train
from pyfuzz.utils.utils import experimentDirectory
from pyfuzz.utils.timeout import Timeout
from pyfuzz.fuzzer.detector.exploit import Exploit
from pyfuzz.fuzzer.detector.vulnerability import Vulnerability

class MutateCandidate():
    def __init__(self, words, start, end, replace, mtype):
        self.start = start
        self.end = end
        self.words = words
        self.replace = replace
        self.mtype = mtype

    def __repr__(self):
        return " ".join(self.words[self.start:self.end]) + " ==> " + " ".join(self.replace)

    def __gt__(self, other):
        type_map = {
            "send": 3,
            "internal": 2,
            "require": 4,
            "if": 1
        }
        if self.mtype in type_map:
            a = type_map[self.mtype]
        else:
            a = 0
        if self.mtype in type_map:
            b = type_map[other.mtype]
        else:
            b = 0
        if a > b:
            return True

class MutateParser():
    def __init__(self):
        self.matches = []

    def parse(self, words):
        self.matches = []
        if_flag = 0
        if_start = -1
        if_stack = []
        require_flag = 0
        require_start = -1
        require_stack = []
        send_flag = 0
        send_start = -1
        send_stack = []
        for i in range(len(words)):
            if words[i] == "internal":
                candidate = MutateCandidate(words, i, i+1, ["external"], "internal")
                self.matches.append(candidate)
            elif words[i] == "private":
                candidate = MutateCandidate(words, i, i+1, ["public"], "internal")
                self.matches.append(candidate)

            if send_flag == 0 and words[i] in ["transfer", "send", "value"]:
                send_flag = 1
            elif send_flag == 1:
                if words[i] == "(":
                    send_flag = 2
                    send_start = i + 1
                    send_stack.append("(")
                else:
                    send_flag = 0
                    send_stack = []
            elif send_flag == 2:
                if words[i] == "(":
                    send_stack.append("(")
                elif words[i] == ")":
                    if len(send_stack) > 0:
                        send_stack.pop()
                if len(send_stack) == 0:
                    send_flag = 0
                    send_stack = []
                    origin = "".join(words[send_start:i])
                    if origin not in ["address(this).balance", "this.balance"]:
                        candidate = MutateCandidate(words, send_start, i, ["this.balance"], "send")
                        self.matches.append(candidate)

            if if_flag == 0 and (words[i] == "if"):
                if_start = i
                if_flag = 1
            elif if_flag == 1:
                if words[i] == "(":
                    if_flag = 2
                    if_stack.append("(")
                else:
                    if_flag = 0
                    if_stack = []
            elif if_flag == 2:
                if words[i] == "(":
                    if_stack.append("(")
                elif words[i] == ")":
                    if len(if_stack) > 0:
                        if_stack.pop()
                if len(if_stack) == 0:
                    if_flag = 0
                    if_stack = []
                    # candidate = MutateCandidate(words, if_start, i+1, ["if(false)"], "if")
                    # self.matches.append(candidate)
                    candidate = MutateCandidate(words, if_start, i+1, ["if(true)"], "if")
                    self.matches.append(candidate)

            if require_flag == 0 and (words[i] in ["require", "assert"]):
                require_start = i
                require_flag = 1
            elif require_flag == 1:
                if words[i] == "(":
                    require_flag = 2
                    require_stack.append("(")
                else:
                    require_flag = 0
                    require_stack = []
            elif require_flag == 2:
                if words[i] == "(":
                    require_stack.append("(")
                elif words[i] == ")":
                    if len(require_stack) > 0:
                        require_stack.pop()
                if len(require_stack) == 0:
                    require_flag = 3
            elif require_flag == 3:
                if words[i] == ";":
                    require_flag = 0
                    require_stack = []
                    candidate = MutateCandidate(words, require_start, i+1, [], "require")
                    self.matches.append(candidate)
                else:
                    require_flag = 0
                    require_stack = []
        return self.matches

class MutateContract():
    def __init__(self, source):
        self.source = source
        self.words = self.segment(source)

    def process(self):
        self.parser = MutateParser()
        self.mutations = sorted(self.parser.parse(self.words), reverse=True)
        self.mutated_sources = []
        self.mutate()
        # self.show_mutations()
        # self.show_sources()

    @staticmethod
    def segment(source):
        source = source.replace("\t", " ")
        source = source.replace("\n", " ")
        source = source.replace("(", " ( ")
        source = source.replace("[", " [ ")
        source = source.replace("{", " { ")
        source = source.replace(")", " ) ")
        source = source.replace("]", " ) ")
        source = source.replace("}", " } ")
        source = source.replace(";", " ; ")
        source = source.replace(",", " , ")
        source = source.replace(".", " . ")
        words = source.split(" ")
        return list(filter(lambda w: w != '', words))
    
    @staticmethod
    def assemble(words):
        source = ""
        layer = 0
        for w in words:
            blank = False
            enter = False
            if len(source) > 0 and source[-1] in [".", "(", "["]:
                blank = False
            else:
                blank = True

            if (len(source) > 0 and source[-1] == "\n") or (len(source) >= 4 and source[-4:] == "    ") or len(source) == 0:
                blank = False
            
            if w in ["(", ")", "[", "]", "."]:
                blank = False
            elif w == "{":
                layer += 1
                blank = True
                enter = True
            elif w == "}":
                layer -= 1
                if len(source) > 4 and source[-4:] == "    ":
                    source = source[:-4]
                blank = False
                enter = True
            elif w == ";":
                blank = False
                enter = True
            else:
                pass

            if blank:
                source += " "
            source += w
            if enter:
                source += ("\n" + "    " * layer)
        return source
            

    def show_mutations(self):
        for mutation in self.mutations:
            print(mutation)

    def show_sources(self):
        for source in self.mutated_sources:
            print(source)

    def mutate(self):
        for mutation in self.mutations:
            mutated_words = mutation.words[:mutation.start] + mutation.replace + mutation.words[mutation.end:]
            self.mutated_sources.append(self.assemble(mutated_words))

class MutateController():
    def __init__(self, input_dir, output_dir):
        self.input_dir = input_dir
        self.output_dir = output_dir
        self.file_list = []
        self.get_files()

    def get_files(self):
        self.file_list = os.listdir(self.input_dir)

    def start(self):
        for filename in self.file_list:
            try:
                with open(os.path.join(self.input_dir, filename), "r") as f:
                    source = f.read()
                
                contract = MutateContract(source)
                flag = False
                for keyword in ["transfer", "send", "callcode", "delegatecall", "call", "selfdestruct"]:
                    if keyword in contract.words:
                        flag = True
                if not flag:
                    continue

                contract.process()
                tmp_file = os.path.join(self.output_dir, "tmp"+filename)
                contract.show_mutations()
                index = 0
                for s in [source] + contract.mutated_sources:
                    try:
                        with open(tmp_file, "w") as f:
                            f.write(s)
                        # try fuzz
                        if self.fuzz(tmp_file):
                            with open(os.path.join(self.output_dir, str(index) + "-" + filename), "w") as f:
                                f.write(s)
                                index += 1
                        os.remove(tmp_file)
                    except Exception as e:
                        logging.error("mutation on " + filename + " failed", e)

            except Exception as e:
                logging.error("processing contract " + filename + " failed", e)

    @staticmethod
    def fuzz(filename):
        # initialize fuzzer framework
        env = Fuzzer(evmEndPoint=None, opts={"exploit": True})

        # Create estimators
        actionProcessor = ActionProcessor()
        stateProcessor = StateProcessor()

        contract_name = filename.split('.')[0].split("#")[-1]

        if not env.loadContract(filename, contract_name):
            return False
        
        try:
            with Timeout(120):
                timeout = 0
                done = 0
                state, seq_len = env.reset()
                while True:
                    if done:
                        return True
                    if timeout:
                        return False
                    try:
                        action = random.choices([i for i in range(12)], [3,1,1,1,3,1,1,1,3,1,1,1])
                        state, seq_len, reward, done, timeout = env.step(action[0])
                    except:
                        return False
        except:
            return False


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Contract fuzzer')
    parser.add_argument("--input", type=str,
                        help="input directory", default="input/")
    parser.add_argument("--output", type=str,
                        help="output directory", default="output/") 

    args = parser.parse_args()
    controller = MutateController(args.input, args.output)
    controller.start()