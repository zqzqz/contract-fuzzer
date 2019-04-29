from matplotlib import pyplot as plt
import numpy as np
import pandas as pd

def train_plot():
    vuln = pd.read_csv("train_plot_vulnerability.csv", header=None)
    exp = pd.read_csv("train_plot_exploit.csv", header=None)
    vuln_r_y = []
    exp_r_y = []
    vuln_q_y = []
    exp_q_y = []
    x = [i for i in range(0, 200, 1)]
    # for i in range(0, 200, 10):
    #     vuln_r_y.append(sum(vuln[0][i:i+10])/10)
    #     exp_r_y.append(sum(exp[0][i:i+10])/10)
    #     vuln_q_y.append(sum(vuln[1][i:i+10])/10)
    #     exp_q_y.append(sum(exp[1][i:i+10])/10)
    # print(vuln_r_y)
    # print(exp_r_y)
    # print(vuln_q_y)
    # print(exp_q_y)

    vuln_q_y = vuln[1][:200]
    vuln_r_y = vuln[0][:200]
    exp_q_y = exp[1][:200]
    exp_r_y = exp[0][:200]

    import seaborn as sns
    plt.plot( 'x', 'y', data=pd.DataFrame({'x':x, 'y':vuln_r_y}))
    plt.show()

train_plot()
    