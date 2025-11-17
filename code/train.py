''' 构建一个能够预测 “给定前缀下最可能出现的下一个字符” 的概率模型（n-gram 模型） '''

import re
import random
import pickle

# 读取数据集预处理, 并且分割为训练集和测试集
def preprocess(path, seed, number = 2000000):
    '''
    输入：原始密码文件路径、随机种子、总样本量
    输出：trainword.txt（训练集）、testword.txt（测试集）
    '''
    passwd = []
    exp = re.compile(r'[^\x20-\x7e]')

    with open(path, encoding="ISO-8859-1") as wordlist:
        for i,line in enumerate(wordlist):
            try:
                wl = line.strip().split(' ', 1)
                num = int(wl[-2])
                pd = wl[-1]
                if exp.search(pd) or ' ' in pd or len(pd) >= 21: # 过滤非ASCLL字符和空格
                    continue
                else:
                    passwd.extend([pd]*num)
            except Exception:
                #print("Exception: ",line)
                continue

    # 切分数据集（训练集和测试集）
    random.seed(seed)
    r = random.sample(range(0, len(passwd)), number)
    lt = [passwd[i] for i in r]
    testword = lt[0:int(number / 2)]
    trainword = lt[int(number / 2):]
    
    with open("data/trainword.txt", "w") as f:
        for pd in trainword:
            f.write(pd + '\n')
        
    with open("data/testword.txt", "w") as f:
        for pd in testword:
            f.write(pd + '\n')

# 读取训练集，为每个密码添加 “起始符号”
def loadpass(path, start_symbol):

    '''
    输入：训练集路径（trainword.txt）、起始符号
    输出：带起始符号的密码频数字典（如{ "^123456": 500, "^password123": 300, ... }）
    '''

    passwd = {} # 统计每个带起始符号的密码的出现次数
    with open(path, 'r') as wordList:
        for line in wordList:
            line = start_symbol + line
            if line in passwd:
                passwd[line] += 1
            else:
                passwd.setdefault(line, 1)
    return passwd

# 统计频数，记录 “前缀 - 后续字符” 的出现次数
def statistic(passwd, order):
    '''
    输入 ：上一步的密码频数字典、模型阶数order
    输出 ：base : 统计“前缀 - 后续字符” 的出现次数
    假设 order = 1， 则 base 可能是这样的：{ "^": { "1": 500, "p": 300 }, "1": { "2": 480 }, ... }

    '''

    base = {}
    for key, value in passwd.items(): # key 是密码， value 是该密码的出现次数

        l = len(key)
        for ord in range(order, order+1): # ord == order
            for i in range(l-ord):
                ps = key[i:i+ord] # 前缀
                qs = key[i+ord] # 后续字符

                if ps in base: # 前缀已存在
                    if qs in base[ps]: # 后续字符已存在，频数继续累加
                        base[ps][qs] += value
                    else:
                        base[ps].setdefault(qs, value)
                else: # 前缀不存在，新增前缀和后续字符
                    base.setdefault(ps, {})
                    base[ps].setdefault(qs, value)
    return base

# laplace平滑和排序
def laplace(base, order, seed, number):
    '''
    输入：步骤 3 的频数表base、模型阶数order、随机种子、样本量
    输出：保存到本地的 n-gram 概率模型文件（.pickle格式）
    '''

    for key, value in base.items():
        num = sum(value.values()) # 该前缀的总频数
        for k, v in value.items():
            base[key][k] = (v * 1.0 + 0.01) / (num + 0.96) # 拉普拉斯平滑 ： 概率 = (频数 + 0.01) / (该前缀的总频数 + 0.96)

    for key, value in base.items(): # 
        base[key] = sorted(value.items(), key=lambda t: t[1], reverse=True) # 降序排序，快速获取某个前缀后出现频率最高的字符

    # 保存模型
    with open('./order{}/order{}_{}_{}.pickle'.format(order, order, seed, number), 'wb') as file:
        pickle.dump(base, file)

