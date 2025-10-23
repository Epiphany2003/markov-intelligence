from train import *
from guess import *
import argparse
import os
from intel import load_keywords

def main():
    # # 每次运行开始时清空guess.txt文件
    with open('guess.txt', 'w') as f:
        pass

    parser = argparse.ArgumentParser(description="Markov-based Password Cracking")
    parser.add_argument('--path', type=str, default='data/rockyou.txt', help='the path of password file')
    parser.add_argument('--number', type=int, default=2000000, help='the total of train and test simpled from password file')
    parser.add_argument('--seed', type=int, default=2, help='random seed')
    parser.add_argument('--order', type=int, default=3, help='')
    parser.add_argument('--intel_path', type=str, default='data/keywords.txt', help='path to keywords file')
    opt = parser.parse_args()

    start_symbol = '#' * opt.order # 开始标识
    path = 'order{}/order{}_{}_{}.pickle'.format(opt.order, opt.order, opt.seed, opt.number)
    if not os.path.exists(path):
        print("Loading Password File ...")
        preprocess(opt.path, opt.seed, opt.number)
        print("Finished ...")
        passwd = loadpass('data/trainword.txt',start_symbol) # 读取训练集，并且加上前缀
        base = statistic(passwd, opt.order) # 统计频数
        laplace(base, opt.order, opt.seed, opt.number) # 消除零概率，并排序

    print("Guessing Password ...")
    testpd = testpass('data/testword.txt') # 统计测试集密码出现次数的字典，用于后续统计猜对的总数量
    with open(path.format(opt.order, opt.order), 'rb') as file:
        base = pickle.load(file)
    # 加载情报关键词
    keywords = load_keywords(opt.intel_path)

    guesser = Guess(base, start_symbol, opt.order, testpd, keywords)

    n = opt.number / 2
    m = 100000
    thre = threhold(m,n)
    guesser.initqueue(thre[0]) # 把起始符号后的第一个字符加入队列

    with open('order{}/memory.txt'.format(opt.order),'w+') as f:
        num = 0
        k = 0
        while guesser.flag: # 当队列不为空时，继续猜测
            k = int(guesser.true_guess / m)
            guesser.insertqueue(thre[k]) # 插入新的猜测序列到队列
            num += 1
            if num % 1000 == 0:
                f.write(str(guesser.true_guess) + ' / ' + str(guesser.num_guess) + '\n')
                print("GUESS: {} / {}".format(guesser.true_guess, guesser.num_guess))

if __name__ == "__main__":

    main()
