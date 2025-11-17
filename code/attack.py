from train import *
from guess import *
import argparse
import os
from intel import load_keywords

def main():
    with open('guess.txt', 'w') as f:
        f.write('')  # 清空之前的猜测结果文件
    parser = argparse.ArgumentParser(description="Markov-based Password Cracking")
    parser.add_argument('--path', type=str, default='../data/rockyou.txt', help='the path of password file')
    parser.add_argument('--number', type=int, default=2000000, help='the total of train and test simpled from password file')
    parser.add_argument('--seed', type=int, default=2, help='random seed')
    parser.add_argument('--order', type=int, default=3, help='')
    parser.add_argument('--intel_path', type=str, default='../data/keywords.txt', help='path to keywords file')
    parser.add_argument('--mask', type=str, default=None, help='password structure mask, e.g. "?l?l?d?d" for 2 lowercase + 2 digits')
    opt = parser.parse_args()

    # 解析掩码
    mask = None
    if opt.mask:
        mask = []
        for c in opt.mask:
            if c == '?':
                continue
            if c == 'l':
                mask.append('lower')
            elif c == 'u':
                mask.append('upper')
            elif c == 'd':
                mask.append('digit')

    start_symbol = '#' * opt.order
    path = '../order{}/order{}_{}_{}.pickle'.format(opt.order, opt.order, opt.seed, opt.number)
    if not os.path.exists(path):
        print("Loading Password File ...")
        preprocess(opt.path, opt.seed, opt.number)
        print("Finished ...")
        passwd = loadpass('../data/trainword.txt',start_symbol)
        base = statistic(passwd, opt.order)
        laplace(base, opt.order, opt.seed, opt.number)

    print("Guessing Password ...")
    testpd = testpass('../data/testword.txt')
    with open(path.format(opt.order, opt.order), 'rb') as file:
        base = pickle.load(file)
    # 加载情报关键词
    keywords = load_keywords(opt.intel_path)
    guesser = Guess(base, start_symbol, opt.order, testpd, keywords, mask=mask)

    n = opt.number / 2
    m = 100000
    # thre = threhold(m,n)
    guesser.initqueue()

    with open('../order{}/memory.txt'.format(opt.order),'w+') as f:
        num = 0
        k = 0
        while guesser.flag:

            k = int(guesser.true_guess / m)
            guesser.insertqueue(0)
            num += 1
            if num % 1000 == 0:
                f.write(str(guesser.true_guess) + ' / ' + str(guesser.num_guess) + '\n')
                print("GUESS: {} / {}".format(guesser.true_guess, guesser.num_guess))
                # 打印所有关键词的有效性状态
    
                for kw, is_valid in guesser.keyword_isvalid.items():
                    is_print = False
                    if is_valid:
                        is_print = True
                        break
                    
                if guesser.keywords and is_print:
                    print("keyword_isvalid:")
                    for kw, is_valid in guesser.keyword_isvalid.items():
                        if is_valid:
                            print(f"{kw}: {is_valid}")

if __name__ == "__main__":

    main()
