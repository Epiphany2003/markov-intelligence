from queue import PriorityQueue

# 导入测试数据
# 后续猜测出的密码会与该字典比对，若匹配则累加其出现次数（统计猜对的总数量）
def testpass(path):
    passwd = {}
    with open(path, 'r') as wordList:
        for line in wordList:
            pd = line.strip()
            if pd in passwd:
                passwd[pd] += 1
            else:
                passwd.setdefault(pd, 1)
    return passwd

# 计算阈值，用于过滤概率过低的密码序列，减少无效猜测，控制计算成本。
def threhold(m, n):

    thre = []
    p = 1.0 / n
    thre.append(p)
    for i in range(int(n/m)):
        p = p / max(2, 1.5 * n / m)
        thre.append(p)
    return thre

class Guess():

    def __init__(self, base, start_symbol, order, testpd):

        self.base = base
        self.start_symbol = start_symbol
        self.order = order
        self.queue = PriorityQueue()
        self.num_guess = 0  # 总共猜测的次数
        self.true_guess = 0  # 猜测正确的次数
        self.flag = 1
        self.testpd = testpd

    # 初始化队列。从起始符号开始，生成初始的密码前缀序列，放入优先队列
    def initqueue(self, thre):
        start = self.start_symbol
        bs = list(self.base[start])
        for b in bs: # b[0] 为字符，b[1] 为概率
            if b[0] == '\n':
                continue
            qobject = [None] * 3 # 序列的最后 order 个字符（作为下一次扩展的 “前缀”）
            qobject[1] = start + b[0] # 当前序列（起始符号 + 字符）
            qobject[0] = -1 * b[1] # 概率取负值，保证优先队列中概率大的在前面，因为python是最小堆

            if qobject[0] > -thre:
                continue

            qobject[2] = qobject[1][-self.order:]
            self.queue.put(qobject) # 符合条件的加入队列

    # 密码生成和验证
    # 循环从队列中取出高概率序列，扩展生成新序列；若遇到密码结束标记，则生成完整密码并验证，统计结果。
    def insertqueue(self, thre):

        # 终止条件：队列空或总猜测次数超过 100 万
        if self.queue.empty() or self.num_guess > 1000000:
            print("all possible gussess have be output")
            print("GUESS:", self.true_guess)
            print("TRUE:", self.num_guess)
            self.flag = 0
            return
        qobject = self.queue.get()
        # 防止生成过长的密码
        if len(qobject[1]) > 20+self.order:
            return
        if qobject[2] in self.base:
            for b in list(self.base[qobject[2]]):
                # 处理密码结束标记
                if b[0] == '\n':
                    if len(qobject[1]) > 3+self.order: # 需要长度足够
                        self.num_guess += 1
                        pwd = qobject[1][self.order:]
                        with open('guess.txt', 'a+') as file: # 记录猜测
                            file.write(pwd+ '\t' + str(qobject[0]) + '\n')
                        if pwd in self.testpd: # 验证
                            self.true_guess += self.testpd[pwd]
                            del self.testpd[pwd]
                    continue

                # 非结束部分
                newobject = [None] * 3
                newobject[1] = qobject[1] + b[0]
                newobject[0] = qobject[0] * b[1] # 计算新序列概率

                if newobject[0] > -thre:
                    # 代码中使用的优先队列是python queue库中内置的PriorityQueue类，它默认的排序方式是由小到大，而在口令猜测时我希望概率越大的口令能够出现在队列的前端，所以我对所有口令概率取的都是负值，从而保证在更短时间内破解更多的口令
                    continue

                newobject[2] = newobject[1][-self.order:] # 用于下次拓展
                self.queue.put(newobject)



