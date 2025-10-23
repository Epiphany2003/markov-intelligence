from queue import PriorityQueue
from intel import load_keywords, match_prefix
import time
import resource

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

    def __init__(self, base, start_symbol, order, testpd, keywords=None):

        self.base = base
        self.start_symbol = start_symbol
        self.order = order
        self.queue = PriorityQueue()
        self.num_guess = 0  # 总共猜测的次数
        self.true_guess = 0  # 猜测正确的次数
        self.flag = 1
        self.testpd = testpd
        self.keywords = keywords or []
        self.processed_kw = set()  # 记录已处理的关键词避免重复
        self.start_time = time.time()
        self.max_runtime = 3600  # 最大运行时间（秒），如1小时
        self.max_memory_mb = 2048  # 最大内存占用（MB）

    # 初始化队列。从起始符号开始，生成初始的密码前缀序列，放入优先队列
    def initqueue(self, thre):
        ''' 加入关键词(可选) '''
        for kw in self.keywords:
            if not kw:
                continue
            # 构建带起始符号的序列
            seq = self.start_symbol + kw
            # 使用极高优先级（-1000确保排在最前）
            qobject = [
                -1000.0,  # 优先级（负值越小优先级越高）
                seq,      # 当前序列
                seq[-self.order:]  # 用于扩展的前缀
            ]
            self.queue.put(qobject)

        '''没有关键词的情况：'''
        # 只处理了起始符号后的第一个字符
        start = self.start_symbol # 由order个 '#' 组成
        bs = list(self.base[start])
        for b in bs: # b[0] 为字符，b[1] 为概率
            if b[0] == '\n':
                continue
            qobject = [None] * 3 # object长度为3
            qobject[1] = start + b[0] # 当前序列（起始符号 + 字符）
            qobject[0] = -1 * b[1] # 概率取负值，保证优先队列中概率大的在前面，因为python是最小堆

            if qobject[0] > -thre:
                continue
            qobject[2] = qobject[1][-self.order:]
            self.queue.put(qobject) # 符合条件的加入队列

    # 密码生成和验证
    # 循环从队列中取出高概率序列，扩展生成新序列；若遇到密码结束标记，则生成完整密码并验证，统计结果。
    def insertqueue(self, thre):
        # 检查运行时间
        if time.time() - self.start_time > self.max_runtime:
            print("超过最大运行时间，主动退出")
            self.flag = 0
            return

        # 检查内存占用（Linux系统）
        mem_usage = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024  # MB
        if mem_usage > self.max_memory_mb:
            print(f"内存占用超过{self.max_memory_mb}MB，主动退出")
            self.flag = 0
            return

        # 终止条件：队列空或总猜测次数超过 100 万
        if self.queue.empty() or self.num_guess > 1000000:
            print("所有的可能的猜测已经输出")
            print("正确猜测:", self.true_guess)
            print("总猜测:", self.num_guess)
            self.flag = 0
            return

        qobject = self.queue.get()
        current_seq = qobject[1]
        current_prob = qobject[0]
        current_prefix = qobject[2]

        # 提取当前有效密码（去除起始符号）
        current_pwd = current_seq[self.order:]

        # 2. 若当前序列包含完整关键词，直接输出并标记已处理
        for kw in self.keywords:
            if kw in current_pwd and kw not in self.processed_kw:
                self.num_guess += 1
                with open('guess.txt', 'w') as f:
                    f.write(f"{current_pwd}\t{abs(current_prob)}\n")
                if current_pwd in self.testpd:
                    self.true_guess += self.testpd[current_pwd]
                    del self.testpd[current_pwd]
                self.processed_kw.add(kw)
                return
        
        # 3. 防止生成过长的密码
        if len(current_seq) > 20 + self.order:
            return

        # 4. 优先基于关键词扩展（如果当前前缀是关键词的一部分）
        matches = match_prefix(current_pwd, self.keywords)
        if matches:
            for kw in matches:
                # 生成完整关键词序列
                full_kw_seq = self.start_symbol + kw
                # 确保序列长度合法
                if len(full_kw_seq) <= 20 + self.order:
                    # 高优先级加入队列
                    ext_object = [
                        -900.0,  # 低于初始关键词但高于普通序列
                        full_kw_seq,
                        full_kw_seq[-self.order:]
                    ]
                    self.queue.put(ext_object)

        if current_prefix in self.base: # 前缀存在于base中
            for b in list(self.base[current_prefix]):
                # 处理密码结束标记
                if b[0] == '\n': # 输出密码
                    if len(current_seq) > 3 + self.order: # 需要长度足够
                        self.num_guess += 1
                        pwd = current_pwd # 去掉起始符号，输出的密码
                        with open('guess.txt', 'w') as file: # 记录猜测
                            file.write(pwd+ '\t' + str(abs(current_prob)) + '\n')
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



