from sortedcontainers import SortedList  # 替换 PriorityQueue
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
        self.queue = SortedList(key=lambda x: -x[0])  # 按概率降序排序
        self.num_guess = 0  # 总共猜测的次数
        self.true_guess = 0  # 猜测正确的次数
        self.flag = 1
        self.testpd = testpd
        self.keywords = keywords or []
        self.processed_kw = set()  # 记录已处理的关键词避免重复

        self.max_queue_size = 20000  # 队列最大容量
        self.start_time = time.time()
        self.max_runtime = 3600  # 最大运行时间（秒），如1小时
        self.max_memory_mb = 2048  # 最大内存占用（MB）

        # 动态调整优先级 的相关参数
        self.keyword_hit_ratio_threshold = 0.6  # 关键词贡献饱和阈值
        self.keyword_true_guess = 0  # 关键词相关的命中数
        self.keyword_priority = 1000.0  # 初始关键词优先级
        self.guessed_pwds = set()  # 记录已生成的密码，用于去重
        self.max_keyword_variants = 500  # 每个关键词的最大变体生成数
        self.keyword_variant_counts = {kw: 0 for kw in (keywords or [])}  # 变体计数

    # 初始化队列。从起始符号开始，生成初始的密码前缀序列，放入优先队列
    def initqueue(self, thre):
        ''' 加入关键词(可选) '''
        for kw in self.keywords:
            if not kw:
                continue
            # 构建带起始符号的序列
            seq = self.start_symbol + kw
            
            qobject = [
                1000.0 / len(kw),  # 使用极高优先级（根据关键词长度加权）
                seq,
                seq[-self.order:]  # 用于扩展的前缀
            ]
            self.queue.add(qobject)  # 使用 add 方法加入队列

        '''没有关键词的情况：'''
        # 只处理了起始符号后的第一个字符
        start = self.start_symbol # 由order个 '#' 组成
        bs = list(self.base[start])
        for b in bs: # b[0] 为字符，b[1] 为概率
            if b[0] == '\n':
                continue
            qobject = [None] * 3 # object长度为3
            qobject[1] = start + b[0] # 当前序列（起始符号 + 字符）
            qobject[0] = b[1] # 直接使用正数概率

            if qobject[0] < thre:
                continue
            qobject[2] = qobject[1][-self.order:]
            self.queue.add(qobject) # 使用 add 方法加入队列

    # 密码生成和验证
    # 循环从队列中取出高概率序列，扩展生成新序列；若遇到密码结束标记，则生成完整密码并验证，统计结果。
    def insertqueue(self, thre):
        # 移除队尾元素以控制队列大小
        if len(self.queue) > self.max_queue_size:
            self.queue.pop()  # 弹出队尾元素（最低概率）

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
        if len(self.queue) == 0 or self.num_guess > 1000000:
            print("所有的可能的猜测已经输出")
            print("正确猜测:", self.true_guess)
            print("总猜测:", self.num_guess)
            self.flag = 0
            return

        qobject = self.queue.pop(0)  # 从队首取出最高概率的元素
        current_seq = qobject[1]
        current_prob = qobject[0]
        current_prefix = qobject[2]

        # 提取当前有效密码（去除起始符号）
        current_pwd = current_seq[self.order:]

        # 2. 若当前序列包含完整关键词，直接输出；去重 + 限制变体
        for kw in self.keywords:
            # 去重检查
            if current_pwd in self.guessed_pwds:
                continue
            if kw in current_pwd and kw not in self.processed_kw:
                self.num_guess += 1
                with open('guess.txt', 'a+') as f:
                    f.write(f"{current_pwd}\t{current_prob}\n")
                self.guessed_pwds.add(current_pwd)  # 记录已生成

                if current_pwd in self.testpd:
                    hit_count = self.testpd[current_pwd] # 验证集中命中的个数
                    self.true_guess += hit_count
                    self.keyword_true_guess += hit_count # 关键词命中
                    del self.testpd[current_pwd]
                self.processed_kw.add(kw)  # 标记已处理
                return
        
        # 3. 防止生成过长的密码
        if len(current_seq) > 20 + self.order:
            return

        # 4. 优先基于关键词扩展（如果当前前缀是关键词的一部分）
        matches = match_prefix(current_pwd, self.keywords) # matches ：所有匹配上的关键词
        if matches:
            current_radio = self._get_keyword_hit_ratio() # 实时计算比例
            for kw in matches:
                # 检查变体是否超过上限
                if self.keyword_variant_counts[kw] >= self.max_keyword_variants:
                    continue
                self.keyword_variant_counts[kw] += 1  # 累加变体计数
                
                # 生成完整关键词序列
                full_kw_seq = self.start_symbol + kw
                # 确保序列长度合法
                if len(full_kw_seq) <= 20 + self.order:
                    # 动态调整扩展关键词的优先级
                    if current_radio < 0.4:
                        ext_priority = 900.0 / len(full_kw_seq) # 高优先级
                    elif current_radio < 0.6:
                        ext_priority = 0.4 / len(full_kw_seq) # 低优先级
                    else:
                        ext_priority = 0

                    ext_object = [
                        ext_priority, 
                        full_kw_seq,
                        full_kw_seq[-self.order:]
                    ]
                    self.queue.add(ext_object)

        # 普通序列拓展
        if current_prefix in self.base: # 前缀存在于base中
            for b in list(self.base[current_prefix]):
                # 处理密码结束标记
                if b[0] == '\n': # 输出密码
                    if len(current_seq) > 3 + self.order: # 需要长度足够
                        pwd = current_pwd # 去掉起始符号，输出的密码
                        # 去重检查  
                        if pwd in self.guessed_pwds:
                            continue
                        self.num_guess += 1
                        with open('guess.txt', 'a+') as file: # 记录猜测
                            file.write(pwd+ '\t' + str(current_prob) + '\n')
                        self.guessed_pwds.add(pwd)  # 记录已生成

                        if pwd in self.testpd: # 验证
                            hit_count = self.testpd[pwd]
                            self.true_guess += hit_count
                            ''' 检测是否未关键词相关代码, 若包含关键词则累加关键词命中 '''
                            if any(kw in pwd for kw in self.keywords):
                                self.keyword_true_guess += hit_count
                            del self.testpd[pwd]
                    continue

                # 非结束符处理
                newobject = [
                    current_prob * b[1],  # 普通序列概率计算
                    current_seq + b[0],
                    (current_seq + b[0])[-self.order:] # 用于下次拓展
                ]
                if newobject[0] >= thre:
                    self.queue.add(newobject)

    def _get_keyword_hit_ratio(self):
        if self.true_guess == 0:
            return 0.0  # 总命中为0时返回0，避免除零
        return self.keyword_true_guess / self.true_guess



