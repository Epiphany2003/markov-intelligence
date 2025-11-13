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
        self.start_time = time.time()
        self.max_runtime = 3600  # 最大运行时间（秒），如1小时
        self.max_memory_mb = 2048  # 最大内存占用（MB）

        # 队列控制参数
        self.max_queue_size = 100000

        # 记录已经生成的密码，防止重复生成
        self.guessed_pwds = set()
        
        # 关键词优先级动态调整相关参数
        self.keyword_initial_priority = 1000.0  # 初始优先级
        self.keyword_priorities = {kw: self.keyword_initial_priority for kw in self.keywords}  # 每个关键词单独的优先级
        self.keyword_isvalid = {kw: True for kw in self.keywords} # 关键词是否有效
        self.true_guess_no_growth_threshold = 200  # 连续10次猜测无新增true_guess触发优化
        self.consecutive_no_growth = 0  # 连续无true_guess增长的猜测次数
        self.priority_decay = 0  # 优先级衰减系数，直接衰减到0
        self.consecutive_no_growth = 0  # 连续无true_guess增长的猜测次数

    # 初始化队列。从起始符号开始，生成初始的密码前缀序列，放入优先队列
    def initqueue(self, thre = 0):
        ''' 加入关键词(可选) '''
        for kw in self.keywords:
            if not kw or not self.keyword_isvalid[kw]:
                continue
            # 构建带起始符号的序列
            seq = self.start_symbol + kw
            
            qobject = [
                self.keyword_priorities[kw] / len(kw),  # 使用极高优先级（根据关键词长度加权）
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

        # 终止条件：队列空或总猜测次数超过 100 万
        if len(self.queue) == 0 or self.num_guess > 500000:
            print("所有的可能的猜测已经输出")
            print("正确猜测:", self.true_guess)
            print("总猜测:", self.num_guess)
            self.flag = 0
            return

        qobject = self.queue.pop(0)  # 从队首取出最高概率的元素
        current_seq = qobject[1]
        current_prob = qobject[0]
        current_prefix = qobject[2]
        current_pwd = current_seq[self.order:] # 当前有效密码（去除起始符号部分）

        # 2. 若当前序列包含完整关键词，直接输出并标记已处理
        for kw in self.keywords:
            # 去重检查
            if current_pwd in self.guessed_pwds:
                continue

            if kw in current_pwd and kw not in self.processed_kw:
                if(self.keyword_isvalid[kw] == False):
                    continue

                self.num_guess += 1

                with open('guess.txt', 'a+') as f:
                    f.write(f"{current_pwd}\t{abs(current_prob)}\n")

                hit_occurred = False # 检测是否命中
                if current_pwd in self.testpd:
                    hit_count = self.testpd[current_pwd] # 验证集中命中的个数
                    hit_occurred = True
                    self.true_guess += hit_count
                    del self.testpd[current_pwd]
                self.processed_kw.add(kw)
                self.guessed_pwds.add(current_pwd)  # 记录已生成的密码

                # 更新连续无增长计数
                if hit_occurred:
                    self.consecutive_no_growth = 0  # 有增长，重置计数
                    self.last_true_guess = self.true_guess  # 记录当前增长后的值
                else:
                    self.consecutive_no_growth += 1  # 无增长，计数+1

                self.is_keywords_valid()
                return
        
        # 3. 防止生成过长的密码
        if len(current_seq) > 20 + self.order:
            return

        # 4. 优先基于关键词扩展（如果当前前缀是关键词的一部分）
        matches = match_prefix(current_pwd, self.keywords) # matches ：所有匹配上的关键词
        if matches:
            # 过滤掉已无效的关键词
            valid_matches = [kw for kw in matches if self.keyword_isvalid[kw]]
            for kw in valid_matches:
                # 计算当前密码与关键词的重叠部分，生成扩展序列
                # 例如：current_pwd是"xyl"，kw是"love"，则重叠"l"，扩展后为"xylove"
                overlap_len = 0
                for i in range(1, min(len(current_pwd), len(kw)) + 1):
                    if current_pwd.endswith(kw[:i]):
                        overlap_len = i

                # 生成包含关键词的新序列（current_pwd + 关键词的非重叠部分）
                extended_pwd = current_pwd + kw[overlap_len:]
                # 生成完整关键词序列
                full_kw_seq = self.start_symbol + extended_pwd
                # 确保序列长度合法
                if len(full_kw_seq) <= 20 + self.order:
                    ext_priority = self.keyword_priorities[kw] / len(kw)    
                    ext_object = [
                        ext_priority,
                        full_kw_seq,
                        full_kw_seq[-self.order:]
                    ]
                    # 仅添加仍有有效优先级的关键词序列（优先级>0）
                    if ext_priority > 0:
                        self.queue.add(ext_object)


        # 普通序列拓展
        if current_prefix in self.base: # 前缀存在于base中
            for b in list(self.base[current_prefix]):
                # 处理密码结束标记
                if b[0] == '\n': # 输出密码
                    if len(current_seq) > 3 + self.order: # 需要长度足够
                        pwd = current_pwd # 去掉起始符号，输出的密码
                        with open('guess.txt', 'a+') as file: # 记录猜测
                            file.write(pwd+ '\t' + str(abs(current_prob)) + '\n')
                            self.num_guess += 1
                            self.guessed_pwds.add(pwd)  # 记录已生成的密码，用于去重

                        hit_occurred = False # 检测是否命中
                        if pwd in self.testpd: # 验证
                            hit_count = self.testpd[pwd]
                            self.true_guess += hit_count
                            hit_occurred = True
                            del self.testpd[pwd]

                        # 更新连续无增长次数和历史记录
                        if hit_occurred:
                            self.consecutive_no_growth = 0  # 有增长，重置计数
                        else:
                            self.consecutive_no_growth += 1  # 无增长，计数+1

                    continue

                # 非结束符处理
                newobject = [
                    current_prob * b[1],  # 普通序列概率计算
                    current_seq + b[0],
                    (current_seq + b[0])[-self.order:] # 用于下次拓展
                ]
                if newobject[0] >= thre:
                    self.queue.add(newobject)

        self.is_keywords_valid()
        # print("连续无增长次数：{}".format(self.consecutive_no_growth))
        
    def is_keywords_valid(self):
        # 当连续多次无新增true_guess时，降低关键词优先级
        if self.consecutive_no_growth >= self.true_guess_no_growth_threshold:
            for kw in self.keywords:
                if self.keyword_isvalid[kw]:
                    # 直接将优先级衰减到0
                    self.keyword_priorities[kw] = 0
                    self.keyword_isvalid[kw] = False  # 标记为无效
                    self._clean_invalid_keyword_sequences()
            self.consecutive_no_growth = 0  # 重置计数

    def _clean_invalid_keyword_sequences(self):
        """清理队列中与已无效关键词相关的序列"""
        invalid_kw = [kw for kw in self.keywords if not self.keyword_isvalid[kw]]
        if not invalid_kw:
            return  # 没有无效关键词，直接返回

        # 过滤队列：移除包含任何无效关键词的序列
        new_queue = []
        for item in self.queue:
            seq = item[1]
            pwd = seq[self.order:]  # 提取有效密码部分
            # 检查是否包含任何无效关键词
            if any(kw in pwd for kw in invalid_kw):
                continue  # 跳过包含无效关键词的序列
            new_queue.append(item)

        # 重建队列（保持排序）
        self.queue = SortedList(new_queue, key=lambda x: -x[0])



