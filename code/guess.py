from sortedcontainers import SortedList  # 替换 PriorityQueue
from intel import load_keywords, match_prefix, is_mask_match_keywords
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

# # 计算阈值，用于过滤概率过低的密码序列，减少无效猜测，控制计算成本。
# def threhold(m, n):

#     thre = []
#     p = 1.0 / n
#     thre.append(p)
#     for i in range(int(n/m)):
#         p = p / max(2, 1.5 * n / m)
#         thre.append(p)
#     return thre

class Guess():

    def __init__(self, base, start_symbol, order, testpd, keywords=None, mask=None):

        self.base = base
        self.start_symbol = start_symbol
        self.order = order
        self.queue = SortedList(key=lambda x: -x[0])  # 按概率降序排序
        self.num_guess = 0  # 总共猜测的次数
        self.true_guess = 0  # 猜测正确的次数
        self.flag = 1
        self.testpd = testpd
        self.keywords = keywords or []# 格式：[(kw, mask), ...]
        self.min_length = 3  # 最小密码长度
        self.max_length = 20  # 最大密码长度

        # 参数控制
        self.max_queue_size = 100000
        self.start_time = time.time()
        self.max_runtime = 3600  # 最大运行时间（秒），如1小时
        self.max_memory_mb = 2048  # 最大内存占用（MB）

        # 去重检查
        self.guessed_pwds = set()  # 记录已经生成的密码
        self.processed_kw = set()  # 记录已处理的关键词

        # 关键词优先级动态调整相关参数
        self.keyword_initial_priority = 1000.0  # 初始优先级
        self.keyword_priorities = {kw: self.keyword_initial_priority for kw, mask in self.keywords}  # 每个关键词单独的优先级
        self.keyword_isvalid = {kw: True for kw, mask in self.keywords} # 关键词是否有效
        self.true_guess_no_growth_threshold = 5  # 连续多次猜测无新增true_guess触发优化
        self.keyword_consecutive_no_growth = {kw: 0 for kw, mask in self.keywords}
        self.priority_decay = 0  # 优先级衰减系数，直接衰减到0

        # 增加评估标准，考虑关键词的贡献度
        self.keywords_true_guess = 0

        # 新增掩码支持
        self.mask = mask  # 掩码类型列表，['lower', 'lower', 'digit']
        self.lower_chars = set('abcdefghijklmnopqrstuvwxyz')
        self.upper_chars = set('ABCDEFGHIJKLMNOPQRSTUVWXYZ')
        self.digit_chars = set('0123456789')

    # 初始化队列。从起始符号开始，生成初始的密码前缀序列，放入优先队列
    def initqueue(self, thre = 0):
        ''' 加入关键词(可选) '''
        # 如果有掩码，先看看看关键词能不能符合掩码要求
        self._matches_mask("", "", isInit=True)

        for kw, _ in self.keywords:
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
            self.queue.add(qobject)

    # 密码生成和验证
    # 循环从队列中取出高概率序列，扩展生成新序列；若遇到密码结束标记，则生成完整密码并验证，统计结果。
    def insertqueue(self, thre):

        # 移除队尾元素以控制队列大小
        if len(self.queue) > self.max_queue_size:
            self.queue.pop()  # 弹出队尾元素（最低概率）

        # 终止条件：队列空或总猜测次数超过 5 万
        if len(self.queue) == 0 or self.num_guess >= 50000:
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

        # 2. 若当前序列包含完整关键词，直接输出
        for kw, kw_mask in self.keywords:
            # 去重检查
            if current_pwd in self.guessed_pwds or kw in self.processed_kw:
                continue

            if (kw in current_pwd 
                and self.keyword_isvalid[kw] 
                and is_mask_match_keywords(current_pwd, kw, kw_mask)):

                self.record_guess(current_pwd, current_prob)

                hit_occurred = False # 检测是否命中
                if current_pwd in self.testpd:
                    hit_count = self.testpd[current_pwd] # 验证集中命中的个数
                    hit_occurred = True
                    self.true_guess += hit_count
                    del self.testpd[current_pwd]
                # self.processed_kw.add(kw)

                # 更新连续无增长计数
                if hit_occurred:
                    self.keyword_consecutive_no_growth[kw] = 0  # 有增长，重置计数
                else:
                    self.keyword_consecutive_no_growth[kw] += 1  # 无增长，计数+1

                self.is_keywords_valid(kw)
                return
        
        # 3. 防止生成过长的密码
        if self.mask:
            if len(current_pwd) > self.order + len(self.mask):
                return
        else:
            if len(current_pwd) > self.max_length + self.order:
                return

        # 基于带掩码的关键词拓展
        matches = match_prefix(current_pwd, self.keywords) # 返回[(kw, mask), ...]
        if matches:
            # 过滤掉已无效的关键词
            valid_matches = [(kw, kw_mask) for kw, kw_mask in matches if self.keyword_isvalid[kw]]
            for kw, kw_mask in valid_matches:
                extended_pwd = None # 初始化拓展后的密码

                # (1) 处理开头掩码：^keyword
                if kw_mask == '^':
                    # 情况1：当前密码为空 -> 直接用关键词作为开头
                    if current_pwd == "":
                        extended_pwd = kw
                    # 情况2：非空，当前密码是关键词的前缀（如current_pwd="ad"，kw="admin"）→ 补全关键词
                    elif kw.startswith(current_pwd):
                        extended_pwd = kw
                    # 其他情况：当前密码已偏离开头位置→ 不扩展

                # (2) 处理结尾掩码：keyword$
                elif kw_mask == '$':
                    # 情况1：当前密码是关键词的后缀（如current_pwd="min"，kw="admin"）→ 补全关键词
                    if kw.endswith(current_pwd):
                        extended_pwd = kw + '\n'  # 确保扩展后关键词在结尾
                    # 情况2：当前密码为空→ 直接用关键词（本身就是结尾）
                    elif not current_pwd:
                        extended_pwd = kw + '\n'
                    # 其他情况：当前密码已偏离结尾位置→ 不扩展

                # (3) 索引掩码：n:keyword
                elif kw_mask.isdigit():
                    start_idx = int(kw_mask)
                    current_len = len(current_pwd)
                    
                    # 当前密码正好到start_idx位置→ 直接拼接关键词
                    if current_len == start_idx:
                        extended_pwd = current_pwd + kw
                    # 其他情况：当前密码已超过start_idx→ 不扩展
                
                # 验证扩展后的密码是否符合掩码位置约束（二次校验）
                if extended_pwd is not None and is_mask_match_keywords(extended_pwd, kw, kw_mask):
                    # 检查是否符合全局掩码长度要求（如果有）
                    if self.mask and len(extended_pwd) > len(self.mask):
                        continue
                    
                    # 生成完整序列并加入队列
                    full_kw_seq = self.start_symbol + extended_pwd
                    if len(full_kw_seq) <= 20 + self.order:  # 控制最大长度
                        ext_priority = self.keyword_priorities[kw] / len(kw)
                        if ext_priority > 0:
                            self.queue.add([
                                ext_priority,
                                full_kw_seq,
                                full_kw_seq[-self.order:]  # 用于下次扩展的前缀
                            ])

                # # 计算当前密码与关键词的重叠部分，生成扩展序列
                # # 例如：current_pwd是"xyl"，kw是"love"，则重叠"l"，扩展后为"xylove"
                # overlap_len = 0
                # for i in range(1, min(len(current_pwd), len(kw)) + 1):
                #     if current_pwd.endswith(kw[:i]):
                #         overlap_len = i

                # # 生成包含关键词的新序列（current_pwd + 关键词的非重叠部分）
                # extended_pwd = current_pwd + kw[overlap_len:]
                # # 检查扩展后的密码是否符合掩码长度要求
                # if self.mask and len(extended_pwd) > len(self.mask):
                #     continue

                # # 生成完整关键词序列
                # full_kw_seq = self.start_symbol + extended_pwd
                # # 确保序列长度合法
                # if len(full_kw_seq) <= 20 + self.order:
                #     ext_priority = self.keyword_priorities[kw] / len(kw)    
                #     ext_object = [
                #         ext_priority,
                #         full_kw_seq,
                #         full_kw_seq[-self.order:]
                #     ]
                #     # 仅添加仍有有效优先级的关键词序列（优先级>0）
                #     if ext_priority > 0:
                #         self.queue.add(ext_object)


        # 普通序列拓展
        if current_prefix in self.base: # 前缀存在于base中
            for b in list(self.base[current_prefix]): # b：{字符， 频率}
                next_char = b[0]
                next_prob = b[1]

                # 处理密码结束标记
                if next_char == '\n': # 输出密码
                    # 如果设置了掩码，需要检查长度
                    if self.mask and len(current_pwd) != len(self.mask):
                        continue

                    if len(current_seq) > self.min_length + self.order: # 需要长度足够
                        pwd = current_pwd # 去掉起始符号的密码

                        if pwd in self.guessed_pwds:
                            continue

                        hit_occurred = False # 检测是否命中
                        if pwd in self.testpd: # 验证
                            hit_count = self.testpd[pwd]
                            self.true_guess += hit_count
                            hit_occurred = True
                            del self.testpd[pwd]

                        isLoop = False
                        # 检测输出的密码中是否包含关键词，如果包含，那么就更新连续无增长次数和历史记录
                        for kw, kw_mask in self.keywords:
                            if not self.keyword_isvalid[kw]: # 无效
                                continue
                                
                            if kw in pwd and is_mask_match_keywords(pwd, kw, kw_mask):                        
                                # 更新连续无增长次数和历史记录
                                if hit_occurred:
                                    self.keyword_consecutive_no_growth[kw] = 0  # 有增长，重置计数
                                else:
                                    self.keyword_consecutive_no_growth[kw] += 1  # 无增长，计数+1

                                self.is_keywords_valid(kw)

                                self.record_guess(pwd, current_prob)
                                isLoop = True

                        if not isLoop:
                            self.record_guess(pwd, current_prob)

                    continue

                # 检查是否符合掩码约束
                if self._matches_mask(current_pwd, b[0]) == False:
                    continue

                # 非结束符处理
                newobject = [
                    current_prob * next_prob,  # 普通序列概率计算
                    current_seq + next_char,
                    (current_seq + next_char)[-self.order:] # 用于下次拓展
                ]
                if newobject[0] >= thre:
                    self.queue.add(newobject)

        # self.is_keywords_valid()
        # print("连续无增长次数：{}".format(self.consecutive_no_growth))
        
    def is_keywords_valid(self, kw):
        if not kw or not self.keyword_isvalid[kw]:
            return  

        # 当连续多次无新增true_guess时，降低关键词优先级
        if self.keyword_consecutive_no_growth[kw] >= self.true_guess_no_growth_threshold:
            # 直接将优先级衰减到0
            self.keyword_priorities[kw] = 0
            self.keyword_isvalid[kw] = False  # 标记为无效
            self._clean_invalid_keyword_sequences(kw)
            self.keyword_consecutive_no_growth[kw] = 0  # 重置计数

    def _clean_invalid_keyword_sequences(self, kw):
        """清理队列中与已无效关键词相关的序列"""
        if not kw:
            return

        # 过滤队列：移除包含任何无效关键词的序列
        new_queue = []
        for item in self.queue:
            seq = item[1]
            pwd = seq[self.order:]  # 提取有效密码部分
            # 检查是否包含任何无效关键词
            if kw in pwd:
                continue  # 跳过包含无效关键词的序列
            new_queue.append(item)

        # 重建队列（保持排序）
        self.queue = SortedList(new_queue, key=lambda x: -x[0])

    # 检查是否符合掩码标准
    def _matches_mask(self, pwd, ch, isInit=False):
        if isInit:
            if not self.mask:
                return
            
            valid_keywords = []
            for kw in self.keywords:
                if len(kw) != len(self.mask):
                    continue  # 长度不匹配
                match = True
                for i, ch in enumerate(kw):
                    char_type = self.mask[i]
                    if char_type == 'lower' and ch not in self.lower_chars:
                        match = False
                        break
                    if char_type == 'upper' and ch not in self.upper_chars:
                        match = False
                        break
                    if char_type == 'digit' and ch not in self.digit_chars:
                        match = False
                        break
                if match:
                    valid_keywords.append(kw)
            self.keywords = valid_keywords

        if not isInit:
            if not self.mask:
                return True  # 无掩码要求，直接通过

            if len(pwd) > len(self.mask):
                return False  # 长度不匹配

            current_pos = len(pwd)  # 当前要添加的是第几个字符
            if current_pos >= len(self.mask):  # 已经达到掩码长度，不再添加字符
                return False

            char_type = self.mask[current_pos]
            # 检查字符是否符合当前位置的掩码要求
            if char_type == 'lower' and ch not in self.lower_chars:
                return False
            if char_type == 'upper' and ch not in self.upper_chars:
                return False
            if char_type == 'digit' and ch not in self.digit_chars:
                return False

            return True

    # 记录猜测
    def record_guess(self, pwd, current_prob):
        with open('guess.txt', 'a+') as file:
            file.write(pwd+ '\t' + str(abs(current_prob)) + '\n')
            self.num_guess += 1
            self.guessed_pwds.add(pwd)  # 记录已生成的密码，用于去重
