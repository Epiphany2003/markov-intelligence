def load_keywords(path):
    """
    从指定txt文件读取带掩码的关键词，支持三种掩码：
    - ^keyword：开头位置
    - keyword$：结尾位置
    - n:keyword：索引n开始（n为数字）
    无掩码的关键词将被过滤（不加载）
    keywords格式：[(kw1, mask1), (kw2, mask2), ...]
    """
    # keywords = []
    # with open(path, 'r') as f:
    #     for line in f:
    #         word = line.strip()
    #         if word:
    #             keywords.append(word)
    # return list(keywords)
    keywords = []
    with open(path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            
            # 解析掩码和关键词
            mask = ""
            kw = ""
            if line.startswith('^'):
                # 开头约束：^keyword
                mask = '^'
                kw = line[1:]
            elif line.endswith('$'):
                # 结尾约束：keyword$
                mask = '$'
                kw = line[:-1]
            elif ':' in line:
                # 索引约束：n:keyword
                parts = line.split(':', 1)
                if parts[0].isdigit():
                    mask = parts[0]  # 存储数字字符串
                    kw = parts[1]
                else:
                    # 不符合n:keyword格式，视为无掩码过滤
                    continue
            else:
                # 无掩码，直接过滤
                continue
            
            if kw:  # 确保关键词非空
                keywords.append((kw, mask))  # 存储为(关键词, 掩码)元组
    return keywords

def match_prefix(seq, keywords):
    """
    检查seq是否为某个关键词的前缀或子串，返回所有匹配的关键词列表。
    """
    matches = []
    for kw, mask in keywords:
        if seq in kw and len(seq) < len(kw):  # 检查seq是否为kw的子串
            matches.append((kw, mask))
    return matches

def is_mask_match_keywords(password, keyword, mask):
    """验证关键词在密码中的位置是否符合掩码规则"""
    kw_len = len(keyword)
    pwd_len = len(password)
    
    # 关键词长度超过密码长度，直接不匹配
    if kw_len > pwd_len:
        return False
    
    # 开头约束（^）
    if mask == '^':
        return password.startswith(keyword)
    
    # 结尾约束（$）
    if mask == '$':
        return password.endswith(keyword)
    
    # 索引位置约束（n）
    if mask.isdigit():
        start_idx = int(mask)
        end_idx = start_idx + kw_len
        if end_idx > pwd_len:  # 超出密码长度
            return False
        return password[start_idx:end_idx] == keyword
    
    return False  # 不应到达此分支（掩码已提前过滤）