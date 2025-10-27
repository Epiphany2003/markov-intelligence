def load_keywords(path):
    """
    从指定txt文件读取关键词（情报片段），每行一个关键词，去除空白和重复。
    返回关键词列表。
    """
    keywords = set()
    with open(path, 'r') as f:
        for line in f:
            word = line.strip()
            if word:
                keywords.add(word)
    return list(keywords)

def match_prefix(seq, keywords):
    """
    检查seq是否为某个关键词的前缀或子串，返回所有匹配的关键词列表。
    """
    matches = []
    for kw in keywords:
        if seq in kw and len(seq) < len(kw):  # 检查seq是否为kw的子串
            matches.append(kw)
    return matches
