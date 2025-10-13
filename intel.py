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
    检查seq是否为某个关键词的前缀，返回所有匹配的关键词列表。
    """
    matches = []
    for kw in keywords:
        if kw.startswith(seq) and len(seq) < len(kw): # kw是否以seq开头且比seq长
            matches.append(kw)
    return matches
