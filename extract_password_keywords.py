def read_passwords(file_path):
    """读取密码文件，返回清洗后的密码列表（去除空行，转为小写）"""
    with open(file_path, 'r', encoding='utf-8') as f:
        # 去除每行的空白字符，过滤空行，统一转为小写
        passwords = [line.strip().lower() for line in f if line.strip()]
    return passwords


def get_substrings(password, min_len=2, max_len=8):
    """生成单个密码中所有可能的子串（指定长度范围），返回不重复的子串集合"""
    substrs = set()
    pwd_len = len(password)
    # 遍历所有可能的起始位置
    for start in range(pwd_len):
        # 遍历可能的子串长度（从min_len到max_len，或到密码末尾）
        max_end = min(start + max_len, pwd_len)
        for end in range(start + min_len, max_end + 1):
            substr = password[start:end]
            substrs.add(substr)
    return substrs


def count_common_substrings(passwords, min_len=2, max_len=8):
    """统计所有密码中出现的子串及其在不同密码中的出现次数"""
    substr_counter = {}
    for pwd in passwords:
        # 获取当前密码的所有子串（去重）
        pwd_substrs = get_substrings(pwd, min_len, max_len)
        # 对每个子串进行计数（每个密码只贡献1次）
        for substr in pwd_substrs:
            if substr in substr_counter:
                substr_counter[substr] += 1
            else:
                substr_counter[substr] = 1
    return substr_counter


def extract_keywords(substr_counter, min_occurrence=2):
    """根据出现次数筛选关键词，返回按出现次数排序的结果"""
    # 筛选出现次数不低于阈值的子串
    keywords = {substr: count for substr, count in substr_counter.items() 
                if count >= min_occurrence}
    # 按出现次数降序排序
    return sorted(keywords.items(), key=lambda x: x[1], reverse=True)


def main(file_path, min_sub_len=2, max_sub_len=8, min_occurrence=2):
    """主函数：读取密码、分析子串、提取关键词并输出"""
    passwords = read_passwords(file_path)
    print(f"成功读取 {len(passwords)} 个密码")
    
    # 统计子串出现次数
    substr_counts = count_common_substrings(passwords, min_sub_len, max_sub_len)
    
    # 提取关键词
    keywords = extract_keywords(substr_counts, min_occurrence)
    
    # 输出结果
    print(f"\n筛选出的关键词（出现次数≥{min_occurrence}）：")
    if keywords:
        for kw, count in keywords:
            print(f"关键词: '{kw}' | 出现于 {count} 个密码中")
    else:
        print("未找到符合条件的关键词，请尝试降低min_occurrence或调整子串长度范围")


if __name__ == "__main__":
    import sys
    
    # 可根据需要调整以下参数
    MIN_SUB_LENGTH = 4    # 子串最小长度（过短可能导致无意义关键词）
    MAX_SUB_LENGTH = 6    # 子串最大长度（过长可能导致关键词过于特殊）
    MIN_OCCURRENCE = 10000    # 关键词至少出现的密码数量
    
    main(
        file_path=f"data/testword.txt",
        min_sub_len=MIN_SUB_LENGTH,
        max_sub_len=MAX_SUB_LENGTH,
        min_occurrence=MIN_OCCURRENCE
    )