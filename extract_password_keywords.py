import sys
import os
from collections import defaultdict


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


def count_keyword_positions(passwords, keywords):
    """统计关键词在密码中的位置分布（按密码长度比例）"""
    pos_ratios = []  # 存储关键词起始位置占密码长度的比例
    for pwd in passwords:
        pwd_len = len(pwd)
        if pwd_len == 0:
            continue
        for kw, _ in keywords:  # 仅使用关键词文本，忽略计数
            kw_len = len(kw)
            if kw_len > pwd_len:
                continue
            # 查找关键词在密码中的所有出现位置
            for i in range(pwd_len - kw_len + 1):
                if pwd[i:i+kw_len] == kw:
                    # 计算位置比例（0~1，0为开头，1为结尾）
                    pos_ratio = i / pwd_len if pwd_len != 0 else 0
                    pos_ratios.append(pos_ratio)
    return pos_ratios


def generate_position_distribution(pos_ratios, bins=3):
    """
    基于位置比例生成概率分布（按区间划分）
    :param pos_ratios: 关键词起始位置占密码长度的比例列表
    :param bins: 划分的区间数量（如3表示前1/3、中1/3、后1/3）
    :return: 区间概率字典，格式为{(lower, upper): probability}
    """
    if not pos_ratios:  # 无数据时返回均匀分布
        default_dist = {}
        bin_width = 1.0 / bins
        for i in range(bins):
            lower = round(i * bin_width, 4)
            upper = round((i + 1) * bin_width, 4)
            default_dist[(lower, upper)] = round(1.0 / bins, 4)
        return default_dist
    
    # 统计每个区间的出现次数
    bin_counts = defaultdict(int)
    total = len(pos_ratios)
    bin_width = 1.0 / bins
    
    for ratio in pos_ratios:
        # 确定当前比例所属区间
        for i in range(bins):
            lower = i * bin_width
            upper = (i + 1) * bin_width
            if lower <= ratio < upper:
                bin_counts[(round(lower, 4), round(upper, 4))] += 1
                break
        else:  # 处理刚好等于1.0的边界情况（归入最后一个区间）
            last_lower = round((bins - 1) * bin_width, 4)
            bin_counts[(last_lower, 1.0)] += 1
    
    # 计算概率（占比）
    distribution = {
        (lower, upper): round(count / total, 4)
        for (lower, upper), count in bin_counts.items()
    }
    return distribution


def save_results(keywords, position_dist, output_dir="results"):
    """保存关键词和位置分布结果到文件"""
    # 创建结果目录
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)
    
    # 保存关键词（带出现次数）
    with open(os.path.join(output_dir, "keywords.txt"), "w", encoding="utf-8") as f:
        f.write("关键词\t出现次数\n")
        for kw, count in keywords:
            f.write(f"{kw}\t{count}\n")
    
    # 保存位置分布
    with open(os.path.join(output_dir, "position_distribution.txt"), "w", encoding="utf-8") as f:
        f.write("位置区间（占密码长度比例）\t概率\n")
        for (lower, upper), prob in sorted(position_dist.keys()):
            f.write(f"[{lower:.2f}, {upper:.2f})\t{prob:.4f}\n")
    
    print(f"\n结果已保存至 {output_dir} 目录")


def main(
    file_path,
    min_sub_len=2,
    max_sub_len=8,
    min_occurrence=2,
    position_bins=3,
    save=False
):
    """
    主函数：读取密码、分析子串、提取关键词、统计位置分布并输出
    :param position_bins: 位置区间划分数量
    :param save: 是否保存结果到文件
    """
    # 1. 读取密码
    passwords = read_passwords(file_path)
    print(f"成功读取 {len(passwords)} 个密码")
    
    # 2. 统计子串出现次数
    substr_counts = count_common_substrings(passwords, min_sub_len, max_sub_len)
    print(f"共统计到 {len(substr_counts)} 个符合长度的子串")
    
    # 3. 提取关键词
    keywords = extract_keywords(substr_counts, min_occurrence)
    print(f"\n筛选出的关键词（出现次数≥{min_occurrence}）：共 {len(keywords)} 个")
    if keywords:
        # 打印前10个关键词（避免输出过长）
        for i, (kw, count) in enumerate(keywords[:10]):
            print(f"[{i+1}] 关键词: '{kw}' | 出现于 {count} 个密码中")
        if len(keywords) > 10:
            print(f"... 还有 {len(keywords)-10} 个关键词未显示")
    
    # 4. 统计关键词位置分布
    if keywords:  # 只有存在关键词时才分析位置
        pos_ratios = count_keyword_positions(passwords, keywords)
        print(f"\n统计到 {len(pos_ratios)} 个关键词位置数据")
        
        # 生成位置概率分布
        position_dist = generate_position_distribution(pos_ratios, bins=position_bins)
        print(f"\n关键词位置概率分布（按 {position_bins} 个区间划分）：")
        for (lower, upper), prob in sorted(position_dist.items()):
            print(f"区间 [{lower:.2f}, {upper:.2f}) | 概率: {prob:.2%}")
    else:
        position_dist = None
        print("\n无关键词可分析位置分布")
    


if __name__ == "__main__":
    # 可根据需要调整以下参数
    MIN_SUB_LENGTH = 4       # 子串最小长度（过短可能导致无意义关键词）
    MAX_SUB_LENGTH = 6       # 子串最大长度（过长可能导致关键词过于特殊）
    MIN_OCCURRENCE = 8000    # 关键词至少出现的密码数量
    POSITION_BINS = 3        # 位置区间划分数量（如3：前1/3、中1/3、后1/3）
    SAVE_RESULTS = True      # 是否保存结果到文件
    
    # 调用主函数
    main(
        file_path="data/trainword.txt",
        min_sub_len=MIN_SUB_LENGTH,
        max_sub_len=MAX_SUB_LENGTH,
        min_occurrence=MIN_OCCURRENCE,
        position_bins=POSITION_BINS,
        save=SAVE_RESULTS
    )