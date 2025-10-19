import matplotlib.pyplot as plt
import os
import numpy as np

# 读取memory.txt数据并处理
def load_data(order):
    file_path = f"order{order}/memory.txt"
    if not os.path.exists(file_path):
        print(f"文件不存在: {file_path}")
        return None
    
    num_guesses = []  # 总猜测数
    true_guesses = []  # 正确猜测数
    
    with open(file_path, 'r') as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            # 从代码可知格式为 true_guess / num_guess
            parts = line.split(' / ')
            if len(parts) != 2:
                continue
            tg, ng = map(int, parts)
            true_guesses.append(tg)
            num_guesses.append(ng)
    
    if not num_guesses or not true_guesses:
        return None
    
    # 计算最大猜测数和最大正确猜测数（作为测试集总数）
    max_num = max(num_guesses)
    max_true = max(true_guesses)
    
    # 计算比例
    guess_ratios = [ng / max_num for ng in num_guesses]
    cracked_percentages = [tg / max_num * 100 for tg in true_guesses]
    
    return (guess_ratios, cracked_percentages, max_num, max_true)

# 准备要绘制的阶数
orders = [3, 4, 5]
data = {}

for order in orders:
    res = load_data(order)
    if res:
        data[order] = res

# 定义要显示的横轴点
target_ratios = [0.0, 0.2, 0.4, 0.6, 0.8, 1.0]

# 绘图设置
plt.figure(figsize=(10, 6))
markers = ['o', 's', '^']
colors = ['r', 'g', 'b']

for i, order in enumerate(orders):
    if order not in data:
        continue
    guess_ratios, cracked_percentages, max_num, max_true = data[order]
    
    # 对数据排序
    sorted_pairs = sorted(zip(guess_ratios, cracked_percentages))
    guess_ratios_sorted = [x[0] for x in sorted_pairs]
    cracked_percentages_sorted = [x[1] for x in sorted_pairs]
    
    # 插值获取目标比例对应的破解百分比
    interp_percentages = np.interp(target_ratios, guess_ratios_sorted, cracked_percentages_sorted)
    
    # 绘制曲线
    plt.plot(guess_ratios_sorted, cracked_percentages_sorted, 
             label=f'Order {order}', 
             color=colors[i], 
             marker=markers[i], 
             markersize=5, 
             linestyle='-', 
             linewidth=2)

# 图表设置
plt.xlabel('Guesses (Ratio)', fontsize=12)
plt.ylabel('Cracked Percentage (%)', fontsize=12)
plt.title('Password Cracking Performance by Markov Order', fontsize=14)
plt.xlim(0, 1.0)
plt.ylim(0, 50)
plt.xticks(target_ratios, [f'{x:.1f}' for x in target_ratios])
plt.yticks(range(0, 51, 10))
plt.grid(True, linestyle='--', alpha=0.7)
plt.legend(fontsize=12)
plt.tight_layout()
# plt.show()
plt.savefig('cracking_performance.png', dpi=300)  # 保存为图片
print("性能曲线图已保存为 cracking_performance.png")