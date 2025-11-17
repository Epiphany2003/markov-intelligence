import re

class RuleEngine:
    """密码规则引擎，用于基于基础密码生成符合常见规则的变体"""
    
    def __init__(self):
        # 定义常见替换规则（如leet替换）
        self.replace_rules = [
            {'pattern': 'o', 'replace': '0'},
            {'pattern': 'i', 'replace': '1'},
            {'pattern': 'l', 'replace': '1'},
            {'pattern': 'e', 'replace': '3'},
            {'pattern': 'a', 'replace': '@'},
            {'pattern': 's', 'replace': '$'},
            {'pattern': 't', 'replace': '7'}
        ]
        
        # 定义常见后缀规则
        self.suffix_rules = [
            lambda: str(random.randint(0, 99)),  # 两位数字
            lambda: str(random.randint(2000, 2024)),  # 年份
            lambda: '!' if random.random() > 0.5 else '?',  # 特殊字符
        ]
        
        # 大小写变换规则
        self.case_rules = [
            lambda s: s.capitalize(),  # 首字母大写
            lambda s: s.upper(),       # 全大写
            lambda s: s.lower(),       # 全小写
            lambda s: self._random_case(s)  # 随机大小写
        ]

    def _random_case(self, s):
        """随机大小写转换"""
        return ''.join([c.upper() if random.random() > 0.5 else c.lower() for c in s])
    
    def apply_replace_rules(self, base_password):
        """应用字符替换规则生成变体"""
        variants = {base_password}  # 保留原始密码
        current = base_password
        
        for rule in self.replace_rules:
            # 替换所有可能的字符
            new_var = current.replace(rule['pattern'], rule['replace'])
            if new_var != current:
                variants.add(new_var)
                current = new_var  # 链式替换
        
        return list(variants)
    
    def apply_suffix_rules(self, base_password):
        """应用后缀规则生成变体"""
        variants = {base_password}
        for suffix_gen in self.suffix_rules:
            suffix = suffix_gen()
            variants.add(f"{base_password}{suffix}")
        
        # 组合后缀（如数字+特殊字符）
        if len(self.suffix_rules) >= 2:
            suffix1 = self.suffix_rules[0]()
            suffix2 = self.suffix_rules[2]()
            variants.add(f"{base_password}{suffix1}{suffix2}")
        
        return list(variants)
    
    def apply_case_rules(self, base_password):
        """应用大小写规则生成变体"""
        variants = set()
        for case_func in self.case_rules:
            variants.add(case_func(base_password))
        return list(variants)
    
    def generate_variants(self, base_password, max_variants=5):
        """生成所有可能的规则变体（限制数量避免爆炸）"""
        if not base_password:
            return []
            
        variants = {base_password}
        
        # 应用所有规则
        case_vars = self.apply_case_rules(base_password)
        replace_vars = []
        for var in case_vars:
            replace_vars.extend(self.apply_replace_rules(var))
        
        suffix_vars = []
        for var in replace_vars:
            suffix_vars.extend(self.apply_suffix_rules(var))
        
        # 合并所有变体
        variants.update(case_vars)
        variants.update(replace_vars)
        variants.update(suffix_vars)
        
        # 限制变体数量并返回
        result = list(variants)
        return result[:max_variants]