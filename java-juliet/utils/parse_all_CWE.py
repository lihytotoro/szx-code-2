# 目标：处理单个 CWE 目录之下的所有 testcases，注意一个目录下可能有多个子目录，s01、s02 等
import os
import pandas as pd
import json
import jsonlines
import re
import numpy as np
import pandas as pd
import csv
# 从各个同目录文件中引用函数
from utils.parse_single_file_testcase import parse_single_file_testcase
from utils.parse_double_file_testcase import parse_double_file_testcase

total_testcases = 0
base_cwes_dir = "../testcases"
testcase_stat_path = "./testcase_stat.csv"
metadata_save_dir = "../testcase_metadata"

# should contain one bad execution and at least one relevant good execution

# 这里记录一下数据集作者的命名规则
# 一定有一个 bad 函数，然后 good 函数里面一般包含了多个（也可能是一个）fixed 的方法
# source 一般是指给数据赋值的操作，而 sink 一般是下游使用这些数据的操作
# good 方法修复时，既可以从 source 的角度进行修复，也就是 good source + bad sink，也可以从 sink 的角度进行修复，即 good sink + bad source

# good source + bad sink: goodG2B，后续可以接上 1、2、3...
# bad source + good sink: hoodB2G，后续可以接上 1、2、3...，注意，两者在该类方法只有一种时，也可以不加序号！

# 在这些函数内，有可能将 source 或者 sink 重新写成了一个封装好的函数，也就是类似 goodG2BSink、badSink 等方法
# 类似地，对于封装好的 source，形如 badSource、goodG2B1Source、goodG2B2Source 等

# 我们首先提取：类、函数（把 main 等函数全部撇去）的从属关系（所处文件、起止行数以及真实文本等）
# 之后，在构造某一个具体的样例时，按照 bad + CWE + 某一种 good 的方式构造三元组，按照类似 megadiff 的方式，处理成 parquet 等格式
# bad 和 good 的具体界限，应当是其中用到的所有函数（对于下游的类，应当把类内的所有其余函数都去掉，只保留用到的某几个函数）

# 目的：处理一个特定 CWE 名下的所有测例
# 输入：id、名称、路径
# 输出：对于每一个测例，返回：CWE 类型、bad execution（大部分情况下，应该只有一种）、good executions（多种，应该每种都算数）
def parse_single_cwe_get_testcase_dict(cwe_id, cwe_name, cwe_dir, in_subdir=False, subdir_path=None):
    '''
    cwe_id: CWE_15
    cwe_name: External_Control_of_System_or_Configuration_Setting（也就是目录名称除了 CWE_id 之外的其他内容）
    '''
    cnt_valid_testcases = 0
    # key: subname，即双下划线之外的名称；value: 一个 list，记录了该 testcase 名下的所有文件名
    valid_testcase_symbols = {}
    # 测试看看有没有次级目录
    test_cwe_sub_dir = os.path.join(cwe_dir, "s01")
    # 
    if os.path.exists(test_cwe_sub_dir):
        # print("CWE id %s has subdir, need to parse dir by dir" % cwe_id)
        sub_dirs = os.listdir(cwe_dir)
        merged_valid_testcase_symbols = {}
        related_file_cnt = 0
        for sub_dir in sub_dirs:
            cwe_sub_dir = os.path.join(cwe_dir, sub_dir)
            # TODO: 这里是逐个处理 CWE 主目录下的各个子目录的逻辑（s01, s02, ...）
            valid_testcase_symbols_i, related_file_cnt_i = parse_single_cwe_get_testcase_dict(cwe_id, cwe_name, cwe_sub_dir, in_subdir=True, subdir_path=sub_dir)
            # if cwe_id in ["CWE190", "CWE191"]:
            #     print("cwe_id:", cwe_id, "\tsubdir:", sub_dir, "\trelated file cnt:", related_file_cnt_i, "\ttestcase cnt:", len(valid_testcase_symbols_i))
            merged_valid_testcase_symbols.update(valid_testcase_symbols_i)
            related_file_cnt += related_file_cnt_i
        return merged_valid_testcase_symbols, related_file_cnt
    
    # 这里是不存在子目录情况下的逻辑，直接处理目录下所有 testcases
    testcase_files = os.listdir(cwe_dir)
    testcase_files = [file for file in testcase_files if file.startswith(cwe_id) and file.endswith(".java")]
    # 然后，逐个向上面的 字典 里添加 testcase
    for file in testcase_files:
        if file in ["CWE690_NULL_Deref_From_Return__Class_Helper.java", "CWE486_Compare_Classes_by_Name__Helper.java", "CWE586_Explicit_Call_to_Finalize__basic_Helper.java", \
                    "CWE499_Sensitive_Data_Serializable__serializable_Helper.java"]:
            continue
        filename_suffix = file.split("__")[-1].removesuffix(".java")
        # 如何从后缀中区分开 子类别名称、序号、测例内部后缀 这三项内容呢？
        # 一般认为，序号都是两位数字？
        # 首先找到中间的两位数字！然后将前面视为子类别名称，将后面视为测例文件后缀
        
        re_res = re.search("_[0-9]{2}", filename_suffix)
        # 默认能找到这样的数字
        if re_res is not None:
            testcase_id_start, testcase_id_end = re_res.span()
        else:
            print(cwe_id, filename_suffix, file)
            raise Exception("Wrong filename suffix")
        testcase_id_start += 1
        testcase_sub_category = filename_suffix[:testcase_id_start].removesuffix("_")
        testcase_id = filename_suffix[testcase_id_start:testcase_id_end]
        testcase_suffix = filename_suffix[testcase_id_end:]
        # 观察后缀，一般有以下形式：1.abcde; 2._bad _base _goodG2B _good1
        if len(testcase_suffix) == 0:
            pass
        elif testcase_suffix.startswith("_"):
            testcase_suffix_1 = testcase_suffix.removeprefix("_")
            if testcase_suffix_1.startswith("bad"):
                pass
            elif testcase_suffix_1.startswith("good"):
                pass
            elif testcase_suffix_1.startswith("base"):
                pass
            else:
                raise Exception("Wrong testcase suffix!")
        elif testcase_suffix.startswith("CWE"):
            pass
        else:
            try:
                assert len(testcase_suffix) == 1 and testcase_suffix[0].islower()
            except:
                print(testcase_suffix, file)

        # 字典的 key
        # 这里要注意，我们的 identifier 是将 sub_category 和后面的 id 连起来了
        testcase_identifier = testcase_sub_category + "-" + testcase_id
        if not testcase_identifier in valid_testcase_symbols:
            # 0128 修改，我们需要将子目录（s01 等加到文件名前面）
            if in_subdir:
                valid_testcase_symbols[testcase_identifier] = {testcase_suffix:os.path.join(subdir_path, file)}
            else:
                valid_testcase_symbols[testcase_identifier] = {testcase_suffix:file}
        else:
            # 注意：如果是单文件测例的话，那么此处的 testcase_suffix 为空值
            if in_subdir:
                valid_testcase_symbols[testcase_identifier][testcase_suffix] = os.path.join(subdir_path, file)
            else:
                valid_testcase_symbols[testcase_identifier][testcase_suffix] = file
    
    # 这样，我们就得到了一个含有内部所有测例文件名归类信息的字典
    return valid_testcase_symbols, len(testcase_files)

# 处理 valid_testcase_dict，期望获得几个 list：sub_category、bad_code、good_code（后两者按照行列表形式保存吧）
def parse_valid_testcase_dict(cwe_id, cwe_name, cwe_dir, valid_testcase_dict):
    '''
    cwe_id: 本次处理的 CWE
    cwe_dir: 本次处理的 CWE 的父目录
    valid_testcase_dict: 目标字典，存储了所有的测例关联的文件的次级路径
    return: 三个 list
    '''
    cwe_id_list, cwe_name_list, sub_category_list, tc_id_list, bad_code_list, good_code_list = [], [], [], [], [], []
    cnt_call = np.zeros(5, dtype=int)
    for tc_identifier, tc_related_files in valid_testcase_dict.items():
        sub_category, tc_id = tc_identifier.split("-")
        # 1. 总共有一个文件
        if len(tc_related_files) == 1:
            bad_code, good_code_list_0 = parse_single_file_testcase(cwe_dir, tc_related_files)
            # 在有 good_code 的情况下，才能认为是合法的例子
            if bad_code is not None and good_code_list_0 is not None:
                cnt_call[0] += 1
                for idx in range(len(good_code_list_0)):
                    cwe_id_list.append(cwe_id)
                    cwe_name_list.append(cwe_name)
                    sub_category_list.append(sub_category)
                    tc_id_list.append(tc_id)
                    bad_code_list.append(bad_code)
                    good_code_list.append(good_code_list_0[idx])
        elif len(tc_related_files) == 2:
            bad_code, good_code_list_1 = parse_double_file_testcase(cwe_dir, tc_related_files)
            cnt_call[1] += 1
            for idx in range(len(good_code_list_1)):
                cwe_id_list.append(cwe_id)
                cwe_name_list.append(cwe_name)
                sub_category_list.append(sub_category)
                tc_id_list.append(tc_id)
                bad_code_list.append(bad_code)
                good_code_list.append(good_code_list_1[idx])
        elif len(tc_related_files) == 3:
            pass
        elif len(tc_related_files) == 4:
            pass
        elif len(tc_related_files) == 5:
            pass
        else:
            print("Too many related files!")
    
    # print("cwe_id:", cwe_id, "\tcall parse_single_file_testcase cnt:", cnt_call)
    return cwe_id_list, cwe_name_list, sub_category_list, tc_id_list, bad_code_list, good_code_list, cnt_call

if __name__ == "__main__":
    cwe_dir_list = os.listdir(base_cwes_dir)
    cwe_dir_list = [dir_i for dir_i in cwe_dir_list if dir_i.startswith("CWE")]
    # print("num of cwes:", len(cwe_dir_list))
    
    df_testcase_stat = pd.read_csv(testcase_stat_path, encoding="utf-8")
    
    all_cwe_id_list, all_cwe_name_list, all_sub_category_list, all_tc_id_list, all_bad_code_list, all_good_code_list = [], [], [], [], [], []
    # 在 for 循环中，一次循环处理一个特定的 CWE
    # valid_testcase_dict 的格式：key 为 sub_category - testcase_id；value 为一个字典，即为这个特定的 tescase 所关联的所有
    file_cnt = [0, 0, 0, 0, 0]
    cnt_total_success = np.zeros(5, dtype=int)
    for cwe_dir in cwe_dir_list:
        cwe_id = cwe_dir.split("_")[0]
        cwe_name = cwe_dir.removeprefix(cwe_id + "_")
        
        # 这里我们首先省略了一些类
        if cwe_id in ["CWE609", "CWE561", "CWE491", "CWE581", "CWE568", "CWE500", "CWE607", "CWE582"]:
            print("skipping cwe_id %s" % cwe_id)
            continue
        
        # 注意，最好在处理的时候先统计一下数目，看看和 juliet 文档里面写的能不能对上
        valid_testcase_dict_i, related_file_cnt = parse_single_cwe_get_testcase_dict(cwe_id=cwe_id, cwe_name=cwe_name, cwe_dir=os.path.join(base_cwes_dir, cwe_dir))
        total_testcases += len(valid_testcase_dict_i)
        # print("cwe id: %s \t\t testcase cnt: %s" % (cwe_id, len(valid_testcase_dict_i)))
        
        golden_truth_testcase_cnt = df_testcase_stat[df_testcase_stat["cwe_id"] == cwe_id].iloc[0, 1]
        
        # 以下是检验格式的部分
        for k, v in valid_testcase_dict_i.items():
            num_file_in_testcase = len(v)
            file_cnt[num_file_in_testcase - 1] += 1
            # if num_file_in_testcase == 5:
            #     testcase_suffix_set = set(v.keys())
            #     standard_suffix_set_1 = set(['_goodB2G', 'a', '_bad', '_base', '_goodG2B'])
            #     standard_suffix_set_2 = set(['a', 'b', 'c', 'd', 'e'])
            #     if not (testcase_suffix_set == standard_suffix_set_1 or testcase_suffix_set == standard_suffix_set_2):
            #         print(testcase_suffix_set)
            # if num_file_in_testcase == 4:
            #     testcase_suffix_set = set(v.keys())
            #     standard_suffix_set_1 = set(['a', '_bad', '_goodG2B', '_base'])
            #     standard_suffix_set_2 = set(['a', 'b', 'c', 'd'])
            #     standard_suffix_set_3 = set(['a', '_bad', '_goodB2G', '_base'])
            #     if not testcase_suffix_set in [standard_suffix_set_1, standard_suffix_set_2, standard_suffix_set_3]:
            #         print(testcase_suffix_set)
            # if num_file_in_testcase == 3:
            #     testcase_suffix_set = set(v.keys())
            #     standard_suffix_set_1 = set(['a', '_bad', '_good1'])
            #     standard_suffix_set_2 = set(['a', 'b', 'c'])
            #     standard_suffix_set_3 = set(['_bad', '_good1', '_good2'])
            #     if not testcase_suffix_set in [standard_suffix_set_1, standard_suffix_set_2, standard_suffix_set_3]:
            #         print(testcase_suffix_set)
            # if num_file_in_testcase == 2:
            #     testcase_suffix_set = set(v.keys())
            #     standard_suffix_set_1 = set(['a', 'b'])
            #     standard_suffix_set_2 = set(['_bad', '_good1'])
            #     if not testcase_suffix_set in [standard_suffix_set_1, standard_suffix_set_2]:
            #         print(testcase_suffix_set)
            # if num_file_in_testcase == 1:
            #     if not "" in v.keys():
            #         raise Exception("Hey!")
        
        # 现在，又确认了 testcase_id 不会出现超出 99 的问题，那么我们现在可以开始挨个处理了
        # 首先保存单个 CWE 的字典
        if not os.path.exists(os.path.join(metadata_save_dir, cwe_id + ".json")):
            with open(os.path.join(metadata_save_dir, cwe_id + ".json"), "w", encoding="utf-8") as fj:
                json.dump(valid_testcase_dict_i, fj, indent=4)
        
        cwe_id_list, cwe_name_list, sub_category_list, tc_id_list, bad_code_list, good_code_list, cnt_call = parse_valid_testcase_dict(cwe_id, cwe_name, os.path.join(base_cwes_dir, cwe_dir), valid_testcase_dict_i)
        cnt_total_success += cnt_call
        
        all_cwe_id_list.extend(cwe_id_list)
        all_cwe_name_list.extend(cwe_name_list)
        all_sub_category_list.extend(sub_category_list)
        all_tc_id_list.extend(tc_id_list)
        all_bad_code_list.extend(bad_code_list)
        all_good_code_list.extend(good_code_list)
    
    # 如果只处理单文件 testcase，那么一共处理了 17839 个 testcase，实际上生成的测例数目应该比这个多不少
    # double files:
    print("cnt_total_success:", cnt_total_success)
    
    # raise Exception("you can now continue!")
        
    # 28881 个 testcase
    # 更新：考虑 double files 情况之后，
    print(file_cnt)
    print("total testcases: %s" % total_testcases)
    
    # 这里应当输出所有 bug 以及对应的字典！
    # 最后，single + double 产生了 62596 个例子！（testcase: 17952 + 8000）
    print(len(all_bad_code_list), len(all_good_code_list))
    
    df_all_cases = pd.DataFrame({"cwe_id":all_cwe_id_list, "cwe_name":all_cwe_name_list, "sub_category":all_sub_category_list, \
                                "testcase_id":all_tc_id_list, "bad_code":all_bad_code_list, "good_code":all_good_code_list})
    # 注意最后的数据格式，分别记录了 cwe_id、sub_category、testcase_id、bad_code、good_code
    df_all_cases.to_parquet("../parsed_dataset//juliet-java_all_testcases_2.parquet", index=False)
    