# 我们将不同文件数目的 testcase 的处理单独区分开
# 处理单一文件的 bug
import os
import re

def parse_single_file_testcase(cwe_dir, tc_related_files):
    '''
    cwe_dir: 本测例所属 CWE 的父目录，和下面的字典记录的相对路径结合起来可以打开文件
    tc_related_files: 存储了本测例相关文件的后缀与文件相对父目录路径的对应关系的字典
    output: bad_code 和 good_code（若干个）
    '''
    tc_related_file_0 = tc_related_files[""]
    with open(os.path.join(cwe_dir, tc_related_file_0), "r", encoding="utf-8") as f0:
        file_0_lines = f0.readlines()
        # 都去掉了右边的 \n
        file_0_lines = [line.rstrip() for line in file_0_lines]
    
    # 从 lines 中，首先找到 class 的起止位置
    class_start_line, class_end_line = -1, -1
    class_cnt = 0
    for line_idx in range(len(file_0_lines)):
        line_i = file_0_lines[line_idx]
        if line_i.startswith("public class"):
            class_cnt += 1
            class_start_line = line_idx
        if class_cnt > 1:
            raise Exception("more than one class in a single file!")
        if line_i.startswith("}") and class_start_line > 0:
            class_end_line = line_idx
    
    # 在 class 的范围之内，找出所有存在的函数
    # 下面的字典，key 应当是函数名（方便后续查找关系），value 应当是一个元组，记录始末行数（左闭右闭）
    funcs_info = {}
    in_func_flag = False
    func_name = ""
    func_start_line, func_end_line = -1, -1
    whitespace, whitespace_str = 0, ""
    for line_idx in range(class_start_line + 1, class_end_line):
        line_i = file_0_lines[line_idx]
        stripped_line_i = line_i.lstrip()
        if not in_func_flag:
            if (stripped_line_i.startswith("public") or stripped_line_i.startswith("private")) and not stripped_line_i.endswith(";"):
                in_func_flag = True
                func_start_line = line_idx
                # 注意，这里我们如何获得真正的函数名称？
                func_name_list = stripped_line_i.split(" ")
                if func_name_list[2] == "static":
                    func_name = func_name_list[4].split("(")[0]
                elif func_name_list[1] in ["static", "synchronized"] or func_name_list[0] in ["static", "synchronized"]:
                    func_name = func_name_list[3].split("(")[0]
                elif func_name_list[2] == "[]":
                    func_name = func_name_list[3].split("(")[0]
                else:
                    func_name = func_name_list[2].split("(")[0]
                if func_name == "main":
                    in_func_flag = False
                    func_start_line = -1
                    func_name = ""
                # 记录这个函数的留白？
                whitespace = len(line_i) - len(stripped_line_i)
                whitespace_str = line_i[:whitespace]
        else:
            target_bad_func_end_line = whitespace_str + "}"
            if target_bad_func_end_line == line_i:
                func_end_line = line_idx
                in_func_flag = False
                funcs_info[func_name] = (func_start_line, func_end_line)
                func_name = ""
                func_start_line, func_end_line = -1, -1
    
    # 获取了 func_info（包含函数名称和起止行），并且不含 main
    assert "bad" in funcs_info
    try:
        assert "good" in funcs_info
    except:
        print("no good function:", tc_related_file_0)
        return None, None
        # exit()
    
    # 下面，确认函数名称都正确！
    for fname, ftuple in funcs_info.items():
        # bad_base
        if fname == "bad":
            pass
        # good_base，从中提取所有用到的函数
        elif fname == "good":
            pass
        # 事实上这几个名称应当是和 goodG2B goodB2G 同级的
        elif re.search(r'^good\d{1}$', fname):
            # 这里证明：good 后面接数字的情况，是不会有任何 source 和 sink 出现的！至少对于单个文件的情况是这样
            for fname_2 in funcs_info.keys():
                if re.match(r'^(bad|good)\S*(Source|_source|Sink|_sink)$', fname_2):
                    print("Hey!", fname_2)
                    raise Exception("")
            pass
        # 若存在，那么 bad 一定会用到；另外 good 也有可能用到
        elif fname in ["badSink", "badSource", "bad_sink", "bad_source"]:
            pass
        elif re.search(r'^good(G2B\d{0,1}|B2G\d{0,1})$', fname):
            pass
        elif re.search(r'^good(G2B\d{0,1}|B2G\d{0,1})(Source|_source|Sink|_sink)$', fname):
            pass
        elif re.search(r'^helper\S*(Bad|Good\d{0,1})$', fname):
            pass
        # 跳过这种函数！
        elif fname in ["privateReturnsTrue", "privateReturnsFalse"]:
            pass
        # from CWE248 Error_01
        # 跳过这种函数！
        elif fname == "runTest":
            pass
        # # from CWE833 Servlet_01
        # elif fname in ["helperAddBad", "helperMultiplyBad", "helperAddGood1", "helperMultiplyGood1"]:
        #     pass
        # # from CWE833 synchronized_methods_Servlet_01
        # elif fname in ["helperBowBad", "helperBowBackBad", "helperBowGood1", "helperBowBackGood1"]:
        #     pass
        else:
            print("function name: %s" % fname)
            print(os.path.join(cwe_dir, tc_related_file_0))
            raise Exception("Unexpected function name!")
    
    
    
    # 首先，处理唯一的 bad 样例
    bad_code_list = []
    # 1. 加入 bad 函数
    bad_func_start, bad_func_end = funcs_info["bad"]
    bad_code_list.extend(extract_func_lines(file_0_lines, bad_func_start, bad_func_end))
    # 2. 加入有可能存在的 source 和 sink
    for fname in ["badSink", "badSource", "bad_source", "bad_sink"]:
        if fname in funcs_info:
            this_func_start, this_func_end = funcs_info[fname]
            bad_code_list.extend(extract_func_lines(file_0_lines, this_func_start, this_func_end))
    # 3. 加入有可能存在的 helper 函数
    for fname in funcs_info.keys():
        if re.search(r'helper\S*Bad', fname):
            helper_func_start, helper_func_end = funcs_info[fname]
            bad_code_list.extend(extract_func_lines(file_0_lines, helper_func_start, helper_func_end))
            
    good_code_list = []
    # 1. 应当寻找所有 good 主函数
    good_main_func_name_list = []
    good_func_start, good_func_end = funcs_info["good"]
    for line_idx in range(good_func_start + 1, good_func_end):
        line_i = file_0_lines[line_idx]
        good_main_func_name = line_i.strip().split("(")[0]
        if good_main_func_name in funcs_info:
            good_main_func_name_list.append(good_main_func_name)
    assert len(good_main_func_name_list) > 0
    
    # 2. 针对所有 good 的子函数，确定其中要带哪些次级函数
    # 对于 goodG2B、goodB2G 以及 good1 等类型，首先将其本身加入，之后将所有关联的 good 次级函数也加入其中
    for good_main_func_name in good_main_func_name_list:
        # 加入一个空列表，然后依次向其中加入代码
        good_code_list.append([])
        if re.search(r'^good\d{1}$', good_main_func_name):
            func_idx = good_main_func_name[-1]
            good_func_start, good_func_end = funcs_info[good_main_func_name]
            good_code_list[-1].extend(extract_func_lines(file_0_lines, good_func_start, good_func_end))
            for fname in funcs_info.keys():
                if re.search(r'^helper\S*Good%s$' % func_idx, fname):
                    helper_func_start, helper_func_end = funcs_info[fname]
                    good_code_list[-1].extend(extract_func_lines(file_0_lines, helper_func_start, helper_func_end))
        # good source and badsink
        elif re.search(r'^goodG2B\d{0,1}$', good_main_func_name):
            if good_main_func_name[-1].isdigit():
                func_idx = good_main_func_name[-1]
            else:
                func_idx = ""
            good_func_start, good_func_end = funcs_info[good_main_func_name]
            good_code_list[-1].extend(extract_func_lines(file_0_lines, good_func_start, good_func_end))
            for fname in funcs_info.keys():
                if re.search(r'^goodG2B%s(Source|_source|Sink|_sink)$' % func_idx, fname):
                    this_func_start, this_func_end = funcs_info[fname]
                    good_code_list[-1].extend(extract_func_lines(file_0_lines, this_func_start, this_func_end))
            for fname in funcs_info.keys():
                if re.search(r'^helper\S*GoodG2B%s$' % func_idx, fname):
                    this_func_start, this_func_end = funcs_info[fname]
                    good_code_list[-1].extend(extract_func_lines(file_0_lines, this_func_start, this_func_end))
        # good sink and bad source
        elif re.search(r'^goodB2G\d{0,1}$', good_main_func_name):
            if good_main_func_name[-1].isdigit():
                func_idx = good_main_func_name[-1]
            else:
                func_idx = ""
            good_func_start, good_func_end = funcs_info[good_main_func_name]
            good_code_list[-1].extend(extract_func_lines(file_0_lines, good_func_start, good_func_end))
            for fname in funcs_info.keys():
                if re.search(r'^goodB2G%s(Source|_source|Sink|_sink)$' % func_idx, fname):
                    this_func_start, this_func_end = funcs_info[fname]
                    good_code_list[-1].extend(extract_func_lines(file_0_lines, this_func_start, this_func_end))
            for fname in funcs_info.keys():
                if re.search(r'^helper\S*GoodB2G%s$' % func_idx, fname):
                    this_func_start, this_func_end = funcs_info[fname]
                    good_code_list[-1].extend(extract_func_lines(file_0_lines, this_func_start, this_func_end))
        else:
            print("good_main_func:", good_main_func_name)
            raise Exception("Unexpected good_main_func_name!")

    bad_code = "\n".join(bad_code_list)
    good_code = ["\n".join(good_code_sublist) for good_code_sublist in good_code_list]

    return bad_code, good_code

def extract_func_lines(file_lines, func_start, func_end):
    '''
    return: func_code_list
    '''
    func_code_list = []
    in_comment = False
    
    # 记录 whitespace
    func_start_line = file_lines[func_start]
    func_end_line = file_lines[func_end]
    whitespace = len(func_start_line) - len(func_start_line.lstrip())
    whitespace_str = func_start_line[:whitespace]
    
    for line_idx in range(func_start, func_end + 1):
        line_i = file_lines[line_idx]
        if in_comment:
            if line_i.endswith("*/"):
                in_comment = False
            continue
        if len(line_i.strip()) == 0:
            continue
        if line_i.strip().startswith("/*"):
            if line_i.endswith("*/"):
                continue
            in_comment = True
            continue
        func_code_list.append(line_i[whitespace:])
    
    return func_code_list    
    
    

# tc_related_file_0 = tc_related_files[""]
# with open(os.path.join(cwe_dir, tc_related_file_0), "r", encoding="utf-8") as f0:
#     file_0_lines = f0.readlines()
#     file_0_lines = [line.rstrip() for line in file_0_lines]
# # 首先去找 bad（应该有且只有一个），然后找到 good 看看里面的函数名，记录下来以后再分别去找
# # 所有序号都以 0 开始计，左闭右闭
# bad_func_start, bad_func_end = -1, -1
# bad_func_cnt = 0
# # 记录目前是否处于目标 bad 函数内部
# bad_func_flag = False
# whitespace, whitespace_str = 0, ""
# for line_idx in range(len(file_0_lines)):
#     line_i = file_0_lines[line_idx]
#     stripped_line_i = line_i.strip()
#     if len(stripped_line_i) == 0:
#         continue
#     if bad_func_flag:
#         target_bad_func_end_line = whitespace + "}"
#         if target_bad_func_end_line == line_i:
#             bad_func_end = line_idx
#     # 视为找到了 bad 函数
#     if stripped_line_i.startswith("public void bad("):
#         if bad_func_cnt == 0:
#             bad_func_cnt += 1
#         else:
#             raise Exception("More than one bad function!")
#         bad_func_start = line_idx
#         bad_func_flag = True
#         # 记录 whitespace
#         whitespace = len(line_i) - len(stripped_line_i)
#         whitespace_str = line_i[:whitespace]