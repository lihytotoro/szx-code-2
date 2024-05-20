# 这里是处理两个文件 testcase 的地方
# 由于 2 文件测例有 8009 个，因此也值得我们进行处理（后三种类别则相对较少）
import os
import re

def parse_double_file_testcase(cwe_dir, tc_related_files):
    '''
    cwe_dir: 本测例所属 CWE 的父目录，和下面的字典记录的相对路径结合起来可以打开文件
    tc_related_files: 存储了本测例相关文件的后缀与文件相对父目录路径的对应关系的字典
    output: bad_code 和 good_code（若干个）
    '''
    testcase_suffix_set = set(tc_related_files.keys())
    standard_suffix_set_1 = set(['a', 'b'])
    standard_suffix_set_2 = set(['_bad', '_good1'])
    if testcase_suffix_set == standard_suffix_set_1:
        file_0 = tc_related_files["a"]
        file_1 = tc_related_files["b"]
        # print("category ab:", cwe_dir, tc_related_files)
    elif testcase_suffix_set == standard_suffix_set_2:
        file_0 = tc_related_files["_bad"]
        file_1 = tc_related_files["_good1"]
        # 这里是打印一下有哪些例子是 bad + good1 的命名类型
        # print("category bg:", cwe_dir, tc_related_files)
    else:
        raise Exception("Error: wrong file names!")
    
    # 我们需要看一下：两种文件格式下，究竟各有多少例子？其中所包含的文件有哪些需要加入测例之中
    # 事实上，后一种例子极其稀少，去除测例过少的 CWE 之外，只有在 CWE563 之中有 4 个例子
    # 仿照之前 single file 的写法，首先，提取出两个文件中的各个函数
    with open(os.path.join(cwe_dir, file_0), "r", encoding="utf-8") as f0:
        file_0_lines = f0.readlines()
        # 都去掉了右边的 \n
        file_0_lines = [remove_suffix_comment(line) for line in file_0_lines]
    with open(os.path.join(cwe_dir, file_1), "r", encoding="utf-8") as f1:
        file_1_lines = f1.readlines()
        # 都去掉了右边的 \n
        file_1_lines = [remove_suffix_comment(line) for line in file_1_lines]
        
    # 在读取完文件之后，首先确定 class 的位置
    class_0_start_line, class_0_end_line = get_class_position(file_0_lines)
    class_1_start_line, class_1_end_line = get_class_position(file_1_lines)
    
    # 流程：遍历每个类，按照定式，获取其中的所有函数名称，以及对应的起始行数、终止行数（所属文件/类）
    funcs_info_0 = get_funcs_info_in_class(0, file_0_lines, class_start_line=class_0_start_line, class_end_line=class_0_end_line)
    funcs_info_1 = get_funcs_info_in_class(1, file_1_lines, class_start_line=class_1_start_line, class_end_line=class_1_end_line)
    
    # 能否下断言：合并之后，函数名没有重复的情况？
    # 测试结果：断言合理！那我们可以进一步研究，各个函数的名称格式了！
    for fname_0 in funcs_info_0.keys():
        if fname_0 in funcs_info_1:
            # 只输出基础主文件名就可以表示整个 testcase
            raise Exception("Duplicate function name! cwe_dir: %s\t\trelated_file_0: %s" % (cwe_dir, file_0))
    
    total_funcs_info = merge_dict(funcs_info_0, funcs_info_1)
    # 那么，我们就可以名正言顺地合并了吗？
    # 先检查格式吧！如果需要检查
    # 两部分合并起来，进行函数名称合法性检测！
    check_func_names(cwe_dir, file_0, total_funcs_info)
    
    # 通过了检测！接下来，我们需要分 bad 和 good 去添加各个函数
    # print(cwe_dir, file_0)
    # print(total_funcs_info)
    bad_code_list, good_code_list = add_func_lines([file_0_lines, file_1_lines], total_funcs_info)
    
    # 最后转化成 string 格式
    bad_code = "\n".join(bad_code_list)
    good_code = ["\n".join(good_code_sublist) for good_code_sublist in good_code_list]
    
    # 最终的返回值仍然是 bad 和 good 的列表！
    return bad_code, good_code
    # return [], []

# 从某一个文件的 lines 中，提取出来函数所在的那些行
# 这里，file_lines 由于多个 file 的存在变得格外有用
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
    
    # 遍历范围内的每一行
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

def get_class_position(file_lines):
    class_start_line, class_end_line = -1, -1
    for line_idx in range(len(file_lines)):
        line_i = file_lines[line_idx]
        if line_i.startswith("public class"):
            class_start_line = line_idx
        if line_i.startswith("}") and class_start_line > 0:
            class_end_line = line_idx
    if class_start_line < 0 or class_end_line < 0:
        raise Exception("Cannot find class in this file!")
    return class_start_line, class_end_line

# 给定类的位置，获取所有内部相关函数的起止位置
def get_funcs_info_in_class(file_idx, file_lines, class_start_line, class_end_line):
    # 这里，我是直接复制的 single 处理函数中的相关部分（获取类内部所有函数信息）
    funcs_info = {}
    # 判断是否在函数内部
    in_func_flag = False
    # 这个是记录函数名称的
    func_name = ""
    # 而这个是记录函数起止行数的
    func_start_line, func_end_line = -1, -1
    # 记录函数的共有缩进
    whitespace, whitespace_str = 0, ""
    # 逐行遍历
    for line_idx in range(class_start_line + 1, class_end_line):
        line_i = file_lines[line_idx]
        # 去除左边的缩进，用于记录缩进情况
        stripped_line_i = line_i.lstrip()
        # 如果不在函数内部，那么寻找 public 或 private 开头的文本，并且末尾不能是分号（认为是变量）
        if not in_func_flag:
            if (stripped_line_i.startswith("public") or stripped_line_i.startswith("private")) and not stripped_line_i.endswith(";"):
                # 进入函数范围
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
                # 丢掉 main 函数不要
                if func_name == "main":
                    in_func_flag = False
                    func_start_line = -1
                    func_name = ""
                # 记录这个函数的留白？
                whitespace = len(line_i) - len(stripped_line_i)
                whitespace_str = line_i[:whitespace]
        # 已经在函数之中
        else:
            # 用于对比，找到函数的末一行
            target_bad_func_end_line = whitespace_str + "}"
            if target_bad_func_end_line == line_i:
                func_end_line = line_idx
                in_func_flag = False
                # 在 double file 的情况下，这里需要变通一下！
                # 除了这个元组，还应该记录一下函数所属的文件
                # 这下，在获取 func 所处的位置时，必须经过两层索引，即 [1][0] 或 [1][1]
                funcs_info[func_name] = (file_idx, (func_start_line, func_end_line))
                func_name = ""
                func_start_line, func_end_line = -1, -1
    
    return funcs_info

def check_func_names(cwe_dir, tc_related_file_0, funcs_info):
    # 获取了 func_info（包含函数名称和起止行），并且不含 main
    try:
        assert "bad" in funcs_info
    except:
        print(os.path.join(cwe_dir, tc_related_file_0))
        raise Exception("no bad function!")
    try:
        assert "good" in funcs_info
    except:
        # 没有找到 good 函数！
        print("no good function:", tc_related_file_0)
        raise Exception("no good function!")
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
        elif re.search(r'^bad(Source|_source|Sink|_sink)$', fname):
            pass
        elif re.search(r'^good(G2B\d{0,1}|B2G\d{0,1})$', fname):
            pass
        elif re.search(r'^good(G2B\d{0,1}|B2G\d{0,1})(Source|_source|Sink|_sink)$', fname):
            pass
        else:
            print("function name: %s" % fname)
            print(os.path.join(cwe_dir, tc_related_file_0))
            raise Exception("Unexpected function name!")
        
def merge_dict(dict1, dict2):
    res = {**dict1, **dict2}
    return res

# 我认为需要定义一个能够去除某一行末尾带着的注释的函数
def remove_suffix_comment(line):
    stripped_line = line.rstrip()
    if stripped_line.endswith("*/"):
        # 使用 re 找到注释部分？
        re_res = re.search(r'\/\*\S*\*\/$', stripped_line)
        if re_res is not None:
            cmt_start, cmt_end = re_res.span()
            stripped_line = stripped_line[cmt_start:cmt_end]
    return stripped_line

# 根据函数名之间的约束关系，向 testcase 中添加函数（写入各个行）
def add_func_lines(file_lines_list, total_funcs_info):
    bad_code_list, good_code_list = [], []
    
    # 1. 加入 bad 函数
    bad_func_file_idx, (bad_func_start, bad_func_end) = total_funcs_info["bad"]
    bad_code_list.extend(extract_func_lines(file_lines_list[bad_func_file_idx], bad_func_start, bad_func_end))
    # 2. 加入有可能存在的 source 和 sink
    for fname in ["badSink", "badSource", "bad_source", "bad_sink"]:
        if fname in total_funcs_info:
            this_func_file_idx, (this_func_start, this_func_end) = total_funcs_info[fname]
            bad_code_list.extend(extract_func_lines(file_lines_list[this_func_file_idx], this_func_start, this_func_end))

    # 接下来向 good_code_list 中添加代码！
    # 1. 从唯一的 good 函数中收集所有主函数名称
    good_main_func_name_list = []
    good_func_file_idx, (good_func_start, good_func_end) = total_funcs_info["good"]
    for line_idx in range(good_func_start + 1, good_func_end):
        line_i = file_lines_list[good_func_file_idx][line_idx]
        good_main_func_name = line_i.strip().split("(")[0]
        if good_main_func_name in total_funcs_info:
            good_main_func_name_list.append(good_main_func_name)
    assert len(good_main_func_name_list) > 0
    
    # 2. 针对所有 good 的子函数，确定其中要带哪些次级函数
    # 对于 goodG2B、goodB2G 以及 good1 等类型，首先将其本身加入，之后将所有关联的 good 次级函数也加入其中
    for good_main_func_name in good_main_func_name_list:
        # 加入一个空列表，然后依次向其中加入代码
        good_code_list.append([])
        if re.search(r'^good\d{1}$', good_main_func_name):
            func_suffix_idx = good_main_func_name[-1]
            good_func_file_idx, (good_func_start, good_func_end) = total_funcs_info[good_main_func_name]
            good_code_list[-1].extend(extract_func_lines(file_lines_list[good_func_file_idx], good_func_start, good_func_end))
        # good source and badsink
        elif re.search(r'^goodG2B\d{0,1}$', good_main_func_name):
            if good_main_func_name[-1].isdigit():
                func_suffix_idx = good_main_func_name[-1]
            else:
                func_suffix_idx = ""
            good_func_file_idx, (good_func_start, good_func_end) = total_funcs_info[good_main_func_name]
            good_code_list[-1].extend(extract_func_lines(file_lines_list[good_func_file_idx], good_func_start, good_func_end))
            for fname in total_funcs_info.keys():
                if re.search(r'^goodG2B%s(Source|_source|Sink|_sink)$' % func_suffix_idx, fname):
                    this_func_file_idx, (this_func_start, this_func_end) = total_funcs_info[fname]
                    good_code_list[-1].extend(extract_func_lines(file_lines_list[this_func_file_idx], this_func_start, this_func_end))
        # good sink and bad source
        elif re.search(r'^goodB2G\d{0,1}$', good_main_func_name):
            if good_main_func_name[-1].isdigit():
                func_suffix_idx = good_main_func_name[-1]
            else:
                func_suffix_idx = ""
            good_func_file_idx, (good_func_start, good_func_end) = total_funcs_info[good_main_func_name]
            good_code_list[-1].extend(extract_func_lines(file_lines_list[good_func_file_idx], good_func_start, good_func_end))
            for fname in total_funcs_info.keys():
                if re.search(r'^goodB2G%s(Source|_source|Sink|_sink)$' % func_suffix_idx, fname):
                    this_func_file_idx, (this_func_start, this_func_end) = total_funcs_info[fname]
                    good_code_list[-1].extend(extract_func_lines(file_lines_list[this_func_file_idx], this_func_start, this_func_end))
        # 如果都不符合，那么我们认定这是非法主函数名
        else:
            print("good_main_func:", good_main_func_name)
            raise Exception("Unexpected good_main_func_name!")

    return bad_code_list, good_code_list