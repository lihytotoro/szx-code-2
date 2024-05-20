# 将原始 parquet 中的数据，构造成 input + output 的提示数据！
# 与 finetune codellama 不同，这里的处理是为了二轮微调 repairllama 的
# 注意：这个版本的数据要遵循：bad_code + cwe_id -> good_code
# 这是 0430 新写的版本，注意，现在所有数据都要整理成 jsonl 的形式，因为现在 full + lora + qlora 的实现可以同时基于 Firefly 完成！
import os
import json
import pandas as pd
from tqdm import tqdm
import jsonlines
from transformers import AutoTokenizer
import random
import shutil
import argparse
import pyarrow.parquet as pq

# 处理各种参数，防止硬编码
def setup_everything():
    parser = argparse.ArgumentParser()
    # 模型路径
    parser.add_argument("--model_dir", type=str, default="", help="")
    parser.add_argument("--tokenizer_dir", type=str, default='', help="")
    
    # 限制长度（在 cwe-apr 任务中，设置为 2048，合理吗？）
    parser.add_argument("--max_input_len", type=int, default=1024, help="")
    
    # 0317 新加入参数：要微调的模型，例：codellama、qwen 等（qwen 则不需要遵循 llama 2 的模板）
    parser.add_argument("--model_type", type=str, default="codellama", help="model to be finetuned.")
    
    # 根据不同的训练框架，数据有不同的训练方式
    parser.add_argument("--raw_data_path", type=str, default="", help="")
    
    # 0430 new: 数据构造的格式，到底是按照说人话的前缀去构造数据，还是直接将信息以注释的形式加到代码里面？
    parser.add_argument("--input_form", type=str, default="", help="input data formation.")
    # 处理完数据之后，保存到的目录
    # 注意，目录是传进来的，但是具体的文件名，根据已经确定的参数直接生成（而不是硬编码）
    parser.add_argument("--save_output_dir", type=str, default="", help="dir to save the parsed dataset.")
    
    parser.add_argument("--output_form", type=str, default="jsonl", help="save file format.")
    parser.add_argument("--task_name", type=str, default="cwe-apr", help="")
    
    # 划分训练集和测试集的比例，如果为 1.0 则表示不划分？
    parser.add_argument("--split_ratio", type=float, default=0.95, help="")
    # cwe metadata
    parser.add_argument("--cwe_metadata_path", type=str, default="/data/public/multimodal/lihaoyu/szx/datasets/java-juliet/src/metadata/all_cwe_metadata.csv")

    args = parser.parse_args()

    # 返回处理的结果
    return args


def transfer_raw_data_to_input_output(raw_data_path, cwe_metadata_path, input_form, tokenizer, max_token_len=2048):
    '''
    raw_data_path: 之前处理好的 java-juliet 数据集？
    cwe_metadata_path: 用于获取实际的 CWE name 以及 CWE description 的 info file 的路径
    input_form: 构造数据的格式，如果尝试使用 comment_1 格式，表示将所有 CWE 相关的信息以注释形式写入
    tokenizer: 用于检测输入输出的长度
    '''
    
    # 读取 src_data 以及 metadata
    # src_data 有以下 6 列：cwe_id、cwe_name、sub_category、testcase_id、bad_code、good_code
    df_cwe_metadata = pd.read_csv(cwe_metadata_path, encoding="utf-8", index_col=False)
    all_cwe_id_list = df_cwe_metadata["CWE-ID"].tolist()
    all_cwe_id_list = [str(cwe_id_i) for cwe_id_i in all_cwe_id_list]
    all_cwe_name_list = df_cwe_metadata["Name"].tolist()
    all_cwe_id_desc_list = df_cwe_metadata["Description"].tolist()
    
    # 存储所有条目
    ans_json_list = []
    valid_testcases_cnt, invalid_testcases_cnt = 0, 0
    
    if raw_data_path.endswith(".parquet"):
        raw_df = pd.read_parquet(raw_data_path)
    else:
        raise Exception("Unexpected data form!")
    
    print("Initially, there are %d testcases!" % len(raw_df))
    
    # 以下是用于构造微调数据的前缀？但是现在证明 codellama 似乎听人话说人话的能力不强？
    # normal
    input_prefix_1 = "The following java code contains a flaw, which belongs to common weakness enumeration type %s."
    input_prefix_2 = "The description of %s is: %s. Please provide the fixed code.\n"
    # comment
    input_comment_1 = "# The following buggy function is mainly caused by a weakness of CWE type %s.\n"
    input_comment_2 = "# Description of %s: %s\n"
    
    # 遍历原文件的每一行，处理每一个 sample
    for row_idx, row in tqdm(raw_df.iterrows(), total=raw_df.shape[0]):
        # 四项都需要！
        cwe_id = row["cwe_id"]
        # cwe_name = row["cwe_name"]
        bad_code = row["bad_code"]
        good_code = row["good_code"]
        
        # 原始的 cwe_id 是包含 CWE 前缀的
        assert cwe_id.startswith("CWE")
        # pure_cwe_id 用于与 metadata 对照，查找对应的 description
        pure_cwe_id = cwe_id.removeprefix("CWE")
        
        # 如果 cwe_id 在最新版的 cwe_list 中没有出现，说明已经废弃了
        if not pure_cwe_id in all_cwe_id_list:
            if pure_cwe_id == "398":
                # 398 是一个 category，而不是一个单独的 cwe
                real_cwe_name = "Poor Code Quality"
                cwe_id_desc = "This category represents one of the phyla in the Seven Pernicious Kingdoms vulnerability \
classification. It includes weaknesses that do not directly introduce a weakness or vulnerability, \
but indicate that the product has not been carefully developed or maintained"
            else:
                print("Deprecated CWE id: %s" % cwe_id)
                invalid_testcases_cnt += 1
                continue
        else:
            # 获取当前 cwe 对应的真实名称
            real_cwe_name = all_cwe_name_list[all_cwe_id_list.index(pure_cwe_id)]
            # 获取当前 cwe 对应的描述
            cwe_id_desc = all_cwe_id_desc_list[all_cwe_id_list.index(pure_cwe_id)]
        
        # 接下来，根据上面的信息进行 finetune 数据构造
        if input_form == "normal_1":
            total_input = (input_prefix_1 % (cwe_id + ":" + real_cwe_name)) + input_prefix_2 % (cwe_id, cwe_id_desc) + bad_code
        elif input_form == "comment_1":
            # 在 comment 做法中，将 CWE 以注释形式输入模型中，而不是以对话形式？
            total_input = input_comment_1 % (cwe_id + ":" + real_cwe_name) + input_comment_2 % (cwe_id, cwe_id_desc) + bad_code
        else:
            raise Exception(f"Unexpected input form {input_form}!")
        
        total_output = good_code
        tokenized_input = tokenizer.tokenize(total_input)
        tokenized_output = tokenizer.tokenize(total_output)
        
        if len(tokenized_input) + len(tokenized_output) > max_token_len:
            continue
    
        ans_json_list.append({"input":total_input, "output":total_output})
        valid_testcases_cnt += 1
    
    print(f"Finally, there are {valid_testcases_cnt} valid testcases if we set max_token_len to {max_token_len}!")
    
    return ans_json_list, valid_testcases_cnt

# shuffle
# train + test(8:2)
def shuffle_and_split_train_test(ans_json_list, ratio=0.95):
    '''
    ans_json_list: 列表中的每一项是一个含有 input 和 output 的字典
    ratio: 切分的比例
    '''
    random.shuffle(ans_json_list)

    # 打乱后的全部数据
    # new_input_list, new_output_list = zip(*combined_lists)
    
    if ratio < 1.0:
        split_idx = int(ratio * len(ans_json_list))
        train_json_list = ans_json_list[:split_idx]
        test_json_list = ans_json_list[split_idx:]
    else:
        train_json_list = ans_json_list[:]
        test_json_list = None
    
    # 注意测试集返回的列表有可能是 None
    return train_json_list, test_json_list

if __name__ == "__main__":
    args = setup_everything()
    
    tokenizer = AutoTokenizer.from_pretrained(args.tokenizer_dir)
    
    ans_json_list, valid_testcases_cnt = \
            transfer_raw_data_to_input_output(raw_data_path=args.raw_data_path, cwe_metadata_path=args.cwe_metadata_path, input_form=args.input_form, tokenizer=tokenizer, max_token_len=args.max_input_len)

    # 这里应该有一个打乱的操作，但是此时我们应该不需要取测试集了？或者说少取一点，比如 0.95
    train_json_list, test_json_list = shuffle_and_split_train_test(ans_json_list=ans_json_list, ratio=args.split_ratio)
    
    train_file_name = f"finetuning_data_maxlen={args.max_input_len}_modeltype={args.model_type}_taskname={args.task_name}_inputform={args.input_form}_trainratio={args.split_ratio}_split=train.jsonl"
    if test_json_list is not None:
        test_file_name = f"finetuning_data_maxlen={args.max_input_len}_modeltype={args.model_type}_taskname={args.task_name}_inputform={args.input_form}_trainratio={args.split_ratio}_split=test.jsonl"
    
    save_train_path = os.path.join(args.save_output_dir, args.output_form, args.task_name, train_file_name)
    if test_json_list is not None:
        save_test_path = os.path.join(args.save_output_dir, args.output_form, args.task_name, test_file_name)
    # as jsonl
    with jsonlines.open(save_train_path, "w") as writer1:
        conv_id = 1
        for item in tqdm(train_json_list):
            total_input = item["input"]
            total_output = item["output"]
            conv = [{"human":total_input, "assistant":total_output}]
            conv_dict = {"conversation_id":conv_id, "category":"Brainstorming", "conversation":conv}
            conv_id += 1
            writer1.write(conv_dict)
            
    if test_json_list is not None:
        with jsonlines.open(save_test_path, "w") as writer2:
            conv_id = 1
            for item in tqdm(test_json_list):
                total_input = item["input"]
                total_output = item["output"]
                conv = [{"human":total_input, "assistant":total_output}]
                conv_dict = {"conversation_id":conv_id, "category":"Brainstorming", "conversation":conv}
                conv_id += 1
                writer2.write(conv_dict)
                
# 62596 -> 61961
# 其中，train split = 58862