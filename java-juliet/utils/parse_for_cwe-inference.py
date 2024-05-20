# 将原始 parquet 中的数据，构造成 input + output 的提示数据！
import pandas as pd
from tqdm import tqdm
import jsonlines
from transformers import AutoTokenizer
import random
import numpy as np
import argparse
import os

# 处理各种参数，防止硬编码
def setup_everything():
    parser = argparse.ArgumentParser()
    # 模型路径
    parser.add_argument("--tokenizer_dir", type=str, default='/data/disk4/lihy/data/models/CodeLlama-7b-Instruct-hf', help="")
    # 限制长度（在 cwe-inference 任务中，设置为 1024 即可）
    parser.add_argument("--max_token_len", type=int, default=1024, help="")
    
    # 0317 新加入参数：要微调的模型，例：codellama、qwen 等（qwen 则不需要遵循 llama 2 的模板）
    parser.add_argument("--model_type", type=str, default="codellama", help="model to be finetuned.")
    
    # 根据不同的训练框架，数据有不同的训练方式
    # lora/repairllama（parquet） + qlora/firefly（jsonl）
    parser.add_argument("--user_type", type=str, default="lora", help="finetuning type.")
    # 原始数据所在的目录
    parser.add_argument("--raw_data_path", type=str, default="/data/disk4/lihy/data/datasets/java-juliet/src/parsed_dataset/src/juliet-java_all_testcases.parquet", help="")
    # 处理完数据之后，保存到的目录
    # 注意，目录是传进来的，但是具体的文件名，根据已经确定的参数直接生成（而不是硬编码）
    parser.add_argument("--save_output_dir", type=str, default="/data/disk4/lihy/data/datasets/java-juliet/src/parsed_dataset", help="")
    # 目标输出格式，parquet 或 jsonl
    parser.add_argument("--output_format", type=str, default="jsonl", help="")
    # 划分训练集和测试集的比例
    parser.add_argument("--split_ratio", type=float, default=0.9, help="")
    # cwe metadata
    parser.add_argument("--cwe_metadata_path", type=str, default="/data/disk4/lihy/data/datasets/java-juliet/src/testcase_metadata/all_cwe_metadata.csv")

    args = parser.parse_args()

    # 返回处理的结果
    return args

# 0227 更新：我们需要把问题后置，并且加上对于回答格式的约束！
# 类似于：buggy code + question(type + definition)，最后跟一句对于输出格式的限定（用两个 FILL_ME 填充）
def transfer_raw_data_to_input_output(model_type, user_type, raw_data_path, cwe_metadata_path, tokenizer, max_token_len=1024):
    df_cwe_metadata = pd.read_csv(cwe_metadata_path, encoding="utf-8", index_col=False)
    all_cwe_id_list = df_cwe_metadata["CWE-ID"].tolist()
    all_cwe_id_list = [str(cwe_id_i) for cwe_id_i in all_cwe_id_list]
    all_cwe_name_list = df_cwe_metadata["Name"].tolist()
    all_cwe_id_desc_list = df_cwe_metadata["Description"].tolist()

    ans_input_list, ans_output_list = [], []
    valid_testcases_cnt = 0
    if raw_data_path.endswith(".parquet"):
        raw_df = pd.read_parquet(raw_data_path)
    else:
        raise Exception("Unexpected data form!")

    print("Initially, there are %d testcases!" % len(raw_df))

    ########## 0307 ##########
    # 根据标准输入格式对 CWE 微调数据进行修改，注意，这种处理是单独针对 codellama 的！
    system = "You are a powerful automatic program repair assistant with plenty of knowledge about common weakness enumeration(CWE). Provide your answer in Markdown."
    user_input_prefix = "The following java code contains a flaw. Read the code snippet carefully and answer the quetion below.\n"
    user_buggy_code_prefix = "Buggy Code:\n"
    user_question_prefix = "Question:\n"
    user_question_content = "What is the exact CWE(common weakness enumeration) type of the flaw? What is the definition of this CWE type? Give your answer in the same format as the following example.\n"
    user_example_prefix = "Answer Example:\n"
    user_example_content_1 = "The CWE type of the code is: CWE129--Improper Validation of Array Index. "
    user_example_content_2 = "The description of CWE129 is: The product uses untrusted input when calculating or using an array index, but the product does not validate or incorrectly validates the index to ensure the index references a valid position within the array.\n"
    user_your_answer_prefix = "Your Answer:"
    
    output_prefix_1 = "The CWE type of the code is: %s. "
    output_prefix_2 = "The description of %s is: %s."

    # 这里开一个列表，用于记录每一条 output 的 token 长度
    # output_token_len_list = []

    # 开始遍历，处理原始数据集中的每一条数据！
    for row_idx, row in tqdm(raw_df.iterrows()):
        # 用这里的 cwe_id 查找对应的 desc
        cwe_id = row["cwe_id"]
        cwe_name = row["cwe_name"]
        bad_code = row["bad_code"]
        good_code = row["good_code"]

        assert cwe_id.startswith("CWE")
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
                continue
        else:
            # 获取当前 cwe 对应的真实名称
            real_cwe_name = all_cwe_name_list[all_cwe_id_list.index(pure_cwe_id)]
            # 获取当前 cwe 对应的描述
            cwe_id_desc = all_cwe_id_desc_list[all_cwe_id_list.index(pure_cwe_id)]

        # 全部的输入，注意新加入了很多指令
        # 只针对 codellama（llama 2）的输入格式
        if model_type == "codellama":
            if user_type == "lora":
                user_input = user_input_prefix + user_buggy_code_prefix + bad_code + "\n" + user_question_prefix + user_question_content + user_example_prefix + \
                    user_example_content_1 + user_example_content_2 + user_your_answer_prefix
                total_input = f"<s>[INST] <<SYS>>\n{system}\n<</SYS>>\n\n{user_input}[/INST]"
                # 这个是全部的输出，我们需要看一下一共有多少个 token
                total_output = output_prefix_1 % (cwe_id + "--" + real_cwe_name) + output_prefix_2 % (cwe_id, cwe_id_desc)
            elif user_type == "qlora":
                # codellama + qlora? 目前还没有确定输入格式的差异是怎么解决的！
                raise Exception("Not Completed Yet!")
            else:
                raise Exception("Unexpected user type: %s" % user_type)
        elif model_type == "qwen":
            if user_type == "lora":
                # 同样的，也没有解决 system 跟 input 的从属关系
                raise Exception("Not Completed Yet!")
            elif user_type == "qlora":
                # 这里，我们目前先只处理单轮情况下的 input、output
                user_input = user_input_prefix + user_buggy_code_prefix + bad_code + "\n" + user_question_prefix + user_question_content + user_example_prefix + \
                    user_example_content_1 + user_example_content_2 + user_your_answer_prefix
                total_input = user_input
                total_output = output_prefix_1 % (cwe_id + "--" + real_cwe_name) + output_prefix_2 % (cwe_id, cwe_id_desc)
            else:
                raise Exception("Unexpected user type: %s" % user_type)

        # 将 input 和 output 的字符串转换为 token
        tokenized_input = tokenizer.tokenize(total_input)
        tokenized_output = tokenizer.tokenize(total_output)

        # output_token_len_list.append(len(tokenized_output))

        # 剔除太长的例子
        if len(tokenized_input) + len(tokenized_output) > max_token_len:
            continue

        ans_input_list.append(total_input)
        ans_output_list.append(total_output)
        valid_testcases_cnt += 1

    print("Finally, there are %d valid testcases if we set max_token_len to %d!" % (valid_testcases_cnt, max_token_len))
    assert len(ans_input_list) == len(ans_output_list)

    # # 这里，计算一下有多少条数据回复长度在 32、64、128、256 以上！以及平均长度
    # output_token_len_list = np.array(output_token_len_list)
    # cnt_32 = np.sum(output_token_len_list > 32)
    # cnt_64 = np.sum(output_token_len_list > 64)
    # cnt_128 = np.sum(output_token_len_list > 128)
    # cnt_256 = np.sum(output_token_len_list > 256)
    # cnt_avg = np.mean(output_token_len_list)
    # # cnt_64(> 64): 49923
    # # cnt_128: 0
    # # cnt_avg: 75.6
    # print("output_token_len_list:", len(output_token_len_list), cnt_32, cnt_64, cnt_128, cnt_256, cnt_avg)
    # exit()

    return ans_input_list, ans_output_list, valid_testcases_cnt

# shuffle
# train + test(8:2)
def shuffle_and_split_train_test(input_list, output_list, ratio=0.8):
    combined_lists = list(zip(input_list, output_list))
    random.shuffle(combined_lists)

    # 打乱后的全部数据
    new_input_list, new_output_list = zip(*combined_lists)

    split_idx = int(ratio * len(new_input_list))
    train_input_list, train_output_list = new_input_list[:split_idx], new_output_list[:split_idx]
    test_input_list, test_output_list = new_input_list[split_idx:], new_output_list[split_idx:]

    return train_input_list, train_output_list, test_input_list, test_output_list

# 用于将 input、ouptut 对转化为 qlora（firefly）所需的格式（这里我们注意要加入 system）
def transfer_data_to_qlora_jsonl(input_list, output_list):
    '''
    input_list: 模型输入
    output_list: 模型输出
    '''
    ans_json_list = []
    assert len(input_list) == len(output_list)
    conv_id = 1
    for idx in range(len(input_list)):
        total_input = input_list[idx]
        total_output = output_list[idx]
        
        # 0317 修改：这里统一加入 system
        system = "You are a powerful automatic program repair assistant with plenty of knowledge about common weakness enumeration(CWE). Provide your answer in Markdown."
        
        conversation = [{"human":total_input, "assistant":total_output}]
        ans_json_list.append({"conversation_id":conv_id, "category":"Brainstorming", "system":system, "conversation":conversation, "dataset":"juliet-java"})
        conv_id += 1
    return ans_json_list

if __name__ == "__main__":
    # 获取 sh 脚本中传入的参数
    args = setup_everything()
    assert args.user_type in ["lora", "qlora"]

    tokenizer = AutoTokenizer.from_pretrained(args.tokenizer_dir)

    # 处理完原始数据集，得到初步的结果？
    ans_input_list, ans_output_list, valid_testcases_cnt = transfer_raw_data_to_input_output(args.model_type, args.user_type, args.raw_data_path, args.cwe_metadata_path, tokenizer, max_token_len=args.max_token_len)

    # 划分为训练集和测试集
    train_input_list, train_output_list, test_input_list, test_output_list = shuffle_and_split_train_test(ans_input_list, ans_output_list, ratio=args.split_ratio)
    print("train: %s\ttest: %s" % (len(train_input_list), len(test_input_list)))

    output_train_file_name = f"finetuning_data_maxlen={args.max_token_len}_modeltype={args.model_type}_usertype={args.user_type}_dataset=cwe-inference_trainratio={args.split_ratio}_split=train.{args.output_format}"
    output_test_file_name = f"finetuning_data_maxlen={args.max_token_len}_modeltype={args.model_type}_usertype={args.user_type}_dataset=cwe-inference_trainratio={args.split_ratio}_split=test.{args.output_format}"
    save_train_path = os.path.join(args.save_output_dir, args.output_format, output_train_file_name)
    save_test_path = os.path.join(args.save_output_dir, args.output_format, output_test_file_name)

    if args.user_type == "qlora":
        train_json_list_final = transfer_data_to_qlora_jsonl(train_input_list, train_output_list)
        test_json_list_final = transfer_data_to_qlora_jsonl(test_input_list, test_output_list)
        with jsonlines.open(save_train_path, "w") as writer:
            for item in train_json_list_final:
                writer.write(item)
        with jsonlines.open(save_test_path, "w") as writer:
            for item in test_json_list_final:
                writer.write(item)
    elif args.user_type == "lora":
        # as parquet
        df_train = pd.DataFrame({"input": train_input_list, "output": train_output_list})
        df_test = pd.DataFrame({"input": test_input_list, "output": test_output_list})
        df_train.to_parquet(save_train_path, index=False)
        df_test.to_parquet(save_test_path, index=False)
    else:
        raise Exception("Unexpected user type!")

    print(f"finish writing into {args.output_format} format for dataset juliet-java in user_type {args.user_type}!")

# 0202 进度
# double file: 62596 -> 61687
