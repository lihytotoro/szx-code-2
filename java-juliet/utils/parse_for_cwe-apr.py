# 将原始 parquet 中的数据，构造成 input + output 的提示数据！
# 与 finetune codellama 不同，这里的处理是为了二轮微调 repairllama 的
# 注意：这个版本的数据要遵循：bad_code + cwe_id -> good_code
import pandas as pd
from tqdm import tqdm
import jsonlines
from transformers import AutoTokenizer
import random

raw_data_path = "../parsed_dataset/src/juliet-java_all_testcases.parquet"
# 记录了所有 cwe 的 description
cwe_metadata_path = "../testcase_metadata/all_cwe_metadata.csv"
max_token_length = 2048
split_ratio=1.0

def transfer_raw_data_to_input_output(raw_data_path, tokenizer, max_token_len=2048):
    df_cwe_metadata = pd.read_csv(cwe_metadata_path, encoding="utf-8", index_col=False)
    all_cwe_id_list = df_cwe_metadata["CWE-ID"].tolist()
    all_cwe_id_list = [str(cwe_id_i) for cwe_id_i in all_cwe_id_list]
    all_cwe_name_list = df_cwe_metadata["Name"].tolist()
    all_cwe_id_desc_list = df_cwe_metadata["Description"].tolist()
    
    ans_json_list = []
    ans_input_list, ans_output_list = [], []
    valid_testcases_cnt = 0
    if raw_data_path.endswith(".parquet"):
        raw_df = pd.read_parquet(raw_data_path)
    else:
        raise Exception("Unexpected data form!")
    
    print("Initially, there are %d testcases!" % len(raw_df))
    
    input_prefix_1 = "The following java code contains a flaw, which belongs to common weakness enumeration type %s."
    input_prefix_2 = "The description of %s is: %s. Please provide the fixed code.\n"
    
    for row_idx, row in tqdm(raw_df.iterrows()):
        # 四项都需要！
        cwe_id = row["cwe_id"]
        cwe_name = row["cwe_name"]
        bad_code = row["bad_code"]
        good_code = row["good_code"]
        
        # 原始的 cwe_id 是包含 CWE 前缀的
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
        
        total_input = (input_prefix_1 % (cwe_id + ":" + real_cwe_name)) + input_prefix_2 % (cwe_id, cwe_id_desc) + bad_code
        total_output = good_code
        tokenized_input = tokenizer.tokenize(total_input)
        tokenized_output = tokenizer.tokenize(total_output)
        
        if len(tokenized_input) + len(tokenized_output) > max_token_len:
            continue
    
        ans_json_list.append({"input":total_input, "output":total_output})
        ans_input_list.append(total_input)
        ans_output_list.append(total_output)
        valid_testcases_cnt += 1
    
    print("Finally, there are %d valid testcases if we set max_token_len to %d!" % (valid_testcases_cnt, max_token_len))
    assert len(ans_json_list) == len(ans_input_list)
    assert len(ans_json_list) == len(ans_output_list)
    
    return ans_json_list, ans_input_list, ans_output_list, valid_testcases_cnt

# shuffle
# train + test(8:2)
def shuffle_and_split_train_test(input_list, output_list, ratio=0.8):
    combined_lists = list(zip(input_list, output_list))
    random.shuffle(combined_lists)

    # 打乱后的全部数据
    new_input_list, new_output_list = zip(*combined_lists)
    
    if ratio < 1.0:
        split_idx = int(ratio * len(new_input_list))
        train_input_list, train_output_list = new_input_list[:split_idx], new_output_list[:split_idx]
        test_input_list, test_output_list = new_input_list[split_idx:], new_output_list[split_idx:]
    else:
        train_input_list, train_output_list = new_input_list, new_output_list
        test_input_list, test_output_list = None, None
    
    # 注意测试集返回的列表有可能是 None
    return train_input_list, train_output_list, test_input_list, test_output_list

if __name__ == "__main__":
    # save_json_path = "../parsed_dataset/finetuning_conversation_data_total_%s_repairllama-cwe_2.jsonl" % str(max_token_length)
    
    save_train_parquet_path = "../parsed_dataset/parquet/finetuning_data_maxlen_%s_desc=true_repairllama-cwe_train.parquet" % str(max_token_length)
    save_test_parquet_path =  "../parsed_dataset/parquet/finetuning_data_maxlen_%s_desc=true_repairllama-cwe_test.parquet" % str(max_token_length)
    
    tokenizer = AutoTokenizer.from_pretrained("/vepfs/lihy/model/codellama/CodeLlama-7b-Instruct-hf")
    
    ans_json_list, ans_input_list, ans_output_list, valid_testcases_cnt = transfer_raw_data_to_input_output(raw_data_path, tokenizer, max_token_len=max_token_length)
    
    train_input_list, train_output_list, test_input_list, test_output_list = shuffle_and_split_train_test(ans_input_list, ans_output_list, ratio=split_ratio)
    if split_ratio < 1.0:
        print("train: %s\ttest: %s" % (len(train_input_list), len(test_input_list)))
    else:
        print("train: %s" % len(train_input_list))

    # # as json
    # with jsonlines.open(save_json_path, "w") as f_jsonl:
    #     for js_sample in ans_json_list:
    #         f_jsonl.write(js_sample)
    
    # as parquet
    df_train = pd.DataFrame({"input":train_input_list, "output":train_output_list})
    df_train.to_parquet(save_train_parquet_path, index=False)
    
    if test_input_list is not None:
        df_test = pd.DataFrame({"input":test_input_list, "output":test_output_list})
        df_test.to_parquet(save_test_parquet_path, index=False)
    
# 0202 进展
# double file:
#   max_len=2048: 62596->62095
#   max_len=1024: 62596->46744