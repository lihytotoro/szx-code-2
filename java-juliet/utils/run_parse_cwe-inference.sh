python parse_for_cwe-inference.py \
    --tokenizer_dir /data/lihy/models/Qwen1.5-7b-chat \
    --max_token_len 1024 \
    --model_type qwen \
    --user_type qlora \
    --raw_data_path /data/lihy/datasets/java-juliet/src/parsed_dataset/src/juliet-java_all_testcases.parquet \
    --save_output_dir /data/lihy/datasets/java-juliet/src/parsed_dataset \
    --output_format jsonl \
    --split_ratio 0.9 \
    --cwe_metadata_path /data/lihy/datasets/java-juliet/src/testcase_metadata/all_cwe_metadata.csv