# 处理 testcase_stat 文件
import pandas as pd

df_testcase_stat = pd.read_csv("./testcase_stat.csv", encoding="utf-8")

cwe_id_list = df_testcase_stat["cwe_id"].tolist()

new_cwe_id_list = [id[6:] for id in cwe_id_list]

df_testcase_stat["cwe_id"] = new_cwe_id_list

df_testcase_stat.to_csv("./testcase_stat.csv", index=False, encoding="utf-8")