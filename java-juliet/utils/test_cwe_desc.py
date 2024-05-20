import pandas as pd

all_cwe_metadata_path = "../testcase_metadata/all_cwe_metadata.csv"

df_cwe_metadata = pd.read_csv(all_cwe_metadata_path, encoding="utf-8", index_col=False)
cwe_id_list = df_cwe_metadata["CWE-ID"].tolist()
cwe_id_desc_list = df_cwe_metadata["Description"].tolist()

# print(cwe_id_desc_list[0])

print(549 in cwe_id_list)

cwe_id_desc = "This category represents one of the phyla in the Seven Pernicious Kingdoms vulnerability \
classification. It includes weaknesses that do not directly introduce a weakness or vulnerability, \
but indicate that the product has not been carefully developed or maintained"
    
print(cwe_id_desc)