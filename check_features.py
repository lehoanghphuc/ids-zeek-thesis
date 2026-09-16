import pandas as pd
df = pd.read_csv('/home/phuc1/ids_samples/zeek_featrues.csv')
print(df.shape)
print(df.iloc[:, :8].describe())
