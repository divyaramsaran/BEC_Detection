import pandas as pd

emails = pd.read_csv('data/emails.csv')
logins = pd.read_csv('data/login_logs.csv')

print(emails.shape)   # should be (15, 7)
print(logins.shape)   # should be (15, 8)
print(emails['label'].value_counts())
print(logins['label'].value_counts())