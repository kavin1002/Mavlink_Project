import pandas as pd

encodings = ['utf-8', 'ISO-8859-1', 'cp1252', 'latin1']
for enc in encodings:
    try:
        df = pd.read_csv('Chacha5.csv', encoding=enc)
        print(f"Success with encoding: {enc}")
        break
    except UnicodeDecodeError as e:
        print(f"Error with encoding {enc}: {e}")
