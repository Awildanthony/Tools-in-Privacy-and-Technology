"""
Given a .csv file database, prints all unique entries for each column.

[Note: Used to manually construct generalization maps in `generalization.py`.]
"""

import pandas as pd


def print_unique_entries(input_file_path):
    # Read the CSV file into a DataFrame
    df = pd.read_csv(input_file_path)

    # Iterate through columns and print unique entries
    for column in df.columns:
        unique_entries = df[column].unique()
        print(f"Column: {column}")
        print(f"Unique Entries: {', '.join(map(str, unique_entries))}\n")

if __name__ == "__main__":
    input_file_path = 'reduced_qi_filled.csv'
    print_unique_entries(input_file_path)
