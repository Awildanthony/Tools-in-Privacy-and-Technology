"""
Given a .csv file database, checks its k-anonymity and continually uses record_suppression (row deletion),
iterating through all possible combinations until a minimum example achieves the desired k-anonymity.
"""

import shutil
import csv
import os
import pandas as pd
from tqdm import tqdm
from anonymity import calculate_k_anonymity


def suppress_rows(input_file_path, desired_k_anonymity, n_deletions=1, save_working_copy=False):
    # Make a working copy of the input file
    df = pd.read_csv(input_file_path)
    working_copy_path = 'rs_copy_of_' + input_file_path
    df.to_csv(working_copy_path, index=False)  # Specify the path and use index=False

    # Initialize variables
    rows_deleted = 0
    current_k_anonymity = calculate_k_anonymity(working_copy_path)
    print(f"Starting k-anonymity is {current_k_anonymity}.")

    # Get the total number of rows
    total_rows = len(df)

    # Create a progress bar
    with tqdm(total=total_rows, dynamic_ncols=True) as pbar:

        # Keep deleting rows until the desired k-anonymity is met or exceeded
        while current_k_anonymity < desired_k_anonymity:
            # Open the working copy file for reading
            with open(working_copy_path, 'r') as input_file:
                csv_reader = csv.reader(input_file)
                header = next(csv_reader)
                rows = list(csv_reader)

            # Check if there are any rows left
            if not rows:
                print(f"All rows deleted: cannot achieve {desired_k_anonymity}-anonymity.")
                break

            # Delete n rows from the working copy
            for _ in range(n_deletions):
                if not rows:
                    break
                rows.pop(0)
                rows_deleted += 1

            # Write the remaining rows back to the working copy
            with open(working_copy_path, 'w', newline='') as output_file:
                csv_writer = csv.writer(output_file)
                csv_writer.writerow(header)
                csv_writer.writerows(rows)

            # Check k-anonymity after every n deletions
            if rows_deleted % n_deletions == 0:
                current_k_anonymity = calculate_k_anonymity(working_copy_path)

            # Update the progress bar
            pbar.update(n_deletions)
            pbar.set_description("Rows Processed")

    if save_working_copy:
        print(f"Altered dataset saved as '{working_copy_path}'.")
    else:
        # Remove the working copy when the desired k-anonymity is met or no more rows can be deleted
        os.remove(working_copy_path)

    print(f"Deleted {rows_deleted} rows to achieve {desired_k_anonymity}-anonymity.")

    # Remove the __pycache__ folder
    pycache_folder = "__pycache__"
    if os.path.exists(pycache_folder):
        shutil.rmtree(pycache_folder)


if __name__ == "__main__":
    input_file_path = 'sorted_reduced_qi_filled.csv'    # Ensure that you call `sort.py` on `reduced_qi_filled.csv` first!
    desired_k_anonymity = 5                             # Change this to your desired k-anonymity
    n_deletions = 1000                                  # Number of deletions to perform before checking k-anonymity
    save_working_copy = True                            # Set this to True to keep the working copy
    suppress_rows(input_file_path, desired_k_anonymity, n_deletions, save_working_copy)
