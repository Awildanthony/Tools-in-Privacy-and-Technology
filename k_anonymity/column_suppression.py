"""
Given a .csv file database, checks its k-anonymity and continually uses column_suppression (deletion),
iterating through all possible combinations until a minimum example achieves the desired k-anonymity.
"""

import os
import itertools
import pandas as pd
from tqdm import tqdm
from anonymity import calculate_k_anonymity


def suppress_columns(input_file_path, desired_k_anonymity, save_working_copy=False):
    # Make a working copy of the input file
    df = pd.read_csv(input_file_path)
    working_copy_path = 'cs_copy_of_' + input_file_path
    df.to_csv(working_copy_path, index=False)  # Specify the path and use index=False

    # Initialize variables
    current_k_anonymity = calculate_k_anonymity(working_copy_path)
    print(f"Starting k-anonymity is {current_k_anonymity}.")

    # Get the total number of columns excluding 'user_id' and 'course_id'
    columns_to_delete = df.columns[2:]  # Exclude the first two columns
    total_columns = len(columns_to_delete)

    # Initialize progress bar variables
    combinations_checked = 0
    total_combinations = sum(1 for num_columns_to_delete in range(1, total_columns + 1) for _ in
                             itertools.combinations(columns_to_delete, num_columns_to_delete))

    # Create a progress bar with proper formatting
    with tqdm(total=total_combinations, unit="combination", dynamic_ncols=True) as pbar:
        # Iterate through the number of columns to delete from 1 to total_columns
        for num_columns_to_delete in range(1, total_columns + 1):
            # Generate all combinations of columns to delete
            column_combinations = itertools.combinations(columns_to_delete, num_columns_to_delete)

            # Check each combination
            for columns_to_remove in column_combinations:
                # Make a copy of the original DataFrame
                df_copy = df.copy()

                # Remove the selected columns
                df_copy.drop(columns=list(columns_to_remove), inplace=True)

                # Create a temporary CSV file for this combination
                temp_path = 'temp.csv'
                df_copy.to_csv(temp_path, index=False)

                # Calculate k-anonymity for this combination
                current_k_anonymity = calculate_k_anonymity(temp_path)

                # Remove the temporary CSV file
                os.remove(temp_path)

                combinations_checked += 1
                pbar.update(1)
                pbar.set_description(f"Combinations Processed")

                # Check if k-anonymity is met or exceeded
                if current_k_anonymity >= desired_k_anonymity:
                    if save_working_copy:
                        # Save the altered dataset with suppressed columns
                        df_copy.to_csv(working_copy_path, index=False)
                    else:
                        # Remove the working copy when k-anonymity is met
                        os.remove(working_copy_path)

                    print(f"Deleted {len(columns_to_remove)} columns to achieve {desired_k_anonymity}-anonymity.")
                    return len(columns_to_remove), list(columns_to_remove)

    # If no satisfactory combination is found, print a message
    print(f"No combination found to achieve {desired_k_anonymity}-anonymity.")
    return 0, []


if __name__ == "__main__":
    input_file_path = 'sorted_reduced_qi_filled.csv'        # Ensure that you call `sort.py` on `reduced_qi_filled.csv` first!
    desired_k_anonymity = 5                                 # Change this to your desired k-anonymity
    save_working_copy = True                                # Set this to True to keep the working copy
    columns_deleted, deleted_columns = suppress_columns(input_file_path, desired_k_anonymity, save_working_copy)
    if columns_deleted > 0:
        print(f"Deleted {columns_deleted} columns: {', '.join(deleted_columns)}")
