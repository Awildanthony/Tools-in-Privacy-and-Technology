"""
Given a .csv file database, checks its k-anonymity.

[Note: quasi-identifiers are assumed to be all columns except for `course_id` and `user_id`.
       Entries that are empty are not up for consideration as duplicates. ]
"""

import csv
from collections import Counter


def calculate_k_anonymity(input_file_path):
    # Open the input CSV file
    with open(input_file_path, 'r') as input_file:
        # Create a CSV reader object
        csv_reader = csv.reader(input_file)

        # Read the header row
        header = next(csv_reader)

        # Get the indices of quasi-identifiers (excluding the first two columns)
        quasi_identifier_indices = list(range(2, len(header)))

        # Create a Counter to count unique sets of quasi-identifiers
        quasi_identifier_counter = Counter()

        # Iterate through the rows in the input CSV
        for row in csv_reader:
            # Create a set of quasi-identifiers for this row, ignoring empty values
            quasi_identifier_set = set()
            for idx in quasi_identifier_indices:
                if row[idx] != "":
                    quasi_identifier_set.add(row[idx])

            # Add the set of quasi-identifiers to the counter
            quasi_identifier_counter[frozenset(quasi_identifier_set)] += 1

    # Check if there are any quasi-identifier sets
    if not quasi_identifier_counter:
        return 0  # Return 0 if there are no sets

    # Find the minimum count among the unique sets of quasi-identifiers
    k_anonymity = min(quasi_identifier_counter.values())

    return k_anonymity


if __name__ == "__main__":
    input_file_path = 'reduced_qi_filled.csv'
    print(f"The k-anonymity value for the dataset is {calculate_k_anonymity(input_file_path)}.")
