"""
Given a .csv file database, sorts its rows from most-unique to least-unique with respect to cell entries
that are shared by other rows in the database. 

[Note: This has applications for optimizing a record-deletion algorithm, allowing for linear-time.]
"""

import csv


def count_unique_combinations(rows):
    unique_combinations = {}
    
    for row in rows:
        # Exclude empty values and the first two columns
        values = [value for value in row[2:] if value != '']
        combination = tuple(values)
        unique_combinations[combination] = unique_combinations.get(combination, 0) + 1
    
    return unique_combinations


def sort_and_save_csv(input_file_path, output_file_path):
    try:
        with open(input_file_path, 'r') as input_file:
            csv_reader = csv.reader(input_file)
            header = next(csv_reader)
            csv_data = [row for row in csv_reader]

        unique_combinations = count_unique_combinations(csv_data)

        # Sort rows by the count of unique combinations (most to least), and then by the row itself
        sorted_rows = sorted(csv_data, key=lambda row: (-unique_combinations[tuple([value for value in row[2:] if value != ''])], row))[::-1]

        with open(output_file_path, 'w', newline='') as output_file:
            csv_writer = csv.writer(output_file)
            csv_writer.writerow(header)
            csv_writer.writerows(sorted_rows)

        print(f"CSV file sorted and saved as {output_file_path}")

    except Exception as e:
        print(f"An error occurred: {str(e)}")


if __name__ == "__main__":
    input_file_path = 'reduced_qi_filled.csv'
    output_file_path = 'sorted_' + input_file_path
    sort_and_save_csv(input_file_path, output_file_path)
