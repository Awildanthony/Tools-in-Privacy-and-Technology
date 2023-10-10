"""
Given a (heavily redacted and truncated) .csv file database of users from the HarvardX platform, defines
generalizations for each data column and simulates all possible combinations of generalizations until a
minimum example achieves a desired k-anonymity. 

[Note: currently too slow for use in production]

[Alternative Algorithm: determine which data columns have the most varied data and prioritize those,
either generalizing one-by-one, or giving priority to those in cols-choose-n combinations first.]
"""

import os
import itertools
import pandas as pd
from tqdm import tqdm                                                       
from anonymity import calculate_k_anonymity
from geopy.geocoders import Nominatim                             
from pycountry_convert import country_alpha2_to_continent_code


# GENERALIZATIONS:

# course_id --> N/A (not a quasi-identifier)
# user_id --> N/A (not a quasi-identifier)

# cc_by_ip --> country code maps to native continent
# city --> city maps to native country
# postalCode --> truncate zip code from 5 to first 3 numbers
# LoE --> binned into college-educated (b = bachelor's?, m = master's?, p = PhD?) and non-college-educated
# YoB --> rounded to nearest 5-year interval (e.g. 1996 -> 1995, 1999 -> 2000)
# gender --> binned into binary (m or f) and non-binary

# nforum_posts --> rounded to nearest 5-response interval (e.g. 2 -> 0, 3 -> 5)
# nforum_votes --> rounded to nearest 5-response interval (e.g. 2 -> 0, 3 -> 5)
# nforum_endorsed --> rounded to nearest 5-response interval (e.g. 2 -> 0, 3 -> 5)
# nforum_threads --> rounded to nearest 5-response interval (e.g. 2 -> 0, 3 -> 5)
# nforum_comments --> rounded to nearest 5-response interval (e.g. 2 -> 0, 3 -> 5)
# nforum_pinned --> rounded to nearest 5-response interval (e.g. 2 -> 0, 3 -> 5)
# nforum_events --> rounded to nearest 5-response interval (e.g. 2 -> 0, 3 -> 5)

def map_city_to_country(city):
    try:
        geolocator = Nominatim(user_agent="geoapiExercises")
        location = geolocator.geocode(city)
        if location:
            return location.address.split(",")[-1].strip()
    except Exception:
        pass
    return None


def map_country_to_continent(country_code):
    try:
        continent_code = country_alpha2_to_continent_code(country_code)
        return continent_code
    except KeyError:
        pass
    return None


def generalize_columns(input_file_path, desired_k_anonymity, save_working_copy=False):
    # Make a working copy of the input file
    df = pd.read_csv(input_file_path)
    working_copy_path = 'gen_copy_of_' + input_file_path
    df.to_csv(working_copy_path, index=False)  # Specify the path and use index=False

    # Initialize variables
    current_k_anonymity = calculate_k_anonymity(working_copy_path)
    print(f"Starting k-anonymity is {current_k_anonymity}.")

    # Get the total number of columns excluding 'user_id' and 'course_id'
    columns_to_generalize = df.columns[2:]      # Exclude the first two columns
    total_columns = len(columns_to_generalize)

    # Initialize progress bar variables
    combinations_checked = 0
    total_combinations = sum(1 for num_columns_to_generalize in range(1, total_columns + 1) for _ in
                             itertools.combinations(columns_to_generalize, num_columns_to_generalize))

    # Define generalization rules
    generalization_rules = {
        'cc_by_ip': lambda x: map_country_to_continent(x),      # Map cc_by_ip to continent using pycountry_convert
        'city': lambda x: map_city_to_country(x),     # Map city to country using geopy
        'postalCode': lambda x: str(x)[:3],                     # Truncate zip code to first 3 numbers
        'LoE': {
            'nan': 'Non-College',       # No input
            'b': 'College',             # Bachelor's
            'm': 'College',             # Master's
            'p': 'College',             # PhD ?
            'hs': 'Non-College',        # High School ?
            'p_se': 'College',          # PhD se... ?
            'other': 'Non-College',     # Other
            'jhs': 'Non-College',       # Junior High School
            'p_oth': 'College',         # PhD other ?
            'none': 'Non-College',      # No Education
            'a': 'Non-College',         # Associate's
            'el': 'Non-College'         # English Learner ?
            # Add more mappings for other values
        },
        'YoB': lambda x: str(int(x) - (int(x) % 5)) if not pd.isna(x) else x,         # Round to nearest 5-year interval
        'gender': {
            'm': 'Binary',              # Male
            'f': 'Binary',              # Female
            'nan': 'Non-Binary',        # No input
            'o': 'Non-Binary'           # Other
            # Add more mappings for other values
        },
        'nforum_posts': lambda x: int(x) - (int(x) % 5) if not pd.isna(x) else x,     # Round to nearest 5-response interval
        'nforum_votes': lambda x: int(x) - (int(x) % 5) if not pd.isna(x) else x,     # Round to nearest 5-response interval
        'nforum_endorsed': lambda x: int(x) - (int(x) % 5) if not pd.isna(x) else x,  # Round to nearest 5-response interval
        'nforum_threads': lambda x: int(x) - (int(x) % 5) if not pd.isna(x) else x,   # Round to nearest 5-response interval
        'nforum_comments': lambda x: int(x) - (int(x) % 5) if not pd.isna(x) else x,  # Round to nearest 5-response interval
        'nforum_pinned': lambda x: int(x) - (int(x) % 5) if not pd.isna(x) else x,    # Round to nearest 5-response interval
        'nforum_events': lambda x: int(x) - (int(x) % 5) if not pd.isna(x) else x,    # Round to nearest 5-response interval
    }

    # Create a progress bar with proper formatting
    with tqdm(total=total_combinations, unit="combination", dynamic_ncols=True) as pbar:
        # Iterate through the number of columns to generalize from 1 to total_columns
        for num_columns_to_generalize in range(1, total_columns + 1):
            # Generate all combinations of columns to generalize
            column_combinations = itertools.combinations(columns_to_generalize, num_columns_to_generalize)

            # Check each combination
            for columns_to_abstract in column_combinations:
                # Make a copy of the original DataFrame
                df_copy = df.copy()

                # Apply generalizations to selected columns
                for column in columns_to_abstract:
                    # Apply the specific generalization rule for each column
                    if column in generalization_rules:
                        if callable(generalization_rules[column]):
                            df_copy[column] = df_copy[column].apply(generalization_rules[column])
                        else:
                            df_copy[column] = df_copy[column].map(generalization_rules[column])

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
                        # Save the altered dataset with generalized columns
                        df_copy.to_csv(working_copy_path, index=False)
                    else:
                        # Remove the working copy when k-anonymity is met
                        os.remove(working_copy_path)

                    print(f"Deleted {len(columns_to_abstract)} columns to achieve {desired_k_anonymity}-anonymity.")
                    return len(columns_to_abstract), list(columns_to_abstract)

    # If no satisfactory combination is found, print a message
    print(f"No combination found to achieve {desired_k_anonymity}-anonymity.")
    return 0, []


if __name__ == "__main__":
    input_file_path = 'sorted_test.csv'
    desired_k_anonymity = 2  # Change this to your desired k-anonymity
    save_working_copy = True  # Set this to True to keep the working copy
    columns_generalized, generalized_columns = generalize_columns(input_file_path, desired_k_anonymity, save_working_copy)
    if columns_generalized > 0:
        print(f"Deleted {columns_generalized} columns: {', '.join(generalized_columns)}")
