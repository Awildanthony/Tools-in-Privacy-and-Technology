"""
Web scraper for HTML bodies of selected Privacy Policies.
"""

import re
import requests
import textstat
from bs4 import BeautifulSoup

# List of URLs to analyze
urls = [
    "https://www.irs.gov/privacy-disclosure/irs-privacy-policy",
    "https://www.nsa.gov/privacy#:~:text=National%20Security%20Agency%2FCentral%20Security%20Service%20Web%20sites%20will%20disclose,on%20National%20Security%20Agency%2FCentral",
    "https://policies.google.com/privacy?hl=en-US",
    "https://policies.google.com/privacy?hl=en-US",
    "https://www.cisco.com/c/en/us/about/trust-center/global-privacy-policy.html#purpose"
]

for url in urls:

    response = requests.get(url)

    # Parse the HTML content of the page
    soup = BeautifulSoup(response.content, "html.parser")

    # Find the entire <body> element
    body = soup.find("body")

    # Extract all the text within the <body> element
    text = body.get_text()

    print("\n")
    print(f"URL: {url}")
    print("\n")

    # Clean the text by removing extra spaces and special characters
    cleaned_text = re.sub(r'\s+', ' ', text)

    # Calculate various text statistics
    word_count = textstat.lexicon_count(cleaned_text)
    sentence_count = textstat.sentence_count(cleaned_text)
    syllable_count = textstat.syllable_count(cleaned_text)
    flesch_reading_ease = textstat.flesch_reading_ease(cleaned_text)
    flesch_kincaid_grade = textstat.flesch_kincaid_grade(cleaned_text)
    gunning_fog = textstat.gunning_fog(cleaned_text)
    automated_readability_index = textstat.automated_readability_index(cleaned_text)
    coleman_liau_index = textstat.coleman_liau_index(cleaned_text)
    smog_index = textstat.smog_index(cleaned_text)

    # Print the results
    print(f"Word Count: {word_count}")
    print(f"Sentence Count: {sentence_count}")
    print(f"Syllable Count: {syllable_count}")
    print(f"Flesch Reading Ease: {flesch_reading_ease}")
    print(f"Flesch-Kincaid Grade Level: {flesch_kincaid_grade}")
    print(f"Gunning Fog Index: {gunning_fog}")
    print(f"Automated Readability Index: {automated_readability_index}")
    print(f"Coleman-Liau Index: {coleman_liau_index}")
    print(f"SMOG Index: {smog_index}")
