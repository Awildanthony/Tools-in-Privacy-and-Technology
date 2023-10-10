"""
MatPlotLib data visualization for selected Privacy Policies.
"""

import matplotlib.pyplot as plt

# Data for word, syllable, and sentence counts
bodies = ["IRS", "NSA", "Google", "Cisco", "Harvard"]
word_counts = [2959, 1310, 9013, 2296, 7194]
syllable_counts = [5279, 2693, 15095, 4544, 13195]
sentence_counts = [107, 50, 373, 99, 164]

# Data for readability indices
flesch_reading_ease = [26.4, 2.6, 38.5, 14.1, 10.0]
flesch_kincaid_grade = [16.5, 19.4, 13.9, 17.1, 22.8]
gunning_fog_index = [14.5, 14.0, 12.0, 13.6, 19.8]
automated_readability_index = [19.2, 20.6, 17.0, 18.0, 27.6]
coleman_liau_index = [15.2, 17.8, 14.6, 16.3, 16.0]
smog_index = [17.5, 19.5, 14.9, 18.4, 22.0]

# Round all data points to one decimal point
word_counts = [round(count, 1) for count in word_counts]
syllable_counts = [round(count, 1) for count in syllable_counts]
sentence_counts = [round(count, 1) for count in sentence_counts]
flesch_reading_ease = [round(score, 1) for score in flesch_reading_ease]
flesch_kincaid_grade = [round(score, 1) for score in flesch_kincaid_grade]
gunning_fog_index = [round(score, 1) for score in gunning_fog_index]
automated_readability_index = [round(score, 1) for score in automated_readability_index]
coleman_liau_index = [round(score, 1) for score in coleman_liau_index]
smog_index = [round(score, 1) for score in smog_index]

# Create two subplots: one for counts and another for readability indices
fig, (ax1, ax2) = plt.subplots(2, 1, figsize=(10, 12))

# Set bar widths separately for each figure
bar_width_counts = 0.2  # Width for counts in the first figure
bar_width_indices = 0.13  # Width for indices in the second figure

# X-axis positions for bars
x = range(len(bodies))

# Colors for bars
count_colors = ['blue', 'violet', 'red']
index_colors = ['red', 'orange', 'yellow', 'green', 'blue', 'indigo']

# Create bars for word counts in the first subplot with custom colors
bars_word = ax1.bar(x, word_counts, width=bar_width_counts, label='Word Count', color=count_colors[0])

# Create bars for syllable counts in the first subplot with custom colors
bars_syllable = ax1.bar([i + bar_width_counts for i in x], syllable_counts, width=bar_width_counts, label='Syllable Count', color=count_colors[1])

# Create bars for sentence counts in the first subplot with custom colors
bars_sentence = ax1.bar([i + 2 * bar_width_counts for i in x], sentence_counts, width=bar_width_counts, label='Sentence Count', color=count_colors[2])

# Set x-axis labels and title for the first subplot
ax1.set_xticks([i + bar_width_counts for i in x])
ax1.set_xticklabels(bodies)
ax1.set_ylabel('Counts')
ax1.set_title('Word, Syllable, and Sentence Counts Comparison')
ax1.legend()

# Function to add labels at the top of bars with width limit
def add_labels(ax, bars, data, width_limit):
    for bar, value in zip(bars, data):
        width = min(bar.get_width(), width_limit)
        ax.annotate(f'{value}',
                    xy=(bar.get_x() + width / 2, bar.get_height()),
                    xytext=(0, 3),  # 3 points vertical offset
                    textcoords="offset points",
                    ha='center', va='bottom')

# Add labels for word counts in the first subplot
add_labels(ax1, bars_word, word_counts, bar_width_counts)

# Add labels for syllable counts in the first subplot
add_labels(ax1, bars_syllable, syllable_counts, bar_width_counts)

# Add labels for sentence counts in the first subplot
add_labels(ax1, bars_sentence, sentence_counts, bar_width_counts)

# Create bars for readability indices in the second subplot with custom colors
bars_flesch_reading_ease = ax2.bar(x, flesch_reading_ease, width=bar_width_indices, label='Flesch Reading Ease', color=index_colors[0])
bars_flesch_kincaid_grade = ax2.bar([i + bar_width_indices for i in x], flesch_kincaid_grade, width=bar_width_indices, label='Flesch-Kincaid Grade', color=index_colors[1])
bars_gunning_fog_index = ax2.bar([i + 2 * bar_width_indices for i in x], gunning_fog_index, width=bar_width_indices, label='Gunning Fog', color=index_colors[2])
bars_automated_readability_index = ax2.bar([i + 3 * bar_width_indices for i in x], automated_readability_index, width=bar_width_indices, label='Automated Readability', color=index_colors[3])
bars_coleman_liau_index = ax2.bar([i + 4 * bar_width_indices for i in x], coleman_liau_index, width=bar_width_indices, label='Coleman-Liau', color=index_colors[4])
bars_smog_index = ax2.bar([i + 5 * bar_width_indices for i in x], smog_index, width=bar_width_indices, label='SMOG', color=index_colors[5])

# Set x-axis labels and title for the second subplot
ax2.set_xticks([i + 2.5 * bar_width_indices for i in x])
ax2.set_xticklabels(bodies)
ax2.set_ylabel('Indices')
ax2.set_title('Readability Indices Comparison')
ax2.legend()

# Add labels for readability indices in the second subplot
add_labels(ax2, bars_flesch_reading_ease, flesch_reading_ease, bar_width_indices)
add_labels(ax2, bars_flesch_kincaid_grade, flesch_kincaid_grade, bar_width_indices)
add_labels(ax2, bars_gunning_fog_index, gunning_fog_index, bar_width_indices)
add_labels(ax2, bars_automated_readability_index, automated_readability_index, bar_width_indices)
add_labels(ax2, bars_coleman_liau_index, coleman_liau_index, bar_width_indices)
add_labels(ax2, bars_smog_index, smog_index, bar_width_indices)

# Add horizontal dotted red lines with captions above the lines
for y, caption in [(20, 'Graduate'), (40, 'College'), (55, 'High Schooler')]:
    ax2.axhline(y=y, color='red', linestyle='--')
    ax2.annotate(caption, xy=(2.75, y), xycoords='data', xytext=(0, 3),
                 textcoords='offset points', color='red', fontsize=8,
                 ha='center', va='bottom')

# Adjust spacing between subplots
plt.tight_layout()

# Show the plot
plt.show()
