import os

INPUT_FILE = r"evaluation\datasets\test.bio"
OUTPUT_FILE = r"evaluation\generated_text\test.txt"

os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

sentence = []

with open(INPUT_FILE, "r", encoding="utf-8") as infile, \
     open(OUTPUT_FILE, "w", encoding="utf-8") as outfile:

    for line in infile:
        line = line.strip()

        # Blank line = end of sentence
        if line == "":
            if sentence:
                outfile.write(" ".join(sentence) + "\n")
                sentence = []
            continue

        parts = line.split()

        if len(parts) < 2:
            continue

        token = parts[0]
        sentence.append(token)

    if sentence:
        outfile.write(" ".join(sentence) + "\n")

print("Done!")
print("Output written to:", OUTPUT_FILE)