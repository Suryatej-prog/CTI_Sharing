print("Step 1")

import json
print("Step 2")

from transformers import pipeline
print("Step 3")

INPUT_FILE = "evaluation/generated_text/test.txt"
OUTPUT_FILE = "evaluation/predictions/predictions.json"

print("Loading model...")

bert_ner = pipeline(
    task="token-classification",
    model="attack-vector/SecureModernBERT-NER",
    tokenizer="attack-vector/SecureModernBERT-NER",
    aggregation_strategy="simple"
)

print("Model loaded")

with open(INPUT_FILE, "r", encoding="utf-8") as f:
    text = f.read()

print("Running inference...")

results = bert_ner(text)

print("Inference complete")

with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
    json.dump(results, f, indent=4)

print(f"Saved {len(results)} predictions to {OUTPUT_FILE}")