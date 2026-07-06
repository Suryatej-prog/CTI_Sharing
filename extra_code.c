from transformers import AutoTokenizer, AutoModelForSequenceClassification

model_name = "SynamicTechnologies/CYBERT"

print("Downloading CyBERT...")
tokenizer = AutoTokenizer.from_pretrained(model_name)
# This perfectly matches the architecture saved in the checkpoint
model = AutoModelForSequenceClassification.from_pretrained(model_name)
print("Download complete! Model is ready to use.")
