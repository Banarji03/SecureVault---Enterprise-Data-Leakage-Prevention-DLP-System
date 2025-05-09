import os
import random
import csv
from faker import Faker

fake = Faker()

# Parameters
NUM_FILES_PER_CLASS = 500
output_file = "dataset_full.csv"

# 🚨 Sensitive content generator
def generate_sensitive_content():
    patterns = [
        f"Username: {fake.user_name()}, Password: {fake.password()}",
        f"Email: {fake.email()}, Alt Email: john.doe[at]company[dot]com",
        f"Credit Card: {fake.credit_card_number()}, CVV: {fake.credit_card_security_code()}",
        f"SSN: {fake.ssn()}, Address: {fake.address()}",
        f"CONFIDENTIAL FINANCIAL DATA - Revenue: ${random.randint(100000, 1000000)}",
        f"Internal IP: 192.168.{random.randint(0, 255)}.{random.randint(1, 254)}",
        f"Internal IP: 10.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}",
        f"Internal Email: employee{random.randint(1000,9999)}@corp.local",
        f"Document Hash (SHA256): {fake.sha256()}",
        f"DOC-ID-{random.randint(10000, 99999)}-{fake.lexify(text='?????').upper()}",
    ]
    return "\n".join(random.sample(patterns, k=4))

# 🟢 Safe content generator
def generate_safe_content():
    lines = [
        f"Meeting notes: {fake.sentence()}",
        f"Project update: {fake.text(max_nb_chars=100)}",
        f"Reminder: {fake.sentence()}",
        f"Team: {fake.name()} completed {fake.bs()}",
        f"Note: {fake.catch_phrase()} is progressing well.",
        f"Checklist: {', '.join(fake.words(nb=5))}"
    ]
    return "\n".join(random.sample(lines, k=4))

# Generate dataset
rows = []

for _ in range(NUM_FILES_PER_CLASS):
    rows.append((generate_safe_content(), "safe"))
    rows.append((generate_sensitive_content(), "sensitive"))

# Save to CSV
with open(output_file, "w", newline="", encoding="utf-8") as f:
    writer = csv.writer(f)
    writer.writerow(["content", "label"])
    writer.writerows(rows)

print(f"Dataset saved as single CSV: {output_file}")
