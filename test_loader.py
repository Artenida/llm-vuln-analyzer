from src.preprocessing.data_loader import load_juliet_folder

samples = load_juliet_folder("data/raw/juliet/juliet/Java/src/testcases")

print(f"Total samples loaded: {len(samples)}")
print(f"Vulnerable (bad): {sum(s.is_vulnerable for s in samples)}")
print(f"Safe (good):      {sum(not s.is_vulnerable for s in samples)}")

# Show one vulnerable sample
print("\n--- First vulnerable sample ---")
vuln = next(s for s in samples if s.is_vulnerable)
print(f"File:       {vuln.file_path}")
print(f"Method:     {vuln.function_name}")
print(f"CWE:        {vuln.cwe_id}")
print(f"Vulnerable: {vuln.is_vulnerable}")
print(f"Code:\n{vuln.source_code[:400]}")

# Show one safe sample
print("\n--- First safe sample ---")
safe = next(s for s in samples if not s.is_vulnerable)
print(f"File:       {safe.file_path}")
print(f"Method:     {safe.function_name}")
print(f"CWE:        {safe.cwe_id}")
print(f"Vulnerable: {safe.is_vulnerable}")
print(f"Code:\n{safe.source_code[:400]}")

# Breakdown by CWE
print("\n--- Breakdown by CWE ---")
from collections import Counter
cwe_counts = Counter(s.cwe_id for s in samples)
for cwe, count in sorted(cwe_counts.items()):
    vuln_count = sum(1 for s in samples if s.cwe_id == cwe and s.is_vulnerable)
    safe_count = sum(1 for s in samples if s.cwe_id == cwe and not s.is_vulnerable)
    print(f"{cwe}: {count} total  |  {vuln_count} vulnerable  |  {safe_count} safe")