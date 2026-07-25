"""
Fetch vulnerability records from Open Source Vulnerabilities (OSV).
"""

#Import
import gzip
import json
import os
import re
import zipfile

import pandas as pd
import requests

from multiprocessing import Pool

# download OSV data in a "bulk" (not a for loop for an everyday file)
os.makedirs("raw/osv", exist_ok=True)
url = "https://osv-vulnerabilities.storage.googleapis.com/all.zip"
zip_path = "raw/osv/osv_all.zip"

print("Downloading OSV bulk data")
r = requests.get(url, stream=True)
with open(zip_path, "wb") as f:
    for chunk in r.iter_content(chunk_size=8192):
        f.write(chunk)

print("Download complete. Filtering files by year ≥ 2020...")

# regex to match CVE IDs with year >= 2020
year_pattern = re.compile(r"CVE-(\d{4})-")

count_total = 0
count_kept = 0

# extract only relevant JSON files
with zipfile.ZipFile(zip_path, "r") as zip_ref:
    for member in zip_ref.infolist():
        if not member.filename.endswith(".json"):
            continue
        count_total += 1
        try:
            with zip_ref.open(member) as f:
                data = json.load(f)
            # check all CVE-like aliases
            aliases = data.get("aliases", [])
            osv_id = data.get("id", "")
            cve_candidates = [a for a in aliases if a.startswith("CVE-")]
            if not cve_candidates and str(osv_id).startswith("CVE-"):
                cve_candidates = [osv_id]

            keep = False
            for cve in cve_candidates:
                m = year_pattern.match(cve)
                if m and int(m.group(1)) >= 2020:
                    keep = True
                    break

            if keep:
                target_path = os.path.join("osv_data", os.path.basename(member.filename))
                with open(target_path, "w") as out_f:
                    json.dump(data, out_f)
                count_kept += 1
        except Exception:
            continue

print(f"Extraction complete. Kept {count_kept} of {count_total} JSON files (year ≥ 2020).")

# extract data from OSV files and create a dataframe
# use parallel processing

def parse_osv_file(file_path):
    try:
        with open(file_path, "r") as f:
            data = json.load(f)
        osv_id = data.get("id", "")
        aliases = data.get("aliases", [])
        cve_candidates = [a for a in aliases if a.startswith("CVE-")]
        cve_id = cve_candidates[0] if cve_candidates else (osv_id if str(osv_id).startswith("CVE-") else None)
        if not cve_id:
            return None
        summary = data.get("summary", "")
        details = data.get("details", "")
        affected_list = []
        for aff in data.get("affected", []):
            pkg = aff.get("package", {})
            name = pkg.get("name")
            eco = pkg.get("ecosystem")
            if name or eco:
                affected_list.append(f"{name} ({eco})")
        affected_pkgs = ", ".join(sorted(set(affected_list)))
        return {
            "osv_id": osv_id,
            "cve_id": cve_id,
            "osv_summary": summary,
            "osv_details": details,
            "osv_affected_packages": affected_pkgs
        }
    except Exception:
        return None

def load_osv_parallel(json_dir="raw/osv", workers=8):
    files = [os.path.join(json_dir, f) for f in os.listdir(json_dir) if f.endswith(".json")]
    with Pool(workers) as p:
        data = [r for r in p.map(parse_osv_file, files) if r]
    df = pd.DataFrame(data)
    df = df.drop_duplicates(subset=["cve_id"])
    return df

df_osv = load_osv_parallel("raw/osv", workers=8)
