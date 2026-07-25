"""
Fetch Exploit Prediction Scoring System (EPSS) scores.
"""

#Import
import gzip
import json
import os

import pandas as pd
import requests

from pathlib import Path
from datetime import datetime


# download EPSS

def download_epss(date_str, save_dir="data/raw/epss_"):
    url = f"https://epss.empiricalsecurity.com/epss_scores-{date_str}.csv.gz"
    save_path = Path(save_dir) / f"epss_scores-{date_str}.csv.gz"
    save_path.parent.mkdir(parents=True, exist_ok=True)

    response = requests.get(url)
    if response.status_code == 200:
        with open(save_path, "wb") as f:
            f.write(response.content)
        print(f"Downloaded: {save_path}")
        return True
    else:
        print(f"Failed: {url} (status={response.status_code})")
        return False


# find the latest available EPSS snapshot

def find_latest_epss(max_backtrack_days=5):
    today = datetime.today()

    for i in range(max_backtrack_days):
        date_try = (today - timedelta(days=i)).strftime("%Y-%m-%d")
        print(f"Trying latest snapshot: {date_try}...")
        if download_epss(date_try):
            return date_try

    raise RuntimeError("Could not find any recent EPSS file (tried last 5 days).")



# define yearly snapshots
yearly_snapshots = [
    "2021-04-14",  # EPSS initial release
    "2022-01-01",
    "2023-01-01",
    "2024-01-01",
    "2025-01-01"
]

# download yearly snapshots
for date in yearly_snapshots:
    download_epss(date)

# download the latest available snapshot
latest_date = find_latest_epss()

# combine all dates
all_dates = yearly_snapshots + [latest_date]

# load and combine EPSS frames
frames = []
base_dir = Path("data/raw/epss")

for date in all_dates:
    path = base_dir / f"epss_scores-{date}.csv.gz"

    if not path.exists():
        print(f"Missing: {path.name} — skipped")
        continue

    df_tmp = pd.read_csv(path, low_memory=False)
    df_tmp["snapshot_date"] = date
    frames.append(df_tmp)

df_epss = pd.concat(frames, ignore_index=True).rename(columns={"cve": "cve_id"})

print("EPSS loaded:", df_epss.shape)
print("Latest snapshot found:", latest_date)
