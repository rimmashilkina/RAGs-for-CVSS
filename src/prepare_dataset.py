"""
Merge and preprocess NVD, OSV, and EPSS datasets into
a unified dataset for CVSS severity prediction.
"""

# NVD

# drop length columns
cols_to_drop = [c for c in df_nvd.columns if "len" in c.lower()]
df_nvd.drop(columns=cols_to_drop, inplace=True, errors='ignore')

# make a copy so original is untouched
df_nvd_clean = df_nvd.copy()

# remove rows with missing CVE, description, or score
df_nvd_clean = df_nvd_clean.dropna(subset=["cve_id", "Description", "CVSS_Score"])

# normalize CVE format
df_nvd_clean["cve_id"] = df_nvd_clean["cve_id"].str.strip()

# remove duplicate CVEs
df_nvd_clean = df_nvd_clean.drop_duplicates(subset="cve_id")

df_nvd_clean.head()

# OSV
df_osv_clean = df_osv.copy()

# clean CVE formatting
df_osv_clean["cve_id"] = df_osv_clean["cve_id"].str.strip()

# replace missing text fields with empty strings
df_osv_clean["osv_summary"] = df_osv_clean["osv_summary"].fillna("")
df_osv_clean["osv_details"] = df_osv_clean["osv_details"].fillna("")

# prefer summary over details; fallback to details
df_osv_clean["osv_text"] = df_osv_clean.apply(
    lambda x: x["osv_summary"] if len(x["osv_summary"]) > 0 else x["osv_details"],
    axis=1
)

# remove rows with no usable OSV text
df_osv_clean = df_osv_clean[df_osv_clean["osv_text"].str.len() > 5]

# keep only one row per CVE
df_osv_clean = df_osv_clean.drop_duplicates(subset="cve_id")

df_osv_clean.head()

# EPSS
df_epss_clean = df_epss.copy()

# convert snapshot to datetime so sorting works
df_epss_clean["snapshot_date"] = pd.to_datetime(df_epss_clean["snapshot_date"])

# keep latest snapshot per CVE
df_epss_latest = (
    df_epss_clean.sort_values(by=["cve_id", "snapshot_date"], ascending=[True, False])
                .drop_duplicates("cve_id")
)

# keep only needed fields
df_epss_latest = df_epss_latest[["cve_id", "epss", "percentile"]]

# remove rows without EPSS score
df_epss_latest = df_epss_latest.dropna(subset=["epss"])

# normalize CVE formatting
df_epss_latest["cve_id"] = df_epss_latest["cve_id"].str.strip()

df_epss_latest.head()

# keep only rows where CVE is present in all 3 datasets

df_nvd_final = df_nvd_clean[df_nvd_clean["cve_id"].isin(cves_all3)].copy()
df_osv_final = df_osv_clean[df_osv_clean["cve_id"].isin(cves_all3)].copy()
df_epss_final = df_epss_latest[df_epss_latest["cve_id"].isin(cves_all3)].copy()

print("Final NVD rows:", len(df_nvd_final))
print("Final OSV rows:", len(df_osv_final))
print("Final EPSS rows:", len(df_epss_final))

# merge NVD + OSV + EPSS into a single modeling dataframe

df_merged = (
    df_nvd_final
    .merge(df_osv_final[["cve_id", "osv_text"]], on="cve_id", how="inner")
    .merge(df_epss_final[["cve_id", "epss", "percentile"]], on="cve_id", how="inner")
)

print(df_merged.head())
print("Merged dataset shape:", df_merged.shape)
