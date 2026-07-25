# RAGs-for-CVSS
Low-Resource Retrieval-Augmented Transformers for CVSS Severity Prediction

This repository reproduces the dataset preparation pipeline.

The scripts download publicly available data from:

National Vulnerability Database (NVD)
Open Source Vulnerabilities (OSV)
Exploit Prediction Scoring System (EPSS)

The datasets are normalized, merged by CVE identifier, and exported as a unified CSV suitable for downstream machine-learning experiments.

This repository includes only the dataset preparation stage of the research.

It includes:

- NVD data collection and CVSS score extraction
- OSV vulnerability metadata collection
- EPSS score collection
- CVE identifier normalization
- merging of NVD, OSV, and EPSS records
- removal of records without CVSS base scores
- filtering of vulnerabilities published from 2020 onward
- export of the prepared dataset

## Repository Structure

RAGs-for-CVSS/
├── README.md
├── requirements.txt
├── LICENSE
├── .gitignore
├── src/
│   ├── fetch_nvd.py
│   ├── fetch_osv.py
│   ├── fetch_epss.py
│   └── prepare_dataset.py
└── data/
    ├── raw/
    │   ├── nvd/
    │   ├── osv/
    │   └── epss/
    └── processed/

## Author

Rimma Shilkina

## Citation

If you use this repository, please cite the accompanying paper:

**Low-Resource Retrieval-Augmented Transformers for CVSS Severity Prediction**

(The DOI and journal citation will be added after publication.)
