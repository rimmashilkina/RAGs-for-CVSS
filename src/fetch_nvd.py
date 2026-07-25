"""
Fetch vulnerability records from the National Vulnerability Database (NVD).

This script downloads NVD vulnerability data and extracts
the fields required for the CVSS severity prediction dataset.
"""
# download NVD files starting from 2020
def download_nvd_data(years, download_dir='data/raw/nvd'):
    """
    Downloads NVD CVE data for the specified years.

    Args:
        years (list): A list of years (e.g., [2020, 2021]).
        download_dir (str): The directory to save the files.
    """
    if not os.path.exists(download_dir):
        os.makedirs(download_dir)

    base_url = "https://nvd.nist.gov/feeds/json/cve/2.0/"

    for year in years:
        file_name = f"nvdcve-2.0-{year}.json.gz"
        url = base_url + file_name
        save_path = os.path.join(download_dir, file_name)

        print(f"Downloading {url}...")
        response = requests.get(url, stream=True)

        if response.status_code == 200:
            with open(save_path, 'wb') as f:
                f.write(response.content)
            print(f"Downloaded and saved to {save_path}")
        else:
            print(f"Failed to download {file_name}. Status code: {response.status_code}")

# process NVD files
def extract_cve_data(file_path):
    """
    Extracts CVE data from a .json.gz NVD file.

    Args:
        file_path (str): Path to the .json.gz file.

    Returns:
        List of dictionaries containing CVE data.
    """
    with gzip.open(file_path, 'rt', encoding='utf-8') as f:
        data = json.load(f)

    cve_items = data.get('vulnerabilities', [])
    extracted = []

    for item in cve_items:
        cve_data = item.get('cve', {})
        cve_id = cve_data.get('id', 'N/A')
        published = cve_data.get('published', '')
        year = published[:4] if published else 'N/A'

        # Get English description
        descriptions = cve_data.get('descriptions', [])
        description = next((d['value'] for d in descriptions if d['lang'] == 'en'), '')


        # Get CVSS score (try v4.0, v3.1, v3.0, then v2)
        metrics = cve_data.get('metrics', {})
        cvss_score = None
        cvss_version = None

        if 'cvssMetricV40' in metrics:
            cvss_score = metrics['cvssMetricV40'][0]['cvssData']['baseScore']
            cvss_version = '4.0'
        elif 'cvssMetricV31' in metrics:
            cvss_score = metrics['cvssMetricV31'][0]['cvssData']['baseScore']
            cvss_version = '3.1'
        elif 'cvssMetricV30' in metrics:
            cvss_score = metrics['cvssMetricV30'][0]['cvssData']['baseScore']
            cvss_version = '3.0'
        elif 'cvssMetricV2' in metrics:
            cvss_score = metrics['cvssMetricV2'][0]['cvssData']['baseScore']
            cvss_version = '2.0'

        extracted.append({
            'CVE_ID': cve_id,
            'Year': year,
            'Published_Date': published,
            'Description': description,
            'CVSS_Score': cvss_score
        })

    return extracted


def process_all_files(data_dir='nvd_data'):
    """
    Processes all .json.gz files in the directory and extracts CVE data.

    Args:
        data_dir (str): Directory containing .json.gz files.

    Returns:
        Pandas DataFrame of extracted CVE data.
    """
    all_data = []
    for file in os.listdir(data_dir):
        if file.endswith('.json.gz'):
            file_path = os.path.join(data_dir, file)
            print(f"Processing {file_path}...")
            extracted = extract_cve_data(file_path)
            all_data.extend(extracted)

    df = pd.DataFrame(all_data)
    return df


if __name__ == "__main__":
    years_to_download = range(2020, 2026)

    download_nvd_data(
        years=list(years_to_download),
        download_dir="data/raw/nvd",
    )

    df = process_all_files("data/raw/nvd")
    df_nvd = df[["CVE_ID", "Description", "CVSS_Score"]].copy()

    df_nvd.to_csv("data/processed/nvd.csv", index=False)

    print(df_nvd.head())
    print("NVD rows:", len(df_nvd))
  
