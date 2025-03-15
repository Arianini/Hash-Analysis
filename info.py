import requests
import pandas as pd
import time
import json

# Your VirusTotal API key
API_KEY = ''

def get_file_info(file_hash):
    headers = {'x-apikey': API_KEY}
    
    # Step 1: Use the search endpoint to confirm the file exists
    search_url = f"https://www.virustotal.com/api/v3/search?query={file_hash}"
    search_response = requests.get(search_url, headers=headers)
    
    # Save the raw search response for inspection
    search_json_filename = f"raw_search_{file_hash}.json"
    with open(search_json_filename, "w", encoding="utf-8") as f:
        f.write(search_response.text)
    
    # If the search endpoint returns data, proceed to call the file details endpoint
    if search_response.status_code == 200:
        search_data = search_response.json()
        if search_data.get("data"):
            # Step 2: Call the file details endpoint for detailed attributes (including signature_date)
            details_url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            details_response = requests.get(details_url, headers=headers)
            
            # Save the raw details response for inspection
            details_json_filename = f"raw_details_{file_hash}.json"
            with open(details_json_filename, "w", encoding="utf-8") as f:
                f.write(details_response.text)
            
            if details_response.status_code == 200:
                details_data = details_response.json()
                attributes = details_data.get("data", {}).get("attributes", {})
            else:
                print(f"Error retrieving file details for hash {file_hash}: {details_response.status_code}")
                attributes = {}
        else:
            print(f"No search data found for hash {file_hash}")
            attributes = {}
    else:
        print(f"Search endpoint error for hash {file_hash}: {search_response.status_code}")
        attributes = {}
    
    # Build a default dictionary with NA for all fields in case attributes are missing
    default_info = {
        'Hash': file_hash,
        'Detection Count': 'NA',
        'Hash-MD5': 'NA',
        'Hash-SHA1': 'NA',
        'Hash-SHA256': 'NA',
        'File Type': 'NA',
        'Magic': 'NA',
        'Creation Time': 'NA',
        'Signature Date': 'NA',
        'First Seen In The Wild': 'NA',
        'First Submission': 'NA',
        'Last Submission': 'NA',
        'Last Analysis': 'NA',
        'Name1': 'NA',
        'Name2': 'NA',
        'Name3': 'NA',
        'Verdict': 'NA'
    }
    
    if attributes:
        # Extract detection count and vendor names from the last_analysis_results
        detection_count = attributes.get('last_analysis_stats', {}).get('malicious', 0)
        analysis_results = attributes.get('last_analysis_results', {})
        vendor_names = list(analysis_results.keys()) if analysis_results else []
        name1 = vendor_names[0] if len(vendor_names) > 0 else 'NA'
        name2 = vendor_names[1] if len(vendor_names) > 1 else 'NA'
        name3 = vendor_names[2] if len(vendor_names) > 2 else 'NA'
        
        file_info = {
            'Hash': file_hash,
            'Detection Count': detection_count,
            'Hash-MD5': attributes.get('md5', 'NA'),
            'Hash-SHA1': attributes.get('sha1', 'NA'),
            'Hash-SHA256': attributes.get('sha256', 'NA'),
            'File Type': attributes.get('type_description', 'NA'),
            'Magic': attributes.get('magic', 'NA'),
            'Creation Time': attributes.get('creation_date', 'NA'),
            'Signature Date': attributes.get('signature_date', 'NA'),
            'First Seen In The Wild': attributes.get('first_submission_date', 'NA'),
            'First Submission': attributes.get('first_submission_date', 'NA'),
            'Last Submission': attributes.get('last_submission_date', 'NA'),
            'Last Analysis': attributes.get('last_analysis_date', 'NA'),
            'Name1': name1,
            'Name2': name2,
            'Name3': name3,
        }
        file_info['Verdict'] = 'Malicious' if detection_count > 0 else 'Benign'
        return file_info
    else:
        return default_info

def get_hashes_from_file(filename='hashes.xlsx'):
    # Read the Excel file and extract the 'Hash' column
    df = pd.read_excel(filename)
    if 'Hash' in df.columns:
        return df['Hash'].tolist()
    else:
        raise ValueError("Expected a column named 'Hash' in the Excel file.")

def main():
    # Read file hashes from the provided Excel file
    file_hashes = get_hashes_from_file('hashes.xlsx')
    
    # Limit to first 5 hashes for testing purposes
    file_hashes = file_hashes[:500]
    
    results = []
    for index, h in enumerate(file_hashes, start=1):
        print(f"Processing hash {index}/{len(file_hashes)}: {h}")
        info = get_file_info(h)
        results.append(info)
        print("Sleeping for 15 seconds to avoid rate limits...")
        time.sleep(15)
    
    # Create a pandas DataFrame from the results
    df = pd.DataFrame(results)
    
    # Display the results in the CLI
    print(df)
    
    # Export the results to CSV
    df.to_csv("file_info.csv", index=False)

if __name__ == '__main__':
    main()
