import os
import requests
import zipfile

def get_rules(github_url, zip_filename, extract_to):
    # Download file from GitHub
    response = requests.get(github_url)
    if response.status_code == 200:
        # Save the downloaded zip file
        with open(zip_filename, "wb") as file:
            file.write(response.content)
        
        # Extract zip file into the destination directory
        with zipfile.ZipFile(zip_filename, 'r') as zip_ref:
            zip_ref.extractall(extract_to)

        # Delete the zip file after extraction
        os.remove(zip_filename)
        print("All Yara Rules have been updated successfully")
    else:
        print(f"Failed to update Yara Rules. Status code: {response.status_code}")

if __name__ == "__main__":
    # URL of the zip file on GitHub
    rule_url = "https://github.com/XiAnzheng-ID/RansomPyShield-Antiransomware/raw/main/Rule.zip"
    
    # Name for the downloaded zip file
    zip_rule = "Rule.zip"
    
    # Set the destination folder inside your home directory
    extract_to = os.path.join(os.path.expanduser('~'), "RansomPyShield", "Rules")

    # Create the destination directory if it doesn't exist
    if not os.path.exists(extract_to):
        os.makedirs(extract_to)

    # Download and extract the zip file
    get_rules(rule_url, zip_rule, extract_to)
