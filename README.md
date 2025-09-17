**AWS Compliance Reporting Tool**

This repository contains a Python-based compliance reporting tool that audits multiple AWS accounts for security and compliance best practices. The tool connects to each AWS account using AWS CLI profiles, runs a set of predefined compliance checks (modules), and generates CSV reports.

**The reports include:**

Per-account reports → Compliance results for each AWS account, broken down by region

📂 Project Structure

├── audit.py         # Main script to run the compliance checks

├── profiles.csv     # Input file with AWS profile names (matches ~/.aws/config)

├── output/          # Folder where compliance reports will be generated

└── README.md        # Project documentation

⚙️ Prerequisites

AWS CLI v2 installed and configured on your system
One or more AWS profiles defined in `~/.aws/config`
Python 3.8+ installed
📝 Input File (profiles.csv) - The script expects a CSV file with profile names that correspond to AWS CLI profiles already configured on your machine.

Example profiles.csv

profile

dev-profile

prod-profile

⚠️ **Important:** The profile names in profiles.csv must match exactly with the profiles in your AWS CLI configuration.

Check available profiles with: `aws configure list-profiles`

🚀 Usage

To run the compliance audit, execute: `python audit.py`

By default: - Reads profiles from profiles.csv - Runs compliance checks for each profile - Generates reports inside the output/ directory

📌 Module Selection

The tool supports modular compliance checks. Users can choose to run:

✅ Select All → Run all available compliance modules

🎯 Multi-select specific modules → Run only chosen modules (e.g., S3, IAM, Security Groups)

This allows flexibility depending on whether you need a full audit or just specific service checks.

🕒 Timestamping

Each generated report includes timestamps for traceability: File name timestamp → Appended in the format MM-DD-YY-HH-MM-SS

📌 Notes

Ensure AWS CLI profiles listed in profiles.csv are correctly configured and have read-only permissions in the target accounts.
Reports are structured by profile name with timestamps for traceability.
New compliance checks can be added by creating new functions inside audit.py and registering them in the module selection logic.
