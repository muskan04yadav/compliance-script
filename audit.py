import boto3
import csv
import os
import json
from datetime import datetime, timezone, timedelta
from module_class import Audit
from inventory_class import Inventory
import questionary
from infra_changes_class import InfraChangeReport
from unused_resources_class import UnusedResources
from concurrent.futures import ThreadPoolExecutor, as_completed


# Generate timestamp once
timestamp = datetime.now().strftime("%m-%d-%y-%H-%M-%S")

def write_csv_row(row_data, OUTPUT_FILE):
    with open(OUTPUT_FILE, mode='a', newline='') as file:
        writer = csv.writer(file)
        writer.writerow(row_data)

def setup_csv(profile, OUTPUT_FILE, headers):
    os.makedirs(profile, exist_ok=True)
    output_path = os.path.join(profile, OUTPUT_FILE)
    if not os.path.exists(output_path):
        with open(output_path, mode='w', newline='') as file:
            writer = csv.writer(file)
            writer.writerow(headers)

def parse_tag_filters(tag_filter_input: str):
    filters = []
    # Split by comma to handle multiple tag=value pairs
    for pair in tag_filter_input.split(","):
        pair = pair.strip()  # remove spaces
        if "=" in pair:
            key, value = pair.split("=", 1)
            filters.append({
                "Name": f"tag:{key.strip()}",
                "Values": [value.strip()]
            })
    return filters

def get_profiles(csv_file):
    profiles = []
    with open(csv_file, newline='') as file:
        reader = csv.DictReader(file)
        for row in reader:
            profiles.append(row['profile_name'])
    return profiles

# ------------------- CATEGORY-WISE MODULES -------------------
MODULES_BY_SECTION = {
    "Reports": [
        "check_s3_encryption",
        "check_backup_plans",
        "check_db_encryption",
        "check_ebs_encryption",
        "check_iam_users_details",
        "check_kms_auto_rotation",
        "check_nacl_permissions",
        "check_sg_open_ports",
        "check_ssm_agent_reporting",
        "check_unused_iam_roles",
        "check_vpc_flow_logs",
        "check_ssm_secure_params",
        "check_lambda_and_rds_log_groups"
    ],
    "Inventory": [
        "list_rds_instance_details",
        "list_windows_ec2_instances",
        "list_ecs_details",
        "list_lambda_functions",
        "list_s3_details",
        "list_alb_details",
        "list_cloudfront_details"
    ],
    "Infra Changes": [
        "list_created_resources", 
        "list_network_changes"
    ],
    "Unused Resources": [
        "stopped_ec2_no_connection",
        "check_unattached_ebs",
        "alb_with_no_listeners",
        "ecs_with_no_services",
        "stopped_rds_no_connection",
        "failing_lambdas",
        "unassociated_eips",
        "list_idle_route53",
        "snapshots_not_tied_to_ami_or_volume",
        "list_unused_kms_keys"
    ]
}

# ------------------- QUESTIONARY SELECTION LOGIC -------------------
def select_profiles(profiles):
    return questionary.checkbox(
        "Select AWS profiles to run audit on:",
        choices=profiles
    ).ask()


def select_section():
    return questionary.select(
        "Select a category of modules:",
        choices=list(MODULES_BY_SECTION.keys())
    ).ask()


def select_modules_from_section(section):
    modules = MODULES_BY_SECTION[section]
    choice = questionary.select(
        "Select how you want to run the modules:",
        choices=["All", "Manually select"]
    ).ask()

    if choice == "All":
        return modules
    else:
        return questionary.checkbox(
            f"Select {section} modules to run:",
            choices=modules
        ).ask()
    

# ------------------- THREAD FUNCTION -------------------
def run_for_profile(profile, section, selected_methods,tag_filter, executor):

    session = boto3.Session(profile_name=profile)
    regions = ["us-east-1","us-east-2","us-west-1","us-west-2"]

    audit = Audit(profile, session, timestamp, regions, write_csv_row, setup_csv)
    inventory = Inventory(profile, session, timestamp, regions, write_csv_row, setup_csv)
    infraChanges = InfraChangeReport(profile, session, timestamp, regions, write_csv_row, setup_csv)
    unusedResources = UnusedResources(profile, session, timestamp, regions, write_csv_row, setup_csv)


    for method in selected_methods:
        print(f"Running: {method} for {profile}")
        try:
            if section == "Inventory":
                executor.submit(getattr(inventory, method)(tag_filter))
            elif section == "Infra Changes":
                if method in ["list_created_resources", "list_network_changes"]:
                    executor.submit(getattr(infraChanges, method)("08/10/2024"))
                else:
                    executor.submit(getattr(infraChanges, method)(tag_filter))
            elif section == "Unused Resources":
                if method in ["stopped_ec2_no_connection", "stopped_rds_no_connection"]:
                    executor.submit(getattr(unusedResources, method), days=60)
                    #getattr(unusedResources, method)(days=60)
                else:
                    executor.submit(getattr(unusedResources, method)())
            else:
                executor.submit(getattr(audit, method)(tag_filter))
        except Exception as e:
            print(f"Error running {method} for {profile}: {e}")


# ------------------- MAIN EXECUTION -------------------
def main():

    # Always find profile.csv in the same folder as this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    profile_csv = os.path.join(script_dir, "profile.csv")

    profiles = get_profiles(profile_csv)


    selected_profiles = select_profiles(profiles)
    if not selected_profiles:
        print("No profiles selected. Exiting.")
        return

    section = select_section()
    selected_methods = select_modules_from_section(section)
    if not selected_methods:
        print("No modules selected. Exiting.")
        return
  
    thread_count = 5

    #print(f"\n Running {section} modules on {len(selected_profiles)} profiles with {thread_count} threads...\n")

            # Ask for tag filter once
    tag_filter_input = questionary.text(
        "Enter tag filter (Key=Value) or leave blank for no filter:",
        default=""
    ).ask()

    tag_filter = parse_tag_filters(tag_filter_input)
    print("Output = " , tag_filter)

    #Pass tag_filter to run_for_profile
    # with ThreadPoolExecutor(max_workers=thread_count) as executor:
    #     futures = [
    #         executor.submit(run_for_profile, profile, section, selected_methods, tag_filter)
    #         for profile in selected_profiles
    #     ]

    #  Multi-threaded execution
    with ThreadPoolExecutor(max_workers=thread_count) as executor:
        futures = [
            executor.submit(run_for_profile, profile, section, selected_methods, tag_filter, executor)
            for profile in selected_profiles
        ]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                print(f"Thread error: {e}")

    print("\n All selected audits completed.")


if __name__ == "__main__":
     main()
