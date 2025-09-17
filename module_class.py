import boto3
import json
from datetime import datetime,timezone
import csv
import botocore.exceptions

class Audit:
    def __init__(self, profile, session, timestamp, regions, write_csv_row, setup_csv):
        self.profile = profile
        self.session = session
        self.regions = regions
        self.write_csv_row = write_csv_row
        self.setup_csv = setup_csv
        self.timezone = timezone.utc
        self.timestamp = timestamp

        

    def read_csv(self,OUTPUT_FILE):
        rows = []
        with open(OUTPUT_FILE,'r',newline='') as file:
            reader = csv.reader(file)
            for row in reader:
                rows.append(row)
        return rows
    
    def _resource_matches_tag_filter(self, resource_tags, tag_filters):
        """
        Checks if a resource's tags match the given tag filters.
        resource_tags can be a list of dicts or a dict.
        tag_filters should be a list of filters in AWS format:
            [{"Name": "tag:Key", "Values": ["value1", "value2"]}, ...]
        """

        if not tag_filters:
            return True  # No filter applied

        # Normalize tags into dict with lowercase keys & values
        if isinstance(resource_tags, list):
            tags_dict = {t["Key"].lower(): str(t["Value"]).lower() for t in resource_tags}
        elif isinstance(resource_tags, dict):
            tags_dict = {k.lower(): str(v).lower() for k, v in resource_tags.items()}
        else:
            return False

        # Check each filter
        for f in tag_filters:
            if not f["Name"].startswith("tag:"):
                continue  # skip non-tag filters

            filter_key = f["Name"].split("tag:")[1].lower()
            filter_values = [v.lower() for v in f.get("Values", [])]

            # If tag doesn't exist or value mismatch → fail
            if filter_key not in tags_dict or tags_dict[filter_key] not in filter_values:
                return False

        return True  # All filters matched


    def check_s3_encryption(self, tag_filter=None):  # working fine with tag filter

        OUTPUT_FILE = f"{self.profile}/BucketSettings_{self.timestamp}.csv"
        headers = ['Account', 'Region', 'Bucket Name', 'Creation Date', 'Default Encryption', 'Encryption Type', 'Visibility', 'Tags', 'Generated On']
        self.setup_csv(self.profile,f"BucketSettings_{self.timestamp}.csv", headers)
        s3 = self.session.client('s3')
        try:
            buckets = s3.list_buckets()['Buckets']
            for bucket in buckets:
                bucket_name = bucket['Name']
                creation_date = bucket['CreationDate'].strftime("%Y-%m-%d %H:%M:%S")
                encryption_status = "No"
                encryption_type = "None"
                tags = "None"
                visibility = "Private"
                tag_dict = {}
                # --- Bucket Encryption Check ---
                try:
                    enc = s3.get_bucket_encryption(Bucket=bucket_name)
                    rules = enc['ServerSideEncryptionConfiguration']['Rules']
                    algo = rules[0]['ApplyServerSideEncryptionByDefault']['SSEAlgorithm']
                    encryption_status = "Yes"
                    encryption_type = algo
                except s3.exceptions.ClientError as e:
                    error_code = e.response['Error']['Code']
                    if error_code == 'ServerSideEncryptionConfigurationNotFoundError':
                        encryption_status = "No"
                        encryption_type = "None"
                    else:
                        encryption_status = f"{bucket_name}: Error - {error_code}"
                except Exception as e:
                    encryption_status = f"{bucket_name}: Unexpected error - {str(e)}"

                # Public access check
                try:
                    acl = s3.get_bucket_acl(Bucket=bucket_name)
                    for grant in acl["Grants"]:
                        uri = grant.get("Grantee", {}).get("URI", "")
                        if "AllUsers" in uri or "AuthenticatedUsers" in uri:
                            visibility = "Public Accessible via ACL"
                            break
                except:
                    pass
                try:
                    policy_status = s3.get_bucket_policy_status(Bucket=bucket_name)
                    if policy_status["PolicyStatus"]["IsPublic"]:
                        visibility = "Public Accessible via policy"
                except:
                    pass

                # --- Get tags ---
                try:
                    tagging = s3.get_bucket_tagging(Bucket=bucket_name)
                    tag_set = tagging.get("TagSet", [])
                    tag_dict = {tag["Key"]: tag["Value"] for tag in tag_set}
                    tags = json.dumps(tag_dict)  # for writing to CSV
                except s3.exceptions.ClientError:
                    pass  # Bucket may not have tags

                # --- Apply tag filter ---
                if tag_filter and not self._resource_matches_tag_filter(tag_dict, tag_filter):
                    continue

                # Use region = global (S3 bucket location is separate)
                try:
                    region = s3.get_bucket_location(Bucket=bucket_name)['LocationConstraint']
                    region = region if region else "us-east-1"
                except:
                    self.region = "Unknown"
                row_data = [self.profile,region , bucket_name, creation_date, encryption_status, encryption_type, visibility, tags, self.timestamp]
                self.write_csv_row(row_data, OUTPUT_FILE)

        except Exception as e:
            pass
    
    def check_kms_auto_rotation(self, tag_filter=None): #working fine with tag filter
        OUTPUT_FILE = f"{self.profile}/KmsRotationcheck_{self.timestamp}.csv"
        headers = ['Account', 'Region', 'Key ID', 'ARN', 'Alias Name', 'CreationDate','Key Type', 'Rotation', 'RotationDate', 'Tags', 'Generated On']
        self.setup_csv(self.profile, f"KmsRotationcheck_{self.timestamp}.csv", headers)

        for region in self.regions:
            try:
                kms = self.session.client('kms', region_name=region)
                keys = kms.list_keys()['Keys']

                for key in keys:
                    key_id = key['KeyId']
                    try:
                        key_metadata = kms.describe_key(KeyId=key_id)['KeyMetadata']
                        key_manager = key_metadata.get('KeyManager', 'Unknown')
                        arn = key_metadata['Arn']
                        creation_date = key_metadata['CreationDate'].strftime('%Y-%m-%d %H:%M:%S')
                        account = self.profile
                        rotation_date = "-"
                        rotation = "-"
                        tags = []
                        tag_dict = {}  

                        if key_metadata.get('KeyManager') == 'CUSTOMER':
                            rotation_status = kms.get_key_rotation_status(KeyId=key_id)
                            rotation = 'Yes' if rotation_status['KeyRotationEnabled'] else 'No'

                            if rotation == 'Yes':
                                # No direct RotationDate in boto3; use CreationDate or leave blank
                                rotation_date = creation_date  # As placeholder
                            else:
                                rotation_date = "-"

                            tag_list = kms.list_resource_tags(KeyId=key_id).get('Tags', [])
                            tags = [f"{tag['TagKey']}={tag['TagValue']}" for tag in tag_list]

                            tag_dict = {t['TagKey']: t['TagValue'] for t in tag_list}
                     # For AWS Managed Keys – cannot enable/disable rotation
                        elif key_manager == 'AWS':
                            rotation = "Managed by AWS"
                            tags = []  # AWS-managed keys don’t support tagging
                            tag_dict = {}

                                         # Apply tag filter
                        if tag_filter and not self._resource_matches_tag_filter(tag_dict, tag_filter):
                            continue  # Skip keys not matching the filter

                        key_aliases = kms.list_aliases(KeyId=key_id).get('Aliases', [])
                        alias_names = [a['AliasName'] for a in key_aliases if 'AliasName' in a]
                        alias_str = ", ".join(alias_names) if alias_names else "None"
                        row_data = [account, region, key_id, arn, alias_str, creation_date, key_manager,rotation, rotation_date, tags, self.timestamp]
                        self.write_csv_row(row_data, OUTPUT_FILE)

                    except kms.exceptions.NotFoundException:
                        continue
                    except Exception as e:
                        pass
            except Exception as e:
                pass

    def check_iam_users_details(self, tag_filter = None): #working fine with tag filter
        OUTPUT_FILE = f"{self.profile}/IamUsersDetails_{self.timestamp}.csv"
        headers = ["Account", "User Name", "User ARN", "Creation Date", "Console Last Login", "Password Enabled", "Access Key Status", "Last Used Access Key", "Group Membership", "MFA Status", "Tags", "Generated On"]
        self.setup_csv(self.profile, f"IamUsersDetails_{self.timestamp}.csv", headers)
        iam = self.session.client('iam')
        users = iam.list_users()['Users']
        for user in users:
                    username = user['UserName']
                    user_arn = user['Arn']
                    creation_date = user['CreateDate']

                    # MFA Devices
                    mfa_devices = iam.list_mfa_devices(UserName=username)['MFADevices']
                    mfa_enabled = 'Yes' if mfa_devices else 'No'

                    # Login profile (Console access)
                    try:
                        iam.get_login_profile(UserName=username)
                        password_enabled = 'Yes'
                    except iam.exceptions.NoSuchEntityException:
                        password_enabled = 'No'

                    # Access Keys
                    access_keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']
                    access_key_status = []
                    last_used_access_key = 'Never Used'
                    for key in access_keys:
                        key_id = key['AccessKeyId']
                        status = key['Status']  # Active / Inactive
                        access_key_status.append(f"{key_id} ({status})")

                        # Last Used
                        last_used = iam.get_access_key_last_used(AccessKeyId=key_id)
                        last_used_date = last_used.get('AccessKeyLastUsed', {}).get('LastUsedDate')
                        if last_used_date:
                            last_used_access_key = f"{key_id} on {last_used_date}"

                    access_key_status_str = ", ".join(access_key_status) if access_key_status else 'None'

                    # Group Membership
                    groups = iam.list_groups_for_user(UserName=username)['Groups']
                    group_names = [g['GroupName'] for g in groups]
                    group_membership = ", ".join(group_names) if group_names else 'None'

                    # Last activity: Use password last used if exists
                    password_last_used = user.get('PasswordLastUsed')
                    last_activity = f"Console: {password_last_used}" if password_last_used else "No Console Access"

                    #checking tags
                    tag_list = iam.list_user_tags(UserName=username).get("Tags", [])
                    tags = [f"{tag['TagKey']}={tag['TagValue']}" for tag in tag_list]

                    
                        # Apply tag filter
                    if tag_filter and not self._resource_matches_tag_filter(tags, tag_filter):
                        continue  # Skip users not matching the filter

                    row_data = [ self.profile, username, user_arn, creation_date,last_activity, password_enabled,access_key_status_str, last_used_access_key, group_membership,mfa_enabled, tags, self.timestamp]
                    self.write_csv_row(row_data, OUTPUT_FILE )

    def check_unused_iam_roles(self, tag_filter=None): # not sure with tags and without need to check further

        OUTPUT_FILE = f"{self.profile}/UnusedIamRoles_{self.timestamp}.csv"
        headers = ["Account", "Role Name", "Role ARN", "Creation Date", "Last Used Date", "Trusted Entities", "Attached Policies","Inline Policies", "Is Service Role", "Tags", "Generated On"]
        self.setup_csv(self.profile, f"UnusedIamRoles_{self.timestamp}.csv", headers)
        iam = self.session.client('iam')

        try:
            roles = iam.list_roles()['Roles']
            threshold = datetime.now(self.timezone.utc) - self.timedelta(days=90)

            for role in roles:
                role_name = role['RoleName']
                role_arn = role['Arn']
                created_date = role['CreateDate']
                role_path = role['Path']
                trust_policy = iam.get_role(RoleName=role_name)['Role']['AssumeRolePolicyDocument']

                trusted_entities = []
                for stmt in trust_policy.get('Statement', []):
                    principal = stmt.get('Principal', {})
                    if isinstance(principal, dict):
                        for k, v in principal.items():
                            if isinstance(v, list):
                                trusted_entities.extend(v)
                            else:
                                trusted_entities.append(v)
                    elif isinstance(principal, str):
                        trusted_entities.append(principal)

                trusted_entities_str = "; ".join(trusted_entities) if trusted_entities else "None"

                # Last used
                last_used_info = role.get('RoleLastUsed', {})
                last_used_date = last_used_info.get('LastUsedDate')
                last_used_str = last_used_date.strftime('%Y-%m-%d') if last_used_date else "Never Used"

                # Policies
                attached_policies = iam.list_attached_role_policies(RoleName=role_name).get("AttachedPolicies", [])
                inline_policies = iam.list_role_policies(RoleName=role_name).get("PolicyNames", [])

                attached_names = "; ".join([p['PolicyName'] for p in attached_policies]) if attached_policies else "None"
                inline_names = "; ".join(inline_policies) if inline_policies else "None"

                # Is Service Role?
                is_service_role = "Yes" if role_path.startswith('/service-role/') else "No"

                # Skip AWS created service roles
                if role_path.startswith('/aws-service-role/') or role_name.startswith('AWSServiceRoleFor') or role_name.startswith('AWS-QuickSetup'):
                    continue

                 # Tags
                tag_list = iam.list_role_tags(RoleName=role_name).get("Tags", [])
                tags_dict = {t['Key']: t['Value'] for t in tag_list}
                tags_str = json.dumps(tags_dict) if tags_dict else "No tags"

                # Apply tag filters
                if tag_filter and not self._resource_matches_tag_filter(tag_list, tag_filter):
                    continue  # Skip roles not matching the filter


                # If unused or older than threshold
                if not last_used_date or last_used_date < threshold:

                    row_data = [self.profile,role_name,role_arn,created_date,last_used_str,trusted_entities_str,attached_names,inline_names,is_service_role,tags_str, self.timestamp  ]
                    self.write_csv_row(row_data, OUTPUT_FILE)
        except Exception as e:
            pass

    def check_db_encryption(self,tag_filter = None):   #working fine with tag filter
        OUTPUT_FILE = f"{self.profile}/EncryptionDB_{self.timestamp}.csv"
        headers = ["Account", "Region", "DB Instance Identifier", "DB Engine", "Storage Encrypted", "KMS Key ID", "DB Cluster", "Instance Class", "Backup Encrypted", "Tags", "Generated On"]
        self.setup_csv(self.profile,f"EncryptionDB_{self.timestamp}.csv", headers)
        for region in self.regions:
            try:
                rds = self.session.client('rds', region_name=region)
                dbs = rds.describe_db_instances()['DBInstances']
                for db in dbs:
                    db_id = db['DBInstanceIdentifier']
                    engine = db['Engine']
                    storage_encrypted = db['StorageEncrypted']
                    kms_key_id = db.get('KmsKeyId', 'None')
                    db_cluster = db.get('DBClusterIdentifier', 'None')
                    instance_class = db['DBInstanceClass']
                    backup_encrypted = db.get('StorageEncrypted', 'N/A')  # Backup encryption shares the storage encryption flag in RDS

                    #Get tags
                    db_arn = db.get('DBInstanceArn')
                    tags_list = []
                    tags_dict = {}
                    try:
                        if db_arn:
                            tags_list = rds.list_tags_for_resource(ResourceName=db_arn).get("TagList", [])
                            tags_dict = {t['Key']: t['Value'] for t in tags_list}
                    except Exception:
                        pass
                    # Apply tag filter
                    if tag_filter and not self._resource_matches_tag_filter(tags_list, tag_filter):
                        continue  # Skip DBs not matching the filter

                    tags_str = json.dumps(tags_dict) if tags_dict else "No tags"


                    row_data = [self.profile, region, db_id, engine, storage_encrypted, kms_key_id, db_cluster, instance_class, backup_encrypted,tags_str, self.timestamp]

                    self.write_csv_row(row_data, OUTPUT_FILE)


            except Exception as e:
                pass

    def check_ssm_secure_params(self,tag_filter = None): # working fine with tag filter
        OUTPUT_FILE = f"{self.profile}/SsmParams_{self.timestamp}.csv"
        headers = ["Account", "Region", "Parameter Name", "Type", "KMS Key ID", "Last Modified Date", "Description", "Tier", "Tags", "Generated On"]
        self.setup_csv(self.profile,f"SsmParams_{self.timestamp}.csv", headers)

        for region in self.regions:
            try:
                ssm = self.session.client('ssm', region_name=region)
                paginator = ssm.get_paginator('describe_parameters')
                for page in paginator.paginate():
                    for param in page['Parameters']:
                        name = param['Name']
                        param_type = param['Type']
                        tier = param.get('Tier', 'Standard')
                        description = param.get('Description', 'N/A')
                        last_modified = param.get('LastModifiedDate')
                        last_modified_str = last_modified.strftime('%Y-%m-%d') if last_modified else 'N/A'

                        # Get full details for KMS Key ID
                        details = ssm.get_parameter(Name=name, WithDecryption=False)
                        kms_key_id = details.get('Parameter', {}).get('KeyId', 'N/A')

                        # Get tags
                        tag_response = ssm.list_tags_for_resource(ResourceType='Parameter', ResourceId=name)
                        tag_list = tag_response.get('TagList', [])
                        tags_dict = {t['Key']: t['Value'] for t in tag_list}
                        tag_str = json.dumps(tags_dict) if tags_dict else "None"

                        # Apply tag filter
                        if tag_filter and not self._resource_matches_tag_filter(tags_dict, tag_filter):
                            continue  # Skip parameters not matching the filter
                        row_data = [self.profile, region, name, param_type, kms_key_id, last_modified_str, description, tier, tag_str, self.timestamp]

                        self.write_csv_row(row_data, OUTPUT_FILE )
            except Exception as e:
                pass

    def check_sg_open_ports(self, tag_filter = None): # working with tag filter
        OUTPUT_FILE = f"{self.profile}/OpenPortSG_{self.timestamp}.csv"
        headers = ["Account","Region","Security Group ID","Security Group Name","VPC ID","Inbound Rule (Port / Protocol / Source)","Description","Is Publicly Accessible?","Attached Resource","Tags","Generated On"]

        self.setup_csv(self.profile,f"OpenPortSG_{self.timestamp}.csv", headers)
    
        for region in self.regions:
            try:
                ec2 = self.session.client('ec2', region_name=region)
                sgs = ec2.describe_security_groups()['SecurityGroups']
                eni_data = ec2.describe_network_interfaces()['NetworkInterfaces']

                sg_to_eni = {}
                for eni in eni_data:
                    for group in eni.get('Groups', []):
                        sg_id = group['GroupId']
                        if sg_id not in sg_to_eni:
                            sg_to_eni[sg_id] = []
                        sg_to_eni[sg_id].append(eni['NetworkInterfaceId'])

                for sg in sgs:
                    sg_id = sg['GroupId']
                    sg_name = sg.get('GroupName', '')
                    vpc_id = sg.get('VpcId', '')
                    description = sg.get('Description', '')
                    attached_resources = ','.join(sg_to_eni.get(sg_id, ['None']))

                    # --- Fetch tags for this SG ---
                    tag_response = ec2.describe_tags(Filters=[{"Name": "resource-id", "Values": [sg_id]}])
                    tag_list = tag_response.get('Tags', [])
                    tags_dict = {t['Key']: t['Value'] for t in tag_list}
                    tag_str = json.dumps(tags_dict) if tags_dict else "None"

                    # --- Apply tag filter ---
                    if tag_filter and not self._resource_matches_tag_filter(tags_dict, tag_filter):
                        continue  # Skip SGs not matching the filter


                    for rule in sg.get('IpPermissions', []):
                        protocol = rule.get('IpProtocol', 'All')
                        from_port = rule.get('FromPort', 'All')
                        to_port = rule.get('ToPort', 'All')
                        port_range = f"{from_port} - {to_port}" if from_port != to_port else str(from_port)

                        for ip in rule.get('IpRanges', []):
                            cidr = ip.get('CidrIp', '')
                            is_public = 'Yes' if cidr == '0.0.0.0/0' else 'No'
                            if is_public == 'Yes':
                                rule_str = f"{port_range} / {protocol} / {cidr}"
                                row_data = [self.profile, region, sg_id, sg_name,vpc_id, rule_str,description, is_public,attached_resources,tag_str, self.timestamp]
                                self.write_csv_row(row_data, OUTPUT_FILE )

                        for ip in rule.get('Ipv6Ranges', []):
                            cidr = ip.get('CidrIpv6', '')
                            is_public = 'Yes' if cidr == '::/0' else 'No'
                            if is_public == 'Yes':
                                rule_str = f"{port_range} / {protocol} / {cidr}"
                                row_data = [self.profile, region, sg_id, sg_name,vpc_id, rule_str,description, is_public,attached_resources, self.timestamp]
                                self.write_csv_row(row_data, OUTPUT_FILE )
            except Exception as e:
                pass

    def check_backup_plans(self, tag_filter=None):
        OUTPUT_FILE = f"{self.profile}/BackupPlans_{self.timestamp}.csv"
        headers = ["Account", "Region", "Backup Plan ID", "Backup Plan Name", "Version ID", "Creation Date", "Creator Request ID", "Tags", "Generated On"]
        self.setup_csv(self.profile, f"BackupPlans_{self.timestamp}.csv", headers)

        for region in self.regions:
            try:
                backup = self.session.client('backup', region_name=region)
                paginator = backup.get_paginator('list_backup_plans')
                for page in paginator.paginate():
                    for plan in page['BackupPlansList']:
                        plan_id = plan['BackupPlanId']
                        plan_name = plan.get('BackupPlanName', 'N/A')
                        version_id = plan.get('VersionId', 'N/A')
                        creation_date = plan.get('CreationDate', 'N/A')
                        creator_request_id = plan.get('CreatorRequestId', 'N/A')

                        # Get tags for backup plan
                        tag_response = backup.list_tags(ResourceArn=plan['BackupPlanArn'])
                        tag_list = tag_response.get('Tags', {})
                        tags_dict = tag_list if isinstance(tag_list, dict) else {}
                        tag_str = json.dumps(tags_dict) if tags_dict else "None"

                        # Apply tag filter
                        if tag_filter and not self._resource_matches_tag_filter(tags_dict, tag_filter):
                            continue  # Skip plans not matching filter

                        row_data = [
                            self.profile, region, plan_id, plan_name,
                            version_id, creation_date, creator_request_id,
                            tag_str, self.timestamp
                        ]
                        self.write_csv_row(row_data, OUTPUT_FILE)
            except Exception as e:
                pass

    def check_nacl_permissions(self, tag_filter = None): # Don't need Tag filters 
        OUTPUT_FILE = f"{self.profile}/NaclPermissions_{self.timestamp}.csv"
        headers = ["Account", "Region", "NACL ID", "VPC ID", "Rule Number", "Direction", "Protocol", "Port Range", "CIDR Block", "Allow/Deny", "Is Public Rule?", "Tags", "Generated On"]
        self.setup_csv(self.profile,f"NaclPermissions_{self.timestamp}.csv", headers)

        for region in self.regions:
            try:
                ec2 = self.session.client('ec2', region_name=region)
                nacls = ec2.describe_network_acls()["NetworkAcls"]

                for nacl in nacls:
                    nacl_id = nacl["NetworkAclId"]
                    vpc_id = nacl.get("VpcId", "")

                    # Collect tags
                    tags_dict = {t["Key"]: t["Value"] for t in nacl.get("Tags", [])}
                    tags_str = "; ".join([f"{k}={v}" for k, v in tags_dict.items()]) if tags_dict else ""
                    # Default: assume match
                    match = True
                    # Apply tag filter if provided
                    if tag_filter:
                        match = all(str(tags_dict.get(k, "")).strip() == str(v).strip()for k, v in tag_filter.items())

                    if not match:
                        print(f"Skipping {nacl_id} in {region} due to tag mismatch. Found tags: {tags_dict}")
                        continue  # skip if filter doesn’t match

                    for entry in nacl["Entries"]:
                        rule_number = entry["RuleNumber"]
                        protocol = entry["Protocol"]
                        direction = "Egress" if entry["Egress"] else "Ingress"
                        rule_action = entry["RuleAction"]

                        # Port range handling
                        port_range = "All"
                        if "PortRange" in entry:
                            from_port = entry["PortRange"].get("From")
                            to_port = entry["PortRange"].get("To")
                            if from_port == to_port:
                                port_range = str(from_port)
                            else:
                                port_range = f"{from_port}-{to_port}"

                        # CIDR block handling
                        cidr_block = entry.get("CidrBlock") or entry.get("Ipv6CidrBlock", "")
                        is_public = "Yes" if cidr_block in ["0.0.0.0/0", "::/0"] else "No"
                        row_data = [self.profile,region,nacl_id,vpc_id, rule_number,direction,protocol,port_range,cidr_block,rule_action,is_public,tags_str,self.timestamp]
                        # Write row
                        self.write_csv_row(row_data, OUTPUT_FILE )
            except Exception as e:
                pass

    def check_ssm_agent_reporting(self, tag_filter=None):  # now works with EC2-style filters
        OUTPUT_FILE = f"{self.profile}/SsmAgentReporting_{self.timestamp}.csv"
        headers = [
            "Account", "Region", "Instance ID", "Instance Name", "Platform", "Agent Version",
            "SSM Managed", "Last Ping Status", "Last Ping Time", "IAM Role", "Compliance Status", "Generated On"
        ]
        self.setup_csv(self.profile, f"SsmAgentReporting_{self.timestamp}.csv", headers)

        for region in self.regions:
            try:
                ec2 = self.session.client('ec2', region_name=region)
                ssm = self.session.client('ssm', region_name=region)

                reservations = ec2.describe_instances()['Reservations']
                for res in reservations:
                    for inst in res['Instances']:
                        instance_id = inst['InstanceId']

                        # tags as dict for filtering and name extraction
                        tag_dict = {t['Key']: t['Value'] for t in inst.get('Tags', [])}
                        instance_name = tag_dict.get('Name', 'N/A')

                        # use the common tag filter function
                        if tag_filter and not self._resource_matches_tag_filter(tag_dict, tag_filter):
                            continue

                        platform = inst.get('Platform', 'Linux/UNIX')
                        iam_role = inst.get('IamInstanceProfile', {}).get('Arn', 'N/A')

                        # Default values for SSM info
                        agent_version = "N/A"
                        ssm_managed = "No"
                        ping_status = "N/A"
                        last_ping_time = "N/A"
                        compliance_status = "N/A"

                        # Get SSM info
                        ssm_info = ssm.describe_instance_information(
                            Filters=[{"Key": "InstanceIds", "Values": [instance_id]}]
                        ).get('InstanceInformationList', [])

                        if ssm_info:
                            ssm_data = ssm_info[0]
                            agent_version = ssm_data.get('AgentVersion', 'N/A')
                            ssm_managed = "Yes"
                            ping_status = ssm_data.get('PingStatus', 'N/A')
                            last_ping_time = ssm_data.get('LastPingDateTime', 'N/A')
                            compliance_status = ssm_data.get('AssociationStatus', 'N/A')

                        # Write row
                        row_data = [
                            self.profile, region, instance_id, instance_name, platform,
                            agent_version, ssm_managed, ping_status, str(last_ping_time),
                            iam_role, compliance_status, self.timestamp
                        ]
                        self.write_csv_row(row_data, OUTPUT_FILE)

            except Exception as e:
                pass

             
    def check_vpc_flow_logs(self, tag_filter=None):
        OUTPUT_FILE = f"{self.profile}/VpcFlowLogs_{self.timestamp}.csv"
        headers = [
            "Account", "Region", "VPC ID", "Flow Log ID", "Log Group", "IAM Role Used",
            "Destination", "Traffic Type", "Log Format", "Creation Time", "Enabled", "Generated On"
        ]
        self.setup_csv(self.profile, f"VpcFlowLogs_{self.timestamp}.csv", headers)

        for region in self.regions:
            try:
                ec2 = self.session.client('ec2', region_name=region)
                logs = ec2.describe_flow_logs()["FlowLogs"]

                if logs:
                    for log in logs:
                        vpc_id = log.get('ResourceId', 'N/A')
                        tags_dict = {}

                        # --- Fetch VPC tags (only if it's a VPC resource) ---
                        if vpc_id.startswith("vpc-"):  
                            try:
                                vpc_desc = ec2.describe_vpcs(VpcIds=[vpc_id])
                                tags = vpc_desc["Vpcs"][0].get("Tags", [])
                                tags_dict = {t["Key"]: t["Value"] for t in tags}
                            except Exception:
                                pass

                        # --- Use common tag filter function ---
                        if not self._resource_matches_tag_filter(tags_dict, tag_filter):
                            continue

                        flow_log_id = log.get('FlowLogId', 'N/A')
                        log_group = log.get('LogGroupName', 'N/A')
                        iam_role = log.get('DeliverLogsPermissionArn', 'N/A')
                        destination = log.get('LogDestination', 'N/A')
                        traffic_type = log.get('TrafficType', 'N/A')
                        log_format = log.get('LogFormat', 'N/A')
                        creation_time = str(log.get('CreationTime', 'N/A'))
                        enabled = log.get('LogDeliveryStatus', 'N/A')

                        row_data = [
                            self.profile, region, vpc_id, flow_log_id, log_group,
                            iam_role, destination, traffic_type, log_format,
                            creation_time, enabled
                        ]
                        self.write_csv_row(row_data, OUTPUT_FILE)
                else:
                    # ✅ safer: log empty row when no flow logs exist
                    row_data = [self.profile, region, "N/A", "N/A", "N/A", "N/A", 
                                "N/A", "N/A", "N/A", "N/A", "N/A"]
                    self.write_csv_row(row_data, OUTPUT_FILE)

            except botocore.exceptions.ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code in ('AuthFailure', 'UnauthorizedOperation', 'UnrecognizedClientException', 'InvalidClientTokenId'):
                    print(f"Skipping region {region} due to authentication failure or inactive region/account.")
                else:
                    print(f"Unexpected AWS error in region {region}: {e}")
            except Exception as e:
                print(f"[{region}] General error checking VPC Flow Logs: {e}")

    def check_ebs_encryption(self, tag_filter=None):
        OUTPUT_FILE = f"{self.profile}/EbsEncryption_{self.timestamp}.csv"
        headers = ["Account", "Region", "Volume ID", "Instance ID", "Device Name","Volume Type",
                "Encrypted", "KMS Key ID", "Size (GiB)", "Tags","Generated On"]
        self.setup_csv(self.profile, f"EbsEncryption_{self.timestamp}.csv", headers)

        for region in self.regions:
            try:
                ec2 = self.session.client('ec2', region_name=region)
                volumes = ec2.describe_volumes()["Volumes"]

                if not volumes:
                    continue

                for vol in volumes:
                    vol_id = vol.get("VolumeId", "N/A")
                    attachments = vol.get("Attachments", [])
                    instance_id = attachments[0].get("InstanceId") if attachments else "N/A"
                    device = attachments[0].get("Device") if attachments else "N/A"
                    vol_type = vol.get("VolumeType", "N/A")
                    encrypted = vol.get("Encrypted", "N/A")
                    kms_key_id = vol.get("KmsKeyId", "N/A")
                    size = vol.get("Size", "N/A")
                    create_time = str(vol.get("CreateTime", "N/A"))

                    # Collect tags
                    tags_dict = {t["Key"]: t["Value"] for t in vol.get("Tags", [])}
                    tags_str = "; ".join([f"{k}={v}" for k, v in tags_dict.items()]) if tags_dict else ""

                    # ✅ Apply tag filter using helper
                    if tag_filter and not self._resource_matches_tag_filter(tags_dict, tag_filter):
                        print(f"Skipping {vol_id} in {region} due to tag mismatch. Found tags: {tags_dict}")
                        continue  

                    row_data = [self.profile, region, vol_id, instance_id, device, vol_type,
                                encrypted, kms_key_id, size, create_time, tags_str, self.timestamp]

                    self.write_csv_row(row_data, OUTPUT_FILE)
            except Exception as e:
                print(f"[{region}] Error checking EBS encryption: {e}")


    def check_lambda_and_rds_log_groups(self, tag_filter=None):
        OUTPUT_FILE = f"{self.profile}/awslogs_{self.timestamp}.csv"
        headers = ["Profile", "Region", "Service", "Log Group Name", "Log Stream Count",
                "Last Event Timestamp", "CloudWatch Retention (days)", "Metric Filters Configured", "Generated On"]
        self.setup_csv(self.profile, f"awslogs_{self.timestamp}.csv", headers)

        prefixes = ["/aws/lambda", "/aws/rds"]

        for region in self.regions:
            try:
                logs_client = self.session.client('logs', region_name=region)

                for prefix in prefixes:
                    next_token = None
                    while True:
                        params = {"logGroupNamePrefix": prefix}
                        if next_token:
                            params["nextToken"] = next_token

                        response = logs_client.describe_log_groups(**params)
                        log_groups = response.get("logGroups", [])

                        for lg in log_groups:
                            log_group_name = lg["logGroupName"]

                            # Collect tags
                            tags_dict = {}
                            try:
                                tags_response = logs_client.list_tags_log_group(logGroupName=log_group_name)
                                tags_dict = tags_response.get("tags", {})
                            except Exception as e:
                                print(f"Error fetching tags for {log_group_name} in {region}: {e}")

                            # ✅ Apply tag filter using helper
                            if tag_filter and not self._resource_matches_tag_filter(tags_dict, tag_filter):
                                continue  

                            retention = lg.get("retentionInDays", "Never Expire")

                            # Log stream info
                            log_streams = logs_client.describe_log_streams(
                                logGroupName=log_group_name,
                                orderBy="LastEventTime",
                                descending=True,
                                limit=1
                            ).get("logStreams", [])
                            stream_count = len(log_streams)
                            last_event = (
                                datetime.fromtimestamp(log_streams[0]['lastEventTimestamp'] / 1000, tz=self.timezone.utc).isoformat()
                                if stream_count > 0 and 'lastEventTimestamp' in log_streams[0] else "N/A"
                            )

                            # Metric filters
                            filters = logs_client.describe_metric_filters(logGroupName=log_group_name).get("metricFilters", [])
                            metric_filter_status = "Yes" if filters else "No"

                            row_data = [self.profile, region,
                                        "Lambda" if prefix == "/aws/lambda" else "RDS",
                                        log_group_name, stream_count, last_event,
                                        retention, metric_filter_status, self.timestamp]

                            self.write_csv_row(row_data, OUTPUT_FILE)

                        next_token = response.get("nextToken")
                        if not next_token:
                            break
            except Exception as e:
                print(f"[{region}] Error checking Lambda/RDS log groups: {e}")
