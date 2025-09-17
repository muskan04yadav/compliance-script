import boto3
import json
from datetime import datetime
import csv

class Inventory:
    def __init__(self, profile, session, timestamp, regions, write_csv_row, setup_csv):
        self.profile = profile
        self.session = session
        self.timestamp = timestamp
        self.regions = regions
        self.write_csv_row = write_csv_row
        self.setup_csv = setup_csv
        

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

    def list_windows_ec2_instances(self, tag_filter=None):
        OUTPUT_FILE = f"{self.profile}/WindowsEC2_{self.timestamp}.csv"
        headers = [
            "Profile", "Region", "Instance ID", "Instance Name", "OS Type", "Platform",
            "Instance State", "AMI ID", "Instance Type", "Launch Time", "VPC ID", "Subnet ID",
            "IAM Role Attached", "SSM Managed", "Tags", "Generated On"
        ]
        
        self.setup_csv(self.profile, f"WindowsEC2_{self.timestamp}.csv", headers)

        for region in self.regions:
            try:
                ec2 = self.session.client('ec2', region_name=region)
                ssm = self.session.client('ssm', region_name=region)

                # Get SSM managed instance IDs
                try:
                    ssm_managed_instances = ssm.describe_instance_information()
                    ssm_ids = [i['InstanceId'] for i in ssm_managed_instances.get('InstanceInformationList', [])]
                except Exception:
                    ssm_ids = []

                

                # --- Build EC2 filters ---
                filters = []
                filters = [{"Name": "platform", "Values": ["windows"]}]
                
                print(filters)

                reservations = ec2.describe_instances(Filters=filters + tag_filter)['Reservations']

                for res in reservations:
                    for inst in res['Instances']:
                        instance_id = inst.get('InstanceId', 'N/A')
                        name = next((tag['Value'] for tag in inst.get('Tags', []) if tag['Key'].lower() == 'name'), 'N/A')
                        os_type = "Windows"
                        platform = inst.get('Platform', 'windows')
                        state = inst.get('State', {}).get('Name', 'N/A')
                        ami_id = inst.get('ImageId', 'N/A')
                        instance_type = inst.get('InstanceType', 'N/A')
                        launch_time = inst.get('LaunchTime', 'N/A')
                        vpc_id = inst.get('VpcId', 'N/A')
                        subnet_id = inst.get('SubnetId', 'N/A')
                        iam_role = inst.get('IamInstanceProfile', {}).get('Arn', 'None').split('/')[-1] if inst.get('IamInstanceProfile') else 'None'
                        ssm_managed = "Yes" if instance_id in ssm_ids else "No"
                        tags = "; ".join([f"{tag['Key']}={tag['Value']}" for tag in inst.get('Tags', [])]) if inst.get('Tags') else "None"

                        row_data = [
                            self.profile, region, instance_id, name, os_type, platform,
                            state, ami_id, instance_type, launch_time, vpc_id, subnet_id,
                            iam_role, ssm_managed, tags
                        ]
                        self.write_csv_row(row_data, OUTPUT_FILE)

            except Exception as e:
                continue

    
    def list_rds_instance_details(self, tag_filter=None):
        OUTPUT_FILE = f"{self.profile}/RDSInstanceDetails_{self.timestamp}.csv"
        headers = [
            "Profile", "Region", "DB Instance Identifier", "DB Instance Class", "Engine", "Engine Version",
            "Multi-AZ", "Storage Type", "Allocated Storage", "VPC ID", "Subnet Group", "Endpoint",
            "IAM Role", "KMS Key ID", "Storage Encrypted", "Backup Retention Period",
            "Monitoring Enabled", "Tags", "Creation Time", "Generated On"
        ]
        self.setup_csv(self.profile, f"RDSInstanceDetails_{self.timestamp}.csv", headers)

        for region in self.regions:
            try:
                rds = self.session.client('rds', region_name=region)

                response = rds.describe_db_instances()
                for db in response.get('DBInstances', []):
                    db_id = db.get('DBInstanceIdentifier', 'N/A')

                    try:
                        arn = db['DBInstanceArn']
                        tag_list = rds.list_tags_for_resource(ResourceName=arn).get('TagList', [])
                        tags_dict = {tag['Key']: tag['Value'] for tag in tag_list}
                        tags = '; '.join([f"{k}={v}" for k, v in tags_dict.items()]) if tag_list else "None"
                    except Exception:
                        tag_list, tags_dict, tags = [], {}, "None"

                    # ✅ Apply tag filter here
                    if tag_filter and not self._resource_matches_tag_filter(tags_dict, tag_filter):
                        continue

                    db_class = db.get('DBInstanceClass', 'N/A')
                    engine = db.get('Engine', 'N/A')
                    engine_ver = db.get('EngineVersion', 'N/A')
                    multi_az = db.get('MultiAZ', False)
                    storage_type = db.get('StorageType', 'N/A')
                    allocated_storage = db.get('AllocatedStorage', 'N/A')
                    vpc_id = db.get('DBSubnetGroup', {}).get('VpcId', 'N/A')
                    subnet_group = db.get('DBSubnetGroup', {}).get('DBSubnetGroupName', 'N/A')
                    endpoint = db.get('Endpoint', {}).get('Address', 'N/A')
                    iam_roles = ', '.join(
                        [role['RoleArn'].split('/')[-1] for role in db.get('AssociatedRoles', [])]
                    ) if db.get('AssociatedRoles') else "None"
                    kms_key_id = db.get('KmsKeyId', 'None')
                    encrypted = db.get('StorageEncrypted', False)
                    backup_retention = db.get('BackupRetentionPeriod', 'N/A')
                    monitoring = "Yes" if db.get('MonitoringInterval', 0) > 0 else "No"
                    creation_time = db.get('InstanceCreateTime', 'N/A')

                    row_data = [
                        self.profile, region, db_id, db_class, engine, engine_ver, multi_az, storage_type,
                        allocated_storage, vpc_id, subnet_group, endpoint, iam_roles, kms_key_id,
                        encrypted, backup_retention, monitoring, tags, creation_time, self.timestamp
                    ]
                    self.write_csv_row(row_data, OUTPUT_FILE)
            except Exception as e:
                print(f"[ERROR] {region} - {str(e)}")

    def list_ecs_details(self, tag_filter=None):
        OUTPUT_FILE = f"{self.profile}/ECSService_{self.timestamp}.csv"
        headers = [
            "Account","Region", "Cluster Name","Cluster ARN","Launch Type","Capacity Providers",
            "Service Name","Task Definition","Desired Count","Running Count","Pending Count",
            "Deployment Status","VPC ID","Subnets","Creation Time","Tags","Generated On"
        ]
        self.setup_csv(self.profile, f"ECSService_{self.timestamp}.csv", headers)

        for region in self.regions:
            try:
                ecs_client = self.session.client('ecs', region_name=region)
                ec2_client = self.session.client('ec2', region_name=region)

                clusters_arns = []
                paginator = ecs_client.get_paginator('list_clusters')
                for page in paginator.paginate():
                    clusters_arns.extend(page['clusterArns'])

                if not clusters_arns:
                    continue

                clusters_info = ecs_client.describe_clusters(clusters=clusters_arns)['clusters']
                for cluster in clusters_info:
                    cluster_name = cluster['clusterName']
                    cluster_arn = cluster['clusterArn']
                    capacity_providers = ", ".join(cluster.get('capacityProviders', [])) or "N/A"

                    service_arns = []
                    paginator = ecs_client.get_paginator('list_services')
                    for page in paginator.paginate(cluster=cluster_name):
                        service_arns.extend(page['serviceArns'])

                    if not service_arns:
                        continue

                    services_info = ecs_client.describe_services(cluster=cluster_name, services=service_arns)['services']
                    for service in services_info:
                        service_arn = service['serviceArn']

                        # Get tags
                        try:
                            tags_resp = ecs_client.list_tags_for_resource(resourceArn=service_arn)
                            tags_dict = {t['key']: t['value'] for t in tags_resp.get('tags', [])}
                            tags = "; ".join(f"{k}={v}" for k, v in tags_dict.items()) if tags_dict else "N/A"
                        except:
                            tags_dict, tags = {}, "N/A"

                        # Apply tag filter
                        if tag_filter and not self._resource_matches_tag_filter(tags_dict, tag_filter):
                            continue

                        launch_type = service.get('launchType', 'N/A')
                        task_definition = service.get('taskDefinition', 'N/A')
                        desired_count = service.get('desiredCount', 'N/A')
                        running_count = service.get('runningCount', 'N/A')
                        pending_count = service.get('pendingCount', 'N/A')
                        deployment_status = service['deployments'][0]['status'] if service.get('deployments') else 'N/A'

                        vpc_id = "N/A"
                        subnets = "N/A"
                        if 'networkConfiguration' in service and 'awsvpcConfiguration' in service['networkConfiguration']:
                            subnet_ids = service['networkConfiguration']['awsvpcConfiguration'].get('subnets', [])
                            subnets = ", ".join(subnet_ids) if subnet_ids else "N/A"
                            if subnet_ids:
                                subnet_desc = ec2_client.describe_subnets(SubnetIds=subnet_ids)['Subnets']
                                vpc_id = subnet_desc[0]['VpcId'] if subnet_desc else "N/A"

                        row_data = [
                            self.profile, region, cluster_name, cluster_arn, launch_type, capacity_providers,
                            service['serviceName'], task_definition, desired_count, running_count, pending_count,
                            deployment_status, vpc_id, subnets, service.get('createdAt', 'N/A'), tags, self.timestamp
                        ]
                        self.write_csv_row(row_data, OUTPUT_FILE)
            except Exception:
                pass


    def list_lambda_functions(self, tag_filter=None):
        OUTPUT_FILE = f"{self.profile}/LambdaFunctions_{self.timestamp}.csv"
        headers = [
            "Account", "Region", "Function Name", "Function ARN", "Runtime","Memory Size", "Timeout",
            "Handler", "Last Modified", "Role ARN","Environment Variables", "VPC Subnets",
            "VPC Security Groups","Layers", "Tags", "Generated On"
        ]
        self.setup_csv(self.profile, f"LambdaFunctions_{self.timestamp}.csv", headers)

        for region in self.regions:
            try:
                lambda_client = self.session.client('lambda', region_name=region)

                paginator = lambda_client.get_paginator('list_functions')
                functions = []
                for page in paginator.paginate():
                    functions.extend(page.get('Functions', []))

                for func in functions:
                    func_arn = func['FunctionArn']
                    try:
                        tags_resp = lambda_client.list_tags(Resource=func_arn)
                        tags_dict = tags_resp.get('Tags', {}) or {}
                        tags_str = "; ".join(f"{k}={v}" for k, v in tags_dict.items()) if tags_dict else "N/A"
                    except:
                        tags_dict, tags_str = {}, "N/A"

                    # ✅ Apply tag filter properly
                    if tag_filter and not self._resource_matches_tag_filter(tags_dict, tag_filter):
                        continue

                    env_vars = func.get('Environment', {}).get('Variables', {})
                    env_vars_str = json.dumps(env_vars) if env_vars else "N/A"

                    vpc_config = func.get('VpcConfig', {})
                    subnets = ", ".join(vpc_config.get('SubnetIds', [])) if vpc_config.get('SubnetIds') else "N/A"
                    sec_groups = ", ".join(vpc_config.get('SecurityGroupIds', [])) if vpc_config.get('SecurityGroupIds') else "N/A"
                    layers = ", ".join([layer['Arn'] for layer in func.get('Layers', [])]) if func.get('Layers') else "N/A"

                    row_data = [
                        self.profile, region, func['FunctionName'], func_arn, func.get('Runtime', 'N/A'),
                        func.get('MemorySize', 'N/A'), func.get('Timeout', 'N/A'), func.get('Handler', 'N/A'),
                        func.get('LastModified', 'N/A'), func.get('Role', 'N/A'), env_vars_str, subnets, sec_groups,
                        layers, tags_str, self.timestamp
                    ]
                    self.write_csv_row(row_data, OUTPUT_FILE)
            except Exception as e:
                print(f"[{region}] Error listing Lambda functions: {e}")
                continue



    def list_s3_details(self, tag_filter=None):
        OUTPUT_FILE = f"{self.profile}/S3Buckets_{self.timestamp}.csv"
        headers = [
            "Account", "Bucket Name", "Region", "Creation Date",
            "Default Encryption (Yes/No)", "KMS Key",
            "Versioning Status", "Logging Enabled", "Access Control (ACL)",
            "Public Access Block Enabled", "Tags", "Generated On"
        ]
        self.setup_csv(self.profile, f"S3Buckets_{self.timestamp}.csv", headers)

        s3_client = self.session.client('s3')
        buckets = s3_client.list_buckets().get('Buckets', [])

        for bucket in buckets:
            bucket_name = bucket['Name']
            creation_date = bucket['CreationDate'].strftime("%Y-%m-%d %H:%M:%S")

            # Get region
            try:
                region = s3_client.get_bucket_location(Bucket=bucket_name).get('LocationConstraint')
                region = region if region else "us-east-1"
            except:
                region = "Unknown"

            # Get tags
            try:
                tags_resp = s3_client.get_bucket_tagging(Bucket=bucket_name)
                tag_list = tags_resp.get('TagSet', [])
                tags_dict = {t['Key']: t['Value'] for t in tag_list}
                tags_str = "; ".join([f"{k}={v}" for k, v in tags_dict.items()])
            except:
                tag_list, tags_dict, tags_str = [], {}, "N/A"

            # 🔹 Apply tag filter using existing helper
            if tag_filter and not self._resource_matches_tag_filter(tag_list, tag_filter):
                continue

            # Get encryption
            encryption_enabled, kms_key = "No", "N/A"
            try:
                enc = s3_client.get_bucket_encryption(Bucket=bucket_name)
                rules = enc['ServerSideEncryptionConfiguration']['Rules']
                if rules:
                    encryption_enabled = "Yes"
                    sse_rule = rules[0]['ApplyServerSideEncryptionByDefault']
                    kms_key = sse_rule.get('KMSMasterKeyID', 'N/A')
            except s3_client.exceptions.ClientError:
                pass

            # Get versioning
            try:
                versioning = s3_client.get_bucket_versioning(Bucket=bucket_name).get('Status', 'Disabled')
            except:
                versioning = "Disabled"

            # Get logging
            try:
                logging_status = s3_client.get_bucket_logging(Bucket=bucket_name)
                logging_enabled = "Yes" if 'LoggingEnabled' in logging_status else "No"
            except:
                logging_enabled = "No"

            # Get ACL
            try:
                acl = s3_client.get_bucket_acl(Bucket=bucket_name)
                grants = [g['Grantee'].get('URI', g['Grantee'].get('ID', 'Unknown')) for g in acl['Grants']]
                acl_str = "; ".join(grants)
            except:
                acl_str = "Unknown"

            # Get public access block
            try:
                pab = s3_client.get_bucket_policy_status(Bucket=bucket_name)
                public_block = "No" if pab['PolicyStatus']['IsPublic'] else "Yes"
            except:
                public_block = "Unknown"

            # Write row
            row_data = [
                self.profile, bucket_name, region, creation_date,
                encryption_enabled, kms_key, versioning, logging_enabled,
                acl_str, public_block, tags_str, self.timestamp
            ]
            self.write_csv_row(row_data, OUTPUT_FILE)


    def list_alb_details(self, tag_filter=None):
        OUTPUT_FILE = f"{self.profile}/ALBDetails_{self.timestamp}.csv"
        headers = [
            "Profile", "Region", "LoadBalancer Name", "DNS Name", "Scheme",
            "VPC ID", "Type", "State", "Security Groups", "Subnets", "Tags", "Created On"
        ]
        self.setup_csv(self.profile, f"ALBDetails_{self.timestamp}.csv", headers)

        for region in self.regions:
            try:
                elbv2 = self.session.client('elbv2', region_name=region)
                response = elbv2.describe_load_balancers()

                for alb in response.get("LoadBalancers", []):
                    alb_arn = alb["LoadBalancerArn"]

                    # Fetch tags
                    tag_list = elbv2.describe_tags(ResourceArns=[alb_arn])["TagDescriptions"][0].get("Tags", [])
                    tags = "; ".join([f"{tag['Key']}={tag['Value']}" for tag in tag_list]) if tag_list else "None"

                    # Apply tag filter
                    if tag_filter and not self._resource_matches_tag_filter(tag_list, tag_filter):
                        continue

                    row_data = [
                        self.profile, region, alb.get("LoadBalancerName", "N/A"),
                        alb.get("DNSName", "N/A"),
                        alb.get("Scheme", "N/A"),
                        alb.get("VpcId", "N/A"),
                        alb.get("Type", "N/A"),
                        alb.get("State", {}).get("Code", "N/A"),
                        ", ".join(alb.get("SecurityGroups", [])),
                        ", ".join(alb.get("AvailabilityZones", [{}])[0].get("SubnetId", []) if alb.get("AvailabilityZones") else []),
                        tags,
                        alb.get("CreatedTime", "N/A"),
                    ]
                    self.write_csv_row(row_data, OUTPUT_FILE)

            except Exception as e:
                print(f"[ERROR] {region} ALB: {e}")

    def list_cloudfront_details(self, tag_filter=None):
        OUTPUT_FILE = f"{self.profile}/CloudFrontDetails_{self.timestamp}.csv"
        headers = [
            "Profile", "Region", "Distribution ID", "Domain Name", "Status",
            "Enabled", "Comment", "Tags", "Created On"
        ]
        self.setup_csv(self.profile, f"CloudFrontDetails_{self.timestamp}.csv", headers)

        try:
            cf = self.session.client("cloudfront", region_name="us-east-1")  # CloudFront is global

            paginator = cf.get_paginator("list_distributions")
            for page in paginator.paginate():
                for dist in page.get("DistributionList", {}).get("Items", []):
                    dist_id = dist["Id"]
                    arn = dist["ARN"]

                    # Fetch tags
                    tag_list = cf.list_tags_for_resource(Resource=arn)["Tags"].get("Items", [])
                    tags = "; ".join([f"{tag['Key']}={tag['Value']}" for tag in tag_list]) if tag_list else "None"

                    # Apply tag filter
                    if tag_filter and not self._resource_matches_tag_filter(tag_list, tag_filter):
                        continue

                    row_data = [
                        self.profile, "us-east-1", dist_id,
                        dist.get("DomainName", "N/A"),
                        dist.get("Status", "N/A"),
                        dist.get("Enabled", False),
                        dist.get("Comment", "N/A"),
                        tags,
                        dist.get("LastModifiedTime", "N/A"),
                    ]
                    self.write_csv_row(row_data, OUTPUT_FILE)

        except Exception as e:
            print(f"[ERROR] CloudFront: {e}")
