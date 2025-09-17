import boto3
from datetime import datetime, timezone
import json
import csv
import botocore

class InfraChangeReport:
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

    def list_created_resources(self, since_date):
        try:
            since_date = datetime.strptime(since_date, "%m/%d/%Y").replace(tzinfo=timezone.utc)
        except ValueError:
            print(f"Invalid date format: {since_date}. Expected MM/DD/YYYY.")
            return

        OUTPUT_FILE = f"{self.profile}/CreatedResources_{self.timestamp}.csv"
        headers = ["Account", "Service", "ResourceId/Name", "CreationTime", "Generated On"]
        self.setup_csv(self.profile, f"CreatedResources_{self.timestamp}.csv", headers)

        collectors = [
            self.list_ec2_resources_creation,
            self.list_rds_instances,
            self.list_cloudwatch_logs,
            self.list_s3_buckets,
            self.list_cognito_pools,
            self.list_load_balancers,
            self.list_ses_identities,
        ]

        for collector in collectors:
            try:
                rows = collector(since_date)
                for row in rows:
                    self.write_csv_row(row, OUTPUT_FILE)
            except Exception as e:
                print(f"Error in {collector.__name__}: {e}")


    # EC2 (Instances true creation date via ENI, SG, VPC, RT)
    def list_ec2_resources_creation(self, since_date):
        rows = []

        # EC2 Instances (via ENI attach time)
        for region in self.regions:
            try:
                ec2_reg = self.session.client("ec2", region_name = region)
                reservations = ec2_reg.describe_instances()["Reservations"]

                # Instances
                for res in reservations:
                    for inst in res["Instances"]:
                        if not inst.get("NetworkInterfaces"):
                            continue
                        eni_id = inst["NetworkInterfaces"][0]["NetworkInterfaceId"]
                        eni = ec2_reg.describe_network_interfaces(NetworkInterfaceIds=[eni_id])["NetworkInterfaces"][0]
                        attach_time = eni["Attachment"]["AttachTime"]
                        if attach_time >= since_date:
                            rows.append([self.profile, f"EC2 Instance ({region})", inst["InstanceId"],
                                         attach_time.strftime("%Y-%m-%d %H:%M:%S"), self.timestamp])

                # Security Groups
                sgs = ec2_reg.describe_security_groups()["SecurityGroups"]
                for sg in sgs:
                    rows.append([self.profile, f"SecurityGroup ({region})", sg["GroupId"], "N/A", self.timestamp])

                # VPCs
                vpcs = ec2_reg.describe_vpcs()["Vpcs"]
                for vpc in vpcs:
                    rows.append([self.profile, f"VPC ({region})", vpc["VpcId"], "N/A", self.timestamp])

                # Route Tables
                rts = ec2_reg.describe_route_tables()["RouteTables"]
                for rt in rts:
                    rows.append([self.profile, f"RouteTable ({region})", rt["RouteTableId"], "N/A", self.timestamp])

            except Exception as e:
                if "AuthFailure" not in str(e):
                    print(f"EC2 error in {region}: {e}")

        return rows

    # RDS
    def list_rds_instances(self, since_date):
        rows = []

        for region in self.regions:
            try:
                rds = self.session.client("rds",region_name=region)
                paginator = rds.get_paginator("describe_db_instances")
                for page in paginator.paginate():
                    for db in page["DBInstances"]:
                        create_time = db["InstanceCreateTime"].replace(tzinfo=timezone.utc)
                        if create_time >= since_date:
                            rows.append([self.profile, f"RDS Instance ({region})", db["DBInstanceIdentifier"],
                                         create_time.strftime("%Y-%m-%d %H:%M:%S"), self.timestamp])
            except Exception as e:
                if "AuthFailure" not in str(e):
                    print(f"RDS error in {region}: {e}")
        return rows

    # CloudWatch Logs
    def list_cloudwatch_logs(self, since_date):
        rows = []
        for region in self.regions:

            logs = self.session.client("logs", region_name= region)

            for lg in logs.describe_log_groups()["logGroups"]:
                creation = datetime.fromtimestamp(lg["creationTime"] / 1000, tz=timezone.utc)
                if creation >= since_date:
                    rows.append([self.profile, "CloudWatch LogGroup", lg["logGroupName"],
                                creation.strftime("%Y-%m-%d %H:%M:%S"), self.timestamp])
            return rows

    # S3
    def list_s3_buckets(self, since_date):
        rows = []
        s3 = self.session.client("s3")
        try:
            for b in s3.list_buckets().get("Buckets", []):
                create_time = b["CreationDate"].replace(tzinfo=timezone.utc)
                if create_time >= since_date:
                    rows.append([
                        self.profile,
                        "S3 Bucket",
                        b["Name"],
                        create_time.strftime("%Y-%m-%d %H:%M:%S"),
                        self.timestamp
                    ])
        except Exception as e:
            print(f"S3 error: {e}")
        return rows

    # Cognito
    def list_cognito_pools(self, since_date):
        rows = []
        for region in self.regions:
            cognito = self.session.client("cognito-idp", region_name = region)
        
            for pool in cognito.list_user_pools(MaxResults=50)["UserPools"]:
                details = cognito.describe_user_pool(UserPoolId=pool["Id"])["UserPool"]
                creation = details["CreationDate"].replace(tzinfo=timezone.utc)
                if creation >= since_date:
                    rows.append([self.profile, "Cognito UserPool", pool["Name"],
                                creation.strftime("%Y-%m-%d %H:%M:%S"), self.timestamp])
            return rows

    # Load Balancers
    def list_load_balancers(self, since_date):
        for region in self.regions:
            elb = self.session.client("elbv2", region_name = region)
            rows = []
            for lb in elb.describe_load_balancers()["LoadBalancers"]:
                creation = lb["CreatedTime"].replace(tzinfo=timezone.utc)
                if creation >= since_date:
                    rows.append([self.profile, "LoadBalancer", lb["LoadBalancerName"],
                                creation.strftime("%Y-%m-%d %H:%M:%S"), self.timestamp])
            return rows

    # SES
    def list_ses_identities(self, since_date):
        for region in self.regions:
            ses = self.session.client("ses", region_name=region)  # SES is regional
            rows = []
            for identity in ses.list_identities()["Identities"]:
                # SES doesn’t expose creation date
                rows.append([self.profile, "SES Identity", identity, "N/A", self.timestamp])
            return rows

# Network changes via cloudtrail

    def list_network_changes(self, since_date):
        try:
            since_date = datetime.strptime(since_date, "%m/%d/%Y").replace(tzinfo=timezone.utc)
        except ValueError:
            print(f"Invalid date format: {since_date}. Expected MM/DD/YYYY.")
            return

        OUTPUT_FILE = f"{self.profile}/NetworkChanges_{self.timestamp}.csv"
        headers = ["Account", "Region", "Event Name", "Username", "Event Time", "Resource Type", "Resource Name", "Change Details", "Generated On"]
        self.setup_csv(self.profile, f"NetworkChanges_{self.timestamp}.csv", headers)

        region = "us-east-1" 
        print(f"Checking network changes in region: {region}")

        event_name_prefixes = ["create", "modify", "delete", "attach", "detach", "associate", "disassociate"]

        networking_resources_keywords = ["securitygroup","networkacl","route","internetgateway","vpcpeeringconnection","loadbalancer","listener","networkinterface","elasticip","vpnconnection","customergateway","dhcpoptions","transitgateway","natgateway","subnet","vpc"]

        try:
            ct_client = self.session.client('cloudtrail', region_name=region)
            paginator = ct_client.get_paginator('lookup_events')
            for page in paginator.paginate(StartTime=since_date, EndTime=datetime.now(timezone.utc)):
                for event in page.get('Events', []):
                    event_name = event.get('EventName', '').lower()

                    # Check if event_name matches any relevant prefixes
                    if not any(event_name.startswith(prefix) for prefix in event_name_prefixes):
                        continue

                    resources = event.get('Resources', [])
                    if not resources:
                        continue

                    # Check if any resource type matches networking keywords
                    matches_network_resource = any(
                        any(keyword in r.get('ResourceType', '').lower() for keyword in networking_resources_keywords)
                        for r in resources
                    )
                    if not matches_network_resource:
                        continue

                    username = event.get('Username', 'N/A')
                    event_time = event['EventTime'].strftime("%Y-%m-%d %H:%M:%S")

                    for r in resources:
                        res_type = r.get('ResourceType', 'N/A')
                        res_name = r.get('ResourceName', 'N/A')
                        # Optional: parse or summarize event details better than raw JSON if needed
                        change_details = json.dumps(event.get('CloudTrailEvent', {}))[:500]

                        row_data = [self.profile,region,event_name,username,event_time,res_type,res_name,change_details,self.timestamp]
                        self.write_csv_row(row_data, OUTPUT_FILE)

        except Exception as e:
            print(f"Error fetching network changes: {e}")