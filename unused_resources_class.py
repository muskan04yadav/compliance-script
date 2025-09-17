import boto3
import json
from datetime import datetime, timezone, timedelta
import csv
import botocore.exceptions

class UnusedResources:
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

    def stopped_ec2_no_connection(self, days=60):
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        OUTPUT_FILE = f"{self.profile}/StoppedEC2_{self.timestamp}.csv"
        headers = ["Profile", "Region", "InstanceId", "State", "LastNetworkActivity", "GeneratedOn"]
        self.setup_csv(self.profile, f"StoppedEC2_{self.timestamp}.csv", headers)

        for region in self.regions:
            try:
                ec2 = self.session.client('ec2', region_name=region)
                cloudwatch = self.session.client('cloudwatch', region_name=region)
                instances = ec2.describe_instances(
                    Filters=[{'Name': 'instance-state-name', 'Values': ['stopped']}]
                )['Reservations']

                if not instances:  # No stopped EC2 instances in this region, skip to next region
                    continue

                for reservation in instances:
                    for instance in reservation['Instances']:
                        instance_id = instance['InstanceId']
                        # Check network in metric
                        metrics = cloudwatch.get_metric_statistics(
                            Namespace='AWS/EC2',
                            MetricName='NetworkIn',
                            Dimensions=[{'Name': 'InstanceId', 'Value': instance_id}],
                            StartTime=cutoff,
                            EndTime=datetime.now(timezone.utc),
                            Period=3600 * 24,
                            Statistics=['Sum']
                        )
                        datapoints = metrics.get('Datapoints', [])
                        if not datapoints or all(dp['Sum'] == 0 for dp in datapoints):
                            row_data = [self.profile, region, instance_id, 'stopped', 'No recent network traffic', self.timestamp]
                            self.write_csv_row(row_data, OUTPUT_FILE)
            except botocore.exceptions.ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code in ('AuthFailure', 'UnauthorizedOperation','UnrecognizedClientException' ,'InvalidClientTokenId'):
                    print(f"Skipping region {region} due to authentication failure or inactive region/account.")
                else:
                    print(f"Unexpected error in region {region}: {e}")
            except Exception as e:
                print(f"General error in region {region}: {e}")      


    def check_unattached_ebs(self):
        OUTPUT_FILE = f"{self.profile}/UnattachedEBS_{self.timestamp}.csv"
        headers = ["Profile", "Region", "VolumeId", "State", "Size (GiB)", "CreateTime", "GeneratedOn"]
        self.setup_csv(self.profile, f"UnattachedEBS_{self.timestamp}.csv", headers)
        

        for region in self.regions:
            try:
                ec2 = self.session.client('ec2', region_name=region)
                volumes = ec2.describe_volumes(Filters=[{'Name': 'status', 'Values': ['available']}])['Volumes']

                for vol in volumes:
                    row_data = [self.profile,region,vol['VolumeId'],vol['State'],vol['Size'],vol['CreateTime'].strftime("%Y-%m-%d %H:%M:%S"),self.timestamp
                    ]
                    try:
                        self.write_csv_row(row_data, OUTPUT_FILE)
                    except Exception as e:
                        print(f"Error writing volume {vol['VolumeId']} data in region {region}: {e}")

            except botocore.exceptions.ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code in ('AuthFailure', 'UnauthorizedOperation', 'InvalidClientTokenId'):
                    print(f"Skipping region {region} due to authentication failure or inactive region/account.")
                else:
                    print(f"Unexpected error in region {region}: {e}")
            except Exception as e:
                print(f"General error in region {region}: {e}")

    def alb_with_no_listeners(self):
        OUTPUT_FILE = f"{self.profile}/ALBsNoListeners_{self.timestamp}.csv"
        headers = ["Profile", "Region", "LoadBalancerName", "LoadBalancerArn", "Scheme", "Type", "State", "GeneratedOn"]
        self.setup_csv(self.profile,f"ALBsNoListeners_{self.timestamp}.csv" , headers)

        for region in self.regions:
            try:
                elbv2 = self.session.client('elbv2', region_name=region)
                lbs = elbv2.describe_load_balancers().get('LoadBalancers', [])

                for lb in lbs:
                    try:
                        listeners = elbv2.describe_listeners(
                            LoadBalancerArn=lb['LoadBalancerArn']
                        ).get('Listeners', [])
                    except botocore.exceptions.ClientError as e:
                        print(f"[{region}] Error describing listeners for ALB {lb['LoadBalancerName']}: {e}")
                        continue  # Skip to next load balancer

                    if not listeners:
                        row_data = [ self.profile, region, lb['LoadBalancerName'], lb['LoadBalancerArn'], lb['Scheme'], lb['Type'], lb['State']['Code'], self.timestamp
                        ]
                        try:
                            self.write_csv_row(row_data, OUTPUT_FILE)
                        except Exception as e:
                            print(f"[{region}] Error writing ALB data for {lb['LoadBalancerName']}: {e}")

            except botocore.exceptions.ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code in ('AuthFailure', 'UnauthorizedOperation', 'InvalidClientTokenId'):
                    print(f"Skipping region {region} due to authentication failure or inactive region/account.")
                else:
                    print(f"Unexpected AWS error in region {region}: {e}")
            except Exception as e:
                print(f"[{region}] General error checking ALBs: {e}")

    def ecs_with_no_services(self):
 
        OUTPUT_FILE = f"{self.profile}/ECS_NoServices_{self.timestamp}.csv"
        headers = ["Profile", "Region", "ClusterName", "ClusterArn", "ServiceName", "DesiredCount", "GeneratedOn"]
        self.setup_csv(self.profile,f"ECS_NoServices_{self.timestamp}.csv" , headers)

        for region in self.regions:
            try:
                ecs_client = self.session.client('ecs', region_name=region)

                    # Get all clusters in this region
                cluster_arns = ecs_client.list_clusters()['clusterArns']
                if not cluster_arns:
                    pass  # No ECS clusters in this region

                for cluster_arn in cluster_arns:
                        cluster_name = cluster_arn.split("/")[-1]

                        # Get services in the cluster
                        service_arns = ecs_client.list_services(cluster=cluster_arn)['serviceArns']
                        if not service_arns:
                            # No services at all
                            row_data = [ self.profile, region, cluster_name, cluster_arn, "No services", 0, self.timestamp]
                            self.write_csv_row(row_data, OUTPUT_FILE)
                            continue

                        # Check each service's DesiredCount
                        services = ecs_client.describe_services(cluster=cluster_arn, services=service_arns)['services']
                        all_zero = True
                        for svc in services:
                            desired = svc.get('desiredCount', 0)
                            if desired > 0:
                                all_zero = False
                            else:
                                row_data = [self.profile,region,cluster_name,cluster_arn,svc['serviceName'],desired,self.timestamp]
                                self.write_csv_row(row_data, OUTPUT_FILE)

                        # If all services have DesiredCount=0, also log cluster-level note
                        if all_zero:
                            row_data = [self.profile,region,cluster_name,cluster_arn,"All services desired=0",0,self.timestamp]
                            self.write_csv_row(row_data, OUTPUT_FILE)

            except botocore.exceptions.ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code in ('AuthFailure', 'UnauthorizedOperation','UnrecognizedClientException', 'InvalidClientTokenId'):
                    print(f"Skipping region {region} due to authentication failure or inactive region/account.")
                else:
                    print(f"Unexpected AWS error in region {region}: {e}")
            except Exception as e:
                print(f"[{region}] General error checking ALBs: {e}")

    def stopped_rds_no_connection(self, days=60):
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)
        OUTPUT_FILE = f"{self.profile}/StoppedRDS_NoConnection_{self.timestamp}.csv"
        headers = ["Profile", "Region", "DBInstanceIdentifier", "DBInstanceStatus", "LastConnectionCheck", "GeneratedOn"]
        self.setup_csv(self.profile,f"StoppedRDS_NoConnection_{self.timestamp}.csv" , headers)

        for region in self.regions:
            try:
                rds = self.session.client('rds', region_name=region)
                cloudwatch = self.session.client('cloudwatch', region_name=region)

                # Describe all RDS instances
                instances = rds.describe_db_instances().get('DBInstances', [])

                for db in instances:
                    status = db.get('DBInstanceStatus', '')
                    db_id = db.get('DBInstanceIdentifier', '')

                    # Check only stopped instances
                    if status != 'stopped':
                        continue

                    # Check DatabaseConnections metric for last 60 days
                    metrics = cloudwatch.get_metric_statistics(
                        Namespace='AWS/RDS',
                        MetricName='DatabaseConnections',
                        Dimensions=[{'Name': 'DBInstanceIdentifier', 'Value': db_id}],
                        StartTime=cutoff,
                        EndTime=datetime.now(timezone.utc),
                        Period=3600*24,  # daily aggregation
                        Statistics=['Sum']
                    )

                    datapoints = metrics.get('Datapoints', [])

                    # If no datapoints or all zero sum, report instance
                    if not datapoints or all(dp['Sum'] == 0 for dp in datapoints):
                        row_data = [self.profile,region,db_id,status,'No recent DB connections',self.timestamp]
                        self.write_csv_row(row_data, OUTPUT_FILE)

            except botocore.exceptions.ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code in ('AuthFailure', 'UnauthorizedOperation', 'InvalidClientTokenId'):
                    print(f"Skipping region {region} due to authentication failure or inactive region/account.")
                else:
                    print(f"Unexpected error in region {region}: {e}")
            except Exception as e:
                print(f"General error in region {region}: {e}")

    def failing_lambdas(self):
        OUTPUT_FILE = f"{self.profile}/FailingLambdas_{self.timestamp}.csv"
        headers = ["Profile", "Region", "FunctionName", "ErrorCountLast7Days", "Generated On"]
        self.setup_csv(self.profile, f"FailingLambdas_{self.timestamp}.csv" , headers)

        for region in self.regions:
            try:
                lambda_client = self.session.client('lambda', region_name=region)
                cloudwatch = self.session.client('cloudwatch', region_name=region)

                paginator = lambda_client.get_paginator('list_functions')
                for page in paginator.paginate():
                    functions = page.get('Functions', [])
                    for fn in functions:
                        function_name = fn['FunctionName']

                        end_time = datetime.now(timezone.utc)
                        start_time = end_time - timedelta(days=7)

                        metrics = cloudwatch.get_metric_statistics( Namespace='AWS/Lambda', MetricName='Errors', Dimensions=[{'Name': 'FunctionName', 'Value': function_name}], StartTime=start_time, EndTime=end_time, Period=3600 * 24,  Statistics=['Sum'])

                        datapoints = metrics.get('Datapoints', [])
                        error_count = 0
                        if datapoints:
                            # Sum errors across all datapoints in 7 days
                            error_count = sum(dp['Sum'] for dp in datapoints)

                        if error_count > 0:
                            row_data = [self.profile,region,function_name,int(error_count),self.timestamp]
                            self.write_csv_row(row_data, OUTPUT_FILE)

            except botocore.exceptions.ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code in ('AuthFailure', 'UnauthorizedOperation', 'UnrecognizedClientException','InvalidClientTokenId'):
                    print(f"Skipping region {region} due to authentication failure or inactive region/account.")
                else:
                    print(f"Unexpected error in region {region}: {e}")
            except Exception as e:
                print(f"General error in region {region}: {e}")

    def unassociated_eips(self):
        OUTPUT_FILE = f"{self.profile}/UnassociatedEIPs_{self.timestamp}.csv"
        headers = ["Profile", "Region", "PublicIp", "AllocationId", "Domain", "CreatedOn"]
        self.setup_csv(self.profile, f"UnassociatedEIPs_{self.timestamp}.csv", headers)

        for region in self.regions:
            try:
                ec2 = self.session.client('ec2', region_name=region)
                addresses = ec2.describe_addresses().get('Addresses', [])

                for addr in addresses:
                    # An unassociated EIP will not have an InstanceId or NetworkInterfaceId
                    if not addr.get('InstanceId') and not addr.get('NetworkInterfaceId'):
                        row_data = [self.profile,region,addr.get('PublicIp', ''),addr.get('AllocationId', ''),addr.get('Domain', ''),self.timestamp]
                        self.write_csv_row(row_data, OUTPUT_FILE)

            except botocore.exceptions.ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code in ('AuthFailure', 'UnauthorizedOperation', 'InvalidClientTokenId'):
                    print(f"Skipping region {region} due to authentication failure or inactive region/account.")
                else:
                    print(f"Unexpected error in region {region}: {e}")
            except Exception as e:
                print(f"General error in region {region}: {e}")

    def list_idle_route53(self):
 
        OUTPUT_FILE = f"{self.profile}/IdleRoute53_{self.timestamp}.csv"
        headers = ["Profile", "Region", "HostedZoneId", "Name", "RecordCount", "GeneratedOn"]
        self.setup_csv(self.profile, f"IdleRoute53_{self.timestamp}.csv", headers)

        # Route 53 is a global service — no region loop needed
        try:
            r53 = self.session.client('route53')
            zones = r53.list_hosted_zones().get('HostedZones', [])

            for zone in zones:
                zone_id = zone['Id'].split('/')[-1]  # Clean up the ID
                name = zone['Name']
                record_count = zone['ResourceRecordSetCount']

                # Get all record sets for this zone
                records = r53.list_resource_record_sets(HostedZoneId=zone_id).get('ResourceRecordSets', [])

                # Exclude default SOA and NS from consideration
                non_default_records = [
                    r for r in records if r['Type'] not in ('SOA', 'NS')
                ]

                if not non_default_records:  # Zone is idle
                    row_data = [self.profile,"global",zone_id,name,record_count,self.timestamp]
                    self.write_csv_row(row_data, OUTPUT_FILE)

        except botocore.exceptions.ClientError as e:
            print(f"Error checking Route 53 zones: {e}")
        except Exception as e:
            print(f"General error checking Route 53: {e}")

    def snapshots_not_tied_to_ami_or_volume(self):

        OUTPUT_FILE = f"{self.profile}/OrphanedSnapshots_{self.timestamp}.csv"
        headers = ["Profile", "Region", "SnapshotId", "Description", "State", "StartTime", "VolumeId", "GeneratedOn"]
        self.setup_csv(self.profile, f"OrphanedSnapshots_{self.timestamp}.csv", headers)

        for region in self.regions:
            try:
                ec2 = self.session.client('ec2', region_name=region)

                # Get all snapshots owned by this account
                snapshots = ec2.describe_snapshots(OwnerIds=['self'])['Snapshots']

                for snap in snapshots:
                    volume_id = snap.get('VolumeId')

                    # If snapshot is not linked to a volume
                    if not volume_id:
                        row_data = [self.profile,region,snap['SnapshotId'],snap.get('Description', ''),snap.get('State', ''),snap.get('StartTime').strftime("%Y-%m-%d %H:%M:%S"),'No associated volume',self.timestamp]
                        self.write_csv_row(row_data, OUTPUT_FILE)

            except botocore.exceptions.ClientError as e:
                error_code = e.response['Error']['Code']
                if error_code in ('AuthFailure', 'UnauthorizedOperation', 'InvalidClientTokenId'):
                    print(f"Skipping region {region} due to authentication failure or inactive region/account.")
                else:
                    print(f"Unexpected error in region {region}: {e}")
            except Exception as e:
                print(f"General error in region {region}: {e}")

    def list_unused_kms_keys(self):

        days = 30  # give the days here 
        cutoff = datetime.now(timezone.utc) - timedelta(days=days)

        OUTPUT_FILE = f"{self.profile}/UnusedKMSKeys_{self.timestamp}.csv"
        headers = ["Profile", "Region", "KeyId", "AliasName", "KeyState", "CreationDate", "LastUsedDate", "GeneratedOn"]
        self.setup_csv(self.profile, f"UnusedKMSKeys_{self.timestamp}.csv", headers)

        for region in self.regions:
            try:
                kms = self.session.client('kms', region_name=region)
                paginator = kms.get_paginator('list_keys')

                for page in paginator.paginate():
                    keys = page.get('Keys', [])
                    for key in keys:
                        key_id = key['KeyId']
                        meta = kms.describe_key(KeyId=key_id)['KeyMetadata']
                        last_used = meta.get('LastUsedDate')
                        aliases_resp = kms.list_aliases(KeyId=key_id)
                        aliases = [a['AliasName'] for a in aliases_resp.get('Aliases', [])]

                        if not last_used or last_used < cutoff:
                            row_data = [self.profile,region,key_id,', '.join(aliases) if aliases else '',meta['KeyState'],meta['CreationDate'].strftime("%Y-%m-%d %H:%M:%S"),last_used.strftime("%Y-%m-%d %H:%M:%S") if last_used else "Never Used",self.timestamp ]
                            self.write_csv_row(row_data, OUTPUT_FILE)

            except Exception as e:
                print(f"Error in region {region} while checking KMS keys: {e}")
