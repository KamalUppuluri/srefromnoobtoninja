


import json
import base64
import boto3
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')




#from aws_cdk import Fn
#from aws_cdk.aws_eks import Cluster, KubernetesManifest
#from aws_cdk.aws_iam import Role, ServicePrincipal, ManagedPolicy



#from kubernetes import client, config
from constructs import Construct
from cdktf import App, TerraformStack, TerraformOutput, Fn
from cdktf_cdktf_provider_aws.provider import AwsProvider
from cdktf_cdktf_provider_aws.vpc import Vpc
from cdktf_cdktf_provider_aws.subnet import Subnet
from cdktf_cdktf_provider_aws.iam_role import IamRole
from cdktf_cdktf_provider_aws.iam_policy import IamPolicy
from cdktf_cdktf_provider_aws.iam_role_policy_attachment import IamRolePolicyAttachment
from cdktf_cdktf_provider_aws.s3_bucket import S3Bucket
from cdktf_cdktf_provider_aws.eks_cluster import EksCluster
from cdktf_cdktf_provider_aws.eks_node_group import EksNodeGroup
from cdktf_cdktf_provider_aws.ecr_repository import EcrRepository
from cdktf_cdktf_provider_aws.rds_cluster import RdsCluster
from cdktf_cdktf_provider_aws.rds_cluster_instance import RdsClusterInstance
from cdktf_cdktf_provider_aws.secretsmanager_secret import SecretsmanagerSecret
from cdktf_cdktf_provider_aws.secretsmanager_secret_version import SecretsmanagerSecretVersion
from cdktf_cdktf_provider_aws.security_group import SecurityGroup, SecurityGroupIngress
from cdktf_cdktf_provider_aws.internet_gateway import InternetGateway
from cdktf_cdktf_provider_aws.route_table import RouteTable
from cdktf_cdktf_provider_aws.route import Route
from cdktf_cdktf_provider_aws.route_table_association import RouteTableAssociation
from cdktf_cdktf_provider_kubernetes.provider import KubernetesProvider
from cdktf_cdktf_provider_kubernetes.deployment import Deployment
from cdktf_cdktf_provider_kubernetes.service import Service,ServiceSpecPort
from cdktf_cdktf_provider_aws.lb import Lb
from cdktf_cdktf_provider_aws import db_subnet_group
from cdktf_cdktf_provider_aws.iam_policy import IamPolicy


from dotenv import load_dotenv
from eks_token import get_token
import os
import subprocess


# Load environment variables from .env file
load_dotenv()


def run_kubectl_command(command):
    """Run a kubectl command and return the output."""
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
        print(f"Output: {e.output}")
        return None
    

def create_managed_node_group(self,cluster_name, nodegroup_name, subnets, node_role_arn):
    # Create an EKS Node Group using CDKTF
    EksNodeGroup(self, f"{nodegroup_name}NodeGroup",
        cluster_name=cluster_name,
        node_group_name=nodegroup_name,
        node_role_arn=node_role_arn,
        subnet_ids=subnets,
        scaling_config={
            'min_size': 1,
            'max_size': 3,
            'desired_size': 2
        },
        instance_types=['t3.micro'],
        ami_type='AL2_x86_64',
        labels={
            'role': 'worker'
        },
        tags={
            'Name': f'{cluster_name}-nodegroup'
        }
    )    

def create_managed_node_group_2(cluster_name, nodegroup_name, subnets, node_role_arn):
    # Convert TfToken to string if necessary
    nodegroup_name_str = Fn.tostring(nodegroup_name)
    subnets_str = [Fn.tostring(subnet) for subnet in subnets]
    node_role_arn_str = Fn.tostring(node_role_arn)
    
    # Example command to create a node group using kubectl
    command = f"kubectl create nodegroup {nodegroup_name_str} --cluster {cluster_name} --role {node_role_arn_str} --subnets {','.join(subnets_str)}"
    output = run_kubectl_command(command)
    if output:
        print(f"Managed Node Group {nodegroup_name_str} creation initiated.")
    else:
        print(f"Failed to create Managed Node Group {nodegroup_name_str}.")
def get_eks_token(cluster_name):
    #eks_client = boto3.client('eks')
    #response = eks_client.get_token(clusterName=cluster_name)
    token = get_token(cluster_name=cluster_name)['status']['token']
    return token

def wait_for_clusters_to_be_active(cluster_names):
    eks_client = boto3.client('eks')
    for cluster_name in cluster_names:
        while True:
            response = eks_client.describe_cluster(name=cluster_name)
            status = response['cluster']['status']
            if status == 'ACTIVE':
                print(f"Cluster {cluster_name} is active.")
                break
            else:
                print(f"Waiting for cluster {cluster_name} to become active. Current status: {status}")
                time.sleep(30)  # Wait for 30 seconds before checking again



def update_aws_auth_configmap_for_all_clusters_2(theClusters):
    # Initialize the EKS client
    eks_client = boto3.client('eks')

    # List all EKS clusters
    #clusters = eks_client.list_clusters()['clusters']

    # Get the current AWS user
    sts_client = boto3.client('sts')
    current_user_arn = sts_client.get_caller_identity()["Arn"]

    for cluster_name in theClusters:
        # Get the cluster details
        cluster_info = eks_client.describe_cluster(name=cluster_name)
        cluster_endpoint = cluster_info['cluster']['endpoint']
        cluster_cert = cluster_info['cluster']['certificateAuthority']['data']

        # Load kubeconfig for the cluster
        configuration = client.Configuration()
        configuration.host = cluster_endpoint
        configuration.verify_ssl = True

        # Decode the base64 certificate and write it to a temporary file
        cert_file = "/tmp/eks_cert.pem"
        with open(cert_file, "w") as f:
            f.write(base64.b64decode(cluster_cert).decode('utf-8'))
        configuration.ssl_ca_cert = cert_file

        configuration.api_key = {"authorization": f"Bearer {get_eks_token(cluster_name)}"}
        client.Configuration.set_default(configuration)

        # Create a Kubernetes API client
        v1 = client.CoreV1Api()

        try:
            # Get the aws-auth ConfigMap
            config_map = v1.read_namespaced_config_map("aws-auth", "kube-system")

            # Check if the user is already in the mapUsers
            map_users = config_map.data.get("mapUsers", "[]")
            map_users_list = json.loads(map_users)
            user_exists = any(user['userarn'] == current_user_arn for user in map_users_list)

            if not user_exists:
                # Add the current user to the mapUsers section
                map_users_list.append({
                    "userarn": current_user_arn,
                    "username": "admin",
                    "groups": ["system:masters"]
                })
                config_map.data["mapUsers"] = json.dumps(map_users_list)

                # Update the ConfigMap
                v1.replace_namespaced_config_map("aws-auth", "kube-system", config_map)
                print(f"Added {current_user_arn} to aws-auth ConfigMap for cluster {cluster_name}.")
            else:
                print(f"{current_user_arn} is already present in aws-auth ConfigMap for cluster {cluster_name}.")
        except ApiException as e:
            print(f"Exception when updating aws-auth ConfigMap for cluster {cluster_name}: {e}")




    
def get_current_user_role_name():
    # Initialize the STS client
    sts_client = boto3.client('sts')

    # Get the current user's ARN
    current_user_arn = sts_client.get_caller_identity()["Arn"]

    print("arn is:",current_user_arn)
    return "fullstackappuser"
    # Check if the ARN is for a role
    if ":role/" in current_user_arn:
        # Extract the role name from the ARN
        role_name = e
        return role_name
    #else:
    #    raise Exception("The current user is not using an IAM role.")

# Function to get the current AWS account ID
def get_account_id():
    sts_client = boto3.client('sts')
    account_id = sts_client.get_caller_identity()["Account"]
    return account_id

# Load configuration
with open('config.json') as config_file:
    config = json.load(config_file)

class MyStack(TerraformStack):

    def update_aws_auth_configmap_for_all_clusters( self,clusters, currentRole):
        for cluster_alias, cluster in clusters.items():
            # Import an existing IAM role by name
            #currentRole= get_current_user_role_name()

            role = Role.from_role_name(self, 'admin-role', currentRole)

            # Add role mapping to the aws-auth ConfigMap
            cluster.aws_auth.add_role_mapping(role, groups=['system:masters'])
    def __init__(self, scope: Construct, id: str):
        super().__init__(scope, id)

        # Add the AWS provider
        AwsProvider(self, "Aws", region="us-east-1")
        # Get the current AWS account ID
        account_id = get_account_id()


         # Create a VPC
        vpc = Vpc(self, 'Vpc', cidr_block='10.0.0.0/16')

        # Create an Internet Gateway
        internet_gateway = InternetGateway(self, 'InternetGateway', vpc_id=vpc.id)

        # Create a Route Table for the public subnets
        public_route_table = RouteTable(self, 'PublicRouteTable', vpc_id=vpc.id)

        # Create a route to the Internet Gateway
        Route(self, 'RouteToInternet', route_table_id=public_route_table.id, destination_cidr_block='0.0.0.0/0', gateway_id=internet_gateway.id)

        # Create subnets
       # Create subnets with auto-assign public IP enabled
        subnet1 = Subnet(self, 'Subnet1', 
            vpc_id=vpc.id, 
            cidr_block='10.0.1.0/24', 
            availability_zone='us-east-1a',
            map_public_ip_on_launch=True,  # Enable auto-assign public IP
            tags={
            'kubernetes.io/role/elb': '1'
        })
        

        subnet2 = Subnet(self, 'Subnet2', vpc_id=vpc.id, cidr_block='10.0.2.0/24', availability_zone='us-east-1b', map_public_ip_on_launch=True, tags={
            'kubernetes.io/role/internal-elb': '1'
        })
        # Associate the public subnets with the Route Table
        RouteTableAssociation(self, 'Subnet1RouteTableAssociation', subnet_id=subnet1.id, route_table_id=public_route_table.id)
        RouteTableAssociation(self, 'Subnet2RouteTableAssociation', subnet_id=subnet2.id, route_table_id=public_route_table.id)

        # Create a security group for EKS clusters
        eks_security_group = SecurityGroup(self, 'EksSecurityGroup', vpc_id=vpc.id, description='EKS Security Group')
        eks_security_group.put_ingress([SecurityGroupIngress(from_port=0, to_port=0, protocol="-1", cidr_blocks=['0.0.0.0/0'])])

        eks_role = IamRole(self, 'EksRole', assume_role_policy='''{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "eks.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        }''')

        eks_node_role = IamRole(self, 'EksNodeRole', assume_role_policy='''{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {
                        "Service": "ec2.amazonaws.com"
                    },
                    "Action": "sts:AssumeRole"
                }
            ]
        }''')

        print("account_id is :",account_id)
        # Define the IAM policy for PassRole dynamically
        pass_role_policy = IamPolicy(self, 'PassRolePolicy', policy=f'''{{
            "Version": "2012-10-17",
            "Statement": [
                {{
                    "Effect": "Allow",
                    "Action": "iam:PassRole",
                    "Resource": "arn:aws:iam::{account_id}:role/{eks_node_role.name}"
                }}
            ]
        }}''')

        # Attach the PassRole policy to the role used by your application
        IamRolePolicyAttachment(self, 'PassRolePolicyAttachment', role=eks_node_role.name, policy_arn=pass_role_policy.arn)

        # Create a policy for S3 access
        s3_access_policy = IamPolicy(self, 'S3AccessPolicy', policy='''{
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:*",
                    "Resource": "arn:aws:s3:::reports/*"
                }
            ]
        }''')

        # Attach S3 access policy to the EKS node role
        IamRolePolicyAttachment(self, 'S3AccessPolicyAttachment', role=eks_node_role.name, policy_arn=s3_access_policy.arn)

        # Attach policies to roles
       # Attach policies to roles
        IamRolePolicyAttachment(self, 'EksPolicyAttachment', role=eks_role.name, policy_arn='arn:aws:iam::aws:policy/AmazonEKSClusterPolicy')
        IamRolePolicyAttachment(self, 'EksNodePolicyAttachment', role=eks_node_role.name, policy_arn='arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy')
        IamRolePolicyAttachment(self, 'CloudWatchPolicyAttachment', role=eks_role.name, policy_arn="arn:aws:iam::aws:policy/CloudWatchLogsFullAccess")

        # Add AmazonEKSWorkerNodePolicy to the EksNodeRole
        IamRolePolicyAttachment(self, 'EksNodeWorkerNodePolicyAttachment', role=eks_node_role.name, policy_arn='arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy')
        # Create EKS clusters for each microservice
        eks_clusters = {}
        #for cluster in config['eks_clusters']:
            #eks_clusters[cluster['alias']] = EksCluster(self, f"{cluster['alias'].capitalize()}EksCluster", name=cluster['name'], role_arn=eks_role.arn, vpc_config={
            #   'subnet_ids': [subnet1.id, subnet2.id],
            #    'security_group_ids': [eks_security_group.id],
                
            #})

        # Outputs
        #for alias, eks_cluster in eks_clusters.items():
        #    TerraformOutput(self, f"{alias}_eks_cluster_name", value=eks_cluster.name)

        #TerraformOutput(self, 'reports_bucket_name', value=reports_bucket.bucket)
        #TerraformOutput(self, 'rds_cluster_endpoint', value=rds_cluster.endpoint)
        #TerraformOutput(self, 'ecr_repository_url', value=ecr_repository.repository_url)

        # Wait for all clusters to be active
        #wait_for_clusters_to_be_active([cluster['name'] for cluster in config['eks_clusters']])


        #update_aws_auth_configmap_for_all_clusters_2(  cluster['name']  for cluster in config['eks_clusters'])
        
        # Create an S3 bucket named 'reports'
        #reports_bucket = S3Bucket(self, 'ReportsBucket', bucket=config['s3_bucket']['name'])

        # Create a DB subnet group for the RDS instance
        the_db_subnet_group = db_subnet_group.DbSubnetGroup(self, 'DbSubnetGroup',
            name='db-subnet-group',
            subnet_ids=[subnet1.id, subnet2.id],
            description='Subnet group for RDS instance'
        )

        # Create a secret in AWS Secrets Manager
        #rds_password_secret = SecretsmanagerSecret(self, 'RdsPasswordSecret', name='springboot-django-rds-password')
        #SecretsmanagerSecretVersion(self, 'RdsPasswordSecretVersion', secret_id=rds_password_secret.id, secret_string=json.dumps({"password": os.getenv('RDS_PASSWORD')}))

        # Create an Aurora RDS MySQL database
        rds_cluster = RdsCluster(self, 'RdsCluster', engine='aurora-mysql', master_username=config['rds']['username'], master_password=os.getenv('RDS_PASSWORD'), vpc_security_group_ids=[eks_security_group.id], db_subnet_group_name=the_db_subnet_group.name)

        # Create an ECR repository
        #ecr_repository = EcrRepository(self, config['ecrRepo']['name'], name=config['ecrRepo']['name'])

        # Create EKS node groups for each cluster
        for cluster in config['eks_clusters']:
         print(cluster)
         try:
          logging.info(f"Creating EKS Node Group for cluster: {cluster['alias']}")
          # Uncomment and use the following line to create the node group
          #EksNodeGroup(self, f"{cluster['alias'].capitalize()}NodeGroup", cluster_name=eks_clusters[cluster['alias']].name, node_role_arn=eks_node_role.arn, subnet_ids=[subnet1.id, subnet2.id], scaling_config=config['node_group'], ami_type="AL2_x86_64", instance_types=["t2.micro"])
          logging.info(f"Successfully created EKS Node Group for cluster: {cluster['alias']}")
         except Exception as e:
           logging.error(f"Failed to create EKS Node Group for cluster: {cluster['alias']}. Error: {e}")
        
        TerraformOutput(self, 'subnets', value=','.join([subnet1.id, subnet2.id]))
        TerraformOutput(self, 'node_role_arn', value=eks_node_role.arn)
        TerraformOutput(self, 'security_groups', value=eks_security_group.id)
        
        '''
        node_role_arn               = "arn:aws:iam::711387112361:role/terraform-20241203193434369600000003"
                     + subnets                     = "subnet-03c2566da24a7ae90,subnet-0e10eab65819cb0e4"
        '''


        
        # Retrieve EKS tokens and configure Kubernetes providers
        """ for alias, eks_cluster in eks_clusters.items():
            token = get_eks_token(eks_cluster.name)
            cert_value = Fn.base64decode(eks_cluster.certificate_authority.get(0).data)
            theProvider=KubernetesProvider(self, f"{alias.capitalize()}K8sProvider", host=eks_cluster.endpoint, token=token, cluster_ca_certificate=cert_value, alias=alias)
         """    #Service(self, f"{alias.capitalize()}Service", metadata={'name': f'{alias}-service'}, spec={
            #    'selector': {'app': alias},
            #    'port': [ServiceSpecPort(port=80, target_port='80')],
            #    'type': 'LoadBalancer'
            #}, provider=theProvider)


        # Define Kubernetes services for each application
        #for alias in eks_clusters.keys():
           


app = App()
MyStack(app, "cdktf-eks-cluster")
app.synth()

