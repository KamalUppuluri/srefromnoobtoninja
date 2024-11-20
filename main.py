


import json
import base64
import boto3
from constructs import Construct
from cdktf import App, TerraformStack, TerraformOutput
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
from cdktf_cdktf_provider_kubernetes.service import Service
from cdktf_cdktf_provider_aws.lb import Lb
from cdktf_cdktf_provider_aws import db_subnet_group


from dotenv import load_dotenv
import os

# Load environment variables from .env file
load_dotenv()

def get_eks_token(cluster_name):
    #eks_client = boto3.client('eks')
    #response = eks_client.get_token(clusterName=cluster_name)
    token = get_token(cluster_name=cluster_name)['status']['token']
    return token


# Load configuration
with open('config.json') as config_file:
    config = json.load(config_file)

class MyStack(Construct):
    def __init__(self, scope: Construct, id: str):
        super().__init__(scope, id)

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
        IamRolePolicyAttachment(self, 'EksPolicyAttachment', role=eks_role.name, policy_arn='arn:aws:iam::aws:policy/AmazonEKSClusterPolicy')
        IamRolePolicyAttachment(self, 'EksNodePolicyAttachment', role=eks_node_role.name, policy_arn='arn:aws:iam::aws:policy/AmazonEKSWorkerNodePolicy')

        # Create EKS clusters for each microservice
        eks_clusters = {}
        for cluster in config['eks_clusters']:
            eks_clusters[cluster['alias']] = EksCluster(self, f"{cluster['alias'].capitalize()}EksCluster", name=cluster['name'], role_arn=eks_role.arn, vpc_config={
                'subnet_ids': [subnet1.id, subnet2.id],
                'security_group_ids': [eks_security_group.id],
            })

        # Create an S3 bucket named 'reports'
        reports_bucket = S3Bucket(self, 'ReportsBucket', bucket=config['s3_bucket']['name'])

        # Create a DB subnet group for the RDS instance
        the_db_subnet_group = db_subnet_group.DbSubnetGroup(self, 'DbSubnetGroup',
            name='db-subnet-group',
            subnet_ids=[subnet1.id, subnet2.id],
            description='Subnet group for RDS instance'
        )

        # Create a secret in AWS Secrets Manager
        rds_password_secret = SecretsmanagerSecret(self, 'RdsPasswordSecret', name='springboot-django-rds-password')
        SecretsmanagerSecretVersion(self, 'RdsPasswordSecretVersion', secret_id=rds_password_secret.id, secret_string=json.dumps({"password": os.getenv('RDS_PASSWORD')}))

        # Create an Aurora RDS MySQL database
        rds_cluster = RdsCluster(self, 'RdsCluster', engine='aurora-mysql', master_username=config['rds']['username'], master_password=os.getenv('RDS_PASSWORD'), vpc_security_group_ids=[eks_security_group.id], db_subnet_group_name=the_db_subnet_group.name)

        # Create an ECR repository
        ecr_repository = EcrRepository(self, config['ecrRepo']['name'], name=config['ecrRepo']['name'])

        # Create EKS node groups for each cluster
        for alias, eks_cluster in eks_clusters.items():
            EksNodeGroup(self, f"{alias.capitalize()}NodeGroup", cluster_name=eks_cluster.name, node_role_arn=eks_node_role.arn, subnet_ids=[subnet1.id, subnet2.id], scaling_config=config['node_group'])

        # Retrieve EKS tokens and configure Kubernetes providers
        for alias, eks_cluster in eks_clusters.items():
            token = get_eks_token(eks_cluster.name)
            cert_value = base64.b64decode(eks_cluster.certificate_authority.get(0).data)
            KubernetesProvider(self, f"{alias.capitalize()}K8sProvider", host=eks_cluster.endpoint, token=token, cluster_ca_certificate=cert_value, alias=alias)

        # Define Kubernetes services for each application
        for alias in eks_clusters.keys():
            Service(self, f"{alias.capitalize()}Service", metadata={'name': f'{alias}-service'}, spec={
                'selector': {'app': alias},
                'port': [ServiceSpecPort(port=80, target_port='80')],
                'type': 'LoadBalancer'
            }, provider=KubernetesProvider(self, f"{alias.capitalize()}K8sProvider"))

        # Outputs
        for alias, eks_cluster in eks_clusters.items():
            TerraformOutput(self, f"{alias}_eks_cluster_name", value=eks_cluster.name)

        TerraformOutput(self, 'reports_bucket_name', value=reports_bucket.bucket)
        TerraformOutput(self, 'rds_cluster_endpoint', value=rds_cluster.endpoint)
        TerraformOutput(self, 'ecr_repository_url', value=ecr_repository.repository_url)

app = App()
MyStack(app, "cdktf-eks-cluster")
app.synth()

