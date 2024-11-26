import json
from constructs import Construct
from cdktf import App, TerraformStack, TerraformOutput
from imports.aws import EcrRepository, EksCluster, EksNodeGroup, IamRole, S3Bucket, RdsCluster
from imports.aws import AwsProvider

# Load configuration from config.json
with open('config.json') as config_file:
    config = json.load(config_file)

class EcrRepositoryConstruct(Construct):
    def __init__(self, scope: Construct, id: str, name: str):
        super().__init__(scope, id)
        self.repository = EcrRepository(self, name, name=name)

class EksClusterConstruct(Construct):
    def __init__(self, scope: Construct, id: str, cluster_name: str, node_role_arn: str, subnet_ids: list, scaling_config: dict):
        super().__init__(scope, id)
        self.cluster = EksCluster(self, cluster_name, name=cluster_name)
        self.node_group = EksNodeGroup(self, f"{cluster_name}NodeGroup",
                                       cluster_name=self.cluster.name,
                                       node_role_arn=node_role_arn,
                                       subnet_ids=subnet_ids,
                                       scaling_config=scaling_config,
                                       instance_types=["t2.micro"])

class S3BucketConstruct(Construct):
    def __init__(self, scope: Construct, id: str, bucket_name: str):
        super().__init__(scope, id)
        self.bucket = S3Bucket(self, bucket_name, bucket=bucket_name)

class RdsClusterConstruct(Construct):
    def __init__(self, scope: Construct, id: str, cluster_name: str):
        super().__init__(scope, id)
        self.cluster = RdsCluster(self, cluster_name, cluster_identifier=cluster_name)

class MyStack(TerraformStack):
    def __init__(self, scope: Construct, id: str):
        super().__init__(scope, id)

        AwsProvider(self, "AWS", region="us-west-2")

        # ECR Repository
        ecr_repo = EcrRepositoryConstruct(self, "EcrRepo", name="my-ecr-repo")

        # S3 Bucket
        reports_bucket = S3BucketConstruct(self, "ReportsBucket", bucket_name="my-reports-bucket")

        # RDS Cluster
        rds_cluster = RdsClusterConstruct(self, "RdsCluster", cluster_name="my-rds-cluster")

        # IAM Role for EKS Node Group
        eks_node_role = IamRole(self, "EksNodeRole", name="eks-node-role",
                                assume_role_policy=json.dumps({
                                    "Version": "2012-10-17",
                                    "Statement": [{
                                        "Action": "sts:AssumeRole",
                                        "Effect": "Allow",
                                        "Principal": {"Service": "ec2.amazonaws.com"}
                                    }]
                                }))

        # EKS Clusters and Node Groups
        eks_clusters = {}
        for alias, cluster_config in config['eks_clusters'].items():
            eks_clusters[alias] = EksClusterConstruct(
                self,
                f"{alias.capitalize()}EksCluster",
                cluster_name=cluster_config['cluster_name'],
                node_role_arn=eks_node_role.arn,
                subnet_ids=cluster_config['subnet_ids'],
                scaling_config=cluster_config['scaling_config']
            )

        # Outputs
        for alias, eks_cluster in eks_clusters.items():
            TerraformOutput(self, f"{alias}_eks_cluster_name", value=eks_cluster.cluster.name)

        TerraformOutput(self, 'reports_bucket_name', value=reports_bucket.bucket.bucket)
        TerraformOutput(self, 'rds_cluster_endpoint', value=rds_cluster.cluster.endpoint)
        TerraformOutput(self, 'ecr_repository_url', value=ecr_repo.repository.repository_url)

app = App()
MyStack(app, "cdktf-eks-cluster")
app.synth()