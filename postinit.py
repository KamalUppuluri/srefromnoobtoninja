import boto3 
import json

with open('config.json') as config_file:
    config = json.load(config_file)


def create_managed_node_group_old(cluster_name, nodegroup_name, subnets, node_role_arn):
    eks_client = boto3.client('eks')

    # Check if the node group already exists
    existing_nodegroups = eks_client.list_nodegroups(clusterName=cluster_name)['nodegroups']
    if nodegroup_name in existing_nodegroups:
        print(f"Node group {nodegroup_name} already exists in cluster {cluster_name}.")
        return eks_client.describe_nodegroup(clusterName=cluster_name, nodegroupName=nodegroup_name)

    # Create a new node group if it doesn't exist
    response = eks_client.create_nodegroup(
        clusterName=cluster_name,
        nodegroupName=nodegroup_name,
        scalingConfig={
            'minSize': 1,
            'maxSize': 3,
            'desiredSize': 2
        },
        diskSize=20,
        subnets=subnets,
        instanceTypes=['t2.micro'],
        nodeRole=node_role_arn,
        labels={
            'role': 'worker'
        },
        tags={
            'Name': f'{cluster_name}-nodegroup'
        }
    )

    print(f"Managed Node Group {nodegroup_name} creation initiated.")
    return response

for cluster in config['eks_clusters']:
            print(cluster)
            create_managed_node_group_old(
            cluster_name=cluster['name'],
            nodegroup_name=cluster['name']+'-nodegroupnew2',
            subnets=["subnet-03c2566da24a7ae90","subnet-0e10eab65819cb0e4"],
            node_role_arn="arn:aws:iam::711387112361:role/terraform-20241203193434369600000003"
            )
        