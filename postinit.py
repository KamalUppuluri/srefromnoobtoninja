import json
import subprocess
import logging

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def run_command(command):
    """Run a shell command and return the output."""
    try:
        result = subprocess.run(command, shell=True, check=True, capture_output=True, text=True)
        return result.stdout.strip()
    except subprocess.CalledProcessError as e:
        logging.error(f"Error executing command: {e}")
        logging.error(f"Output: {e.output}")
        return None

def create_eks_clusters_from_config(config_file):
    # Load configuration
    with open(config_file) as f:
        config = json.load(f)

    node_group_config = config.get("node_group", {})
    desired_size = node_group_config.get("desired_size", 2)
    max_size = node_group_config.get("max_size", 2)
    min_size = node_group_config.get("min_size", 1)

    for cluster in config.get("eks_clusters", []):
        cluster_name = cluster.get("name")
        alias = cluster.get("alias")

        # Generate eksctl command
        eksctl_command = (
            f"eksctl create cluster "
            f"--name {cluster_name} "
            f"--region us-west-1 "  # Specify the region as needed
            f"--nodegroup-name {alias}-nodegroup "
            f"--nodes {desired_size} "
            f"--nodes-min {min_size} "
            f"--nodes-max {max_size} "
            f"--node-type t2.micro  --verbose 4"  # Specify the instance type as needed
        )

        # Run eksctl command
        logging.info(f"Creating EKS cluster: {cluster_name}")
        output = run_command(eksctl_command)
        if output:
            logging.info(f"Cluster {cluster_name} created successfully.")
            logging.info(output)

            # Output cluster details
            logging.info(f"Cluster Name: {cluster_name}")
            logging.info(f"Node Group Name: {alias}nodegroup")
            logging.info(f"Desired Size: {desired_size}")
            logging.info(f"Max Size: {max_size}")
            logging.info(f"Min Size: {min_size}")
        else:
            logging.error(f"Failed to create cluster {cluster_name}.")

# Example usage
create_eks_clusters_from_config('config.json')