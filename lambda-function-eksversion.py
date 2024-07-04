import json
import boto3
import logging

logger = logging.getLogger()
logger.setLevel(logging.INFO)

sns = boto3.client('sns')
eks = boto3.client('eks')

def lambda_handler(event, context):
    try:
        # Extract relevant details (same as before)
        finding_title = event["detail"]["findings"][0]["Title"]
        account_id = event["detail"]["findings"][0]["AwsAccountId"]
        region = event["detail"]["findings"][0]["Region"]
        severity = event["detail"]["findings"][0]["Severity"]["Label"]
        finding_types = ", ".join(event["detail"]["findings"][0]["Types"])
        description = event["detail"]["findings"][0]["Description"]

        # Find EKS cluster ARN in the Security Hub finding (adjust if needed)
        eks_cluster_arn = None
        for resource in event["detail"]["findings"][0].get("Resources", []):
            if resource["Type"] == "AwsEksCluster":
                eks_cluster_arn = resource["Id"]
                break

        if eks_cluster_arn:
            # Get cluster name from EKS
            cluster_description = eks.describe_cluster(name=eks_cluster_arn.split("/")[-1])
            cluster_name = cluster_description["cluster"]["name"]
        else:
            cluster_name = "Unknown Cluster"
            logger.warning("EKS Cluster ARN not found in Security Hub finding")

        # Format message (with cluster name and extended support message)
        message = (
            f"Security Alert!\n"
            f"Finding: {finding_title}\n"
            f"Cluster Name: {cluster_name}\n"
            f"Account: {account_id}\n"
            f"Region: {region}\n"
            f"Severity: {severity}\n"
            f"Types: {finding_types}\n"
            f"Description: {description}\n"
            f"***WARNING***\n"  # Added extended support message
            f"Extended support until October 11, 2024\n"  # Added extended support message
        )

        # Publish to SNS Topic
        # Can be an Environment variables
        sns_topic_arn = "arn:aws:sns:us-east-1:0000000000:Eks-Version-NonComplianceAlerts"  

        sns.publish(
            TopicArn=sns_topic_arn,
            Message=message,
            Subject="Security Hub Finding Alert", # Optional subject for the email
        )
        
        logger.info(f"Message published to SNS topic: {sns_topic_arn}")

    except KeyError as e:
        logger.error(f"KeyError: Missing key '{e}' in event data.")
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
