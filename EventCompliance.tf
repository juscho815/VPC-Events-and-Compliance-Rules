provider "aws" {
}

data "aws_caller_identity" "current" {}






data "aws_iam_policy_document" "s3-bucket-policy-forS3SharedBucket" {

  statement {
    actions = ["s3:GetBucketAcl"]
    effect = "Allow"
    resources = [aws_s3_bucket.S3SharedBucket.arn]
    principals {
      type = "Service"
      identifiers = ["cloudtrail.amazonaws.com","config.amazonaws.com"]
    }
  }
  statement {
    actions = ["s3:PutObject"]
    effect = "Allow"
    resources = [join("",["",aws_s3_bucket.S3SharedBucket.arn,"/*"])]
    principals {
      type = "Service"
      identifiers = ["cloudtrail.amazonaws.com","config.amazonaws.com"]
    }
    condition {
      test = "StringEquals"
      variable = "s3:x-amz-acl"
      values = ["bucket-owner-full-control"]
    }
  }
}
resource "aws_s3_bucket_policy" "BucketPolicy" {
  bucket = aws_s3_bucket.S3SharedBucket.id
  policy = data.aws_iam_policy_document.s3-bucket-policy-forS3SharedBucket.json
}

resource "aws_cloudtrail" "CloudTrail" {
  name = "ManagementEventsTrail"
  s3_bucket_name = aws_s3_bucket.S3SharedBucket.id
  is_multi_region_trail = true
  enable_log_file_validation = true
  cloud_watch_logs_group_arn = "CloudTrailLogs"
  cloud_watch_logs_role_arn = aws_iam_role.CwLogIamRole.arn
  depends_on = [ aws_s3_bucket_policy.BucketPolicy ]

  event_selector {
    include_management_events = true
    read_write_type = "All"
  }
}

resource "aws_iam_role" "CwLogIamRole" {
  assume_role_policy = jsonencode(
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": ["cloudtrail.amazonaws.com"]
      },
      "Effect": "Allow",
    }
  ]
}
)
}

resource "aws_iam_role_policy" "CwLogIamRoleInlinePolicyRoleAttachment0" {
  name = "allow-access-to-cw-logs"
  role = aws_iam_role.CwLogIamRole.id
  policy = jsonencode(
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "logs:CreateLogStream",
                "logs:PutLogEvents"
            ],
            "Resource": "*"
        }
    ]
}
)
}





resource "aws_cloudwatch_log_group" "CWLogGroupForCloudTrail" {
  name = "CloudTrailLogs"
  retention_in_days = 90
}

resource "aws_config_configuration_recorder" "ConfigurationRecorder" {
  role_arn = aws_iam_role.ConfigIamRole.arn

  recording_group {
    all_supported = true
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "DeliveryChannel" {
  s3_bucket_name = aws_s3_bucket.S3SharedBucket.id
  depends_on = [ aws_config_configuration_recorder.ConfigurationRecorder ]
}

resource "aws_config_configuration_recorder_status" "ConfigurationRecorderStatus" {
  name = aws_config_configuration_recorder.ConfigurationRecorder.name
  is_enabled = true
  depends_on = [ aws_config_delivery_channel.DeliveryChannel ]
}

resource "aws_iam_role" "ConfigIamRole" {
  name = "iamRoleForAWSConfig"
  assume_role_policy = jsonencode(
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": ["config.amazonaws.com"]
      },
      "Effect": "Allow",
    }
  ]
}
)
}

resource "aws_iam_role_policy_attachment" "ConfigIamRoleManagedPolicyRoleAttachment0" {
  role = aws_iam_role.ConfigIamRole.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSConfigRole"
}

resource "aws_iam_role_policy" "ConfigIamRoleInlinePolicyRoleAttachment0" {
  name = "allow-access-to-config-s3-bucket"
  role = aws_iam_role.ConfigIamRole.id
  policy = jsonencode(
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:PutObject"
            ],
            "Resource": [
                "arn:aws:s3:::s3-bucket-random-name-FApgg/*"
            ],
            "Condition": {
                "StringLike": {
                    "s3:x-amz-acl": "bucket-owner-full-control"
                }
            }
        },
        {
            "Effect": "Allow",
            "Action": [
                "s3:GetBucketAcl"
            ],
            "Resource": "arn:aws:s3:::s3-bucket-random-name-FApgg"
        }
    ]
}
)
}





resource "aws_s3_bucket" "S3SharedBucket" {
  bucket = "s3-bucket-random-name-shqkBBHkXvVutGY"
  acl = "log-delivery-write"

  server_side_encryption_configuration {
    rule {
      apply_server_side_encryption_by_default {
        sse_algorithm = "AES256"
      }
    }
  }

  logging {
    target_bucket = "s3-bucket-random-name-shqkBBHkXvVutGY"
    target_prefix = ""
  }
}

resource "aws_s3_bucket_public_access_block" "blockPublicAccess" {
  bucket = aws_s3_bucket.S3SharedBucket.id
  block_public_acls = true
  block_public_policy = true
  ignore_public_acls = true
  restrict_public_buckets = true
  depends_on = [ aws_s3_bucket_policy.BucketPolicy ]
}

module "SnsTopic1" {
  source = "github.com/asecurecloud/tf_sns_email"

  display_name = "sns-topic"
  email_address = "email@example.com"
  stack_name = "tf-cfn-stack-SnsTopic1-RWodX"
}



resource "aws_config_config_rule" "ConfigRule1" {
  name = "restricted-ssh"
  description = "A Config rule that checks whether security groups in use do not allow restricted incoming SSH traffic. This rule applies only to IPv4."
  depends_on = [ aws_config_configuration_recorder.ConfigurationRecorder ]

  source {
    owner = "AWS"
    source_identifier = "INCOMING_SSH_DISABLED"
  }
  scope {
    compliance_resource_types = ["AWS::EC2::SecurityGroup"]
  }
}

resource "aws_config_config_rule" "ConfigRule2" {
  name = "restricted-common-ports"
  description = "A Config rule that checks whether security groups in use do not allow restricted incoming TCP traffic to the specified ports. This rule applies only to IPv4."
  input_parameters = "{\"blockedPort1\":\"20\",\"blockedPort2\":\"21\",\"blockedPort3\":\"3389\",\"blockedPort4\":\"3306\",\"blockedPort5\":\"4333\"}"
  depends_on = [ aws_config_configuration_recorder.ConfigurationRecorder ]

  source {
    owner = "AWS"
    source_identifier = "RESTRICTED_INCOMING_TRAFFIC"
  }
  scope {
    compliance_resource_types = ["AWS::EC2::SecurityGroup"]
  }
}

resource "aws_config_config_rule" "ConfigRule3" {
  name = "ec2_vpc_public_subnet"
  description = "A Config rule that checks that no EC2 Instances are in Public Subnet."
  depends_on = [ aws_config_configuration_recorder.ConfigurationRecorder,aws_lambda_permission.LambdaPermissionConfigRule3 ]

  scope {
    compliance_resource_types = ["AWS::EC2::Instance"]
  }
  source {
    owner = "CUSTOM_LAMBDA"
    source_identifier = aws_lambda_function.LambdaFunctionConfigRule3.arn
    source_detail {
      event_source = "aws.config"
      message_type = "ConfigurationItemChangeNotification"
    }
    source_detail {
      event_source = "aws.config"
      message_type = "OversizedConfigurationItemChangeNotification"
    }
  }
}

data "archive_file" "lambda_zip_inline_LambdaFunctionConfigRule3" {
  type = "zip"
  output_path = "/tmp/lambda_zip_inlinetmpfileLambdaFunctionConfigRule3.zip"

  source {
    filename = "index.py"
    content = <<EOF

#
# This file made available under CC0 1.0 Universal (https://creativecommons.org/publicdomain/zero/1.0/legalcode)
#
# Description: Check that no EC2 Instances are in Public Subnet
#
# Trigger Type: Change Triggered
# Scope of Changes: EC2:Instance
# Accepted Parameters: None
# Your Lambda function execution role will need to have a policy that provides the appropriate
# permissions.  Here is a policy that you can consider.  You should validate this for your own
# environment
#{
#    "Version": "2012-10-17",
#    "Statement": [
#        {
#            "Effect": "Allow",
#            "Action": [
#                "logs:CreateLogGroup",
#                "logs:CreateLogStream",
#                "logs:PutLogEvents"
#            ],
#            "Resource": "arn:aws:logs:*:*:*"
#        },
#        {
#            "Effect": "Allow",
#            "Action": [
#                "config:PutEvaluations",
#                "ec2:DescribeRouteTables"
#            ],
#            "Resource": "*"
#        }
#    ]
#}
#

import boto3
import botocore
import json
import logging

log = logging.getLogger()
log.setLevel(logging.INFO)

def evaluate_compliance(configuration_item):
    subnet_id   = configuration_item["configuration"]["subnetId"]
    vpc_id      = configuration_item["configuration"]["vpcId"]
    client      = boto3.client("ec2");

    response    = client.describe_route_tables()

    # If the subnet is explicitly associated to a route table, check if there
    # is a public route. If no explicit association exists, check if the main
    # route table has a public route.

    private = True
    mainTableIsPublic = False
    noExplicitAssociationFound = True
    explicitAssocationIsPublic = False

    for i in response['RouteTables']:
        if i['VpcId'] == vpc_id:
            for j in i['Associations']:
                if j['Main'] == True:
                    for k in i['Routes']:
                        if k['DestinationCidrBlock'] == '0.0.0.0/0' or k['GatewayId'].startswith('igw-'):
                            mainTableIsPublic = True
                else:
                    if j['SubnetId'] == subnet_id:
                        noExplicitAssociationFound = False
                        for k in i['Routes']:
                            if k['DestinationCidrBlock'] == '0.0.0.0/0' or k['GatewayId'].startswith('igw-'):
                                explicitAssocationIsPublic = True

    if (mainTableIsPublic and noExplicitAssociationFound) or explicitAssocationIsPublic:
        private = False

    if private:
        return {
            "compliance_type": "COMPLIANT",
            "annotation": 'Its in private subnet'
        }
    else:
        return {
            "compliance_type" : "NON_COMPLIANT",
            "annotation" : 'Not in private subnet'
        }

def lambda_handler(event, context):
    log.debug('Event %s', event)
    invoking_event      = json.loads(event['invokingEvent'])
    configuration_item  = invoking_event["configurationItem"]
    evaluation          = evaluate_compliance(configuration_item)
    config              = boto3.client('config')

    response = config.put_evaluations(
       Evaluations=[
           {
               'ComplianceResourceType':    invoking_event['configurationItem']['resourceType'],
               'ComplianceResourceId':      invoking_event['configurationItem']['resourceId'],
               'ComplianceType':            evaluation["compliance_type"],
               "Annotation":                evaluation["annotation"],
               'OrderingTimestamp':         invoking_event['configurationItem']['configurationItemCaptureTime']
           },
       ],
       ResultToken=event['resultToken'])

EOF

  }
}

resource "aws_lambda_function" "LambdaFunctionConfigRule3" {
  function_name = "LambdaFunctionForec2_vpc_public_subnet"
  timeout = "300"
  runtime = "python3.6"
  handler = "index.lambda_handler"
  role = aws_iam_role.LambdaIamRoleConfigRule3.arn
  filename = data.archive_file.lambda_zip_inline_LambdaFunctionConfigRule3.output_path
  source_code_hash = data.archive_file.lambda_zip_inline_LambdaFunctionConfigRule3.output_base64sha256
}

resource "aws_lambda_permission" "LambdaPermissionConfigRule3" {
  action = "lambda:InvokeFunction"
  function_name = aws_lambda_function.LambdaFunctionConfigRule3.function_name
  principal = "config.amazonaws.com"
}

resource "aws_iam_role" "LambdaIamRoleConfigRule3" {
  name = "IamRoleForec2_vpc_public_subnet"
  assume_role_policy = jsonencode(
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": "sts:AssumeRole",
      "Principal": {
        "Service": ["lambda.amazonaws.com"]
      },
      "Effect": "Allow",
    }
  ]
}
)
}

resource "aws_iam_role_policy_attachment" "LambdaIamRoleConfigRule3ManagedPolicyRoleAttachment0" {
  role = aws_iam_role.LambdaIamRoleConfigRule3.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonEC2ReadOnlyAccess"
}

resource "aws_iam_role_policy_attachment" "LambdaIamRoleConfigRule3ManagedPolicyRoleAttachment1" {
  role = aws_iam_role.LambdaIamRoleConfigRule3.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSConfigRulesExecutionRole"
}

resource "aws_iam_role_policy_attachment" "LambdaIamRoleConfigRule3ManagedPolicyRoleAttachment2" {
  role = aws_iam_role.LambdaIamRoleConfigRule3.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole"
}





resource "aws_cloudwatch_event_rule" "CwEvent1" {
  name = "detect-config-rule-compliance-changes"
  description = "A CloudWatch Event Rule that detects changes to AWS Config Rule compliance status and publishes change events to an SNS topic for notification."
  is_enabled = true
  event_pattern = <<PATTERN
{
  "detail-type": [
    "Config Rules Compliance Change"
  ],
  "source": [
    "aws.config"
  ]
}
PATTERN

}

resource "aws_cloudwatch_event_target" "TargetForCwEvent1" {
  rule = aws_cloudwatch_event_rule.CwEvent1.name
  target_id = "target-id1"
  arn = module.SnsTopic1.arn
}

data "aws_iam_policy_document" "topic-policy-PolicyForSnsTopic" {
  policy_id = "__default_policy_ID"

  statement {
    actions = [
      "SNS:GetTopicAttributes",
      "SNS:SetTopicAttributes",
      "SNS:AddPermission",
      "SNS:RemovePermission",
      "SNS:DeleteTopic",
      "SNS:Subscribe",
      "SNS:ListSubscriptionsByTopic",
      "SNS:Publish",
      "SNS:Receive"
    ]

    condition {
      test     = "StringEquals"
      variable = "AWS:SourceOwner"

      values = [
        data.aws_caller_identity.current.account_id
      ]
    }

    effect = "Allow"

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }

    resources = [
      module.SnsTopic1.arn
    ]

    sid = "__default_statement_ID"
  }
  
  statement {
    actions = [
      "sns:Publish"
    ]

    effect = "Allow"

    principals {
      type        = "Service"
      identifiers = ["events.amazonaws.com"]
    }

    resources = [
      module.SnsTopic1.arn
    ]

    sid = "TrustCWEToPublishEventsToMyTopic"
  }
}

resource "aws_sns_topic_policy" "TopicPolicyForSnsTopic1" {
  arn = module.SnsTopic1.arn
  policy = data.aws_iam_policy_document.topic-policy-PolicyForSnsTopic.json
}

resource "aws_cloudwatch_metric_alarm" "CwAlarm1" {
  alarm_name = "igw_changes"
  alarm_description = "A CloudWatch Alarm that triggers when changes are made to an Internet Gateway in a VPC."
  metric_name = "GatewayEventCount"
  namespace = "CloudTrailMetrics"
  statistic = "Sum"
  period = "300"
  threshold = "1"
  evaluation_periods = "1"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions = [ module.SnsTopic1.arn ]
  treat_missing_data = "notBreaching"
}

resource "aws_cloudwatch_log_metric_filter" "MetricFilter1" {
  log_group_name = aws_cloudwatch_log_group.CWLogGroupForCloudTrail.name
  pattern = "{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }"
  name = "GatewayEventCount"

  metric_transformation {
    name = "GatewayEventCount"
    value = "1"
    namespace = "CloudTrailMetrics"
  }

}

resource "aws_cloudwatch_metric_alarm" "CwAlarm2" {
  alarm_name = "vpc_changes"
  alarm_description = "A CloudWatch Alarm that triggers when changes are made to a VPC."
  metric_name = "VpcEventCount"
  namespace = "CloudTrailMetrics"
  statistic = "Sum"
  period = "300"
  threshold = "1"
  evaluation_periods = "1"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions = [ module.SnsTopic1.arn ]
  treat_missing_data = "notBreaching"
}

resource "aws_cloudwatch_log_metric_filter" "MetricFilter2" {
  log_group_name = aws_cloudwatch_log_group.CWLogGroupForCloudTrail.name
  pattern = "{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }"
  name = "VpcEventCount"

  metric_transformation {
    name = "VpcEventCount"
    value = "1"
    namespace = "CloudTrailMetrics"
  }

}

resource "aws_cloudwatch_metric_alarm" "CwAlarm3" {
  alarm_name = "securitygroup_changes"
  alarm_description = "A CloudWatch Alarm that triggers when changes are made to Security Groups."
  metric_name = "SecurityGroupEventCount"
  namespace = "CloudTrailMetrics"
  statistic = "Sum"
  period = "300"
  threshold = "1"
  evaluation_periods = "1"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions = [ module.SnsTopic1.arn ]
  treat_missing_data = "notBreaching"
}

resource "aws_cloudwatch_log_metric_filter" "MetricFilter3" {
  log_group_name = aws_cloudwatch_log_group.CWLogGroupForCloudTrail.name
  pattern = "{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }"
  name = "SecurityGroupEventCount"

  metric_transformation {
    name = "SecurityGroupEventCount"
    value = "1"
    namespace = "CloudTrailMetrics"
  }

}

resource "aws_cloudwatch_metric_alarm" "CwAlarm4" {
  alarm_name = "nacl_changes"
  alarm_description = "A CloudWatch Alarm that triggers when changes are made to Network ACLs."
  metric_name = "NetworkAclEventCount"
  namespace = "CloudTrailMetrics"
  statistic = "Sum"
  period = "300"
  threshold = "1"
  evaluation_periods = "1"
  comparison_operator = "GreaterThanOrEqualToThreshold"
  alarm_actions = [ module.SnsTopic1.arn ]
  treat_missing_data = "notBreaching"
}

resource "aws_cloudwatch_log_metric_filter" "MetricFilter4" {
  log_group_name = aws_cloudwatch_log_group.CWLogGroupForCloudTrail.name
  pattern = "{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }"
  name = "NetworkAclEventCount"

  metric_transformation {
    name = "NetworkAclEventCount"
    value = "1"
    namespace = "CloudTrailMetrics"
  }

}
