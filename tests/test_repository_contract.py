import re
import sys
import unittest
from pathlib import Path

import yaml


ROOT = Path(__file__).resolve().parents[1]


def template():
    return yaml.load((ROOT / "template.yaml").read_text(encoding="utf-8"), Loader=yaml.BaseLoader)


class RepositoryContractTests(unittest.TestCase):
    def test_runtime_module_names_do_not_shadow_the_python_standard_library(self):
        module_names = {
            path.stem
            for path in (ROOT / "src").rglob("*.py")
            if path.name != "__init__.py"
        }
        self.assertEqual(module_names.intersection(sys.stdlib_module_names), set())

    def test_has_one_worker_no_api_and_no_dev_or_deploy_surface(self):
        value = template()
        resources = value["Resources"]
        functions = {key: item for key, item in resources.items() if item["Type"] == "AWS::Serverless::Function"}
        self.assertEqual(set(functions), {"SmtpDeliveryWorkerFunction"})
        function = functions["SmtpDeliveryWorkerFunction"]["Properties"]
        self.assertEqual(function["Handler"], "handlers.smtp_delivery_worker.lambda_handler")
        self.assertEqual(function["Runtime"], "python3.13")
        self.assertEqual(function["Timeout"], "30")
        self.assertEqual(function["ReservedConcurrentExecutions"], "2")
        self.assertEqual(
            function["Environment"]["Variables"]["INTEGRATIONS_API_ID"],
            {"Ref": "IntegrationsApiId"},
        )
        self.assertEqual(
            function["Environment"]["Variables"]["INTEGRATIONS_URL_SUFFIX"],
            {"Ref": "AWS::URLSuffix"},
        )
        self.assertNotIn("INTEGRATIONS_API_BASE_URL", function["Environment"]["Variables"])
        self.assertFalse(any(item["Type"] in {"AWS::Serverless::Api", "AWS::ApiGateway::RestApi", "AWS::ApiGatewayV2::Api"} for item in resources.values()))
        environment = value["Parameters"]["EnvironmentName"]
        self.assertEqual(environment["AllowedValues"], ["test", "production"])
        self.assertNotIn("Default", environment)
        self.assertFalse((ROOT / "samconfig.toml").exists())
        self.assertFalse((ROOT / ".github" / "workflows").exists())

    def test_queue_dlq_subscription_filter_and_partial_batch_are_exact(self):
        value = template()
        resources = value["Resources"]
        queue = resources["NotificationQueue"]["Properties"]
        dlq = resources["NotificationDeadLetterQueue"]["Properties"]
        self.assertEqual(queue["VisibilityTimeout"], "180")
        self.assertEqual(queue["SqsManagedSseEnabled"], "true")
        self.assertEqual(dlq["SqsManagedSseEnabled"], "true")
        self.assertEqual(queue["RedrivePolicy"]["maxReceiveCount"], "5")
        event = resources["SmtpDeliveryWorkerFunction"]["Properties"]["Events"]["NotificationQueue"]["Properties"]
        self.assertEqual(event["BatchSize"], "1")
        self.assertEqual(event["FunctionResponseTypes"], ["ReportBatchItemFailures"])
        self.assertEqual(event["ScalingConfig"], {"MaximumConcurrency": "2"})
        subscription = resources["CommerceNotificationSubscription"]["Properties"]
        self.assertEqual(subscription["Protocol"], "sqs")
        self.assertEqual(subscription["RawMessageDelivery"], "true")
        self.assertEqual(subscription["FilterPolicyScope"], "MessageBody")
        self.assertEqual(subscription["FilterPolicy"], {"eventType": ["notification.requested.v1"]})
        statement = resources["NotificationQueuePolicy"]["Properties"]["PolicyDocument"]["Statement"]
        self.assertEqual(len(statement), 1)
        self.assertEqual(statement[0]["Principal"], {"Service": "sns.amazonaws.com"})
        self.assertEqual(statement[0]["Condition"]["ArnEquals"]["aws:SourceArn"], {"Ref": "CommerceNotificationRequestsTopicArn"})

    def test_ledger_is_on_demand_encrypted_recoverable_retained_and_ttl_bound(self):
        resource = template()["Resources"]["DeliveryLedger"]
        self.assertEqual(resource["DeletionPolicy"], "Retain")
        self.assertEqual(resource["UpdateReplacePolicy"], "Retain")
        properties = resource["Properties"]
        self.assertEqual(properties["BillingMode"], "PAY_PER_REQUEST")
        self.assertEqual(properties["SSESpecification"], {"SSEEnabled": "true"})
        self.assertEqual(properties["PointInTimeRecoverySpecification"], {"PointInTimeRecoveryEnabled": "true"})
        self.assertEqual(properties["TimeToLiveSpecification"], {"AttributeName": "expiresAt", "Enabled": "true"})
        self.assertNotIn("GlobalSecondaryIndexes", properties)

    def test_iam_is_exact_and_forbids_cross_domain_or_mutating_capabilities(self):
        value = template()
        resources = value["Resources"]
        function = resources["SmtpDeliveryWorkerFunction"]["Properties"]
        self.assertEqual(function["Role"], {"Fn::GetAtt": ["SmtpDeliveryWorkerRole", "Arn"]})
        self.assertNotIn("Policies", function)
        role = resources["SmtpDeliveryWorkerRole"]
        self.assertEqual(role["Type"], "AWS::IAM::Role")
        policies = role["Properties"]["Policies"]
        statements = [
            statement
            for policy in policies
            for statement in policy["PolicyDocument"]["Statement"]
        ]
        actions = {
            action
            for statement in statements
            for action in (statement["Action"] if isinstance(statement["Action"], list) else [statement["Action"]])
        }
        self.assertTrue({
            "sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes",
            "logs:CreateLogStream", "logs:PutLogEvents",
            "dynamodb:GetItem", "dynamodb:PutItem", "dynamodb:UpdateItem", "s3:GetObject",
            "secretsmanager:DescribeSecret", "secretsmanager:GetSecretValue",
            "execute-api:Invoke", "cloudwatch:PutMetricData",
        }.issubset(actions))
        for forbidden in (
            "dynamodb:Scan", "dynamodb:Query", "dynamodb:DeleteItem",
            "secretsmanager:CreateSecret", "secretsmanager:PutSecretValue", "secretsmanager:TagResource",
            "sns:Publish", "s3:ListBucket", "s3:PutObject",
        ):
            self.assertNotIn(forbidden, actions)
        rendered = (ROOT / "template.yaml").read_text(encoding="utf-8")
        self.assertIn("/sites/*/versions/*/_manifest.json", rendered)
        self.assertIn("/sites/*/versions/*/*/server/notification-policies.json", rendered)
        self.assertIn("/notifications/smtp/*-*", rendered)
        self.assertIn("/notifications/recipients/*/*/*-*", rendered)
        invoke = next(statement for statement in statements if "execute-api:Invoke" in statement["Action"])
        expected_stage = {
            "Fn::FindInMap": [
                "IntegrationsStageByEnvironment",
                {"Ref": "EnvironmentName"},
                "Stage",
            ]
        }
        self.assertEqual(
            invoke["Resource"],
            {
                "Fn::Sub": [
                    "arn:${AWS::Partition}:execute-api:${AWS::Region}:${AWS::AccountId}:${IntegrationsApiId}/${IntegrationsStage}/POST/internal/v1/integrations/connection-resolve",
                    {"IntegrationsStage": expected_stage},
                ]
            },
        )
        metric = next(statement for statement in statements if "cloudwatch:PutMetricData" in statement["Action"])
        self.assertEqual(metric["Condition"], {"StringEquals": {"cloudwatch:namespace": "Zoolanding/Notifications"}})
        self.assertEqual(metric["Resource"], "*")
        self.assertEqual(
            [statement for statement in statements if statement.get("Resource") == "*"],
            [metric],
            "CloudWatch PutMetricData is the only IAM action that requires Resource '*'",
        )
        sqs = next(statement for statement in statements if "sqs:ReceiveMessage" in statement["Action"])
        self.assertEqual(
            sqs,
            {
                "Effect": "Allow",
                "Action": ["sqs:ReceiveMessage", "sqs:DeleteMessage", "sqs:GetQueueAttributes"],
                "Resource": {"Fn::GetAtt": ["NotificationQueue", "Arn"]},
            },
        )
        logs = next(statement for statement in statements if "logs:PutLogEvents" in statement["Action"])
        self.assertEqual(logs["Action"], ["logs:CreateLogStream", "logs:PutLogEvents"])
        self.assertEqual(
            logs["Resource"],
            {"Fn::Sub": "arn:${AWS::Partition}:logs:${AWS::Region}:${AWS::AccountId}:log-group:/aws/lambda/zoolanding-notifications-${EnvironmentName}-smtp-delivery:*"},
        )

    def test_iam_interpolated_parameters_reject_wildcards_and_path_injection(self):
        parameters = template()["Parameters"]
        cases = {
            "ConfigRegistryTableName": (
                "zoolanding-config-registry-test",
                ("table*", "table/name", "${AWS::AccountId}"),
            ),
            "ConfigPayloadsBucketName": (
                "zoolanding-config-payloads-test",
                ("bucket*", "bucket/name", "${AWS::AccountId}"),
            ),
            "IntegrationsApiId": (
                "abc123def4",
                ("short", "ABC123DEF4", "abc123def*", "abc123def/"),
            ),
            "CommerceNotificationRequestsTopicArn": (
                "arn:aws:sns:us-east-1:123456789012:commerce-notifications-test",
                ("arn:aws:sns:us-east-1:123456789012:*",),
            ),
            "AlarmTopicArn": (
                "arn:aws:sns:us-east-1:123456789012:operator-alarms-test",
                ("arn:aws:sns:us-east-1:123456789012:operator-*",),
            ),
        }
        for name, (valid, invalid_values) in cases.items():
            pattern = parameters[name].get("AllowedPattern")
            self.assertIsInstance(pattern, str, name)
            self.assertIsNotNone(re.fullmatch(pattern, valid), name)
            for invalid in invalid_values:
                with self.subTest(parameter=name, invalid=invalid):
                    self.assertIsNone(re.fullmatch(pattern, invalid))
        self.assertNotIn("IntegrationsApiBaseUrl", parameters)
        self.assertNotIn("IntegrationsConnectionResolveArn", parameters)

    def test_retained_log_group_and_required_alarms_are_present(self):
        resources = template()["Resources"]
        log = resources["SmtpDeliveryWorkerLogGroup"]
        self.assertEqual((log["DeletionPolicy"], log["UpdateReplacePolicy"]), ("Retain", "Retain"))
        alarms = {key for key, value in resources.items() if value["Type"] == "AWS::CloudWatch::Alarm"}
        self.assertEqual(
            alarms,
            {"DlqDepthAlarm", "QueueAgeAlarm", "LambdaErrorsAlarm", "LambdaThrottlesAlarm", "SmtpCircuitAlarm"},
        )
        for key in alarms:
            props = resources[key]["Properties"]
            self.assertEqual(props["AlarmActions"], [{"Ref": "AlarmTopicArn"}])
            self.assertEqual(props["TreatMissingData"], "notBreaching")

    def test_dependencies_and_repository_text_have_no_runtime_mail_library_or_sensitive_fixture(self):
        root = [line.strip() for line in (ROOT / "requirements.txt").read_text().splitlines() if line.strip()]
        runtime = [line.strip() for line in (ROOT / "src" / "requirements.txt").read_text().splitlines() if line.strip()]
        dev = [line.strip() for line in (ROOT / "requirements-dev.txt").read_text().splitlines() if line.strip()]
        self.assertEqual(root, ["boto3==1.39.13"])
        self.assertEqual(runtime, ["boto3==1.39.13"])
        self.assertEqual(dev, ["boto3==1.39.13", "PyYAML==6.0.2"])
        source = "\n".join(path.read_text(encoding="utf-8") for path in (ROOT / "src").rglob("*.py"))
        self.assertIn("smtplib.SMTP_SSL", source)
        self.assertIn("ssl.create_default_context", source)
        self.assertNotIn("starttls(", source.lower())
        self.assertNotIn("sendgrid", source.lower())
        self.assertNotIn("resend", source.lower())
        self.assertNotIn("print(", source)
        tool_source = (ROOT / "tools" / "manage_recipient_secret.py").read_text(encoding="utf-8")
        self.assertIn("getpass.getpass", tool_source)
        self.assertNotIn("--address", tool_source)


if __name__ == "__main__":
    unittest.main()
