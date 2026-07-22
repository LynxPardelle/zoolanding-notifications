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

    def test_has_one_worker_no_api_and_only_test_production_deploy_surfaces(self):
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
        self.assertTrue((ROOT / "samconfig.toml").is_file())
        self.assertEqual(
            {path.name for path in (ROOT / ".github" / "workflows").glob("*.yml")},
            {"ci.yml", "deploy-test.yml", "deploy-production.yml"},
        )
        samconfig = (ROOT / "samconfig.toml").read_text(encoding="utf-8")
        self.assertIn("[test.deploy.parameters]", samconfig)
        self.assertIn("[production.deploy.parameters]", samconfig)
        self.assertNotRegex(samconfig, r"(?m)^\[(?:dev|default)\.")

    def test_cross_service_identifiers_use_exact_environment_scoped_ssm_paths(self):
        value = template()
        parameters = value["Parameters"]
        expected_paths = {
            "ConfigRegistryTableName": "config/registry-table-name",
            "ConfigPayloadsBucketName": "config/payload-bucket-name",
            "CommerceNotificationRequestsTopicArn": "topics/commerce-notification-requests-arn",
            "IntegrationsApiId": "services/integrations/api-id",
        }
        for name, suffix in expected_paths.items():
            self.assertEqual(parameters[name]["Type"], "AWS::SSM::Parameter::Value<String>")
            self.assertEqual(
                parameters[name]["AllowedPattern"],
                rf"^/zoolanding/(test|production)/{suffix}$",
            )
            self.assertEqual(
                parameters[name]["AllowedValues"],
                [f"/zoolanding/test/{suffix}", f"/zoolanding/production/{suffix}"],
            )
        rendered = (ROOT / "template.yaml").read_text(encoding="utf-8")
        for environment in ("test", "production"):
            for suffix in expected_paths.values():
                self.assertIn(f"/zoolanding/{environment}/{suffix}", rendered)

        resources = value["Resources"]
        published = {
            key: item
            for key, item in resources.items()
            if item["Type"] == "AWS::SSM::Parameter"
        }
        self.assertEqual(
            set(published),
            {
                "SmtpWorkerRoleArnParameter",
                "NotificationQueueArnParameter",
                "DeliveryLedgerNameParameter",
            },
        )
        self.assertEqual(
            published["SmtpWorkerRoleArnParameter"]["Properties"]["Name"],
            {"Fn::Sub": "/zoolanding/${EnvironmentName}/services/notifications/smtp-worker-role-arn"},
        )
        self.assertEqual(
            published["NotificationQueueArnParameter"]["Properties"]["Name"],
            {"Fn::Sub": "/zoolanding/${EnvironmentName}/queues/notification-requests-arn"},
        )
        self.assertEqual(
            published["DeliveryLedgerNameParameter"]["Properties"]["Name"],
            {"Fn::Sub": "/zoolanding/${EnvironmentName}/tables/notifications-delivery-ledger-name"},
        )
        for item in published.values():
            self.assertEqual(item["Properties"]["Type"], "String")
            self.assertNotIn("SecureString", item["Properties"])
        self.assertEqual(
            published["SmtpWorkerRoleArnParameter"]["Properties"]["Value"],
            {"Fn::GetAtt": ["SmtpDeliveryWorkerRole", "Arn"]},
        )
        self.assertEqual(
            published["NotificationQueueArnParameter"]["Properties"]["Value"],
            {"Fn::GetAtt": ["NotificationQueue", "Arn"]},
        )
        self.assertEqual(
            published["DeliveryLedgerNameParameter"]["Properties"]["Value"],
            {"Ref": "DeliveryLedger"},
        )

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
        self.assertIn("/notifications/smtp/*-??????", rendered)
        self.assertIn("/notifications/recipients/*/*/*-??????", rendered)
        self.assertNotIn("/notifications/smtp/*-*", rendered)
        self.assertNotIn("/notifications/recipients/*/*/*-*", rendered)
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
                "/zoolanding/test/config/registry-table-name",
                ("zoolanding-config-registry-test", "/zoolanding/dev/config/registry-table-name"),
            ),
            "ConfigPayloadsBucketName": (
                "/zoolanding/production/config/payload-bucket-name",
                ("bucket-name", "/zoolanding/dev/config/payload-bucket-name"),
            ),
            "IntegrationsApiId": (
                "/zoolanding/test/services/integrations/api-id",
                ("abc123def4", "/zoolanding/dev/services/integrations/api-id"),
            ),
            "CommerceNotificationRequestsTopicArn": (
                "/zoolanding/production/topics/commerce-notification-requests-arn",
                ("arn:aws:sns:us-east-1:123456789012:topic", "/zoolanding/dev/topics/commerce-notification-requests-arn"),
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
            {
                "QueueDepthAlarm", "QueueAgeAlarm", "DlqDepthAlarm", "DlqAgeAlarm",
                "LambdaErrorsAlarm", "LambdaThrottlesAlarm", "SmtpCircuitAlarm",
                "Smtp2GoAuthenticationAlarm", "Smtp2GoQuotaAlarm",
                "Smtp2GoThrottleAlarm", "TestLiveMismatchAlarm",
            },
        )
        for key in alarms:
            props = resources[key]["Properties"]
            self.assertEqual(props["AlarmActions"], [{"Ref": "AlarmTopicArn"}])
            self.assertEqual(props["TreatMissingData"], "notBreaching")
        for key in {
            "SmtpCircuitAlarm", "Smtp2GoAuthenticationAlarm", "Smtp2GoQuotaAlarm",
            "Smtp2GoThrottleAlarm", "TestLiveMismatchAlarm",
        }:
            self.assertEqual(
                resources[key]["Properties"]["Dimensions"],
                [{"Name": "Environment", "Value": {"Ref": "EnvironmentName"}}],
            )

    def test_ci_and_protected_deploy_workflows_are_digest_bound_and_oidc_is_deploy_only(self):
        workflows = ROOT / ".github" / "workflows"
        ci_text = (workflows / "ci.yml").read_text(encoding="utf-8")
        self.assertRegex(ci_text, r"(?m)^\s{2}push:\s*$")
        self.assertRegex(ci_text, r"(?m)^\s{2}pull_request:\s*$")
        self.assertNotIn("configure-aws-credentials", ci_text)
        self.assertNotIn("id-token: write", ci_text)
        self.assertIn("python -m pip_audit -r requirements-dev.txt", ci_text)

        cases = {
            "deploy-test.yml": ("test", "dev", "test"),
            "deploy-production.yml": ("production", "test", "main"),
        }
        for filename, (environment, source, target) in cases.items():
            text = (workflows / filename).read_text(encoding="utf-8")
            with self.subTest(filename=filename):
                self.assertIn(f"environment: {environment}", text)
                self.assertIn(f"SOURCE_BRANCH: {source}", text)
                self.assertIn(f"TARGET_BRANCH: {target}", text)
                self.assertGreaterEqual(text.count("promotion_target_tip_mismatch"), 2)
                self.assertIn("manifest_digest", text)
                self.assertIn("sha256sum --check --strict", text)
                self.assertIn("artifact-ids:", text)
                self.assertEqual(text.count("id-token: write"), 1)
                self.assertEqual(text.count("configure-aws-credentials@"), 1)
                self.assertLess(text.rfind("promotion_target_tip_mismatch"), text.index("configure-aws-credentials@"))
                self.assertIn(f'"EnvironmentName={environment}"', text)
                self.assertIn(f'"ConfigRegistryTableName=/zoolanding/{environment}/config/registry-table-name"', text)
                self.assertIn(f'"ConfigPayloadsBucketName=/zoolanding/{environment}/config/payload-bucket-name"', text)
                self.assertIn(f'"CommerceNotificationRequestsTopicArn=/zoolanding/{environment}/topics/commerce-notification-requests-arn"', text)
                self.assertIn(f'"IntegrationsApiId=/zoolanding/{environment}/services/integrations/api-id"', text)
                self.assertIn("python -m pip_audit -r requirements-dev.txt", text)
                for uses in re.findall(r"(?m)^\s*-?\s*uses:\s*([^\s#]+)", text):
                    self.assertRegex(uses, r"^[^@]+@[a-f0-9]{40}$")

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
