import * as cdk from "aws-cdk-lib";
import { Construct } from "constructs";
import {
  aws_chatbot as ChatBot,
  aws_cloudtrail as CloudTrail,
  aws_cloudwatch as CloudWatch,
  aws_cloudwatch_actions as CloudWatchActions,
  aws_config as Config,
  aws_iam as Iam,
  aws_logs as Logs,
  aws_s3 as S3,
  aws_sns as Sns,
  cloudformation_include as CloudFormationInclude,
  aws_events as Events,
  aws_events_targets as EventsTargets,
} from "aws-cdk-lib";
import * as dotenv from "dotenv";
import path = require("path");

dotenv.config();

export class HardeningStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

    // https://dev.classmethod.jp/articles/aws-baseline-setting-202206/
    const DURATION = {
      ONE_MONTH: cdk.Duration.days(30),
      ONE_YEAR: cdk.Duration.days(365),
      THREE_YEARS: cdk.Duration.days(365 * 3),
    } as const;

    const bucket = new S3.Bucket(this, "Bucket", {
      blockPublicAccess: S3.BlockPublicAccess.BLOCK_ALL,
      encryption: S3.BucketEncryption.S3_MANAGED,
      removalPolicy: cdk.RemovalPolicy.RETAIN,
      enforceSSL: true,
      objectLockEnabled: true,
      objectOwnership: S3.ObjectOwnership.BUCKET_OWNER_ENFORCED,
      serverAccessLogsPrefix: "access-logs/",
      lifecycleRules: [
        {
          expiration: DURATION.THREE_YEARS,
          transitions: [
            {
              transitionAfter: DURATION.ONE_MONTH,
              storageClass: S3.StorageClass.INFREQUENT_ACCESS,
            },
            {
              transitionAfter: DURATION.ONE_YEAR,
              storageClass: S3.StorageClass.GLACIER,
            },
          ],
        },
      ],
    });
    const trail = new CloudTrail.Trail(this, "CloudTrail", {
      enableFileValidation: true,
      isMultiRegionTrail: true,
      includeGlobalServiceEvents: true,
      insightTypes: [
        CloudTrail.InsightType.API_CALL_RATE,
        CloudTrail.InsightType.API_ERROR_RATE,
      ],
      bucket,
      sendToCloudWatchLogs: true,
      cloudWatchLogsRetention: Logs.RetentionDays.ONE_WEEK,
    });

    // https://dev.classmethod.jp/articles/cloudtrail-insights-unusual-activity-alert/
    // https://dev.classmethod.jp/articles/aws-chatbot-slack-notification-cdk/
    const metricFilter = trail.logGroup!.addMetricFilter("MetricFilter", {
      metricNamespace: "Hardening",
      metricName: "CloudTrailInsights",
      metricValue: "1",
      filterPattern: {
        logPatternString: "{ ( $.eventType=AwsCloudTrailInsight ) }",
      },
    });
    const alarm = new CloudWatch.Alarm(this, "Alarm", {
      alarmName: "CloudTrailInsigtsAlarm",
      alarmDescription: "CloudTrail Insights Alarm",
      metric: metricFilter.metric(),
      threshold: 1,
      comparisonOperator:
        CloudWatch.ComparisonOperator.GREATER_THAN_OR_EQUAL_TO_THRESHOLD,
      evaluationPeriods: 5,
      treatMissingData: CloudWatch.TreatMissingData.NOT_BREACHING,
    });
    const snsTopic = new Sns.Topic(this, "SnsTopic", {
      displayName: "CloudTrail SNS Topic",
    });
    const action = new CloudWatchActions.SnsAction(snsTopic);
    alarm.addAlarmAction(action);
    const chatBotRole = new Iam.Role(this, "ChatBotPolicy", {
      assumedBy: new Iam.ServicePrincipal("chatbot.amazonaws.com"),
      managedPolicies: [
        Iam.ManagedPolicy.fromAwsManagedPolicyName("ReadOnlyAccess"),
      ],
    });
    new ChatBot.SlackChannelConfiguration(this, "ChatBot", {
      slackChannelConfigurationName: "CloudTrailInsights",
      slackWorkspaceId: process.env.SLACK_WORKSPACE_ID!,
      slackChannelId: process.env.SLACK_CHANNEL_ID!,
      notificationTopics: [snsTopic],
      role: chatBotRole,
      guardrailPolicies: [
        Iam.ManagedPolicy.fromAwsManagedPolicyName("ReadOnlyAccess"),
      ],
    });

    // https://github.com/aws/aws-cdk/issues/3492#issuecomment-617706845
    // https://aws.amazon.com/jp/blogs/news/service-notice-upcoming-changes-required-for-aws-config/
    const configRole = new Iam.Role(this, "ConfigRole", {
      assumedBy: new Iam.ServicePrincipal("config.amazonaws.com"),
      managedPolicies: [
        Iam.ManagedPolicy.fromAwsManagedPolicyName(
          "service-role/AWS_ConfigRole"
        ),
      ],
    });
    new Config.CfnConfigurationRecorder(this, "ConfigurationRecorder", {
      name: "Default",
      roleArn: configRole.roleArn,
      recordingGroup: {
        allSupported: true,
        includeGlobalResourceTypes: true,
      },
    });
    bucket.addToResourcePolicy(
      new Iam.PolicyStatement({
        effect: Iam.Effect.ALLOW,
        principals: [configRole],
        actions: ["s3:GetBucketAcl"],
        resources: [bucket.bucketArn],
      })
    );
    bucket.addToResourcePolicy(
      new Iam.PolicyStatement({
        effect: Iam.Effect.ALLOW,
        principals: [configRole],
        actions: ["s3:PutObject"],
        resources: [
          bucket.arnForObjects(
            `AWSLogs/${cdk.Stack.of(this).account}/Config/*`
          ),
        ],
        conditions: {
          StringEquals: {
            "s3:x-amz-acl": "bucket-owner-full-control",
          },
        },
      })
    );
    new Config.CfnDeliveryChannel(this, "ConfigDeliveryChannel", {
      s3BucketName: bucket.bucketName,
    });

    // https://aws.amazon.com/jp/blogs/news/aws-config-conformance-packs/
    const conformancePackRole = new Iam.Role(this, "Role", {
      assumedBy: new Iam.ServicePrincipal("config-conforms.amazonaws.com"),
    });
    bucket.addToResourcePolicy(
      new Iam.PolicyStatement({
        effect: Iam.Effect.ALLOW,
        principals: [conformancePackRole],
        actions: ["s3:GetBucketAcl"],
        resources: [bucket.bucketArn],
      })
    );
    bucket.addToResourcePolicy(
      new Iam.PolicyStatement({
        effect: Iam.Effect.ALLOW,
        principals: [conformancePackRole],
        actions: ["s3:PutObject"],
        resources: [
          bucket.arnForObjects(
            `AWSLogs/${cdk.Stack.of(this).account}/Config/*`
          ),
        ],
        conditions: {
          StringEquals: {
            "s3:x-amz-acl": "bucket-owner-full-control",
          },
        },
      })
    );
    bucket.addToResourcePolicy(
      new Iam.PolicyStatement({
        effect: Iam.Effect.ALLOW,
        principals: [conformancePackRole],
        actions: ["s3:GetObject"],
        resources: [
          bucket.arnForObjects(
            `AWSLogs/${cdk.Stack.of(this).account}/Config/*`
          ),
        ],
      })
    );
    new Events.Rule(this, "ConfigRuleComplianceNotifications", {
      ruleName: "ConfigRuleComplianceNotifications",
      description: "Config Rule Compliance Notifications",
      enabled: true,
      eventPattern: {
        source: ["aws.config"],
        detailType: ["Config Rules Compliance Change"],
        detail: {
          configRuleName: ["*"],
          complianceType: ["NON_COMPLIANT"],
        },
      },
      targets: [new EventsTargets.SnsTopic(snsTopic)],
    });
    new CloudFormationInclude.CfnInclude(this, "ConformancePack", {
      templateFile: path.resolve(
        //"./aws-config-rules/aws-config-conformance-packs/Security-Best-Practices-for-CloudTrail.yaml"
        //"./aws-config-rules/aws-config-conformance-packs/Operational-Best-Practices-for-Amazon-S3.yaml"
        "./aws-config-rules/aws-config-conformance-packs/Operational-Best-Practices-for-API-Gateway.yaml"
      ),
    });
  }
}
