import * as cdk from "aws-cdk-lib";
import { Construct } from "constructs";
import {
  aws_chatbot as ChatBot,
  aws_cloudtrail as CloudTrail,
  aws_cloudwatch as CloudWatch,
  aws_cloudwatch_actions as CloudWatchActions,
  aws_iam as Iam,
  aws_logs as Logs,
  aws_s3 as S3,
  aws_sns as Sns,
} from "aws-cdk-lib";
import * as dotenv from "dotenv";

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
  }
}
