import * as cdk from "aws-cdk-lib";
import { Construct } from "constructs";
import { aws_cloudtrail as CloudTrail, aws_s3 as S3 } from "aws-cdk-lib";

export class HardeningStack extends cdk.Stack {
  constructor(scope: Construct, id: string, props?: cdk.StackProps) {
    super(scope, id, props);

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

    new CloudTrail.Trail(this, "CloudTrail", {
      enableFileValidation: true,
      isMultiRegionTrail: true,
      includeGlobalServiceEvents: true,
      insightTypes: [
        CloudTrail.InsightType.API_CALL_RATE,
        CloudTrail.InsightType.API_ERROR_RATE,
      ],
      bucket,
    });
  }
}
