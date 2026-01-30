/**
 * AWS API Client with Signature Version 4
 *
 * This client implements AWS Signature V4 authentication and provides
 * methods for interacting with various AWS services.
 *
 * MULTI-TENANT: Credentials are passed per-request via AwsCredentials,
 * allowing a single server to serve multiple AWS accounts.
 */

import type {
  CallerIdentity,
  CloudFrontDistribution,
  CloudFrontInvalidation,
  CloudFrontInvalidationSummary,
  CloudWatchAlarm,
  CloudWatchFilteredLogEvent,
  CloudWatchLogEvent,
  CloudWatchLogGroup,
  CloudWatchLogStream,
  CloudWatchMetricDatapoint,
  CloudWatchPutMetricDataParams,
  DynamoDBBatchGetItemParams,
  DynamoDBBatchWriteItemParams,
  DynamoDBDeleteItemParams,
  DynamoDBGetItemParams,
  DynamoDBItem,
  DynamoDBPutItemParams,
  DynamoDBQueryParams,
  DynamoDBScanParams,
  DynamoDBTable,
  DynamoDBUpdateItemParams,
  EC2AvailabilityZone,
  EC2ElasticIp,
  EC2Image,
  EC2Instance,
  EC2KeyPair,
  EC2LaunchTemplate,
  EC2NatGateway,
  EC2SecurityGroup,
  EC2SecurityGroupRule,
  EC2Snapshot,
  EC2Subnet,
  EC2Volume,
  EC2Vpc,
  ECSCluster,
  ECSNetworkConfiguration,
  ECSService,
  ECSTask,
  ECSTaskDefinition,
  EKSAddon,
  EKSCluster,
  EKSFargateProfile,
  EKSIdentityProviderConfig,
  EKSNodegroup,
  IAMAccessKey,
  IAMAttachedPolicy,
  IAMGroup,
  IAMGroupForUser,
  IAMInstanceProfile,
  IAMMfaDevice,
  IAMPolicy,
  IAMRole,
  IAMUser,
  LambdaAlias,
  LambdaEventSourceMapping,
  LambdaFunction,
  LambdaInvokeParams,
  LambdaInvokeResponse,
  LambdaLayer,
  LambdaLayerVersion,
  LambdaVersion,
  RDSCluster,
  RDSDBParameterGroup,
  RDSDBSubnetGroup,
  RDSInstance,
  RDSSnapshot,
  Route53ChangeInfo,
  Route53HealthCheck,
  Route53HostedZone,
  Route53RecordSet,
  S3Bucket,
  S3BucketEncryption,
  S3BucketTagging,
  S3BucketVersioning,
  S3CopyObjectParams,
  S3CorsRule,
  S3DeleteObjectParams,
  S3GetObjectParams,
  S3HeadObjectResponse,
  S3LifecycleRule,
  S3ListObjectsParams,
  S3ListObjectsResponse,
  S3Object,
  S3ObjectTagging,
  S3PutObjectParams,
  S3WebsiteConfiguration,
  SecretInfo,
  SecretValue,
  SecretsCreateSecretParams,
  SNSCreateTopicParams,
  SNSPublishParams,
  SNSSubscription,
  SNSTopic,
  SNSTopicAttributes,
  SQSCreateQueueParams,
  SQSMessage,
  SQSQueue,
  SQSReceiveMessageParams,
  SQSSendMessageParams,
  STSCredentials,
} from './types/aws.js';
import type { AwsCredentials } from './types/env.js';
import { parseAwsError } from './utils/errors.js';

// =============================================================================
// AWS Signature V4 Implementation
// =============================================================================

/**
 * Convert ArrayBuffer to hex string
 */
function toHex(buffer: ArrayBuffer): string {
  return Array.from(new Uint8Array(buffer))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

/**
 * SHA-256 hash
 */
async function sha256(message: string): Promise<ArrayBuffer> {
  const encoder = new TextEncoder();
  const data = encoder.encode(message);
  return crypto.subtle.digest('SHA-256', data);
}

/**
 * HMAC-SHA256
 */
async function hmacSha256(key: ArrayBuffer | Uint8Array, message: string): Promise<ArrayBuffer> {
  const cryptoKey = await crypto.subtle.importKey(
    'raw',
    key,
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign']
  );
  const encoder = new TextEncoder();
  return crypto.subtle.sign('HMAC', cryptoKey, encoder.encode(message));
}

/**
 * Get signing key for AWS Signature V4
 */
async function getSigningKey(
  secretKey: string,
  dateStamp: string,
  region: string,
  service: string
): Promise<ArrayBuffer> {
  const encoder = new TextEncoder();
  const kSecret: Uint8Array = encoder.encode(`AWS4${secretKey}`);

  const kDate = await hmacSha256(kSecret, dateStamp);
  const kRegion = await hmacSha256(kDate, region);
  const kService = await hmacSha256(kRegion, service);
  const kSigning = await hmacSha256(kService, 'aws4_request');

  return kSigning;
}

/**
 * Sign a request using AWS Signature V4
 */
async function signRequest(
  method: string,
  url: URL,
  headers: Record<string, string>,
  body: string,
  credentials: AwsCredentials,
  service: string
): Promise<Record<string, string>> {
  const now = new Date();
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');
  const dateStamp = amzDate.slice(0, 8);

  // Add required headers
  const signedHeaders: Record<string, string> = {
    ...headers,
    host: url.host,
    'x-amz-date': amzDate,
  };

  if (credentials.sessionToken) {
    signedHeaders['x-amz-security-token'] = credentials.sessionToken;
  }

  // Create canonical request
  const sortedHeaderNames = Object.keys(signedHeaders)
    .map((k) => k.toLowerCase())
    .sort();
  const canonicalHeaders = sortedHeaderNames.map((k) => `${k}:${signedHeaders[k] || signedHeaders[k.split('-').map((p, i) => i === 0 ? p : p.charAt(0).toUpperCase() + p.slice(1)).join('-')] || ''}`).join('\n') + '\n';
  const signedHeadersStr = sortedHeaderNames.join(';');

  const payloadHash = toHex(await sha256(body));

  const canonicalUri = url.pathname || '/';
  const canonicalQueryString = url.search ? url.search.slice(1).split('&').sort().join('&') : '';

  const canonicalRequest = [
    method,
    canonicalUri,
    canonicalQueryString,
    canonicalHeaders,
    signedHeadersStr,
    payloadHash,
  ].join('\n');

  // Create string to sign
  const algorithm = 'AWS4-HMAC-SHA256';
  const credentialScope = `${dateStamp}/${credentials.region}/${service}/aws4_request`;
  const stringToSign = [
    algorithm,
    amzDate,
    credentialScope,
    toHex(await sha256(canonicalRequest)),
  ].join('\n');

  // Calculate signature
  const signingKey = await getSigningKey(
    credentials.secretAccessKey,
    dateStamp,
    credentials.region,
    service
  );
  const signature = toHex(await hmacSha256(signingKey, stringToSign));

  // Create authorization header
  const authorization = `${algorithm} Credential=${credentials.accessKeyId}/${credentialScope}, SignedHeaders=${signedHeadersStr}, Signature=${signature}`;

  return {
    ...signedHeaders,
    authorization,
    'x-amz-content-sha256': payloadHash,
  };
}

// =============================================================================
// AWS Client Interface
// =============================================================================

export interface AwsClient {
  // STS
  testConnection(): Promise<{ connected: boolean; message: string; identity?: CallerIdentity }>;
  getCallerIdentity(): Promise<CallerIdentity>;
  stsAssumeRole(roleArn: string, roleSessionName: string, durationSeconds?: number, externalId?: string): Promise<STSCredentials>;
  stsGetSessionToken(durationSeconds?: number): Promise<STSCredentials>;
  stsGetFederationToken(name: string, durationSeconds?: number, policy?: string): Promise<STSCredentials & { federatedUser: { federatedUserId: string; arn: string } }>;
  stsDecodeAuthorizationMessage(encodedMessage: string): Promise<string>;

  // S3
  s3ListBuckets(): Promise<S3Bucket[]>;
  s3ListObjects(params: S3ListObjectsParams): Promise<S3ListObjectsResponse>;
  s3GetObject(params: S3GetObjectParams): Promise<string>;
  s3PutObject(params: S3PutObjectParams): Promise<{ etag: string }>;
  s3DeleteObject(params: S3DeleteObjectParams): Promise<void>;
  s3DeleteObjects(bucket: string, keys: string[]): Promise<{ deleted: string[]; errors: Array<{ key: string; code: string; message: string }> }>;
  s3CopyObject(params: S3CopyObjectParams): Promise<void>;
  s3GetBucketLocation(bucket: string): Promise<string>;
  s3HeadObject(bucket: string, key: string): Promise<S3HeadObjectResponse>;
  s3GetBucketVersioning(bucket: string): Promise<S3BucketVersioning>;
  s3CreateBucket(bucket: string, region?: string): Promise<void>;
  s3DeleteBucket(bucket: string): Promise<void>;
  s3GetBucketPolicy(bucket: string): Promise<string>;
  s3PutBucketPolicy(bucket: string, policy: string): Promise<void>;
  s3DeleteBucketPolicy(bucket: string): Promise<void>;
  s3GetBucketCors(bucket: string): Promise<S3CorsRule[]>;
  s3PutBucketCors(bucket: string, rules: S3CorsRule[]): Promise<void>;
  s3DeleteBucketCors(bucket: string): Promise<void>;
  s3GetBucketTagging(bucket: string): Promise<S3BucketTagging>;
  s3PutBucketTagging(bucket: string, tags: Array<{ key: string; value: string }>): Promise<void>;
  s3DeleteBucketTagging(bucket: string): Promise<void>;
  s3PutBucketVersioning(bucket: string, status: 'Enabled' | 'Suspended'): Promise<void>;
  s3GetBucketLifecycleConfiguration(bucket: string): Promise<S3LifecycleRule[]>;
  s3PutBucketLifecycleConfiguration(bucket: string, rules: S3LifecycleRule[]): Promise<void>;
  s3DeleteBucketLifecycleConfiguration(bucket: string): Promise<void>;
  s3GetBucketEncryption(bucket: string): Promise<S3BucketEncryption>;
  s3PutBucketEncryption(bucket: string, sseAlgorithm: 'AES256' | 'aws:kms', kmsMasterKeyId?: string): Promise<void>;
  s3DeleteBucketEncryption(bucket: string): Promise<void>;
  s3GetBucketWebsite(bucket: string): Promise<S3WebsiteConfiguration>;
  s3PutBucketWebsite(bucket: string, config: S3WebsiteConfiguration): Promise<void>;
  s3DeleteBucketWebsite(bucket: string): Promise<void>;
  s3GetObjectTagging(bucket: string, key: string): Promise<S3ObjectTagging>;
  s3PutObjectTagging(bucket: string, key: string, tags: Array<{ key: string; value: string }>): Promise<void>;
  s3DeleteObjectTagging(bucket: string, key: string): Promise<void>;
  s3GetBucketAcl(bucket: string): Promise<{ owner: { id: string; displayName?: string }; grants: Array<{ grantee: { type: string; id?: string; uri?: string }; permission: string }> }>;
  s3GetObjectAcl(bucket: string, key: string): Promise<{ owner: { id: string; displayName?: string }; grants: Array<{ grantee: { type: string; id?: string; uri?: string }; permission: string }> }>;
  s3ListObjectVersions(bucket: string, prefix?: string): Promise<{ versions: Array<{ key: string; versionId: string; isLatest: boolean; lastModified: string; size: number }>; deleteMarkers: Array<{ key: string; versionId: string; isLatest: boolean; lastModified: string }> }>;
  s3GetBucketLogging(bucket: string): Promise<{ targetBucket?: string; targetPrefix?: string }>;
  s3PutBucketLogging(bucket: string, targetBucket: string, targetPrefix?: string): Promise<void>;
  s3GetBucketNotificationConfiguration(bucket: string): Promise<{ lambdaFunctionConfigurations?: Array<{ id?: string; lambdaFunctionArn: string; events: string[] }>; queueConfigurations?: Array<{ id?: string; queueArn: string; events: string[] }>; topicConfigurations?: Array<{ id?: string; topicArn: string; events: string[] }> }>;

  // EC2
  ec2DescribeInstances(params?: {
    instanceIds?: string[];
    filters?: Array<{ name: string; values: string[] }>;
  }): Promise<EC2Instance[]>;
  ec2DescribeSecurityGroups(groupIds?: string[]): Promise<EC2SecurityGroup[]>;
  ec2DescribeVolumes(volumeIds?: string[]): Promise<EC2Volume[]>;
  ec2DescribeVpcs(vpcIds?: string[]): Promise<EC2Vpc[]>;
  ec2DescribeSubnets(subnetIds?: string[]): Promise<EC2Subnet[]>;
  ec2DescribeImages(params?: { imageIds?: string[]; owners?: string[] }): Promise<EC2Image[]>;
  ec2DescribeKeyPairs(): Promise<EC2KeyPair[]>;
  ec2StartInstances(instanceIds: string[]): Promise<void>;
  ec2StopInstances(instanceIds: string[]): Promise<void>;
  ec2RebootInstances(instanceIds: string[]): Promise<void>;
  ec2TerminateInstances(instanceIds: string[]): Promise<void>;
  ec2DescribeSnapshots(params?: { snapshotIds?: string[]; ownerIds?: string[] }): Promise<EC2Snapshot[]>;
  ec2DescribeNatGateways(natGatewayIds?: string[]): Promise<EC2NatGateway[]>;
  ec2DescribeLaunchTemplates(launchTemplateIds?: string[]): Promise<EC2LaunchTemplate[]>;
  ec2DescribeAddresses(allocationIds?: string[]): Promise<EC2ElasticIp[]>;
  ec2DescribeAvailabilityZones(): Promise<EC2AvailabilityZone[]>;
  ec2CreateSecurityGroup(groupName: string, description: string, vpcId?: string): Promise<{ groupId: string }>;
  ec2DeleteSecurityGroup(groupId: string): Promise<void>;
  ec2AuthorizeSecurityGroupIngress(groupId: string, rules: EC2SecurityGroupRule[]): Promise<void>;
  ec2RevokeSecurityGroupIngress(groupId: string, rules: EC2SecurityGroupRule[]): Promise<void>;
  ec2AuthorizeSecurityGroupEgress(groupId: string, rules: EC2SecurityGroupRule[]): Promise<void>;
  ec2RevokeSecurityGroupEgress(groupId: string, rules: EC2SecurityGroupRule[]): Promise<void>;
  ec2AllocateAddress(): Promise<{ allocationId: string; publicIp: string }>;
  ec2ReleaseAddress(allocationId: string): Promise<void>;
  ec2AssociateAddress(allocationId: string, instanceId?: string, networkInterfaceId?: string): Promise<{ associationId: string }>;
  ec2DisassociateAddress(associationId: string): Promise<void>;
  ec2CreateTags(resourceIds: string[], tags: Array<{ key: string; value: string }>): Promise<void>;
  ec2DeleteTags(resourceIds: string[], tags: Array<{ key: string }>): Promise<void>;
  ec2CreateVolume(params: {
    availabilityZone: string;
    size?: number;
    snapshotId?: string;
    volumeType?: string;
    iops?: number;
    encrypted?: boolean;
    kmsKeyId?: string;
  }): Promise<EC2Volume>;
  ec2DeleteVolume(volumeId: string): Promise<void>;
  ec2AttachVolume(volumeId: string, instanceId: string, device: string): Promise<{ attachTime: string; device: string; instanceId: string; state: string; volumeId: string }>;
  ec2DetachVolume(volumeId: string, force?: boolean): Promise<{ attachTime: string; device: string; instanceId: string; state: string; volumeId: string }>;
  ec2CreateSnapshot(volumeId: string, description?: string): Promise<EC2Snapshot>;
  ec2DeleteSnapshot(snapshotId: string): Promise<void>;
  ec2CopySnapshot(sourceSnapshotId: string, sourceRegion: string, description?: string): Promise<{ snapshotId: string }>;
  ec2CreateVpc(cidrBlock: string, instanceTenancy?: string): Promise<EC2Vpc>;
  ec2DeleteVpc(vpcId: string): Promise<void>;
  ec2CreateSubnet(vpcId: string, cidrBlock: string, availabilityZone?: string): Promise<EC2Subnet>;
  ec2DeleteSubnet(subnetId: string): Promise<void>;
  ec2DescribeInternetGateways(internetGatewayIds?: string[]): Promise<Array<{ internetGatewayId: string; attachments: Array<{ vpcId: string; state: string }> }>>;
  ec2CreateInternetGateway(): Promise<{ internetGatewayId: string }>;
  ec2DeleteInternetGateway(internetGatewayId: string): Promise<void>;
  ec2AttachInternetGateway(internetGatewayId: string, vpcId: string): Promise<void>;
  ec2DetachInternetGateway(internetGatewayId: string, vpcId: string): Promise<void>;
  ec2DescribeRouteTables(routeTableIds?: string[]): Promise<Array<{ routeTableId: string; vpcId: string; routes: Array<{ destinationCidrBlock?: string; gatewayId?: string; state: string }> }>>;
  ec2CreateRouteTable(vpcId: string): Promise<{ routeTableId: string }>;
  ec2DeleteRouteTable(routeTableId: string): Promise<void>;
  ec2CreateRoute(routeTableId: string, destinationCidrBlock: string, gatewayId?: string, natGatewayId?: string): Promise<void>;
  ec2DeleteRoute(routeTableId: string, destinationCidrBlock: string): Promise<void>;
  ec2AssociateRouteTable(routeTableId: string, subnetId: string): Promise<{ associationId: string }>;
  ec2DisassociateRouteTable(associationId: string): Promise<void>;
  ec2DescribeNetworkInterfaces(networkInterfaceIds?: string[]): Promise<Array<{ networkInterfaceId: string; subnetId: string; vpcId: string; availabilityZone: string; description?: string; privateIpAddress: string; status: string; attachment?: { instanceId?: string; deviceIndex: number; status: string } }>>;
  ec2CreateNetworkInterface(subnetId: string, description?: string, securityGroupIds?: string[]): Promise<{ networkInterfaceId: string; subnetId: string; vpcId: string; privateIpAddress: string }>;
  ec2DeleteNetworkInterface(networkInterfaceId: string): Promise<void>;
  ec2AttachNetworkInterface(networkInterfaceId: string, instanceId: string, deviceIndex: number): Promise<{ attachmentId: string }>;
  ec2DetachNetworkInterface(attachmentId: string, force?: boolean): Promise<void>;
  ec2DescribePlacementGroups(groupNames?: string[]): Promise<Array<{ groupName: string; strategy: string; state: string; groupId: string }>>;
  ec2CreatePlacementGroup(groupName: string, strategy: 'cluster' | 'spread' | 'partition'): Promise<{ groupName: string }>;
  ec2DeletePlacementGroup(groupName: string): Promise<void>;
  ec2ModifyInstanceAttribute(instanceId: string, attribute: string, value: string): Promise<void>;
  ec2GetConsoleOutput(instanceId: string): Promise<{ instanceId: string; output?: string; timestamp?: string }>;

  // Lambda
  lambdaListFunctions(): Promise<LambdaFunction[]>;
  lambdaGetFunction(functionName: string): Promise<LambdaFunction>;
  lambdaInvoke(params: LambdaInvokeParams): Promise<LambdaInvokeResponse>;
  lambdaListAliases(functionName: string): Promise<LambdaAlias[]>;
  lambdaListVersions(functionName: string): Promise<LambdaVersion[]>;
  lambdaListEventSourceMappings(functionName?: string): Promise<LambdaEventSourceMapping[]>;
  lambdaListLayers(): Promise<LambdaLayer[]>;
  lambdaListLayerVersions(layerName: string): Promise<LambdaLayerVersion[]>;
  lambdaGetFunctionConcurrency(functionName: string): Promise<{ reservedConcurrentExecutions?: number }>;
  lambdaPublishVersion(functionName: string, description?: string): Promise<LambdaVersion>;
  lambdaUpdateFunctionConfiguration(functionName: string, params: {
    description?: string;
    handler?: string;
    memorySize?: number;
    timeout?: number;
    environment?: Record<string, string>;
    runtime?: string;
  }): Promise<LambdaFunction>;
  lambdaDeleteFunction(functionName: string, qualifier?: string): Promise<void>;
  lambdaPutFunctionConcurrency(functionName: string, reservedConcurrency: number): Promise<{ reservedConcurrentExecutions: number }>;
  lambdaDeleteFunctionConcurrency(functionName: string): Promise<void>;
  lambdaGetEventSourceMapping(uuid: string): Promise<LambdaEventSourceMapping>;
  lambdaCreateEventSourceMapping(params: {
    eventSourceArn: string;
    functionName: string;
    batchSize?: number;
    enabled?: boolean;
    startingPosition?: string;
  }): Promise<LambdaEventSourceMapping>;
  lambdaUpdateEventSourceMapping(uuid: string, params: {
    functionName?: string;
    batchSize?: number;
    enabled?: boolean;
  }): Promise<LambdaEventSourceMapping>;
  lambdaDeleteEventSourceMapping(uuid: string): Promise<void>;
  lambdaCreateAlias(functionName: string, name: string, functionVersion: string, description?: string): Promise<LambdaAlias>;
  lambdaUpdateAlias(functionName: string, name: string, functionVersion?: string, description?: string): Promise<LambdaAlias>;
  lambdaDeleteAlias(functionName: string, name: string): Promise<void>;
  lambdaAddPermission(functionName: string, statementId: string, action: string, principal: string, sourceArn?: string): Promise<{ statement: string }>;
  lambdaRemovePermission(functionName: string, statementId: string): Promise<void>;
  lambdaGetPolicy(functionName: string): Promise<{ policy: string; revisionId: string }>;
  lambdaTagResource(resourceArn: string, tags: Record<string, string>): Promise<void>;
  lambdaUntagResource(resourceArn: string, tagKeys: string[]): Promise<void>;
  lambdaListTags(resourceArn: string): Promise<Record<string, string>>;

  // IAM
  iamListUsers(): Promise<IAMUser[]>;
  iamGetUser(userName: string): Promise<IAMUser>;
  iamListRoles(): Promise<IAMRole[]>;
  iamGetRole(roleName: string): Promise<IAMRole>;
  iamListPolicies(onlyAttached?: boolean): Promise<IAMPolicy[]>;
  iamGetPolicy(policyArn: string): Promise<IAMPolicy>;
  iamListGroups(): Promise<IAMGroup[]>;
  iamListAccessKeys(userName: string): Promise<IAMAccessKey[]>;
  iamListAttachedUserPolicies(userName: string): Promise<IAMAttachedPolicy[]>;
  iamListAttachedRolePolicies(roleName: string): Promise<IAMAttachedPolicy[]>;
  iamListGroupsForUser(userName: string): Promise<IAMGroupForUser[]>;
  iamListMfaDevices(userName?: string): Promise<IAMMfaDevice[]>;
  iamListInstanceProfiles(): Promise<IAMInstanceProfile[]>;
  iamGetInstanceProfile(instanceProfileName: string): Promise<IAMInstanceProfile>;
  iamCreateUser(userName: string): Promise<IAMUser>;
  iamDeleteUser(userName: string): Promise<void>;
  iamCreateRole(roleName: string, assumeRolePolicyDocument: string, description?: string): Promise<IAMRole>;
  iamDeleteRole(roleName: string): Promise<void>;
  iamAttachUserPolicy(userName: string, policyArn: string): Promise<void>;
  iamDetachUserPolicy(userName: string, policyArn: string): Promise<void>;
  iamAttachRolePolicy(roleName: string, policyArn: string): Promise<void>;
  iamDetachRolePolicy(roleName: string, policyArn: string): Promise<void>;
  iamCreateAccessKey(userName: string): Promise<{ accessKeyId: string; secretAccessKey: string }>;
  iamDeleteAccessKey(userName: string, accessKeyId: string): Promise<void>;
  iamUpdateAccessKey(userName: string, accessKeyId: string, status: 'Active' | 'Inactive'): Promise<void>;
  iamCreatePolicy(policyName: string, policyDocument: string, description?: string): Promise<IAMPolicy>;
  iamDeletePolicy(policyArn: string): Promise<void>;
  iamGetPolicyVersion(policyArn: string, versionId: string): Promise<{ document: string; versionId: string; isDefaultVersion: boolean; createDate?: string }>;
  iamListPolicyVersions(policyArn: string): Promise<Array<{ versionId: string; isDefaultVersion: boolean; createDate?: string }>>;
  iamCreatePolicyVersion(policyArn: string, policyDocument: string, setAsDefault?: boolean): Promise<{ versionId: string }>;
  iamDeletePolicyVersion(policyArn: string, versionId: string): Promise<void>;
  iamAddUserToGroup(groupName: string, userName: string): Promise<void>;
  iamRemoveUserFromGroup(groupName: string, userName: string): Promise<void>;
  iamCreateGroup(groupName: string): Promise<IAMGroup>;
  iamDeleteGroup(groupName: string): Promise<void>;
  iamTagUser(userName: string, tags: Array<{ key: string; value: string }>): Promise<void>;
  iamUntagUser(userName: string, tagKeys: string[]): Promise<void>;
  iamTagRole(roleName: string, tags: Array<{ key: string; value: string }>): Promise<void>;
  iamUntagRole(roleName: string, tagKeys: string[]): Promise<void>;

  // CloudWatch
  cloudwatchListMetrics(namespace?: string): Promise<Array<{ namespace: string; metricName: string; dimensions: Array<{ name: string; value: string }> }>>;
  cloudwatchGetMetricStatistics(params: {
    namespace: string;
    metricName: string;
    dimensions?: Array<{ name: string; value: string }>;
    startTime: string;
    endTime: string;
    period: number;
    statistics: string[];
  }): Promise<CloudWatchMetricDatapoint[]>;
  cloudwatchDescribeAlarms(alarmNames?: string[]): Promise<CloudWatchAlarm[]>;
  cloudwatchSetAlarmState(alarmName: string, stateValue: string, stateReason: string): Promise<void>;
  cloudwatchPutMetricData(params: CloudWatchPutMetricDataParams): Promise<void>;
  cloudwatchPutMetricAlarm(params: {
    alarmName: string;
    namespace: string;
    metricName: string;
    statistic: string;
    period: number;
    evaluationPeriods: number;
    threshold: number;
    comparisonOperator: string;
    dimensions?: Array<{ name: string; value: string }>;
    alarmDescription?: string;
    alarmActions?: string[];
    okActions?: string[];
    insufficientDataActions?: string[];
    treatMissingData?: string;
  }): Promise<void>;
  cloudwatchDeleteAlarms(alarmNames: string[]): Promise<void>;
  cloudwatchEnableAlarmActions(alarmNames: string[]): Promise<void>;
  cloudwatchDisableAlarmActions(alarmNames: string[]): Promise<void>;

  // CloudWatch Logs
  cloudwatchLogsDescribeLogGroups(prefix?: string): Promise<CloudWatchLogGroup[]>;
  cloudwatchLogsDescribeLogStreams(logGroupName: string): Promise<CloudWatchLogStream[]>;
  cloudwatchLogsGetLogEvents(logGroupName: string, logStreamName: string, params?: {
    startTime?: number;
    endTime?: number;
    limit?: number;
  }): Promise<CloudWatchLogEvent[]>;
  cloudwatchLogsFilterLogEvents(logGroupName: string, params?: {
    filterPattern?: string;
    startTime?: number;
    endTime?: number;
    limit?: number;
    logStreamNames?: string[];
  }): Promise<CloudWatchFilteredLogEvent[]>;
  cloudwatchLogsCreateLogGroup(logGroupName: string, tags?: Record<string, string>): Promise<void>;
  cloudwatchLogsDeleteLogGroup(logGroupName: string): Promise<void>;
  cloudwatchLogsPutRetentionPolicy(logGroupName: string, retentionInDays: number): Promise<void>;
  cloudwatchLogsDeleteRetentionPolicy(logGroupName: string): Promise<void>;
  cloudwatchLogsCreateLogStream(logGroupName: string, logStreamName: string): Promise<void>;
  cloudwatchLogsDeleteLogStream(logGroupName: string, logStreamName: string): Promise<void>;
  cloudwatchLogsPutLogEvents(logGroupName: string, logStreamName: string, logEvents: Array<{ timestamp: number; message: string }>, sequenceToken?: string): Promise<{ nextSequenceToken?: string }>;

  // DynamoDB
  dynamodbListTables(): Promise<string[]>;
  dynamodbDescribeTable(tableName: string): Promise<DynamoDBTable>;
  dynamodbQuery(params: DynamoDBQueryParams): Promise<{ items: DynamoDBItem[]; lastEvaluatedKey?: Record<string, unknown> }>;
  dynamodbScan(params: DynamoDBScanParams): Promise<{ items: DynamoDBItem[]; lastEvaluatedKey?: Record<string, unknown> }>;
  dynamodbGetItem(params: DynamoDBGetItemParams): Promise<DynamoDBItem | null>;
  dynamodbPutItem(params: DynamoDBPutItemParams): Promise<void>;
  dynamodbDeleteItem(params: DynamoDBDeleteItemParams): Promise<void>;
  dynamodbUpdateItem(params: DynamoDBUpdateItemParams): Promise<void>;
  dynamodbBatchGetItem(params: DynamoDBBatchGetItemParams): Promise<{ responses: Record<string, DynamoDBItem[]>; unprocessedKeys?: Record<string, unknown> }>;
  dynamodbBatchWriteItem(params: DynamoDBBatchWriteItemParams): Promise<{ unprocessedItems?: Record<string, unknown> }>;
  dynamodbCreateTable(params: {
    tableName: string;
    keySchema: Array<{ attributeName: string; keyType: 'HASH' | 'RANGE' }>;
    attributeDefinitions: Array<{ attributeName: string; attributeType: 'S' | 'N' | 'B' }>;
    billingMode?: 'PROVISIONED' | 'PAY_PER_REQUEST';
    provisionedThroughput?: { readCapacityUnits: number; writeCapacityUnits: number };
  }): Promise<DynamoDBTable>;
  dynamodbDeleteTable(tableName: string): Promise<void>;
  dynamodbUpdateTimeToLive(tableName: string, attributeName: string, enabled: boolean): Promise<void>;
  dynamodbDescribeTimeToLive(tableName: string): Promise<{ attributeName?: string; status: string }>;
  dynamodbCreateBackup(tableName: string, backupName: string): Promise<{ backupArn: string; backupName: string; backupStatus: string; tableArn: string }>;
  dynamodbListBackups(tableName?: string): Promise<Array<{ backupArn: string; backupName: string; backupStatus: string; tableName: string; backupCreationDateTime?: string }>>;
  dynamodbDescribeBackup(backupArn: string): Promise<{ backupArn: string; backupName: string; backupStatus: string; tableName: string; backupCreationDateTime?: string; backupSizeBytes?: number }>;
  dynamodbDeleteBackup(backupArn: string): Promise<void>;
  dynamodbRestoreTableFromBackup(targetTableName: string, backupArn: string): Promise<DynamoDBTable>;
  dynamodbEnableContinuousBackups(tableName: string): Promise<void>;
  dynamodbDescribeContinuousBackups(tableName: string): Promise<{ pointInTimeRecoveryStatus: string; earliestRestorableDateTime?: string; latestRestorableDateTime?: string }>;
  dynamodbRestoreTableToPointInTime(sourceTableName: string, targetTableName: string, restoreDateTime?: Date): Promise<DynamoDBTable>;
  dynamodbUpdateTable(tableName: string, params: { provisionedThroughput?: { readCapacityUnits: number; writeCapacityUnits: number }; billingMode?: 'PROVISIONED' | 'PAY_PER_REQUEST' }): Promise<DynamoDBTable>;
  dynamodbListGlobalTables(): Promise<Array<{ globalTableName: string; replicationGroup: Array<{ regionName: string }> }>>;
  dynamodbDescribeGlobalTable(globalTableName: string): Promise<{ globalTableName: string; replicationGroup: Array<{ regionName: string }>; globalTableStatus: string; creationDateTime?: string }>;
  dynamodbTagResource(resourceArn: string, tags: Array<{ key: string; value: string }>): Promise<void>;
  dynamodbUntagResource(resourceArn: string, tagKeys: string[]): Promise<void>;
  dynamodbListTagsOfResource(resourceArn: string): Promise<Array<{ key: string; value: string }>>;
  dynamodbDescribeTableReplicaAutoScaling(tableName: string): Promise<{ tableName: string; replicas: Array<{ regionName: string; globalSecondaryIndexes?: Array<{ indexName: string; indexStatus: string }> }> }>;
  dynamodbDescribeLimits(): Promise<{ accountMaxReadCapacityUnits: number; accountMaxWriteCapacityUnits: number; tableMaxReadCapacityUnits: number; tableMaxWriteCapacityUnits: number }>;

  // SQS
  sqsListQueues(): Promise<string[]>;
  sqsGetQueueAttributes(queueUrl: string): Promise<SQSQueue>;
  sqsSendMessage(params: SQSSendMessageParams): Promise<{ messageId: string }>;
  sqsReceiveMessage(params: SQSReceiveMessageParams): Promise<SQSMessage[]>;
  sqsDeleteMessage(queueUrl: string, receiptHandle: string): Promise<void>;
  sqsPurgeQueue(queueUrl: string): Promise<void>;
  sqsCreateQueue(params: SQSCreateQueueParams): Promise<{ queueUrl: string }>;
  sqsDeleteQueue(queueUrl: string): Promise<void>;
  sqsGetQueueUrl(queueName: string): Promise<string>;
  sqsSetQueueAttributes(queueUrl: string, attributes: Record<string, string>): Promise<void>;
  sqsTagQueue(queueUrl: string, tags: Record<string, string>): Promise<void>;
  sqsListQueueTags(queueUrl: string): Promise<Record<string, string>>;
  sqsUntagQueue(queueUrl: string, tagKeys: string[]): Promise<void>;
  sqsSendMessageBatch(queueUrl: string, entries: Array<{ id: string; messageBody: string; delaySeconds?: number }>): Promise<{ successful: Array<{ id: string; messageId: string }>; failed: Array<{ id: string; code: string; message: string }> }>;
  sqsDeleteMessageBatch(queueUrl: string, entries: Array<{ id: string; receiptHandle: string }>): Promise<{ successful: Array<{ id: string }>; failed: Array<{ id: string; code: string; message: string }> }>;
  sqsChangeMessageVisibility(queueUrl: string, receiptHandle: string, visibilityTimeout: number): Promise<void>;
  sqsChangeMessageVisibilityBatch(queueUrl: string, entries: Array<{ id: string; receiptHandle: string; visibilityTimeout: number }>): Promise<{ successful: Array<{ id: string }>; failed: Array<{ id: string; code: string; message: string }> }>;
  sqsListDeadLetterSourceQueues(queueUrl: string): Promise<string[]>;

  // SNS
  snsListTopics(): Promise<SNSTopic[]>;
  snsListSubscriptions(topicArn?: string): Promise<SNSSubscription[]>;
  snsPublish(params: SNSPublishParams): Promise<{ messageId: string }>;
  snsGetTopicAttributes(topicArn: string): Promise<SNSTopicAttributes>;
  snsSubscribe(topicArn: string, protocol: string, endpoint: string): Promise<{ subscriptionArn: string }>;
  snsCreateTopic(params: SNSCreateTopicParams): Promise<{ topicArn: string }>;
  snsDeleteTopic(topicArn: string): Promise<void>;
  snsUnsubscribe(subscriptionArn: string): Promise<void>;
  snsSetTopicAttributes(topicArn: string, attributeName: string, attributeValue: string): Promise<void>;
  snsTagResource(resourceArn: string, tags: Array<{ key: string; value: string }>): Promise<void>;
  snsListTagsForResource(resourceArn: string): Promise<Array<{ key: string; value: string }>>;
  snsConfirmSubscription(topicArn: string, token: string): Promise<{ subscriptionArn: string }>;
  snsGetSubscriptionAttributes(subscriptionArn: string): Promise<Record<string, string>>;
  snsSetSubscriptionAttributes(subscriptionArn: string, attributeName: string, attributeValue: string): Promise<void>;
  snsUntagResource(resourceArn: string, tagKeys: string[]): Promise<void>;
  snsPublishBatch(topicArn: string, entries: Array<{ id: string; message: string; subject?: string }>): Promise<{ successful: Array<{ id: string; messageId: string }>; failed: Array<{ id: string; code: string; message: string }> }>;

  // Secrets Manager
  secretsListSecrets(): Promise<SecretInfo[]>;
  secretsGetSecretValue(secretId: string): Promise<SecretValue>;
  secretsDescribeSecret(secretId: string): Promise<SecretInfo>;
  secretsCreateSecret(params: SecretsCreateSecretParams): Promise<{ arn: string; name: string; versionId?: string }>;
  secretsUpdateSecret(secretId: string, secretString: string): Promise<{ arn: string; name: string; versionId?: string }>;
  secretsDeleteSecret(secretId: string, forceDeleteWithoutRecovery?: boolean): Promise<{ arn: string; name: string; deletionDate?: string }>;
  secretsRestoreSecret(secretId: string): Promise<{ arn: string; name: string }>;
  secretsRotateSecret(secretId: string, rotationLambdaARN?: string): Promise<{ arn: string; name: string; versionId?: string }>;
  secretsPutSecretValue(secretId: string, secretString: string, versionStages?: string[]): Promise<{ arn: string; name: string; versionId: string }>;
  secretsTagResource(secretId: string, tags: Array<{ key: string; value: string }>): Promise<void>;
  secretsUntagResource(secretId: string, tagKeys: string[]): Promise<void>;
  secretsGetResourcePolicy(secretId: string): Promise<{ arn: string; name: string; resourcePolicy?: string }>;
  secretsPutResourcePolicy(secretId: string, resourcePolicy: string): Promise<{ arn: string; name: string }>;
  secretsDeleteResourcePolicy(secretId: string): Promise<{ arn: string; name: string }>;
  secretsCancelRotateSecret(secretId: string): Promise<{ arn: string; name: string }>;
  secretsListSecretVersionIds(secretId: string): Promise<Array<{ versionId: string; versionStages?: string[]; createdDate?: string }>>;
  secretsUpdateSecretVersionStage(secretId: string, versionStage: string, moveToVersionId?: string, removeFromVersionId?: string): Promise<{ arn: string; name: string }>;

  // Route53
  route53ListHostedZones(): Promise<Route53HostedZone[]>;
  route53ListResourceRecordSets(hostedZoneId: string): Promise<Route53RecordSet[]>;
  route53ChangeResourceRecordSets(hostedZoneId: string, changes: Array<{
    action: 'CREATE' | 'DELETE' | 'UPSERT';
    resourceRecordSet: {
      name: string;
      type: string;
      ttl?: number;
      resourceRecords?: Array<{ value: string }>;
    };
  }>): Promise<Route53ChangeInfo>;
  route53ListHealthChecks(): Promise<Route53HealthCheck[]>;
  route53GetHostedZone(hostedZoneId: string): Promise<Route53HostedZone>;
  route53CreateHostedZone(name: string, callerReference: string, comment?: string, privateZone?: boolean, vpcId?: string, vpcRegion?: string): Promise<{ hostedZone: Route53HostedZone; changeInfo: Route53ChangeInfo }>;
  route53DeleteHostedZone(hostedZoneId: string): Promise<Route53ChangeInfo>;
  route53GetHealthCheck(healthCheckId: string): Promise<Route53HealthCheck>;
  route53CreateHealthCheck(callerReference: string, config: {
    ipAddress?: string;
    port?: number;
    type: string;
    resourcePath?: string;
    fullyQualifiedDomainName?: string;
    requestInterval?: number;
    failureThreshold?: number;
  }): Promise<Route53HealthCheck>;
  route53DeleteHealthCheck(healthCheckId: string): Promise<void>;
  route53GetChange(changeId: string): Promise<Route53ChangeInfo>;

  // CloudFront
  cloudfrontListDistributions(): Promise<CloudFrontDistribution[]>;
  cloudfrontGetDistribution(id: string): Promise<CloudFrontDistribution>;
  cloudfrontCreateInvalidation(distributionId: string, paths: string[], callerReference?: string): Promise<CloudFrontInvalidation>;
  cloudfrontListInvalidations(distributionId: string): Promise<CloudFrontInvalidationSummary[]>;
  cloudfrontGetInvalidation(distributionId: string, invalidationId: string): Promise<CloudFrontInvalidation>;
  cloudfrontListTagsForResource(resourceArn: string): Promise<Array<{ key: string; value: string }>>;
  cloudfrontTagResource(resourceArn: string, tags: Array<{ key: string; value: string }>): Promise<void>;
  cloudfrontUntagResource(resourceArn: string, tagKeys: string[]): Promise<void>;

  // ECS
  ecsListClusters(): Promise<string[]>;
  ecsDescribeClusters(clusterArns: string[]): Promise<ECSCluster[]>;
  ecsListServices(clusterArn: string): Promise<string[]>;
  ecsDescribeServices(clusterArn: string, serviceArns: string[]): Promise<ECSService[]>;
  ecsListTasks(clusterArn: string, serviceName?: string): Promise<string[]>;
  ecsDescribeTasks(clusterArn: string, taskArns: string[]): Promise<ECSTask[]>;
  ecsDescribeTaskDefinition(taskDefinition: string): Promise<ECSTaskDefinition>;
  ecsListTaskDefinitions(familyPrefix?: string): Promise<string[]>;
  ecsUpdateService(clusterArn: string, serviceName: string, params: { desiredCount?: number; taskDefinition?: string; forceNewDeployment?: boolean }): Promise<ECSService>;
  ecsRunTask(clusterArn: string, taskDefinition: string, params?: { count?: number; launchType?: string; networkConfiguration?: ECSNetworkConfiguration }): Promise<ECSTask[]>;
  ecsStopTask(clusterArn: string, taskArn: string, reason?: string): Promise<ECSTask>;
  ecsDeleteService(clusterArn: string, serviceName: string, force?: boolean): Promise<ECSService>;
  ecsDeregisterTaskDefinition(taskDefinition: string): Promise<ECSTaskDefinition>;
  ecsListContainerInstances(clusterArn: string): Promise<string[]>;
  ecsDescribeContainerInstances(clusterArn: string, containerInstanceArns: string[]): Promise<Array<{ containerInstanceArn: string; ec2InstanceId?: string; status: string; runningTasksCount: number; pendingTasksCount: number; agentConnected: boolean; registeredAt?: string }>>;
  ecsCreateCluster(clusterName: string): Promise<ECSCluster>;
  ecsDeleteCluster(clusterArn: string): Promise<ECSCluster>;
  ecsCreateService(clusterArn: string, serviceName: string, taskDefinition: string, desiredCount: number, launchType?: string, networkConfiguration?: ECSNetworkConfiguration): Promise<ECSService>;
  ecsTagResource(resourceArn: string, tags: Array<{ key: string; value: string }>): Promise<void>;
  ecsUntagResource(resourceArn: string, tagKeys: string[]): Promise<void>;
  ecsListTagsForResource(resourceArn: string): Promise<Array<{ key: string; value: string }>>;
  ecsListTaskDefinitionFamilies(familyPrefix?: string): Promise<string[]>;
  ecsUpdateContainerInstancesState(clusterArn: string, containerInstanceArns: string[], status: 'ACTIVE' | 'DRAINING'): Promise<Array<{ containerInstanceArn: string; status: string }>>;

  // RDS
  rdsDescribeDBInstances(dbInstanceIdentifier?: string): Promise<RDSInstance[]>;
  rdsDescribeDBClusters(dbClusterIdentifier?: string): Promise<RDSCluster[]>;
  rdsDescribeDBSnapshots(dbInstanceIdentifier?: string): Promise<RDSSnapshot[]>;
  rdsDescribeDBParameterGroups(dbParameterGroupName?: string): Promise<RDSDBParameterGroup[]>;
  rdsDescribeDBSubnetGroups(dbSubnetGroupName?: string): Promise<RDSDBSubnetGroup[]>;
  rdsCreateDBSnapshot(dbInstanceIdentifier: string, dbSnapshotIdentifier: string): Promise<RDSSnapshot>;
  rdsDeleteDBSnapshot(dbSnapshotIdentifier: string): Promise<void>;
  rdsStartDBInstance(dbInstanceIdentifier: string): Promise<RDSInstance>;
  rdsStopDBInstance(dbInstanceIdentifier: string, dbSnapshotIdentifier?: string): Promise<RDSInstance>;
  rdsRebootDBInstance(dbInstanceIdentifier: string, forceFailover?: boolean): Promise<RDSInstance>;
  rdsDeleteDBInstance(dbInstanceIdentifier: string, skipFinalSnapshot?: boolean, finalSnapshotIdentifier?: string): Promise<RDSInstance>;
  rdsModifyDBInstance(dbInstanceIdentifier: string, params: {
    dbInstanceClass?: string;
    allocatedStorage?: number;
    masterUserPassword?: string;
    backupRetentionPeriod?: number;
    multiAZ?: boolean;
    applyImmediately?: boolean;
  }): Promise<RDSInstance>;
  rdsDescribeDBClusterSnapshots(dbClusterIdentifier?: string): Promise<Array<{ dbClusterSnapshotIdentifier: string; dbClusterIdentifier: string; snapshotType: string; status: string; engine: string; engineVersion?: string; snapshotCreateTime?: string; allocatedStorage?: number; storageEncrypted: boolean }>>;
  rdsCreateDBClusterSnapshot(dbClusterIdentifier: string, dbClusterSnapshotIdentifier: string): Promise<{ dbClusterSnapshotIdentifier: string; dbClusterIdentifier: string; status: string }>;
  rdsDeleteDBClusterSnapshot(dbClusterSnapshotIdentifier: string): Promise<void>;
  rdsDescribeDBSecurityGroups(dbSecurityGroupName?: string): Promise<Array<{ dbSecurityGroupName: string; dbSecurityGroupDescription: string; ownerId: string; vpcId?: string }>>;
  rdsDescribeOptionGroups(optionGroupName?: string): Promise<Array<{ optionGroupName: string; optionGroupDescription: string; engineName: string; majorEngineVersion: string; vpcId?: string }>>;
  rdsDescribeDBEngineVersions(engine?: string): Promise<Array<{ engine: string; engineVersion: string; dbEngineDescription: string; dbEngineVersionDescription: string; validUpgradeTarget?: string[] }>>;
  rdsDescribeOrderableDBInstanceOptions(engine: string): Promise<Array<{ dbInstanceClass: string; engine: string; engineVersion: string; storageType: string; supportsStorageEncryption: boolean; supportsIAMDatabaseAuthentication: boolean }>>;
  rdsDescribeEvents(params?: { sourceType?: string; sourceIdentifier?: string; duration?: number }): Promise<Array<{ sourceIdentifier: string; sourceType: string; message: string; date: string }>>;
  rdsDescribePendingMaintenanceActions(resourceIdentifier?: string): Promise<Array<{ resourceIdentifier: string; pendingMaintenanceActionDetails: Array<{ action: string; autoAppliedAfterDate?: string; currentApplyDate?: string; description: string }> }>>;
  rdsAddTagsToResource(resourceArn: string, tags: Array<{ key: string; value: string }>): Promise<void>;
  rdsRemoveTagsFromResource(resourceArn: string, tagKeys: string[]): Promise<void>;
  rdsListTagsForResource(resourceArn: string): Promise<Array<{ key: string; value: string }>>;
  rdsRestoreDBInstanceFromDBSnapshot(dbInstanceIdentifier: string, dbSnapshotIdentifier: string, dbInstanceClass?: string): Promise<RDSInstance>;
  rdsCopyDBSnapshot(sourceSnapshotIdentifier: string, targetSnapshotIdentifier: string): Promise<{ dbSnapshotIdentifier: string; status: string }>;

  // EKS
  eksListClusters(): Promise<string[]>;
  eksDescribeCluster(name: string): Promise<EKSCluster>;
  eksListNodegroups(clusterName: string): Promise<string[]>;
  eksDescribeNodegroup(clusterName: string, nodegroupName: string): Promise<EKSNodegroup>;
  eksListFargateProfiles(clusterName: string): Promise<string[]>;
  eksDescribeFargateProfile(clusterName: string, fargateProfileName: string): Promise<EKSFargateProfile>;
  eksListAddons(clusterName: string): Promise<string[]>;
  eksDescribeAddon(clusterName: string, addonName: string): Promise<EKSAddon>;
  eksListIdentityProviderConfigs(clusterName: string): Promise<Array<{ type: string; name: string }>>;
  eksDescribeIdentityProviderConfig(clusterName: string, type: string, name: string): Promise<EKSIdentityProviderConfig>;
  eksUpdateNodegroupConfig(clusterName: string, nodegroupName: string, scalingConfig?: { minSize?: number; maxSize?: number; desiredSize?: number }): Promise<{ updateId: string; status: string }>;
  eksTagResource(resourceArn: string, tags: Record<string, string>): Promise<void>;
  eksUntagResource(resourceArn: string, tagKeys: string[]): Promise<void>;
  eksListUpdates(clusterName: string, nodegroupName?: string, addonName?: string): Promise<string[]>;
  eksDescribeUpdate(clusterName: string, updateId: string, nodegroupName?: string, addonName?: string): Promise<{ id: string; status: string; type: string; createdAt?: string; errors?: Array<{ errorCode: string; errorMessage: string }> }>;

  // CloudFormation
  cfnListStacks(statusFilter?: string[]): Promise<Array<{ stackId: string; stackName: string; stackStatus: string; creationTime: string; lastUpdatedTime?: string; templateDescription?: string }>>;
  cfnDescribeStack(stackName: string): Promise<{ stackId: string; stackName: string; stackStatus: string; stackStatusReason?: string; creationTime: string; lastUpdatedTime?: string; parameters?: Array<{ key: string; value: string }>; outputs?: Array<{ key: string; value: string; description?: string; exportName?: string }>; tags?: Array<{ key: string; value: string }> }>;
  cfnGetTemplate(stackName: string): Promise<{ templateBody: string }>;
  cfnListStackResources(stackName: string): Promise<Array<{ logicalResourceId: string; physicalResourceId?: string; resourceType: string; resourceStatus: string; lastUpdatedTimestamp?: string }>>;
  cfnDescribeStackEvents(stackName: string): Promise<Array<{ eventId: string; stackName: string; logicalResourceId?: string; physicalResourceId?: string; resourceType?: string; resourceStatus?: string; resourceStatusReason?: string; timestamp: string }>>;
  cfnCreateStack(params: { stackName: string; templateBody?: string; templateUrl?: string; parameters?: Array<{ key: string; value: string }>; capabilities?: string[]; tags?: Array<{ key: string; value: string }> }): Promise<{ stackId: string }>;
  cfnUpdateStack(params: { stackName: string; templateBody?: string; templateUrl?: string; parameters?: Array<{ key: string; value: string }>; capabilities?: string[] }): Promise<{ stackId: string }>;
  cfnDeleteStack(stackName: string): Promise<void>;
  cfnListChangeSets(stackName: string): Promise<Array<{ changeSetId: string; changeSetName: string; status: string; statusReason?: string; executionStatus: string; creationTime: string }>>;
  cfnDescribeChangeSet(stackName: string, changeSetName: string): Promise<{ changeSetId: string; changeSetName: string; stackName: string; status: string; statusReason?: string; executionStatus: string; changes?: Array<{ resourceChange: { action: string; logicalResourceId: string; physicalResourceId?: string; resourceType: string; replacement?: string } }> }>;
  cfnCreateChangeSet(params: { stackName: string; changeSetName: string; templateBody?: string; templateUrl?: string; parameters?: Array<{ key: string; value: string }>; capabilities?: string[]; changeSetType?: 'CREATE' | 'UPDATE' }): Promise<{ changeSetId: string; stackId: string }>;
  cfnExecuteChangeSet(stackName: string, changeSetName: string): Promise<void>;
  cfnDeleteChangeSet(stackName: string, changeSetName: string): Promise<void>;
  cfnValidateTemplate(templateBody?: string, templateUrl?: string): Promise<{ parameters?: Array<{ parameterKey: string; defaultValue?: string; noEcho?: boolean; description?: string }>; description?: string; capabilities?: string[] }>;
}

// =============================================================================
// AWS Client Implementation
// =============================================================================

class AwsClientImpl implements AwsClient {
  private credentials: AwsCredentials;

  constructor(credentials: AwsCredentials) {
    this.credentials = credentials;
  }

  // ===========================================================================
  // HTTP Request Helpers
  // ===========================================================================

  private getServiceEndpoint(service: string, region?: string): string {
    const r = region || this.credentials.region;

    // Global services
    if (service === 'iam' || service === 'sts' || service === 'route53' || service === 'cloudfront') {
      if (service === 'iam') return 'https://iam.amazonaws.com';
      if (service === 'sts') return 'https://sts.amazonaws.com';
      if (service === 'route53') return 'https://route53.amazonaws.com';
      if (service === 'cloudfront') return 'https://cloudfront.amazonaws.com';
    }

    // S3 has a different endpoint pattern
    if (service === 's3') {
      return `https://s3.${r}.amazonaws.com`;
    }

    return `https://${service}.${r}.amazonaws.com`;
  }

  private async request<T>(
    service: string,
    method: string,
    path: string,
    options: {
      body?: string;
      headers?: Record<string, string>;
      query?: Record<string, string>;
      region?: string;
    } = {}
  ): Promise<T> {
    const endpoint = this.getServiceEndpoint(service, options.region);
    const urlStr = options.query
      ? `${endpoint}${path}?${new URLSearchParams(options.query).toString()}`
      : `${endpoint}${path}`;
    const url = new URL(urlStr);

    const body = options.body || '';
    const baseHeaders = options.headers || {};

    const signedHeaders = await signRequest(
      method,
      url,
      baseHeaders,
      body,
      { ...this.credentials, region: options.region || this.credentials.region },
      service
    );

    const response = await fetch(url.toString(), {
      method,
      headers: signedHeaders,
      body: body || undefined,
    });

    const responseText = await response.text();
    const requestId = response.headers.get('x-amz-request-id') || response.headers.get('x-amzn-requestid') || undefined;

    if (!response.ok) {
      throw parseAwsError(response.status, responseText, requestId);
    }

    // Handle empty responses
    if (!responseText || response.status === 204) {
      return undefined as T;
    }

    // Try to parse as JSON first (Lambda, DynamoDB, etc.)
    try {
      return JSON.parse(responseText) as T;
    } catch {
      // Return raw text for XML responses (S3, EC2, etc.)
      return responseText as T;
    }
  }

  // ===========================================================================
  // XML Parsing Helpers (for EC2, S3, IAM, etc.)
  // ===========================================================================

  private parseXmlValue(xml: string, tag: string): string | undefined {
    const match = xml.match(new RegExp(`<${tag}>([^<]*)</${tag}>`));
    return match ? match[1] : undefined;
  }

  // ===========================================================================
  // STS
  // ===========================================================================

  async testConnection(): Promise<{ connected: boolean; message: string; identity?: CallerIdentity }> {
    try {
      const identity = await this.getCallerIdentity();
      return {
        connected: true,
        message: `Connected as ${identity.arn}`,
        identity,
      };
    } catch (error) {
      return {
        connected: false,
        message: error instanceof Error ? error.message : 'Connection failed',
      };
    }
  }

  async getCallerIdentity(): Promise<CallerIdentity> {
    const response = await this.request<string>('sts', 'POST', '/', {
      body: 'Action=GetCallerIdentity&Version=2011-06-15',
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
    });

    return {
      userId: this.parseXmlValue(response, 'UserId') || '',
      account: this.parseXmlValue(response, 'Account') || '',
      arn: this.parseXmlValue(response, 'Arn') || '',
    };
  }

  async stsAssumeRole(
    roleArn: string,
    roleSessionName: string,
    durationSeconds?: number,
    externalId?: string
  ): Promise<STSCredentials> {
    const params = new URLSearchParams({
      Action: 'AssumeRole',
      Version: '2011-06-15',
      RoleArn: roleArn,
      RoleSessionName: roleSessionName,
    });
    if (durationSeconds) params.set('DurationSeconds', durationSeconds.toString());
    if (externalId) params.set('ExternalId', externalId);

    const response = await this.request<string>('sts', 'POST', '/', {
      body: params.toString(),
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
    });

    return {
      accessKeyId: this.parseXmlValue(response, 'AccessKeyId') || '',
      secretAccessKey: this.parseXmlValue(response, 'SecretAccessKey') || '',
      sessionToken: this.parseXmlValue(response, 'SessionToken') || '',
      expiration: this.parseXmlValue(response, 'Expiration') || '',
    };
  }

  async stsGetSessionToken(durationSeconds?: number): Promise<STSCredentials> {
    const params = new URLSearchParams({
      Action: 'GetSessionToken',
      Version: '2011-06-15',
    });
    if (durationSeconds) params.set('DurationSeconds', durationSeconds.toString());

    const response = await this.request<string>('sts', 'POST', '/', {
      body: params.toString(),
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
    });

    return {
      accessKeyId: this.parseXmlValue(response, 'AccessKeyId') || '',
      secretAccessKey: this.parseXmlValue(response, 'SecretAccessKey') || '',
      sessionToken: this.parseXmlValue(response, 'SessionToken') || '',
      expiration: this.parseXmlValue(response, 'Expiration') || '',
    };
  }

  async stsGetFederationToken(
    name: string,
    durationSeconds?: number,
    policy?: string
  ): Promise<STSCredentials & { federatedUser: { federatedUserId: string; arn: string } }> {
    const params = new URLSearchParams({
      Action: 'GetFederationToken',
      Version: '2011-06-15',
      Name: name,
    });
    if (durationSeconds) params.set('DurationSeconds', durationSeconds.toString());
    if (policy) params.set('Policy', policy);

    const response = await this.request<string>('sts', 'POST', '/', {
      body: params.toString(),
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
    });

    return {
      accessKeyId: this.parseXmlValue(response, 'AccessKeyId') || '',
      secretAccessKey: this.parseXmlValue(response, 'SecretAccessKey') || '',
      sessionToken: this.parseXmlValue(response, 'SessionToken') || '',
      expiration: this.parseXmlValue(response, 'Expiration') || '',
      federatedUser: {
        federatedUserId: this.parseXmlValue(response, 'FederatedUserId') || '',
        arn: this.parseXmlValue(response, 'Arn') || '',
      },
    };
  }

  async stsDecodeAuthorizationMessage(encodedMessage: string): Promise<string> {
    const params = new URLSearchParams({
      Action: 'DecodeAuthorizationMessage',
      Version: '2011-06-15',
      EncodedMessage: encodedMessage,
    });

    const response = await this.request<string>('sts', 'POST', '/', {
      body: params.toString(),
      headers: { 'content-type': 'application/x-www-form-urlencoded' },
    });

    return this.parseXmlValue(response, 'DecodedMessage') || '';
  }

  // ===========================================================================
  // S3
  // ===========================================================================

  async s3ListBuckets(): Promise<S3Bucket[]> {
    const response = await this.request<string>('s3', 'GET', '/');

    const buckets: S3Bucket[] = [];
    const bucketMatches = response.matchAll(/<Bucket>([\s\S]*?)<\/Bucket>/g);

    for (const match of bucketMatches) {
      const bucketXml = match[1];
      buckets.push({
        name: this.parseXmlValue(bucketXml, 'Name') || '',
        creationDate: this.parseXmlValue(bucketXml, 'CreationDate') || '',
      });
    }

    return buckets;
  }

  async s3ListObjects(params: S3ListObjectsParams): Promise<S3ListObjectsResponse> {
    const query: Record<string, string> = { 'list-type': '2' };
    if (params.prefix) query.prefix = params.prefix;
    if (params.delimiter) query.delimiter = params.delimiter;
    if (params.maxKeys) query['max-keys'] = String(params.maxKeys);
    if (params.continuationToken) query['continuation-token'] = params.continuationToken;

    const response = await this.request<string>('s3', 'GET', `/${params.bucket}`, { query });

    const objects: S3Object[] = [];
    const contentMatches = response.matchAll(/<Contents>([\s\S]*?)<\/Contents>/g);

    for (const match of contentMatches) {
      const contentXml = match[1];
      objects.push({
        key: this.parseXmlValue(contentXml, 'Key') || '',
        size: Number.parseInt(this.parseXmlValue(contentXml, 'Size') || '0', 10),
        lastModified: this.parseXmlValue(contentXml, 'LastModified') || '',
        etag: this.parseXmlValue(contentXml, 'ETag')?.replace(/"/g, ''),
        storageClass: this.parseXmlValue(contentXml, 'StorageClass'),
      });
    }

    const commonPrefixes: string[] = [];
    const prefixMatches = response.matchAll(/<CommonPrefixes>[\s\S]*?<Prefix>([^<]*)<\/Prefix>[\s\S]*?<\/CommonPrefixes>/g);
    for (const match of prefixMatches) {
      commonPrefixes.push(match[1]);
    }

    return {
      objects,
      commonPrefixes,
      isTruncated: this.parseXmlValue(response, 'IsTruncated') === 'true',
      nextContinuationToken: this.parseXmlValue(response, 'NextContinuationToken'),
    };
  }

  async s3GetObject(params: S3GetObjectParams): Promise<string> {
    return this.request<string>('s3', 'GET', `/${params.bucket}/${encodeURIComponent(params.key)}`);
  }

  async s3PutObject(params: S3PutObjectParams): Promise<{ etag: string }> {
    const headers: Record<string, string> = {};
    if (params.contentType) {
      headers['content-type'] = params.contentType;
    }

    await this.request<string>('s3', 'PUT', `/${params.bucket}/${encodeURIComponent(params.key)}`, {
      body: params.body,
      headers,
    });

    return { etag: '' }; // ETag is returned in headers but we simplify here
  }

  async s3DeleteObject(params: S3DeleteObjectParams): Promise<void> {
    await this.request<void>('s3', 'DELETE', `/${params.bucket}/${encodeURIComponent(params.key)}`);
  }

  async s3CopyObject(params: S3CopyObjectParams): Promise<void> {
    await this.request<void>(
      's3',
      'PUT',
      `/${params.destinationBucket}/${encodeURIComponent(params.destinationKey)}`,
      {
        headers: {
          'x-amz-copy-source': `/${params.sourceBucket}/${encodeURIComponent(params.sourceKey)}`,
        },
      }
    );
  }

  async s3GetBucketLocation(bucket: string): Promise<string> {
    const response = await this.request<string>('s3', 'GET', `/${bucket}`, {
      query: { location: '' },
    });
    const location = this.parseXmlValue(response, 'LocationConstraint');
    return location || 'us-east-1';
  }

  async s3HeadObject(bucket: string, key: string): Promise<S3HeadObjectResponse> {
    const endpoint = this.getServiceEndpoint('s3');
    const url = new URL(`${endpoint}/${bucket}/${encodeURIComponent(key)}`);

    const signedHeaders = await signRequest(
      'HEAD',
      url,
      {},
      '',
      this.credentials,
      's3'
    );

    const response = await fetch(url.toString(), {
      method: 'HEAD',
      headers: signedHeaders,
    });

    if (!response.ok) {
      const requestId = response.headers.get('x-amz-request-id') || undefined;
      throw parseAwsError(response.status, '', requestId);
    }

    return {
      contentLength: parseInt(response.headers.get('content-length') || '0', 10),
      contentType: response.headers.get('content-type') || undefined,
      etag: response.headers.get('etag') || undefined,
      lastModified: response.headers.get('last-modified') || undefined,
      storageClass: response.headers.get('x-amz-storage-class') || undefined,
      versionId: response.headers.get('x-amz-version-id') || undefined,
    };
  }

  async s3DeleteObjects(
    bucket: string,
    keys: string[]
  ): Promise<{ deleted: string[]; errors: Array<{ key: string; code: string; message: string }> }> {
    const deleteXml = `<?xml version="1.0" encoding="UTF-8"?>
<Delete>
  <Quiet>false</Quiet>
  ${keys.map((key) => `<Object><Key>${key}</Key></Object>`).join('\n  ')}
</Delete>`;

    const response = await this.request<string>('s3', 'POST', `/${bucket}`, {
      query: { delete: '' },
      body: deleteXml,
      headers: { 'content-type': 'application/xml' },
    });

    const deleted: string[] = [];
    const deletedMatches = response.matchAll(/<Deleted>[\s\S]*?<Key>([^<]+)<\/Key>[\s\S]*?<\/Deleted>/g);
    for (const match of deletedMatches) {
      deleted.push(match[1]);
    }

    const errors: Array<{ key: string; code: string; message: string }> = [];
    const errorMatches = response.matchAll(/<Error>[\s\S]*?<Key>([^<]+)<\/Key>[\s\S]*?<Code>([^<]+)<\/Code>[\s\S]*?<Message>([^<]+)<\/Message>[\s\S]*?<\/Error>/g);
    for (const match of errorMatches) {
      errors.push({ key: match[1], code: match[2], message: match[3] });
    }

    return { deleted, errors };
  }

  async s3GetBucketVersioning(bucket: string): Promise<S3BucketVersioning> {
    const response = await this.request<string>('s3', 'GET', `/${bucket}`, {
      query: { versioning: '' },
    });

    const status = this.parseXmlValue(response, 'Status') as 'Enabled' | 'Suspended' | undefined;
    const mfaDelete = this.parseXmlValue(response, 'MfaDelete') as 'Enabled' | 'Disabled' | undefined;

    return { status, mfaDelete };
  }

  async s3CreateBucket(bucket: string, region?: string): Promise<void> {
    let body = '';
    if (region && region !== 'us-east-1') {
      body = `<?xml version="1.0" encoding="UTF-8"?>
<CreateBucketConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <LocationConstraint>${region}</LocationConstraint>
</CreateBucketConfiguration>`;
    }

    await this.request<string>('s3', 'PUT', `/${bucket}`, {
      body: body || undefined,
      headers: body ? { 'content-type': 'application/xml' } : {},
    });
  }

  async s3DeleteBucket(bucket: string): Promise<void> {
    await this.request<string>('s3', 'DELETE', `/${bucket}`);
  }

  async s3GetBucketPolicy(bucket: string): Promise<string> {
    const response = await this.request<string>('s3', 'GET', `/${bucket}`, {
      query: { policy: '' },
    });
    return response;
  }

  async s3PutBucketPolicy(bucket: string, policy: string): Promise<void> {
    await this.request<string>('s3', 'PUT', `/${bucket}`, {
      query: { policy: '' },
      body: policy,
      headers: { 'content-type': 'application/json' },
    });
  }

  async s3DeleteBucketPolicy(bucket: string): Promise<void> {
    await this.request<string>('s3', 'DELETE', `/${bucket}`, {
      query: { policy: '' },
    });
  }

  async s3GetBucketCors(bucket: string): Promise<S3CorsRule[]> {
    const response = await this.request<string>('s3', 'GET', `/${bucket}`, {
      query: { cors: '' },
    });

    const rules: S3CorsRule[] = [];
    const ruleMatches = response.matchAll(/<CORSRule>([\s\S]*?)<\/CORSRule>/g);

    for (const match of ruleMatches) {
      const ruleXml = match[1];

      const allowedOrigins: string[] = [];
      const originMatches = ruleXml.matchAll(/<AllowedOrigin>([^<]+)<\/AllowedOrigin>/g);
      for (const om of originMatches) allowedOrigins.push(om[1]);

      const allowedMethods: string[] = [];
      const methodMatches = ruleXml.matchAll(/<AllowedMethod>([^<]+)<\/AllowedMethod>/g);
      for (const mm of methodMatches) allowedMethods.push(mm[1]);

      const allowedHeaders: string[] = [];
      const headerMatches = ruleXml.matchAll(/<AllowedHeader>([^<]+)<\/AllowedHeader>/g);
      for (const hm of headerMatches) allowedHeaders.push(hm[1]);

      const exposeHeaders: string[] = [];
      const exposeMatches = ruleXml.matchAll(/<ExposeHeader>([^<]+)<\/ExposeHeader>/g);
      for (const em of exposeMatches) exposeHeaders.push(em[1]);

      const maxAgeSeconds = this.parseXmlValue(ruleXml, 'MaxAgeSeconds');

      rules.push({
        allowedOrigins,
        allowedMethods,
        allowedHeaders: allowedHeaders.length > 0 ? allowedHeaders : undefined,
        exposeHeaders: exposeHeaders.length > 0 ? exposeHeaders : undefined,
        maxAgeSeconds: maxAgeSeconds ? parseInt(maxAgeSeconds, 10) : undefined,
      });
    }

    return rules;
  }

  async s3PutBucketCors(bucket: string, rules: S3CorsRule[]): Promise<void> {
    const rulesXml = rules
      .map((rule) => {
        const parts = [
          ...rule.allowedOrigins.map((o) => `<AllowedOrigin>${o}</AllowedOrigin>`),
          ...rule.allowedMethods.map((m) => `<AllowedMethod>${m}</AllowedMethod>`),
          ...(rule.allowedHeaders || []).map((h) => `<AllowedHeader>${h}</AllowedHeader>`),
          ...(rule.exposeHeaders || []).map((h) => `<ExposeHeader>${h}</ExposeHeader>`),
        ];
        if (rule.maxAgeSeconds) parts.push(`<MaxAgeSeconds>${rule.maxAgeSeconds}</MaxAgeSeconds>`);
        return `<CORSRule>${parts.join('')}</CORSRule>`;
      })
      .join('');

    const body = `<?xml version="1.0" encoding="UTF-8"?>
<CORSConfiguration>${rulesXml}</CORSConfiguration>`;

    await this.request<string>('s3', 'PUT', `/${bucket}`, {
      query: { cors: '' },
      body,
      headers: { 'content-type': 'application/xml' },
    });
  }

  async s3DeleteBucketCors(bucket: string): Promise<void> {
    await this.request<string>('s3', 'DELETE', `/${bucket}`, {
      query: { cors: '' },
    });
  }

  async s3GetBucketTagging(bucket: string): Promise<S3BucketTagging> {
    const response = await this.request<string>('s3', 'GET', `/${bucket}`, {
      query: { tagging: '' },
    });

    const tagSet: Array<{ key: string; value: string }> = [];
    const tagMatches = response.matchAll(/<Tag>([\s\S]*?)<\/Tag>/g);

    for (const match of tagMatches) {
      tagSet.push({
        key: this.parseXmlValue(match[1], 'Key') || '',
        value: this.parseXmlValue(match[1], 'Value') || '',
      });
    }

    return { tagSet };
  }

  async s3PutBucketTagging(bucket: string, tags: Array<{ key: string; value: string }>): Promise<void> {
    const tagsXml = tags
      .map((t) => `<Tag><Key>${t.key}</Key><Value>${t.value}</Value></Tag>`)
      .join('');

    const body = `<?xml version="1.0" encoding="UTF-8"?>
<Tagging><TagSet>${tagsXml}</TagSet></Tagging>`;

    await this.request<string>('s3', 'PUT', `/${bucket}`, {
      query: { tagging: '' },
      body,
      headers: { 'content-type': 'application/xml' },
    });
  }

  async s3DeleteBucketTagging(bucket: string): Promise<void> {
    await this.request<string>('s3', 'DELETE', `/${bucket}`, {
      query: { tagging: '' },
    });
  }

  async s3PutBucketVersioning(bucket: string, status: 'Enabled' | 'Suspended'): Promise<void> {
    const body = `<?xml version="1.0" encoding="UTF-8"?>
<VersioningConfiguration><Status>${status}</Status></VersioningConfiguration>`;

    await this.request<string>('s3', 'PUT', `/${bucket}`, {
      query: { versioning: '' },
      body,
      headers: { 'content-type': 'application/xml' },
    });
  }

  async s3GetBucketLifecycleConfiguration(bucket: string): Promise<S3LifecycleRule[]> {
    const response = await this.request<string>('s3', 'GET', `/${bucket}`, {
      query: { lifecycle: '' },
    });

    const rules: S3LifecycleRule[] = [];
    const ruleMatches = response.matchAll(/<Rule>([\s\S]*?)<\/Rule>/g);

    for (const match of ruleMatches) {
      const ruleXml = match[1];
      const rule: S3LifecycleRule = {
        id: this.parseXmlValue(ruleXml, 'ID'),
        status: (this.parseXmlValue(ruleXml, 'Status') as 'Enabled' | 'Disabled') || 'Enabled',
        prefix: this.parseXmlValue(ruleXml, 'Prefix'),
      };

      // Parse expiration
      const expirationMatch = ruleXml.match(/<Expiration>([\s\S]*?)<\/Expiration>/);
      if (expirationMatch) {
        const expXml = expirationMatch[1];
        rule.expiration = {};
        const days = this.parseXmlValue(expXml, 'Days');
        if (days) rule.expiration.days = parseInt(days, 10);
        const date = this.parseXmlValue(expXml, 'Date');
        if (date) rule.expiration.date = date;
        const deleteMarker = this.parseXmlValue(expXml, 'ExpiredObjectDeleteMarker');
        if (deleteMarker) rule.expiration.expiredObjectDeleteMarker = deleteMarker === 'true';
      }

      // Parse transitions
      const transitions: S3LifecycleRule['transitions'] = [];
      const transitionMatches = ruleXml.matchAll(/<Transition>([\s\S]*?)<\/Transition>/g);
      for (const transMatch of transitionMatches) {
        const transXml = transMatch[1];
        const transition: NonNullable<S3LifecycleRule['transitions']>[0] = {
          storageClass: this.parseXmlValue(transXml, 'StorageClass') || '',
        };
        const transitionDays = this.parseXmlValue(transXml, 'Days');
        if (transitionDays) transition.days = parseInt(transitionDays, 10);
        const transitionDate = this.parseXmlValue(transXml, 'Date');
        if (transitionDate) transition.date = transitionDate;
        transitions.push(transition);
      }
      if (transitions.length > 0) rule.transitions = transitions;

      // Parse noncurrent version expiration
      const noncurrentMatch = ruleXml.match(/<NoncurrentVersionExpiration>([\s\S]*?)<\/NoncurrentVersionExpiration>/);
      if (noncurrentMatch) {
        const noncurrentDays = this.parseXmlValue(noncurrentMatch[1], 'NoncurrentDays');
        if (noncurrentDays) {
          rule.noncurrentVersionExpiration = { noncurrentDays: parseInt(noncurrentDays, 10) };
        }
      }

      rules.push(rule);
    }

    return rules;
  }

  async s3PutBucketLifecycleConfiguration(bucket: string, rules: S3LifecycleRule[]): Promise<void> {
    const rulesXml = rules
      .map((rule) => {
        let xml = '<Rule>';
        if (rule.id) xml += `<ID>${rule.id}</ID>`;
        xml += `<Status>${rule.status}</Status>`;
        if (rule.prefix !== undefined) xml += `<Prefix>${rule.prefix}</Prefix>`;
        // Use Filter for modern lifecycle rules
        if (rule.prefix !== undefined) {
          xml += `<Filter><Prefix>${rule.prefix}</Prefix></Filter>`;
        } else {
          xml += '<Filter></Filter>';
        }
        if (rule.expiration) {
          xml += '<Expiration>';
          if (rule.expiration.days !== undefined) xml += `<Days>${rule.expiration.days}</Days>`;
          if (rule.expiration.date) xml += `<Date>${rule.expiration.date}</Date>`;
          if (rule.expiration.expiredObjectDeleteMarker !== undefined) {
            xml += `<ExpiredObjectDeleteMarker>${rule.expiration.expiredObjectDeleteMarker}</ExpiredObjectDeleteMarker>`;
          }
          xml += '</Expiration>';
        }
        if (rule.transitions) {
          for (const transition of rule.transitions) {
            xml += '<Transition>';
            if (transition.days !== undefined) xml += `<Days>${transition.days}</Days>`;
            if (transition.date) xml += `<Date>${transition.date}</Date>`;
            xml += `<StorageClass>${transition.storageClass}</StorageClass>`;
            xml += '</Transition>';
          }
        }
        if (rule.noncurrentVersionExpiration) {
          xml += '<NoncurrentVersionExpiration>';
          if (rule.noncurrentVersionExpiration.noncurrentDays !== undefined) {
            xml += `<NoncurrentDays>${rule.noncurrentVersionExpiration.noncurrentDays}</NoncurrentDays>`;
          }
          xml += '</NoncurrentVersionExpiration>';
        }
        xml += '</Rule>';
        return xml;
      })
      .join('');

    const body = `<?xml version="1.0" encoding="UTF-8"?>
<LifecycleConfiguration>${rulesXml}</LifecycleConfiguration>`;

    await this.request<string>('s3', 'PUT', `/${bucket}`, {
      query: { lifecycle: '' },
      body,
      headers: { 'content-type': 'application/xml' },
    });
  }

  async s3DeleteBucketLifecycleConfiguration(bucket: string): Promise<void> {
    await this.request<string>('s3', 'DELETE', `/${bucket}`, {
      query: { lifecycle: '' },
    });
  }

  async s3GetBucketEncryption(bucket: string): Promise<S3BucketEncryption> {
    const response = await this.request<string>('s3', 'GET', `/${bucket}`, {
      query: { encryption: '' },
    });

    const rules: S3BucketEncryption['rules'] = [];
    const ruleMatches = response.matchAll(/<Rule>([\s\S]*?)<\/Rule>/g);

    for (const match of ruleMatches) {
      const ruleXml = match[1];
      const rule: S3BucketEncryption['rules'][0] = {};

      const applyMatch = ruleXml.match(/<ApplyServerSideEncryptionByDefault>([\s\S]*?)<\/ApplyServerSideEncryptionByDefault>/);
      if (applyMatch) {
        const applyXml = applyMatch[1];
        rule.applyServerSideEncryptionByDefault = {
          sseAlgorithm: (this.parseXmlValue(applyXml, 'SSEAlgorithm') as 'AES256' | 'aws:kms') || 'AES256',
        };
        const kmsKeyId = this.parseXmlValue(applyXml, 'KMSMasterKeyID');
        if (kmsKeyId) rule.applyServerSideEncryptionByDefault.kmsMasterKeyId = kmsKeyId;
      }

      const bucketKeyEnabled = this.parseXmlValue(ruleXml, 'BucketKeyEnabled');
      if (bucketKeyEnabled) rule.bucketKeyEnabled = bucketKeyEnabled === 'true';

      rules.push(rule);
    }

    return { rules };
  }

  async s3PutBucketEncryption(bucket: string, sseAlgorithm: 'AES256' | 'aws:kms', kmsMasterKeyId?: string): Promise<void> {
    let applyXml = `<SSEAlgorithm>${sseAlgorithm}</SSEAlgorithm>`;
    if (kmsMasterKeyId) {
      applyXml += `<KMSMasterKeyID>${kmsMasterKeyId}</KMSMasterKeyID>`;
    }

    const body = `<?xml version="1.0" encoding="UTF-8"?>
<ServerSideEncryptionConfiguration>
  <Rule>
    <ApplyServerSideEncryptionByDefault>${applyXml}</ApplyServerSideEncryptionByDefault>
  </Rule>
</ServerSideEncryptionConfiguration>`;

    await this.request<string>('s3', 'PUT', `/${bucket}`, {
      query: { encryption: '' },
      body,
      headers: { 'content-type': 'application/xml' },
    });
  }

  async s3DeleteBucketEncryption(bucket: string): Promise<void> {
    await this.request<string>('s3', 'DELETE', `/${bucket}`, {
      query: { encryption: '' },
    });
  }

  async s3GetBucketWebsite(bucket: string): Promise<S3WebsiteConfiguration> {
    const response = await this.request<string>('s3', 'GET', `/${bucket}`, {
      query: { website: '' },
    });

    const config: S3WebsiteConfiguration = {};

    const indexDoc = this.parseXmlValue(response, 'Suffix');
    if (indexDoc) config.indexDocument = indexDoc;

    // Check if there's an ErrorDocument with a Key
    const errorDocMatch = response.match(/<ErrorDocument>[\s\S]*?<Key>([^<]+)<\/Key>[\s\S]*?<\/ErrorDocument>/);
    if (errorDocMatch) config.errorDocument = errorDocMatch[1];

    const redirectMatch = response.match(/<RedirectAllRequestsTo>([\s\S]*?)<\/RedirectAllRequestsTo>/);
    if (redirectMatch) {
      config.redirectAllRequestsTo = {
        hostName: this.parseXmlValue(redirectMatch[1], 'HostName') || '',
      };
      const protocol = this.parseXmlValue(redirectMatch[1], 'Protocol');
      if (protocol) config.redirectAllRequestsTo.protocol = protocol as 'http' | 'https';
    }

    return config;
  }

  async s3PutBucketWebsite(bucket: string, config: S3WebsiteConfiguration): Promise<void> {
    let body = '<?xml version="1.0" encoding="UTF-8"?>\n<WebsiteConfiguration>';

    if (config.redirectAllRequestsTo) {
      body += '<RedirectAllRequestsTo>';
      body += `<HostName>${config.redirectAllRequestsTo.hostName}</HostName>`;
      if (config.redirectAllRequestsTo.protocol) {
        body += `<Protocol>${config.redirectAllRequestsTo.protocol}</Protocol>`;
      }
      body += '</RedirectAllRequestsTo>';
    } else {
      if (config.indexDocument) {
        body += `<IndexDocument><Suffix>${config.indexDocument}</Suffix></IndexDocument>`;
      }
      if (config.errorDocument) {
        body += `<ErrorDocument><Key>${config.errorDocument}</Key></ErrorDocument>`;
      }
    }

    body += '</WebsiteConfiguration>';

    await this.request<string>('s3', 'PUT', `/${bucket}`, {
      query: { website: '' },
      body,
      headers: { 'content-type': 'application/xml' },
    });
  }

  async s3DeleteBucketWebsite(bucket: string): Promise<void> {
    await this.request<string>('s3', 'DELETE', `/${bucket}`, {
      query: { website: '' },
    });
  }

  async s3GetObjectTagging(bucket: string, key: string): Promise<S3ObjectTagging> {
    const response = await this.request<string>('s3', 'GET', `/${bucket}/${encodeURIComponent(key)}`, {
      query: { tagging: '' },
    });

    const tagSet: S3ObjectTagging['tagSet'] = [];
    const tagMatches = response.matchAll(/<Tag>([\s\S]*?)<\/Tag>/g);

    for (const match of tagMatches) {
      tagSet.push({
        key: this.parseXmlValue(match[1], 'Key') || '',
        value: this.parseXmlValue(match[1], 'Value') || '',
      });
    }

    return { tagSet };
  }

  async s3PutObjectTagging(bucket: string, key: string, tags: Array<{ key: string; value: string }>): Promise<void> {
    const tagsXml = tags
      .map((t) => `<Tag><Key>${t.key}</Key><Value>${t.value}</Value></Tag>`)
      .join('');

    const body = `<?xml version="1.0" encoding="UTF-8"?>
<Tagging><TagSet>${tagsXml}</TagSet></Tagging>`;

    await this.request<string>('s3', 'PUT', `/${bucket}/${encodeURIComponent(key)}`, {
      query: { tagging: '' },
      body,
      headers: { 'content-type': 'application/xml' },
    });
  }

  async s3DeleteObjectTagging(bucket: string, key: string): Promise<void> {
    await this.request<string>('s3', 'DELETE', `/${bucket}/${encodeURIComponent(key)}`, {
      query: { tagging: '' },
    });
  }

  async s3GetBucketAcl(bucket: string): Promise<{ owner: { id: string; displayName?: string }; grants: Array<{ grantee: { type: string; id?: string; uri?: string }; permission: string }> }> {
    const response = await this.request<string>('s3', 'GET', `/${bucket}`, { query: { acl: '' } });
    const owner = {
      id: this.parseXmlValue(response, 'ID') || '',
      displayName: this.parseXmlValue(response, 'DisplayName'),
    };
    const grants: Array<{ grantee: { type: string; id?: string; uri?: string }; permission: string }> = [];
    const grantMatches = response.matchAll(/<Grant>([\s\S]*?)<\/Grant>/g);
    for (const match of grantMatches) {
      const xml = match[1];
      const granteeMatch = xml.match(/<Grantee[^>]*>([\s\S]*?)<\/Grantee>/);
      const typeMatch = xml.match(/xsi:type="([^"]+)"/);
      if (granteeMatch) {
        grants.push({
          grantee: {
            type: typeMatch ? typeMatch[1] : 'Unknown',
            id: this.parseXmlValue(granteeMatch[1], 'ID'),
            uri: this.parseXmlValue(granteeMatch[1], 'URI'),
          },
          permission: this.parseXmlValue(xml, 'Permission') || '',
        });
      }
    }
    return { owner, grants };
  }

  async s3GetObjectAcl(bucket: string, key: string): Promise<{ owner: { id: string; displayName?: string }; grants: Array<{ grantee: { type: string; id?: string; uri?: string }; permission: string }> }> {
    const response = await this.request<string>('s3', 'GET', `/${bucket}/${encodeURIComponent(key)}`, { query: { acl: '' } });
    const owner = {
      id: this.parseXmlValue(response, 'ID') || '',
      displayName: this.parseXmlValue(response, 'DisplayName'),
    };
    const grants: Array<{ grantee: { type: string; id?: string; uri?: string }; permission: string }> = [];
    const grantMatches = response.matchAll(/<Grant>([\s\S]*?)<\/Grant>/g);
    for (const match of grantMatches) {
      const xml = match[1];
      const granteeMatch = xml.match(/<Grantee[^>]*>([\s\S]*?)<\/Grantee>/);
      const typeMatch = xml.match(/xsi:type="([^"]+)"/);
      if (granteeMatch) {
        grants.push({
          grantee: {
            type: typeMatch ? typeMatch[1] : 'Unknown',
            id: this.parseXmlValue(granteeMatch[1], 'ID'),
            uri: this.parseXmlValue(granteeMatch[1], 'URI'),
          },
          permission: this.parseXmlValue(xml, 'Permission') || '',
        });
      }
    }
    return { owner, grants };
  }

  async s3ListObjectVersions(bucket: string, prefix?: string): Promise<{ versions: Array<{ key: string; versionId: string; isLatest: boolean; lastModified: string; size: number }>; deleteMarkers: Array<{ key: string; versionId: string; isLatest: boolean; lastModified: string }> }> {
    const query: Record<string, string> = { versions: '' };
    if (prefix) query.prefix = prefix;
    const response = await this.request<string>('s3', 'GET', `/${bucket}`, { query });

    const versions: Array<{ key: string; versionId: string; isLatest: boolean; lastModified: string; size: number }> = [];
    const deleteMarkers: Array<{ key: string; versionId: string; isLatest: boolean; lastModified: string }> = [];

    const versionMatches = response.matchAll(/<Version>([\s\S]*?)<\/Version>/g);
    for (const match of versionMatches) {
      const xml = match[1];
      versions.push({
        key: this.parseXmlValue(xml, 'Key') || '',
        versionId: this.parseXmlValue(xml, 'VersionId') || '',
        isLatest: this.parseXmlValue(xml, 'IsLatest') === 'true',
        lastModified: this.parseXmlValue(xml, 'LastModified') || '',
        size: parseInt(this.parseXmlValue(xml, 'Size') || '0', 10),
      });
    }

    const deleteMarkerMatches = response.matchAll(/<DeleteMarker>([\s\S]*?)<\/DeleteMarker>/g);
    for (const match of deleteMarkerMatches) {
      const xml = match[1];
      deleteMarkers.push({
        key: this.parseXmlValue(xml, 'Key') || '',
        versionId: this.parseXmlValue(xml, 'VersionId') || '',
        isLatest: this.parseXmlValue(xml, 'IsLatest') === 'true',
        lastModified: this.parseXmlValue(xml, 'LastModified') || '',
      });
    }

    return { versions, deleteMarkers };
  }

  async s3GetBucketLogging(bucket: string): Promise<{ targetBucket?: string; targetPrefix?: string }> {
    const response = await this.request<string>('s3', 'GET', `/${bucket}`, { query: { logging: '' } });
    return {
      targetBucket: this.parseXmlValue(response, 'TargetBucket'),
      targetPrefix: this.parseXmlValue(response, 'TargetPrefix'),
    };
  }

  async s3PutBucketLogging(bucket: string, targetBucket: string, targetPrefix?: string): Promise<void> {
    const xml = `<?xml version="1.0" encoding="UTF-8"?>
<BucketLoggingStatus xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <LoggingEnabled>
    <TargetBucket>${targetBucket}</TargetBucket>
    <TargetPrefix>${targetPrefix || ''}</TargetPrefix>
  </LoggingEnabled>
</BucketLoggingStatus>`;
    await this.request<string>('s3', 'PUT', `/${bucket}`, {
      query: { logging: '' },
      body: xml,
      headers: { 'content-type': 'application/xml' },
    });
  }

  async s3GetBucketNotificationConfiguration(bucket: string): Promise<{ lambdaFunctionConfigurations?: Array<{ id?: string; lambdaFunctionArn: string; events: string[] }>; queueConfigurations?: Array<{ id?: string; queueArn: string; events: string[] }>; topicConfigurations?: Array<{ id?: string; topicArn: string; events: string[] }> }> {
    const response = await this.request<string>('s3', 'GET', `/${bucket}`, { query: { notification: '' } });

    const lambdaFunctionConfigurations: Array<{ id?: string; lambdaFunctionArn: string; events: string[] }> = [];
    const queueConfigurations: Array<{ id?: string; queueArn: string; events: string[] }> = [];
    const topicConfigurations: Array<{ id?: string; topicArn: string; events: string[] }> = [];

    const lambdaMatches = response.matchAll(/<CloudFunctionConfiguration>([\s\S]*?)<\/CloudFunctionConfiguration>/g);
    for (const match of lambdaMatches) {
      const xml = match[1];
      const events: string[] = [];
      const eventMatches = xml.matchAll(/<Event>([^<]+)<\/Event>/g);
      for (const em of eventMatches) events.push(em[1]);
      lambdaFunctionConfigurations.push({
        id: this.parseXmlValue(xml, 'Id'),
        lambdaFunctionArn: this.parseXmlValue(xml, 'CloudFunction') || '',
        events,
      });
    }

    const queueMatches = response.matchAll(/<QueueConfiguration>([\s\S]*?)<\/QueueConfiguration>/g);
    for (const match of queueMatches) {
      const xml = match[1];
      const events: string[] = [];
      const eventMatches = xml.matchAll(/<Event>([^<]+)<\/Event>/g);
      for (const em of eventMatches) events.push(em[1]);
      queueConfigurations.push({
        id: this.parseXmlValue(xml, 'Id'),
        queueArn: this.parseXmlValue(xml, 'Queue') || '',
        events,
      });
    }

    const topicMatches = response.matchAll(/<TopicConfiguration>([\s\S]*?)<\/TopicConfiguration>/g);
    for (const match of topicMatches) {
      const xml = match[1];
      const events: string[] = [];
      const eventMatches = xml.matchAll(/<Event>([^<]+)<\/Event>/g);
      for (const em of eventMatches) events.push(em[1]);
      topicConfigurations.push({
        id: this.parseXmlValue(xml, 'Id'),
        topicArn: this.parseXmlValue(xml, 'Topic') || '',
        events,
      });
    }

    return {
      lambdaFunctionConfigurations: lambdaFunctionConfigurations.length > 0 ? lambdaFunctionConfigurations : undefined,
      queueConfigurations: queueConfigurations.length > 0 ? queueConfigurations : undefined,
      topicConfigurations: topicConfigurations.length > 0 ? topicConfigurations : undefined,
    };
  }

  // ===========================================================================
  // EC2
  // ===========================================================================

  async ec2DescribeInstances(params?: {
    instanceIds?: string[];
    filters?: Array<{ name: string; values: string[] }>;
  }): Promise<EC2Instance[]> {
    const queryParams: Record<string, string> = {
      Action: 'DescribeInstances',
      Version: '2016-11-15',
    };

    if (params?.instanceIds) {
      params.instanceIds.forEach((id, i) => {
        queryParams[`InstanceId.${i + 1}`] = id;
      });
    }

    if (params?.filters) {
      params.filters.forEach((filter, i) => {
        queryParams[`Filter.${i + 1}.Name`] = filter.name;
        filter.values.forEach((val, j) => {
          queryParams[`Filter.${i + 1}.Value.${j + 1}`] = val;
        });
      });
    }

    const response = await this.request<string>('ec2', 'GET', '/', { query: queryParams });

    const instances: EC2Instance[] = [];
    const instanceMatches = response.matchAll(/<item>([\s\S]*?instanceId[\s\S]*?)<\/item>/g);

    for (const match of instanceMatches) {
      const instanceXml = match[1];
      if (!instanceXml.includes('<instanceId>')) continue;

      // Parse security groups
      const securityGroups: Array<{ groupId: string; groupName: string }> = [];
      const sgMatches = instanceXml.matchAll(/<groupSet>[\s\S]*?<item>([\s\S]*?)<\/item>[\s\S]*?<\/groupSet>/g);
      for (const sgMatch of sgMatches) {
        securityGroups.push({
          groupId: this.parseXmlValue(sgMatch[1], 'groupId') || '',
          groupName: this.parseXmlValue(sgMatch[1], 'groupName') || '',
        });
      }

      // Parse tags
      const tags: Array<{ key: string; value: string }> = [];
      const tagMatches = instanceXml.matchAll(/<tagSet>[\s\S]*?<item>([\s\S]*?)<\/item>[\s\S]*?<\/tagSet>/g);
      for (const tagMatch of tagMatches) {
        tags.push({
          key: this.parseXmlValue(tagMatch[1], 'key') || '',
          value: this.parseXmlValue(tagMatch[1], 'value') || '',
        });
      }

      instances.push({
        instanceId: this.parseXmlValue(instanceXml, 'instanceId') || '',
        instanceType: this.parseXmlValue(instanceXml, 'instanceType') || '',
        state: this.parseXmlValue(instanceXml, 'name') || '',
        publicIpAddress: this.parseXmlValue(instanceXml, 'ipAddress'),
        privateIpAddress: this.parseXmlValue(instanceXml, 'privateIpAddress'),
        launchTime: this.parseXmlValue(instanceXml, 'launchTime') || '',
        availabilityZone: this.parseXmlValue(instanceXml, 'availabilityZone'),
        vpcId: this.parseXmlValue(instanceXml, 'vpcId'),
        subnetId: this.parseXmlValue(instanceXml, 'subnetId'),
        securityGroups,
        tags,
      });
    }

    return instances;
  }

  async ec2DescribeSecurityGroups(groupIds?: string[]): Promise<EC2SecurityGroup[]> {
    const queryParams: Record<string, string> = {
      Action: 'DescribeSecurityGroups',
      Version: '2016-11-15',
    };

    if (groupIds) {
      groupIds.forEach((id, i) => {
        queryParams[`GroupId.${i + 1}`] = id;
      });
    }

    const response = await this.request<string>('ec2', 'GET', '/', { query: queryParams });

    const groups: EC2SecurityGroup[] = [];
    const groupMatches = response.matchAll(/<item>([\s\S]*?groupId[\s\S]*?)<\/item>/g);

    for (const match of groupMatches) {
      const groupXml = match[1];
      if (!groupXml.includes('<groupId>')) continue;

      const parseRules = (rulesXml: string): EC2SecurityGroupRule[] => {
        const rules: EC2SecurityGroupRule[] = [];
        const ruleMatches = rulesXml.matchAll(/<item>([\s\S]*?)<\/item>/g);
        for (const ruleMatch of ruleMatches) {
          const ruleXml = ruleMatch[1];
          rules.push({
            protocol: this.parseXmlValue(ruleXml, 'ipProtocol') || '',
            fromPort: this.parseXmlValue(ruleXml, 'fromPort') ? Number.parseInt(this.parseXmlValue(ruleXml, 'fromPort')!, 10) : undefined,
            toPort: this.parseXmlValue(ruleXml, 'toPort') ? Number.parseInt(this.parseXmlValue(ruleXml, 'toPort')!, 10) : undefined,
            cidrIpv4: this.parseXmlValue(ruleXml, 'cidrIp'),
          });
        }
        return rules;
      };

      const ingressMatch = groupXml.match(/<ipPermissions>([\s\S]*?)<\/ipPermissions>/);
      const egressMatch = groupXml.match(/<ipPermissionsEgress>([\s\S]*?)<\/ipPermissionsEgress>/);

      const tags: Array<{ key: string; value: string }> = [];
      const tagMatches = groupXml.matchAll(/<tagSet>[\s\S]*?<item>([\s\S]*?)<\/item>[\s\S]*?<\/tagSet>/g);
      for (const tagMatch of tagMatches) {
        tags.push({
          key: this.parseXmlValue(tagMatch[1], 'key') || '',
          value: this.parseXmlValue(tagMatch[1], 'value') || '',
        });
      }

      groups.push({
        groupId: this.parseXmlValue(groupXml, 'groupId') || '',
        groupName: this.parseXmlValue(groupXml, 'groupName') || '',
        description: this.parseXmlValue(groupXml, 'groupDescription') || '',
        vpcId: this.parseXmlValue(groupXml, 'vpcId'),
        ingressRules: ingressMatch ? parseRules(ingressMatch[1]) : [],
        egressRules: egressMatch ? parseRules(egressMatch[1]) : [],
        tags,
      });
    }

    return groups;
  }

  async ec2DescribeVolumes(volumeIds?: string[]): Promise<EC2Volume[]> {
    const queryParams: Record<string, string> = {
      Action: 'DescribeVolumes',
      Version: '2016-11-15',
    };

    if (volumeIds) {
      volumeIds.forEach((id, i) => {
        queryParams[`VolumeId.${i + 1}`] = id;
      });
    }

    const response = await this.request<string>('ec2', 'GET', '/', { query: queryParams });

    const volumes: EC2Volume[] = [];
    const volumeMatches = response.matchAll(/<item>([\s\S]*?volumeId[\s\S]*?)<\/item>/g);

    for (const match of volumeMatches) {
      const volumeXml = match[1];
      if (!volumeXml.includes('<volumeId>')) continue;

      const attachments: Array<{ instanceId: string; device: string; state: string }> = [];
      const attachMatches = volumeXml.matchAll(/<attachmentSet>[\s\S]*?<item>([\s\S]*?)<\/item>[\s\S]*?<\/attachmentSet>/g);
      for (const attachMatch of attachMatches) {
        attachments.push({
          instanceId: this.parseXmlValue(attachMatch[1], 'instanceId') || '',
          device: this.parseXmlValue(attachMatch[1], 'device') || '',
          state: this.parseXmlValue(attachMatch[1], 'status') || '',
        });
      }

      const tags: Array<{ key: string; value: string }> = [];
      const tagMatches = volumeXml.matchAll(/<tagSet>[\s\S]*?<item>([\s\S]*?)<\/item>[\s\S]*?<\/tagSet>/g);
      for (const tagMatch of tagMatches) {
        tags.push({
          key: this.parseXmlValue(tagMatch[1], 'key') || '',
          value: this.parseXmlValue(tagMatch[1], 'value') || '',
        });
      }

      volumes.push({
        volumeId: this.parseXmlValue(volumeXml, 'volumeId') || '',
        size: Number.parseInt(this.parseXmlValue(volumeXml, 'size') || '0', 10),
        volumeType: this.parseXmlValue(volumeXml, 'volumeType') || '',
        state: this.parseXmlValue(volumeXml, 'status') || '',
        availabilityZone: this.parseXmlValue(volumeXml, 'availabilityZone') || '',
        encrypted: this.parseXmlValue(volumeXml, 'encrypted') === 'true',
        iops: this.parseXmlValue(volumeXml, 'iops') ? Number.parseInt(this.parseXmlValue(volumeXml, 'iops')!, 10) : undefined,
        attachments,
        tags,
      });
    }

    return volumes;
  }

  async ec2DescribeVpcs(vpcIds?: string[]): Promise<EC2Vpc[]> {
    const queryParams: Record<string, string> = {
      Action: 'DescribeVpcs',
      Version: '2016-11-15',
    };

    if (vpcIds) {
      vpcIds.forEach((id, i) => {
        queryParams[`VpcId.${i + 1}`] = id;
      });
    }

    const response = await this.request<string>('ec2', 'GET', '/', { query: queryParams });

    const vpcs: EC2Vpc[] = [];
    const vpcMatches = response.matchAll(/<item>([\s\S]*?vpcId[\s\S]*?)<\/item>/g);

    for (const match of vpcMatches) {
      const vpcXml = match[1];
      if (!vpcXml.includes('<vpcId>')) continue;

      const tags: Array<{ key: string; value: string }> = [];
      const tagMatches = vpcXml.matchAll(/<tagSet>[\s\S]*?<item>([\s\S]*?)<\/item>[\s\S]*?<\/tagSet>/g);
      for (const tagMatch of tagMatches) {
        tags.push({
          key: this.parseXmlValue(tagMatch[1], 'key') || '',
          value: this.parseXmlValue(tagMatch[1], 'value') || '',
        });
      }

      vpcs.push({
        vpcId: this.parseXmlValue(vpcXml, 'vpcId') || '',
        cidrBlock: this.parseXmlValue(vpcXml, 'cidrBlock') || '',
        state: this.parseXmlValue(vpcXml, 'state') || '',
        isDefault: this.parseXmlValue(vpcXml, 'isDefault') === 'true',
        tags,
      });
    }

    return vpcs;
  }

  async ec2DescribeSubnets(subnetIds?: string[]): Promise<EC2Subnet[]> {
    const queryParams: Record<string, string> = {
      Action: 'DescribeSubnets',
      Version: '2016-11-15',
    };

    if (subnetIds) {
      subnetIds.forEach((id, i) => {
        queryParams[`SubnetId.${i + 1}`] = id;
      });
    }

    const response = await this.request<string>('ec2', 'GET', '/', { query: queryParams });

    const subnets: EC2Subnet[] = [];
    const subnetMatches = response.matchAll(/<item>([\s\S]*?subnetId[\s\S]*?)<\/item>/g);

    for (const match of subnetMatches) {
      const subnetXml = match[1];
      if (!subnetXml.includes('<subnetId>')) continue;

      const tags: Array<{ key: string; value: string }> = [];
      const tagMatches = subnetXml.matchAll(/<tagSet>[\s\S]*?<item>([\s\S]*?)<\/item>[\s\S]*?<\/tagSet>/g);
      for (const tagMatch of tagMatches) {
        tags.push({
          key: this.parseXmlValue(tagMatch[1], 'key') || '',
          value: this.parseXmlValue(tagMatch[1], 'value') || '',
        });
      }

      subnets.push({
        subnetId: this.parseXmlValue(subnetXml, 'subnetId') || '',
        vpcId: this.parseXmlValue(subnetXml, 'vpcId') || '',
        cidrBlock: this.parseXmlValue(subnetXml, 'cidrBlock') || '',
        availabilityZone: this.parseXmlValue(subnetXml, 'availabilityZone') || '',
        availableIpAddressCount: Number.parseInt(this.parseXmlValue(subnetXml, 'availableIpAddressCount') || '0', 10),
        mapPublicIpOnLaunch: this.parseXmlValue(subnetXml, 'mapPublicIpOnLaunch') === 'true',
        tags,
      });
    }

    return subnets;
  }

  async ec2DescribeImages(params?: { imageIds?: string[]; owners?: string[] }): Promise<EC2Image[]> {
    const queryParams: Record<string, string> = {
      Action: 'DescribeImages',
      Version: '2016-11-15',
    };

    if (params?.imageIds) {
      params.imageIds.forEach((id, i) => {
        queryParams[`ImageId.${i + 1}`] = id;
      });
    }

    if (params?.owners) {
      params.owners.forEach((owner, i) => {
        queryParams[`Owner.${i + 1}`] = owner;
      });
    }

    const response = await this.request<string>('ec2', 'GET', '/', { query: queryParams });

    const images: EC2Image[] = [];
    const imageMatches = response.matchAll(/<item>([\s\S]*?imageId[\s\S]*?)<\/item>/g);

    for (const match of imageMatches) {
      const imageXml = match[1];
      if (!imageXml.includes('<imageId>')) continue;

      const tags: Array<{ key: string; value: string }> = [];
      const tagMatches = imageXml.matchAll(/<tagSet>[\s\S]*?<item>([\s\S]*?)<\/item>[\s\S]*?<\/tagSet>/g);
      for (const tagMatch of tagMatches) {
        tags.push({
          key: this.parseXmlValue(tagMatch[1], 'key') || '',
          value: this.parseXmlValue(tagMatch[1], 'value') || '',
        });
      }

      images.push({
        imageId: this.parseXmlValue(imageXml, 'imageId') || '',
        name: this.parseXmlValue(imageXml, 'name') || '',
        description: this.parseXmlValue(imageXml, 'description'),
        state: this.parseXmlValue(imageXml, 'imageState') || '',
        architecture: this.parseXmlValue(imageXml, 'architecture') || '',
        platform: this.parseXmlValue(imageXml, 'platform'),
        creationDate: this.parseXmlValue(imageXml, 'creationDate'),
        ownerId: this.parseXmlValue(imageXml, 'imageOwnerId') || '',
        public: this.parseXmlValue(imageXml, 'isPublic') === 'true',
        tags,
      });
    }

    return images;
  }

  async ec2DescribeKeyPairs(): Promise<EC2KeyPair[]> {
    const response = await this.request<string>('ec2', 'GET', '/', {
      query: { Action: 'DescribeKeyPairs', Version: '2016-11-15' },
    });

    const keyPairs: EC2KeyPair[] = [];
    const keyMatches = response.matchAll(/<item>([\s\S]*?keyName[\s\S]*?)<\/item>/g);

    for (const match of keyMatches) {
      const keyXml = match[1];

      const tags: Array<{ key: string; value: string }> = [];
      const tagMatches = keyXml.matchAll(/<tagSet>[\s\S]*?<item>([\s\S]*?)<\/item>[\s\S]*?<\/tagSet>/g);
      for (const tagMatch of tagMatches) {
        tags.push({
          key: this.parseXmlValue(tagMatch[1], 'key') || '',
          value: this.parseXmlValue(tagMatch[1], 'value') || '',
        });
      }

      keyPairs.push({
        keyName: this.parseXmlValue(keyXml, 'keyName') || '',
        keyPairId: this.parseXmlValue(keyXml, 'keyPairId') || '',
        keyFingerprint: this.parseXmlValue(keyXml, 'keyFingerprint') || '',
        tags,
      });
    }

    return keyPairs;
  }

  async ec2StartInstances(instanceIds: string[]): Promise<void> {
    const queryParams: Record<string, string> = {
      Action: 'StartInstances',
      Version: '2016-11-15',
    };
    instanceIds.forEach((id, i) => {
      queryParams[`InstanceId.${i + 1}`] = id;
    });

    await this.request<string>('ec2', 'POST', '/', { query: queryParams });
  }

  async ec2StopInstances(instanceIds: string[]): Promise<void> {
    const queryParams: Record<string, string> = {
      Action: 'StopInstances',
      Version: '2016-11-15',
    };
    instanceIds.forEach((id, i) => {
      queryParams[`InstanceId.${i + 1}`] = id;
    });

    await this.request<string>('ec2', 'POST', '/', { query: queryParams });
  }

  async ec2RebootInstances(instanceIds: string[]): Promise<void> {
    const queryParams: Record<string, string> = {
      Action: 'RebootInstances',
      Version: '2016-11-15',
    };
    instanceIds.forEach((id, i) => {
      queryParams[`InstanceId.${i + 1}`] = id;
    });

    await this.request<string>('ec2', 'POST', '/', { query: queryParams });
  }

  async ec2TerminateInstances(instanceIds: string[]): Promise<void> {
    const queryParams: Record<string, string> = {
      Action: 'TerminateInstances',
      Version: '2016-11-15',
    };
    instanceIds.forEach((id, i) => {
      queryParams[`InstanceId.${i + 1}`] = id;
    });

    await this.request<string>('ec2', 'POST', '/', { query: queryParams });
  }

  async ec2DescribeSnapshots(params?: { snapshotIds?: string[]; ownerIds?: string[] }): Promise<EC2Snapshot[]> {
    const queryParams: Record<string, string> = {
      Action: 'DescribeSnapshots',
      Version: '2016-11-15',
    };

    if (params?.snapshotIds) {
      params.snapshotIds.forEach((id, i) => {
        queryParams[`SnapshotId.${i + 1}`] = id;
      });
    }

    if (params?.ownerIds) {
      params.ownerIds.forEach((id, i) => {
        queryParams[`Owner.${i + 1}`] = id;
      });
    } else {
      queryParams['Owner.1'] = 'self';
    }

    const response = await this.request<string>('ec2', 'GET', '/', { query: queryParams });

    const snapshots: EC2Snapshot[] = [];
    const snapshotMatches = response.matchAll(/<item>([\s\S]*?snapshotId[\s\S]*?)<\/item>/g);

    for (const match of snapshotMatches) {
      const snapshotXml = match[1];
      if (!snapshotXml.includes('<snapshotId>')) continue;

      const tags: Array<{ key: string; value: string }> = [];
      const tagMatches = snapshotXml.matchAll(/<tagSet>[\s\S]*?<item>([\s\S]*?)<\/item>[\s\S]*?<\/tagSet>/g);
      for (const tagMatch of tagMatches) {
        const tagXml = tagMatch[1];
        tags.push({
          key: this.parseXmlValue(tagXml, 'key') || '',
          value: this.parseXmlValue(tagXml, 'value') || '',
        });
      }

      snapshots.push({
        snapshotId: this.parseXmlValue(snapshotXml, 'snapshotId') || '',
        volumeId: this.parseXmlValue(snapshotXml, 'volumeId') || '',
        state: this.parseXmlValue(snapshotXml, 'status') || '',
        progress: this.parseXmlValue(snapshotXml, 'progress') || '',
        startTime: this.parseXmlValue(snapshotXml, 'startTime') || '',
        volumeSize: parseInt(this.parseXmlValue(snapshotXml, 'volumeSize') || '0', 10),
        description: this.parseXmlValue(snapshotXml, 'description'),
        ownerId: this.parseXmlValue(snapshotXml, 'ownerId') || '',
        encrypted: this.parseXmlValue(snapshotXml, 'encrypted') === 'true',
        tags,
      });
    }

    return snapshots;
  }

  async ec2DescribeNatGateways(natGatewayIds?: string[]): Promise<EC2NatGateway[]> {
    const queryParams: Record<string, string> = {
      Action: 'DescribeNatGateways',
      Version: '2016-11-15',
    };

    if (natGatewayIds) {
      natGatewayIds.forEach((id, i) => {
        queryParams[`NatGatewayId.${i + 1}`] = id;
      });
    }

    const response = await this.request<string>('ec2', 'GET', '/', { query: queryParams });

    const natGateways: EC2NatGateway[] = [];
    const ngMatches = response.matchAll(/<item>([\s\S]*?natGatewayId[\s\S]*?)<\/item>/g);

    for (const match of ngMatches) {
      const ngXml = match[1];
      if (!ngXml.includes('<natGatewayId>')) continue;

      const addresses: EC2NatGateway['natGatewayAddresses'] = [];
      const addrMatches = ngXml.matchAll(/<natGatewayAddressSet>[\s\S]*?<item>([\s\S]*?)<\/item>[\s\S]*?<\/natGatewayAddressSet>/g);
      for (const addrMatch of addrMatches) {
        const addrXml = addrMatch[1];
        addresses.push({
          allocationId: this.parseXmlValue(addrXml, 'allocationId'),
          networkInterfaceId: this.parseXmlValue(addrXml, 'networkInterfaceId'),
          privateIp: this.parseXmlValue(addrXml, 'privateIp'),
          publicIp: this.parseXmlValue(addrXml, 'publicIp'),
        });
      }

      const tags: Array<{ key: string; value: string }> = [];
      const tagMatches = ngXml.matchAll(/<tagSet>[\s\S]*?<item>([\s\S]*?)<\/item>[\s\S]*?<\/tagSet>/g);
      for (const tagMatch of tagMatches) {
        const tagXml = tagMatch[1];
        tags.push({
          key: this.parseXmlValue(tagXml, 'key') || '',
          value: this.parseXmlValue(tagXml, 'value') || '',
        });
      }

      natGateways.push({
        natGatewayId: this.parseXmlValue(ngXml, 'natGatewayId') || '',
        vpcId: this.parseXmlValue(ngXml, 'vpcId') || '',
        subnetId: this.parseXmlValue(ngXml, 'subnetId') || '',
        state: this.parseXmlValue(ngXml, 'state') || '',
        connectivityType: this.parseXmlValue(ngXml, 'connectivityType') || 'public',
        natGatewayAddresses: addresses,
        createTime: this.parseXmlValue(ngXml, 'createTime') || '',
        tags,
      });
    }

    return natGateways;
  }

  async ec2DescribeLaunchTemplates(launchTemplateIds?: string[]): Promise<EC2LaunchTemplate[]> {
    const queryParams: Record<string, string> = {
      Action: 'DescribeLaunchTemplates',
      Version: '2016-11-15',
    };

    if (launchTemplateIds) {
      launchTemplateIds.forEach((id, i) => {
        queryParams[`LaunchTemplateId.${i + 1}`] = id;
      });
    }

    const response = await this.request<string>('ec2', 'GET', '/', { query: queryParams });

    const templates: EC2LaunchTemplate[] = [];
    const ltMatches = response.matchAll(/<item>([\s\S]*?launchTemplateId[\s\S]*?)<\/item>/g);

    for (const match of ltMatches) {
      const ltXml = match[1];
      if (!ltXml.includes('<launchTemplateId>')) continue;

      const tags: Array<{ key: string; value: string }> = [];
      const tagMatches = ltXml.matchAll(/<tagSet>[\s\S]*?<item>([\s\S]*?)<\/item>[\s\S]*?<\/tagSet>/g);
      for (const tagMatch of tagMatches) {
        const tagXml = tagMatch[1];
        tags.push({
          key: this.parseXmlValue(tagXml, 'key') || '',
          value: this.parseXmlValue(tagXml, 'value') || '',
        });
      }

      templates.push({
        launchTemplateId: this.parseXmlValue(ltXml, 'launchTemplateId') || '',
        launchTemplateName: this.parseXmlValue(ltXml, 'launchTemplateName') || '',
        createTime: this.parseXmlValue(ltXml, 'createTime') || '',
        createdBy: this.parseXmlValue(ltXml, 'createdBy') || '',
        defaultVersionNumber: parseInt(this.parseXmlValue(ltXml, 'defaultVersionNumber') || '1', 10),
        latestVersionNumber: parseInt(this.parseXmlValue(ltXml, 'latestVersionNumber') || '1', 10),
        tags,
      });
    }

    return templates;
  }

  async ec2DescribeAddresses(allocationIds?: string[]): Promise<EC2ElasticIp[]> {
    const queryParams: Record<string, string> = {
      Action: 'DescribeAddresses',
      Version: '2016-11-15',
    };

    if (allocationIds) {
      allocationIds.forEach((id, i) => {
        queryParams[`AllocationId.${i + 1}`] = id;
      });
    }

    const response = await this.request<string>('ec2', 'GET', '/', { query: queryParams });

    const addresses: EC2ElasticIp[] = [];
    const addrMatches = response.matchAll(/<item>([\s\S]*?publicIp[\s\S]*?)<\/item>/g);

    for (const match of addrMatches) {
      const addrXml = match[1];
      if (!addrXml.includes('<publicIp>')) continue;

      const tags: Array<{ key: string; value: string }> = [];
      const tagMatches = addrXml.matchAll(/<tags>[\s\S]*?<item>([\s\S]*?)<\/item>[\s\S]*?<\/tags>/g);
      for (const tagMatch of tagMatches) {
        const tagXml = tagMatch[1];
        tags.push({
          key: this.parseXmlValue(tagXml, 'key') || '',
          value: this.parseXmlValue(tagXml, 'value') || '',
        });
      }

      addresses.push({
        publicIp: this.parseXmlValue(addrXml, 'publicIp') || '',
        allocationId: this.parseXmlValue(addrXml, 'allocationId') || '',
        domain: this.parseXmlValue(addrXml, 'domain') || 'vpc',
        instanceId: this.parseXmlValue(addrXml, 'instanceId'),
        associationId: this.parseXmlValue(addrXml, 'associationId'),
        networkInterfaceId: this.parseXmlValue(addrXml, 'networkInterfaceId'),
        privateIpAddress: this.parseXmlValue(addrXml, 'privateIpAddress'),
        tags,
      });
    }

    return addresses;
  }

  async ec2DescribeAvailabilityZones(): Promise<EC2AvailabilityZone[]> {
    const queryParams: Record<string, string> = {
      Action: 'DescribeAvailabilityZones',
      Version: '2016-11-15',
    };

    const response = await this.request<string>('ec2', 'GET', '/', { query: queryParams });

    const zones: EC2AvailabilityZone[] = [];
    const zoneMatches = response.matchAll(/<item>([\s\S]*?zoneName[\s\S]*?)<\/item>/g);

    for (const match of zoneMatches) {
      const zoneXml = match[1];
      if (!zoneXml.includes('<zoneName>')) continue;

      zones.push({
        zoneName: this.parseXmlValue(zoneXml, 'zoneName') || '',
        zoneId: this.parseXmlValue(zoneXml, 'zoneId') || '',
        regionName: this.parseXmlValue(zoneXml, 'regionName') || '',
        state: this.parseXmlValue(zoneXml, 'zoneState') || '',
        zoneType: this.parseXmlValue(zoneXml, 'zoneType') || 'availability-zone',
      });
    }

    return zones;
  }

  async ec2CreateSecurityGroup(groupName: string, description: string, vpcId?: string): Promise<{ groupId: string }> {
    const query: Record<string, string> = {
      Action: 'CreateSecurityGroup',
      Version: '2016-11-15',
      GroupName: groupName,
      GroupDescription: description,
    };
    if (vpcId) query.VpcId = vpcId;

    const response = await this.request<string>('ec2', 'POST', '/', { query });
    return { groupId: this.parseXmlValue(response, 'groupId') || '' };
  }

  async ec2DeleteSecurityGroup(groupId: string): Promise<void> {
    await this.request<string>('ec2', 'POST', '/', {
      query: { Action: 'DeleteSecurityGroup', Version: '2016-11-15', GroupId: groupId },
    });
  }

  private buildSecurityGroupRulesQuery(rules: EC2SecurityGroupRule[], prefix: string): Record<string, string> {
    const query: Record<string, string> = {};
    rules.forEach((rule, i) => {
      const p = `${prefix}.${i + 1}`;
      query[`${p}.IpProtocol`] = rule.protocol;
      if (rule.fromPort !== undefined) query[`${p}.FromPort`] = String(rule.fromPort);
      if (rule.toPort !== undefined) query[`${p}.ToPort`] = String(rule.toPort);
      if (rule.cidrIpv4) query[`${p}.IpRanges.1.CidrIp`] = rule.cidrIpv4;
      if (rule.cidrIpv6) query[`${p}.Ipv6Ranges.1.CidrIpv6`] = rule.cidrIpv6;
      if (rule.sourceSecurityGroupId) query[`${p}.UserIdGroupPairs.1.GroupId`] = rule.sourceSecurityGroupId;
      if (rule.description) {
        if (rule.cidrIpv4) query[`${p}.IpRanges.1.Description`] = rule.description;
        else if (rule.cidrIpv6) query[`${p}.Ipv6Ranges.1.Description`] = rule.description;
        else if (rule.sourceSecurityGroupId) query[`${p}.UserIdGroupPairs.1.Description`] = rule.description;
      }
    });
    return query;
  }

  async ec2AuthorizeSecurityGroupIngress(groupId: string, rules: EC2SecurityGroupRule[]): Promise<void> {
    const query: Record<string, string> = {
      Action: 'AuthorizeSecurityGroupIngress',
      Version: '2016-11-15',
      GroupId: groupId,
      ...this.buildSecurityGroupRulesQuery(rules, 'IpPermissions'),
    };
    await this.request<string>('ec2', 'POST', '/', { query });
  }

  async ec2RevokeSecurityGroupIngress(groupId: string, rules: EC2SecurityGroupRule[]): Promise<void> {
    const query: Record<string, string> = {
      Action: 'RevokeSecurityGroupIngress',
      Version: '2016-11-15',
      GroupId: groupId,
      ...this.buildSecurityGroupRulesQuery(rules, 'IpPermissions'),
    };
    await this.request<string>('ec2', 'POST', '/', { query });
  }

  async ec2AuthorizeSecurityGroupEgress(groupId: string, rules: EC2SecurityGroupRule[]): Promise<void> {
    const query: Record<string, string> = {
      Action: 'AuthorizeSecurityGroupEgress',
      Version: '2016-11-15',
      GroupId: groupId,
      ...this.buildSecurityGroupRulesQuery(rules, 'IpPermissions'),
    };
    await this.request<string>('ec2', 'POST', '/', { query });
  }

  async ec2RevokeSecurityGroupEgress(groupId: string, rules: EC2SecurityGroupRule[]): Promise<void> {
    const query: Record<string, string> = {
      Action: 'RevokeSecurityGroupEgress',
      Version: '2016-11-15',
      GroupId: groupId,
      ...this.buildSecurityGroupRulesQuery(rules, 'IpPermissions'),
    };
    await this.request<string>('ec2', 'POST', '/', { query });
  }

  async ec2AllocateAddress(): Promise<{ allocationId: string; publicIp: string }> {
    const response = await this.request<string>('ec2', 'POST', '/', {
      query: { Action: 'AllocateAddress', Version: '2016-11-15', Domain: 'vpc' },
    });
    return {
      allocationId: this.parseXmlValue(response, 'allocationId') || '',
      publicIp: this.parseXmlValue(response, 'publicIp') || '',
    };
  }

  async ec2ReleaseAddress(allocationId: string): Promise<void> {
    await this.request<string>('ec2', 'POST', '/', {
      query: { Action: 'ReleaseAddress', Version: '2016-11-15', AllocationId: allocationId },
    });
  }

  async ec2AssociateAddress(allocationId: string, instanceId?: string, networkInterfaceId?: string): Promise<{ associationId: string }> {
    const query: Record<string, string> = {
      Action: 'AssociateAddress',
      Version: '2016-11-15',
      AllocationId: allocationId,
    };
    if (instanceId) query.InstanceId = instanceId;
    if (networkInterfaceId) query.NetworkInterfaceId = networkInterfaceId;

    const response = await this.request<string>('ec2', 'POST', '/', { query });
    return { associationId: this.parseXmlValue(response, 'associationId') || '' };
  }

  async ec2DisassociateAddress(associationId: string): Promise<void> {
    await this.request<string>('ec2', 'POST', '/', {
      query: { Action: 'DisassociateAddress', Version: '2016-11-15', AssociationId: associationId },
    });
  }

  async ec2CreateTags(resourceIds: string[], tags: Array<{ key: string; value: string }>): Promise<void> {
    const query: Record<string, string> = {
      Action: 'CreateTags',
      Version: '2016-11-15',
    };
    resourceIds.forEach((id, i) => { query[`ResourceId.${i + 1}`] = id; });
    tags.forEach((tag, i) => {
      query[`Tag.${i + 1}.Key`] = tag.key;
      query[`Tag.${i + 1}.Value`] = tag.value;
    });
    await this.request<string>('ec2', 'POST', '/', { query });
  }

  async ec2DeleteTags(resourceIds: string[], tags: Array<{ key: string }>): Promise<void> {
    const query: Record<string, string> = {
      Action: 'DeleteTags',
      Version: '2016-11-15',
    };
    resourceIds.forEach((id, i) => { query[`ResourceId.${i + 1}`] = id; });
    tags.forEach((tag, i) => { query[`Tag.${i + 1}.Key`] = tag.key; });
    await this.request<string>('ec2', 'POST', '/', { query });
  }

  async ec2CreateVolume(params: {
    availabilityZone: string;
    size?: number;
    snapshotId?: string;
    volumeType?: string;
    iops?: number;
    encrypted?: boolean;
    kmsKeyId?: string;
  }): Promise<EC2Volume> {
    const query: Record<string, string> = {
      Action: 'CreateVolume',
      Version: '2016-11-15',
      AvailabilityZone: params.availabilityZone,
    };

    if (params.size !== undefined) query.Size = String(params.size);
    if (params.snapshotId) query.SnapshotId = params.snapshotId;
    if (params.volumeType) query.VolumeType = params.volumeType;
    if (params.iops !== undefined) query.Iops = String(params.iops);
    if (params.encrypted !== undefined) query.Encrypted = String(params.encrypted);
    if (params.kmsKeyId) query.KmsKeyId = params.kmsKeyId;

    const response = await this.request<string>('ec2', 'POST', '/', { query });

    return {
      volumeId: this.parseXmlValue(response, 'volumeId') || '',
      size: Number.parseInt(this.parseXmlValue(response, 'size') || '0', 10),
      availabilityZone: this.parseXmlValue(response, 'availabilityZone') || '',
      state: this.parseXmlValue(response, 'status') || '',
      volumeType: this.parseXmlValue(response, 'volumeType') || '',
      encrypted: this.parseXmlValue(response, 'encrypted') === 'true',
      iops: this.parseXmlValue(response, 'iops') ? Number.parseInt(this.parseXmlValue(response, 'iops')!, 10) : undefined,
      attachments: [],
      tags: [],
    };
  }

  async ec2DeleteVolume(volumeId: string): Promise<void> {
    await this.request<string>('ec2', 'POST', '/', {
      query: {
        Action: 'DeleteVolume',
        Version: '2016-11-15',
        VolumeId: volumeId,
      },
    });
  }

  async ec2AttachVolume(volumeId: string, instanceId: string, device: string): Promise<{ attachTime: string; device: string; instanceId: string; state: string; volumeId: string }> {
    const response = await this.request<string>('ec2', 'POST', '/', {
      query: {
        Action: 'AttachVolume',
        Version: '2016-11-15',
        VolumeId: volumeId,
        InstanceId: instanceId,
        Device: device,
      },
    });

    return {
      attachTime: this.parseXmlValue(response, 'attachTime') || '',
      device: this.parseXmlValue(response, 'device') || '',
      instanceId: this.parseXmlValue(response, 'instanceId') || '',
      state: this.parseXmlValue(response, 'status') || '',
      volumeId: this.parseXmlValue(response, 'volumeId') || '',
    };
  }

  async ec2DetachVolume(volumeId: string, force?: boolean): Promise<{ attachTime: string; device: string; instanceId: string; state: string; volumeId: string }> {
    const query: Record<string, string> = {
      Action: 'DetachVolume',
      Version: '2016-11-15',
      VolumeId: volumeId,
    };
    if (force) query.Force = 'true';

    const response = await this.request<string>('ec2', 'POST', '/', { query });

    return {
      attachTime: this.parseXmlValue(response, 'attachTime') || '',
      device: this.parseXmlValue(response, 'device') || '',
      instanceId: this.parseXmlValue(response, 'instanceId') || '',
      state: this.parseXmlValue(response, 'status') || '',
      volumeId: this.parseXmlValue(response, 'volumeId') || '',
    };
  }

  async ec2CreateSnapshot(volumeId: string, description?: string): Promise<EC2Snapshot> {
    const query: Record<string, string> = {
      Action: 'CreateSnapshot',
      Version: '2016-11-15',
      VolumeId: volumeId,
    };
    if (description) query.Description = description;

    const response = await this.request<string>('ec2', 'POST', '/', { query });

    return {
      snapshotId: this.parseXmlValue(response, 'snapshotId') || '',
      volumeId: this.parseXmlValue(response, 'volumeId') || '',
      state: this.parseXmlValue(response, 'status') || '',
      volumeSize: Number.parseInt(this.parseXmlValue(response, 'volumeSize') || '0', 10),
      startTime: this.parseXmlValue(response, 'startTime') || '',
      progress: this.parseXmlValue(response, 'progress') || '',
      ownerId: this.parseXmlValue(response, 'ownerId') || '',
      description: this.parseXmlValue(response, 'description'),
      encrypted: this.parseXmlValue(response, 'encrypted') === 'true',
      tags: [],
    };
  }

  async ec2DeleteSnapshot(snapshotId: string): Promise<void> {
    await this.request<string>('ec2', 'POST', '/', {
      query: {
        Action: 'DeleteSnapshot',
        Version: '2016-11-15',
        SnapshotId: snapshotId,
      },
    });
  }

  async ec2CopySnapshot(sourceSnapshotId: string, sourceRegion: string, description?: string): Promise<{ snapshotId: string }> {
    const query: Record<string, string> = {
      Action: 'CopySnapshot',
      Version: '2016-11-15',
      SourceSnapshotId: sourceSnapshotId,
      SourceRegion: sourceRegion,
    };
    if (description) query.Description = description;

    const response = await this.request<string>('ec2', 'POST', '/', { query });

    return {
      snapshotId: this.parseXmlValue(response, 'snapshotId') || '',
    };
  }

  async ec2CreateVpc(cidrBlock: string, instanceTenancy?: string): Promise<EC2Vpc> {
    const query: Record<string, string> = {
      Action: 'CreateVpc',
      Version: '2016-11-15',
      CidrBlock: cidrBlock,
    };
    if (instanceTenancy) query.InstanceTenancy = instanceTenancy;

    const response = await this.request<string>('ec2', 'POST', '/', { query });

    return {
      vpcId: this.parseXmlValue(response, 'vpcId') || '',
      cidrBlock: this.parseXmlValue(response, 'cidrBlock') || cidrBlock,
      state: this.parseXmlValue(response, 'state') || 'pending',
      isDefault: false,
      tags: [],
    };
  }

  async ec2DeleteVpc(vpcId: string): Promise<void> {
    await this.request<string>('ec2', 'POST', '/', {
      query: {
        Action: 'DeleteVpc',
        Version: '2016-11-15',
        VpcId: vpcId,
      },
    });
  }

  async ec2CreateSubnet(vpcId: string, cidrBlock: string, availabilityZone?: string): Promise<EC2Subnet> {
    const query: Record<string, string> = {
      Action: 'CreateSubnet',
      Version: '2016-11-15',
      VpcId: vpcId,
      CidrBlock: cidrBlock,
    };
    if (availabilityZone) query.AvailabilityZone = availabilityZone;

    const response = await this.request<string>('ec2', 'POST', '/', { query });

    return {
      subnetId: this.parseXmlValue(response, 'subnetId') || '',
      vpcId: this.parseXmlValue(response, 'vpcId') || vpcId,
      cidrBlock: this.parseXmlValue(response, 'cidrBlock') || cidrBlock,
      availabilityZone: this.parseXmlValue(response, 'availabilityZone') || '',
      availableIpAddressCount: parseInt(this.parseXmlValue(response, 'availableIpAddressCount') || '0', 10),
      mapPublicIpOnLaunch: this.parseXmlValue(response, 'mapPublicIpOnLaunch') === 'true',
      tags: [],
    };
  }

  async ec2DeleteSubnet(subnetId: string): Promise<void> {
    await this.request<string>('ec2', 'POST', '/', {
      query: {
        Action: 'DeleteSubnet',
        Version: '2016-11-15',
        SubnetId: subnetId,
      },
    });
  }

  async ec2DescribeInternetGateways(internetGatewayIds?: string[]): Promise<Array<{ internetGatewayId: string; attachments: Array<{ vpcId: string; state: string }> }>> {
    const query: Record<string, string> = {
      Action: 'DescribeInternetGateways',
      Version: '2016-11-15',
    };
    if (internetGatewayIds) {
      internetGatewayIds.forEach((id, i) => {
        query[`InternetGatewayId.${i + 1}`] = id;
      });
    }

    const response = await this.request<string>('ec2', 'GET', '/', { query });

    const gateways: Array<{ internetGatewayId: string; attachments: Array<{ vpcId: string; state: string }> }> = [];
    const igwMatches = response.matchAll(/<item>([\s\S]*?internetGatewayId[\s\S]*?)<\/item>/g);

    for (const match of igwMatches) {
      const igwXml = match[1];
      if (!igwXml.includes('<internetGatewayId>')) continue;

      const attachments: Array<{ vpcId: string; state: string }> = [];
      const attachmentMatches = igwXml.matchAll(/<attachmentSet>[\s\S]*?<item>([\s\S]*?)<\/item>[\s\S]*?<\/attachmentSet>/g);
      for (const attachMatch of attachmentMatches) {
        attachments.push({
          vpcId: this.parseXmlValue(attachMatch[1], 'vpcId') || '',
          state: this.parseXmlValue(attachMatch[1], 'state') || '',
        });
      }

      gateways.push({
        internetGatewayId: this.parseXmlValue(igwXml, 'internetGatewayId') || '',
        attachments,
      });
    }

    return gateways;
  }

  async ec2CreateInternetGateway(): Promise<{ internetGatewayId: string }> {
    const response = await this.request<string>('ec2', 'POST', '/', {
      query: {
        Action: 'CreateInternetGateway',
        Version: '2016-11-15',
      },
    });

    return {
      internetGatewayId: this.parseXmlValue(response, 'internetGatewayId') || '',
    };
  }

  async ec2DeleteInternetGateway(internetGatewayId: string): Promise<void> {
    await this.request<string>('ec2', 'POST', '/', {
      query: {
        Action: 'DeleteInternetGateway',
        Version: '2016-11-15',
        InternetGatewayId: internetGatewayId,
      },
    });
  }

  async ec2AttachInternetGateway(internetGatewayId: string, vpcId: string): Promise<void> {
    await this.request<string>('ec2', 'POST', '/', {
      query: {
        Action: 'AttachInternetGateway',
        Version: '2016-11-15',
        InternetGatewayId: internetGatewayId,
        VpcId: vpcId,
      },
    });
  }

  async ec2DetachInternetGateway(internetGatewayId: string, vpcId: string): Promise<void> {
    await this.request<string>('ec2', 'POST', '/', {
      query: {
        Action: 'DetachInternetGateway',
        Version: '2016-11-15',
        InternetGatewayId: internetGatewayId,
        VpcId: vpcId,
      },
    });
  }

  async ec2DescribeRouteTables(routeTableIds?: string[]): Promise<Array<{ routeTableId: string; vpcId: string; routes: Array<{ destinationCidrBlock?: string; gatewayId?: string; state: string }> }>> {
    const query: Record<string, string> = {
      Action: 'DescribeRouteTables',
      Version: '2016-11-15',
    };
    if (routeTableIds) {
      routeTableIds.forEach((id, i) => {
        query[`RouteTableId.${i + 1}`] = id;
      });
    }

    const response = await this.request<string>('ec2', 'GET', '/', { query });

    const routeTables: Array<{ routeTableId: string; vpcId: string; routes: Array<{ destinationCidrBlock?: string; gatewayId?: string; state: string }> }> = [];
    const rtMatches = response.matchAll(/<item>([\s\S]*?routeTableId[\s\S]*?)<\/item>/g);

    for (const match of rtMatches) {
      const rtXml = match[1];
      if (!rtXml.includes('<routeTableId>')) continue;

      const routes: Array<{ destinationCidrBlock?: string; gatewayId?: string; state: string }> = [];
      const routeMatches = rtXml.matchAll(/<routeSet>[\s\S]*?<item>([\s\S]*?)<\/item>[\s\S]*?<\/routeSet>/g);
      for (const routeMatch of routeMatches) {
        routes.push({
          destinationCidrBlock: this.parseXmlValue(routeMatch[1], 'destinationCidrBlock'),
          gatewayId: this.parseXmlValue(routeMatch[1], 'gatewayId'),
          state: this.parseXmlValue(routeMatch[1], 'state') || '',
        });
      }

      routeTables.push({
        routeTableId: this.parseXmlValue(rtXml, 'routeTableId') || '',
        vpcId: this.parseXmlValue(rtXml, 'vpcId') || '',
        routes,
      });
    }

    return routeTables;
  }

  async ec2CreateRouteTable(vpcId: string): Promise<{ routeTableId: string }> {
    const response = await this.request<string>('ec2', 'POST', '/', {
      query: {
        Action: 'CreateRouteTable',
        Version: '2016-11-15',
        VpcId: vpcId,
      },
    });

    return {
      routeTableId: this.parseXmlValue(response, 'routeTableId') || '',
    };
  }

  async ec2DeleteRouteTable(routeTableId: string): Promise<void> {
    await this.request<string>('ec2', 'POST', '/', {
      query: {
        Action: 'DeleteRouteTable',
        Version: '2016-11-15',
        RouteTableId: routeTableId,
      },
    });
  }

  async ec2CreateRoute(routeTableId: string, destinationCidrBlock: string, gatewayId?: string, natGatewayId?: string): Promise<void> {
    const query: Record<string, string> = {
      Action: 'CreateRoute',
      Version: '2016-11-15',
      RouteTableId: routeTableId,
      DestinationCidrBlock: destinationCidrBlock,
    };
    if (gatewayId) query.GatewayId = gatewayId;
    if (natGatewayId) query.NatGatewayId = natGatewayId;

    await this.request<string>('ec2', 'POST', '/', { query });
  }

  async ec2DeleteRoute(routeTableId: string, destinationCidrBlock: string): Promise<void> {
    await this.request<string>('ec2', 'POST', '/', {
      query: {
        Action: 'DeleteRoute',
        Version: '2016-11-15',
        RouteTableId: routeTableId,
        DestinationCidrBlock: destinationCidrBlock,
      },
    });
  }

  async ec2AssociateRouteTable(routeTableId: string, subnetId: string): Promise<{ associationId: string }> {
    const response = await this.request<string>('ec2', 'POST', '/', {
      query: {
        Action: 'AssociateRouteTable',
        Version: '2016-11-15',
        RouteTableId: routeTableId,
        SubnetId: subnetId,
      },
    });

    return {
      associationId: this.parseXmlValue(response, 'associationId') || '',
    };
  }

  async ec2DisassociateRouteTable(associationId: string): Promise<void> {
    await this.request<string>('ec2', 'POST', '/', {
      query: {
        Action: 'DisassociateRouteTable',
        Version: '2016-11-15',
        AssociationId: associationId,
      },
    });
  }

  async ec2DescribeNetworkInterfaces(networkInterfaceIds?: string[]): Promise<Array<{ networkInterfaceId: string; subnetId: string; vpcId: string; availabilityZone: string; description?: string; privateIpAddress: string; status: string; attachment?: { instanceId?: string; deviceIndex: number; status: string } }>> {
    const query: Record<string, string> = {
      Action: 'DescribeNetworkInterfaces',
      Version: '2016-11-15',
    };
    if (networkInterfaceIds) {
      networkInterfaceIds.forEach((id, i) => {
        query[`NetworkInterfaceId.${i + 1}`] = id;
      });
    }
    const response = await this.request<string>('ec2', 'POST', '/', { query });
    const interfaces: Array<{ networkInterfaceId: string; subnetId: string; vpcId: string; availabilityZone: string; description?: string; privateIpAddress: string; status: string; attachment?: { instanceId?: string; deviceIndex: number; status: string } }> = [];
    const itemMatches = response.matchAll(/<item>([\s\S]*?)<\/item>/g);
    for (const match of itemMatches) {
      const xml = match[1];
      if (xml.includes('<networkInterfaceId>')) {
        const attachmentMatch = xml.match(/<attachment>([\s\S]*?)<\/attachment>/);
        interfaces.push({
          networkInterfaceId: this.parseXmlValue(xml, 'networkInterfaceId') || '',
          subnetId: this.parseXmlValue(xml, 'subnetId') || '',
          vpcId: this.parseXmlValue(xml, 'vpcId') || '',
          availabilityZone: this.parseXmlValue(xml, 'availabilityZone') || '',
          description: this.parseXmlValue(xml, 'description'),
          privateIpAddress: this.parseXmlValue(xml, 'privateIpAddress') || '',
          status: this.parseXmlValue(xml, 'status') || '',
          attachment: attachmentMatch ? {
            instanceId: this.parseXmlValue(attachmentMatch[1], 'instanceId'),
            deviceIndex: parseInt(this.parseXmlValue(attachmentMatch[1], 'deviceIndex') || '0', 10),
            status: this.parseXmlValue(attachmentMatch[1], 'status') || '',
          } : undefined,
        });
      }
    }
    return interfaces;
  }

  async ec2CreateNetworkInterface(subnetId: string, description?: string, securityGroupIds?: string[]): Promise<{ networkInterfaceId: string; subnetId: string; vpcId: string; privateIpAddress: string }> {
    const query: Record<string, string> = {
      Action: 'CreateNetworkInterface',
      Version: '2016-11-15',
      SubnetId: subnetId,
    };
    if (description) query.Description = description;
    if (securityGroupIds) {
      securityGroupIds.forEach((id, i) => {
        query[`SecurityGroupId.${i + 1}`] = id;
      });
    }
    const response = await this.request<string>('ec2', 'POST', '/', { query });
    return {
      networkInterfaceId: this.parseXmlValue(response, 'networkInterfaceId') || '',
      subnetId: this.parseXmlValue(response, 'subnetId') || '',
      vpcId: this.parseXmlValue(response, 'vpcId') || '',
      privateIpAddress: this.parseXmlValue(response, 'privateIpAddress') || '',
    };
  }

  async ec2DeleteNetworkInterface(networkInterfaceId: string): Promise<void> {
    await this.request<string>('ec2', 'POST', '/', {
      query: {
        Action: 'DeleteNetworkInterface',
        Version: '2016-11-15',
        NetworkInterfaceId: networkInterfaceId,
      },
    });
  }

  async ec2AttachNetworkInterface(networkInterfaceId: string, instanceId: string, deviceIndex: number): Promise<{ attachmentId: string }> {
    const response = await this.request<string>('ec2', 'POST', '/', {
      query: {
        Action: 'AttachNetworkInterface',
        Version: '2016-11-15',
        NetworkInterfaceId: networkInterfaceId,
        InstanceId: instanceId,
        DeviceIndex: deviceIndex.toString(),
      },
    });
    return {
      attachmentId: this.parseXmlValue(response, 'attachmentId') || '',
    };
  }

  async ec2DetachNetworkInterface(attachmentId: string, force?: boolean): Promise<void> {
    const query: Record<string, string> = {
      Action: 'DetachNetworkInterface',
      Version: '2016-11-15',
      AttachmentId: attachmentId,
    };
    if (force) query.Force = 'true';
    await this.request<string>('ec2', 'POST', '/', { query });
  }

  async ec2DescribePlacementGroups(groupNames?: string[]): Promise<Array<{ groupName: string; strategy: string; state: string; groupId: string }>> {
    const query: Record<string, string> = {
      Action: 'DescribePlacementGroups',
      Version: '2016-11-15',
    };
    if (groupNames) {
      groupNames.forEach((name, i) => {
        query[`GroupName.${i + 1}`] = name;
      });
    }
    const response = await this.request<string>('ec2', 'POST', '/', { query });
    const groups: Array<{ groupName: string; strategy: string; state: string; groupId: string }> = [];
    const itemMatches = response.matchAll(/<item>([\s\S]*?)<\/item>/g);
    for (const match of itemMatches) {
      const xml = match[1];
      if (xml.includes('<groupName>')) {
        groups.push({
          groupName: this.parseXmlValue(xml, 'groupName') || '',
          strategy: this.parseXmlValue(xml, 'strategy') || '',
          state: this.parseXmlValue(xml, 'state') || '',
          groupId: this.parseXmlValue(xml, 'groupId') || '',
        });
      }
    }
    return groups;
  }

  async ec2CreatePlacementGroup(groupName: string, strategy: 'cluster' | 'spread' | 'partition'): Promise<{ groupName: string }> {
    await this.request<string>('ec2', 'POST', '/', {
      query: {
        Action: 'CreatePlacementGroup',
        Version: '2016-11-15',
        GroupName: groupName,
        Strategy: strategy,
      },
    });
    return { groupName };
  }

  async ec2DeletePlacementGroup(groupName: string): Promise<void> {
    await this.request<string>('ec2', 'POST', '/', {
      query: {
        Action: 'DeletePlacementGroup',
        Version: '2016-11-15',
        GroupName: groupName,
      },
    });
  }

  async ec2ModifyInstanceAttribute(instanceId: string, attribute: string, value: string): Promise<void> {
    const query: Record<string, string> = {
      Action: 'ModifyInstanceAttribute',
      Version: '2016-11-15',
      InstanceId: instanceId,
    };
    query[`${attribute}.Value`] = value;
    await this.request<string>('ec2', 'POST', '/', { query });
  }

  async ec2GetConsoleOutput(instanceId: string): Promise<{ instanceId: string; output?: string; timestamp?: string }> {
    const response = await this.request<string>('ec2', 'POST', '/', {
      query: {
        Action: 'GetConsoleOutput',
        Version: '2016-11-15',
        InstanceId: instanceId,
      },
    });
    const encodedOutput = this.parseXmlValue(response, 'output');
    let decodedOutput: string | undefined;
    if (encodedOutput) {
      try {
        decodedOutput = atob(encodedOutput);
      } catch {
        decodedOutput = encodedOutput;
      }
    }
    return {
      instanceId: this.parseXmlValue(response, 'instanceId') || instanceId,
      output: decodedOutput,
      timestamp: this.parseXmlValue(response, 'timestamp'),
    };
  }

  // ===========================================================================
  // Lambda
  // ===========================================================================

  async lambdaListFunctions(): Promise<LambdaFunction[]> {
    const response = await this.request<{ Functions: Array<Record<string, unknown>> }>(
      'lambda',
      'GET',
      '/2015-03-31/functions/',
      { headers: { 'content-type': 'application/json' } }
    );

    return (response.Functions || []).map((f) => ({
      functionName: f.FunctionName as string,
      functionArn: f.FunctionArn as string,
      runtime: f.Runtime as string | undefined,
      handler: f.Handler as string,
      codeSize: f.CodeSize as number,
      memorySize: f.MemorySize as number,
      timeout: f.Timeout as number,
      lastModified: f.LastModified as string,
      description: f.Description as string | undefined,
      role: f.Role as string,
      state: f.State as string | undefined,
      stateReason: f.StateReason as string | undefined,
    }));
  }

  async lambdaGetFunction(functionName: string): Promise<LambdaFunction> {
    const response = await this.request<{
      Configuration: Record<string, unknown>;
      Tags?: Record<string, string>;
    }>('lambda', 'GET', `/2015-03-31/functions/${encodeURIComponent(functionName)}`, {
      headers: { 'content-type': 'application/json' },
    });

    const f = response.Configuration;
    return {
      functionName: f.FunctionName as string,
      functionArn: f.FunctionArn as string,
      runtime: f.Runtime as string | undefined,
      handler: f.Handler as string,
      codeSize: f.CodeSize as number,
      memorySize: f.MemorySize as number,
      timeout: f.Timeout as number,
      lastModified: f.LastModified as string,
      description: f.Description as string | undefined,
      role: f.Role as string,
      state: f.State as string | undefined,
      stateReason: f.StateReason as string | undefined,
      environment: (f.Environment as Record<string, Record<string, string>> | undefined)?.Variables,
      tags: response.Tags,
    };
  }

  async lambdaInvoke(params: LambdaInvokeParams): Promise<LambdaInvokeResponse> {
    const headers: Record<string, string> = {
      'content-type': 'application/json',
    };

    if (params.invocationType) {
      headers['X-Amz-Invocation-Type'] = params.invocationType;
    }

    const response = await this.request<unknown>(
      'lambda',
      'POST',
      `/2015-03-31/functions/${encodeURIComponent(params.functionName)}/invocations`,
      {
        headers,
        body: params.payload ? JSON.stringify(params.payload) : '',
      }
    );

    return {
      statusCode: 200,
      payload: response,
    };
  }

  async lambdaListAliases(functionName: string): Promise<LambdaAlias[]> {
    const response = await this.request<{ Aliases: Array<Record<string, unknown>> }>(
      'lambda',
      'GET',
      `/2015-03-31/functions/${encodeURIComponent(functionName)}/aliases`,
      { headers: { 'content-type': 'application/json' } }
    );

    return (response.Aliases || []).map((a) => ({
      name: a.Name as string,
      functionVersion: a.FunctionVersion as string,
      description: a.Description as string | undefined,
      revisionId: a.RevisionId as string | undefined,
    }));
  }

  async lambdaListVersions(functionName: string): Promise<LambdaVersion[]> {
    const response = await this.request<{ Versions: Array<Record<string, unknown>> }>(
      'lambda',
      'GET',
      `/2015-03-31/functions/${encodeURIComponent(functionName)}/versions`,
      { headers: { 'content-type': 'application/json' } }
    );

    return (response.Versions || []).map((v) => ({
      version: v.Version as string,
      description: v.Description as string | undefined,
      revisionId: v.RevisionId as string | undefined,
      lastModified: v.LastModified as string | undefined,
    }));
  }

  async lambdaListEventSourceMappings(functionName?: string): Promise<LambdaEventSourceMapping[]> {
    const query: Record<string, string> = {};
    if (functionName) {
      query.FunctionName = functionName;
    }

    const response = await this.request<{ EventSourceMappings: Array<Record<string, unknown>> }>(
      'lambda',
      'GET',
      '/2015-03-31/event-source-mappings/',
      { headers: { 'content-type': 'application/json' }, query: Object.keys(query).length ? query : undefined }
    );

    return (response.EventSourceMappings || []).map((e) => ({
      uuid: e.UUID as string,
      functionArn: e.FunctionArn as string,
      eventSourceArn: e.EventSourceArn as string | undefined,
      state: e.State as string,
      stateTransitionReason: e.StateTransitionReason as string | undefined,
      batchSize: e.BatchSize as number | undefined,
      maximumBatchingWindowInSeconds: e.MaximumBatchingWindowInSeconds as number | undefined,
      lastModified: e.LastModified as string | undefined,
      startingPosition: e.StartingPosition as string | undefined,
    }));
  }

  async lambdaListLayers(): Promise<LambdaLayer[]> {
    const response = await this.request<{ Layers: Array<Record<string, unknown>> }>(
      'lambda',
      'GET',
      '/2018-10-31/layers',
      { headers: { 'content-type': 'application/json' } }
    );

    return (response.Layers || []).map((l) => ({
      layerName: l.LayerName as string,
      layerArn: l.LayerArn as string,
      latestMatchingVersion: l.LatestMatchingVersion
        ? {
            layerVersionArn: (l.LatestMatchingVersion as Record<string, unknown>).LayerVersionArn as string,
            version: (l.LatestMatchingVersion as Record<string, unknown>).Version as number,
            description: (l.LatestMatchingVersion as Record<string, unknown>).Description as string | undefined,
            compatibleRuntimes: (l.LatestMatchingVersion as Record<string, unknown>).CompatibleRuntimes as string[] | undefined,
            createdDate: (l.LatestMatchingVersion as Record<string, unknown>).CreatedDate as string | undefined,
          }
        : undefined,
    }));
  }

  async lambdaListLayerVersions(layerName: string): Promise<LambdaLayerVersion[]> {
    const response = await this.request<{ LayerVersions: Array<Record<string, unknown>> }>(
      'lambda',
      'GET',
      `/2018-10-31/layers/${encodeURIComponent(layerName)}/versions`,
      { headers: { 'content-type': 'application/json' } }
    );

    return (response.LayerVersions || []).map((v) => ({
      layerVersionArn: v.LayerVersionArn as string,
      version: v.Version as number,
      description: v.Description as string | undefined,
      createdDate: v.CreatedDate as string | undefined,
      compatibleRuntimes: v.CompatibleRuntimes as string[] | undefined,
      compatibleArchitectures: v.CompatibleArchitectures as string[] | undefined,
    }));
  }

  async lambdaGetFunctionConcurrency(functionName: string): Promise<{ reservedConcurrentExecutions?: number }> {
    const response = await this.request<{ ReservedConcurrentExecutions?: number }>(
      'lambda',
      'GET',
      `/2019-09-30/functions/${encodeURIComponent(functionName)}/concurrency`,
      { headers: { 'content-type': 'application/json' } }
    );

    return {
      reservedConcurrentExecutions: response.ReservedConcurrentExecutions,
    };
  }

  async lambdaPublishVersion(functionName: string, description?: string): Promise<LambdaVersion> {
    const body: Record<string, unknown> = {};
    if (description) body.Description = description;

    const response = await this.request<Record<string, unknown>>(
      'lambda',
      'POST',
      `/2015-03-31/functions/${encodeURIComponent(functionName)}/versions`,
      {
        body: JSON.stringify(body),
        headers: { 'content-type': 'application/json' },
      }
    );

    return {
      version: response.Version as string,
      description: response.Description as string | undefined,
      revisionId: response.RevisionId as string | undefined,
      lastModified: response.LastModified as string | undefined,
    };
  }

  async lambdaUpdateFunctionConfiguration(
    functionName: string,
    params: {
      description?: string;
      handler?: string;
      memorySize?: number;
      timeout?: number;
      environment?: Record<string, string>;
      runtime?: string;
    }
  ): Promise<LambdaFunction> {
    const body: Record<string, unknown> = {};
    if (params.description !== undefined) body.Description = params.description;
    if (params.handler) body.Handler = params.handler;
    if (params.memorySize) body.MemorySize = params.memorySize;
    if (params.timeout) body.Timeout = params.timeout;
    if (params.runtime) body.Runtime = params.runtime;
    if (params.environment) body.Environment = { Variables: params.environment };

    const response = await this.request<Record<string, unknown>>(
      'lambda',
      'PUT',
      `/2015-03-31/functions/${encodeURIComponent(functionName)}/configuration`,
      {
        body: JSON.stringify(body),
        headers: { 'content-type': 'application/json' },
      }
    );

    return {
      functionName: response.FunctionName as string,
      functionArn: response.FunctionArn as string,
      runtime: response.Runtime as string | undefined,
      handler: response.Handler as string,
      codeSize: response.CodeSize as number,
      memorySize: response.MemorySize as number,
      timeout: response.Timeout as number,
      lastModified: response.LastModified as string,
      description: response.Description as string | undefined,
      role: response.Role as string,
      state: response.State as string | undefined,
    };
  }

  async lambdaDeleteFunction(functionName: string, qualifier?: string): Promise<void> {
    let path = `/2015-03-31/functions/${encodeURIComponent(functionName)}`;
    if (qualifier) path += `?Qualifier=${encodeURIComponent(qualifier)}`;

    await this.request<void>('lambda', 'DELETE', path, {
      headers: { 'content-type': 'application/json' },
    });
  }

  async lambdaPutFunctionConcurrency(functionName: string, reservedConcurrency: number): Promise<{ reservedConcurrentExecutions: number }> {
    const response = await this.request<{ ReservedConcurrentExecutions: number }>(
      'lambda',
      'PUT',
      `/2017-10-31/functions/${encodeURIComponent(functionName)}/concurrency`,
      {
        body: JSON.stringify({ ReservedConcurrentExecutions: reservedConcurrency }),
        headers: { 'content-type': 'application/json' },
      }
    );

    return { reservedConcurrentExecutions: response.ReservedConcurrentExecutions };
  }

  async lambdaDeleteFunctionConcurrency(functionName: string): Promise<void> {
    await this.request<void>(
      'lambda',
      'DELETE',
      `/2017-10-31/functions/${encodeURIComponent(functionName)}/concurrency`,
      { headers: { 'content-type': 'application/json' } }
    );
  }

  async lambdaGetEventSourceMapping(uuid: string): Promise<LambdaEventSourceMapping> {
    const response = await this.request<Record<string, unknown>>(
      'lambda',
      'GET',
      `/2015-03-31/event-source-mappings/${uuid}`,
      { headers: { 'content-type': 'application/json' } }
    );

    return {
      uuid: response.UUID as string,
      eventSourceArn: response.EventSourceArn as string | undefined,
      functionArn: response.FunctionArn as string,
      state: response.State as string,
      batchSize: response.BatchSize as number | undefined,
      lastModified: response.LastModified as string | undefined,
      stateTransitionReason: response.StateTransitionReason as string | undefined,
    };
  }

  async lambdaCreateEventSourceMapping(params: {
    eventSourceArn: string;
    functionName: string;
    batchSize?: number;
    enabled?: boolean;
    startingPosition?: string;
  }): Promise<LambdaEventSourceMapping> {
    const body: Record<string, unknown> = {
      EventSourceArn: params.eventSourceArn,
      FunctionName: params.functionName,
    };
    if (params.batchSize !== undefined) body.BatchSize = params.batchSize;
    if (params.enabled !== undefined) body.Enabled = params.enabled;
    if (params.startingPosition) body.StartingPosition = params.startingPosition;

    const response = await this.request<Record<string, unknown>>(
      'lambda',
      'POST',
      '/2015-03-31/event-source-mappings/',
      {
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
      }
    );

    return {
      uuid: response.UUID as string,
      eventSourceArn: response.EventSourceArn as string | undefined,
      functionArn: response.FunctionArn as string,
      state: response.State as string,
      batchSize: response.BatchSize as number | undefined,
      lastModified: response.LastModified as string | undefined,
      stateTransitionReason: response.StateTransitionReason as string | undefined,
    };
  }

  async lambdaUpdateEventSourceMapping(uuid: string, params: {
    functionName?: string;
    batchSize?: number;
    enabled?: boolean;
  }): Promise<LambdaEventSourceMapping> {
    const body: Record<string, unknown> = {};
    if (params.functionName) body.FunctionName = params.functionName;
    if (params.batchSize !== undefined) body.BatchSize = params.batchSize;
    if (params.enabled !== undefined) body.Enabled = params.enabled;

    const response = await this.request<Record<string, unknown>>(
      'lambda',
      'PUT',
      `/2015-03-31/event-source-mappings/${uuid}`,
      {
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
      }
    );

    return {
      uuid: response.UUID as string,
      eventSourceArn: response.EventSourceArn as string | undefined,
      functionArn: response.FunctionArn as string,
      state: response.State as string,
      batchSize: response.BatchSize as number | undefined,
      lastModified: response.LastModified as string | undefined,
      stateTransitionReason: response.StateTransitionReason as string | undefined,
    };
  }

  async lambdaDeleteEventSourceMapping(uuid: string): Promise<void> {
    await this.request<void>(
      'lambda',
      'DELETE',
      `/2015-03-31/event-source-mappings/${uuid}`,
      { headers: { 'content-type': 'application/json' } }
    );
  }

  async lambdaCreateAlias(functionName: string, name: string, functionVersion: string, description?: string): Promise<LambdaAlias> {
    const body: Record<string, unknown> = {
      Name: name,
      FunctionVersion: functionVersion,
    };
    if (description) body.Description = description;

    const response = await this.request<Record<string, unknown>>(
      'lambda',
      'POST',
      `/2015-03-31/functions/${encodeURIComponent(functionName)}/aliases`,
      {
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
      }
    );

    return {
      name: response.Name as string,
      functionVersion: response.FunctionVersion as string,
      description: response.Description as string | undefined,
      revisionId: response.RevisionId as string | undefined,
    };
  }

  async lambdaUpdateAlias(functionName: string, name: string, functionVersion?: string, description?: string): Promise<LambdaAlias> {
    const body: Record<string, unknown> = {};
    if (functionVersion) body.FunctionVersion = functionVersion;
    if (description !== undefined) body.Description = description;

    const response = await this.request<Record<string, unknown>>(
      'lambda',
      'PUT',
      `/2015-03-31/functions/${encodeURIComponent(functionName)}/aliases/${encodeURIComponent(name)}`,
      {
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
      }
    );

    return {
      name: response.Name as string,
      functionVersion: response.FunctionVersion as string,
      description: response.Description as string | undefined,
      revisionId: response.RevisionId as string | undefined,
    };
  }

  async lambdaDeleteAlias(functionName: string, name: string): Promise<void> {
    await this.request<void>(
      'lambda',
      'DELETE',
      `/2015-03-31/functions/${encodeURIComponent(functionName)}/aliases/${encodeURIComponent(name)}`,
      { headers: { 'content-type': 'application/json' } }
    );
  }

  async lambdaAddPermission(
    functionName: string,
    statementId: string,
    action: string,
    principal: string,
    sourceArn?: string
  ): Promise<{ statement: string }> {
    const body: Record<string, unknown> = {
      StatementId: statementId,
      Action: action,
      Principal: principal,
    };
    if (sourceArn) body.SourceArn = sourceArn;

    const response = await this.request<{ Statement: string }>(
      'lambda',
      'POST',
      `/2015-03-31/functions/${encodeURIComponent(functionName)}/policy`,
      {
        body: JSON.stringify(body),
        headers: { 'content-type': 'application/json' },
      }
    );

    return { statement: response.Statement };
  }

  async lambdaRemovePermission(functionName: string, statementId: string): Promise<void> {
    await this.request<void>(
      'lambda',
      'DELETE',
      `/2015-03-31/functions/${encodeURIComponent(functionName)}/policy/${encodeURIComponent(statementId)}`,
      { headers: { 'content-type': 'application/json' } }
    );
  }

  async lambdaGetPolicy(functionName: string): Promise<{ policy: string; revisionId: string }> {
    const response = await this.request<{ Policy: string; RevisionId: string }>(
      'lambda',
      'GET',
      `/2015-03-31/functions/${encodeURIComponent(functionName)}/policy`,
      { headers: { 'content-type': 'application/json' } }
    );

    return { policy: response.Policy, revisionId: response.RevisionId };
  }

  async lambdaTagResource(resourceArn: string, tags: Record<string, string>): Promise<void> {
    await this.request<void>(
      'lambda',
      'POST',
      `/2017-03-31/tags/${encodeURIComponent(resourceArn)}`,
      {
        body: JSON.stringify({ Tags: tags }),
        headers: { 'content-type': 'application/json' },
      }
    );
  }

  async lambdaUntagResource(resourceArn: string, tagKeys: string[]): Promise<void> {
    const query = tagKeys.map((key) => `tagKeys=${encodeURIComponent(key)}`).join('&');
    await this.request<void>(
      'lambda',
      'DELETE',
      `/2017-03-31/tags/${encodeURIComponent(resourceArn)}?${query}`,
      { headers: { 'content-type': 'application/json' } }
    );
  }

  async lambdaListTags(resourceArn: string): Promise<Record<string, string>> {
    const response = await this.request<{ Tags: Record<string, string> }>(
      'lambda',
      'GET',
      `/2017-03-31/tags/${encodeURIComponent(resourceArn)}`,
      { headers: { 'content-type': 'application/json' } }
    );

    return response.Tags || {};
  }

  // ===========================================================================
  // IAM
  // ===========================================================================

  async iamListUsers(): Promise<IAMUser[]> {
    const response = await this.request<string>('iam', 'GET', '/', {
      query: { Action: 'ListUsers', Version: '2010-05-08' },
    });

    const users: IAMUser[] = [];
    const userMatches = response.matchAll(/<member>([\s\S]*?UserName[\s\S]*?)<\/member>/g);

    for (const match of userMatches) {
      const userXml = match[1];
      users.push({
        userName: this.parseXmlValue(userXml, 'UserName') || '',
        userId: this.parseXmlValue(userXml, 'UserId') || '',
        arn: this.parseXmlValue(userXml, 'Arn') || '',
        path: this.parseXmlValue(userXml, 'Path') || '',
        createDate: this.parseXmlValue(userXml, 'CreateDate') || '',
        passwordLastUsed: this.parseXmlValue(userXml, 'PasswordLastUsed'),
      });
    }

    return users;
  }

  async iamGetUser(userName: string): Promise<IAMUser> {
    const response = await this.request<string>('iam', 'GET', '/', {
      query: { Action: 'GetUser', Version: '2010-05-08', UserName: userName },
    });

    return {
      userName: this.parseXmlValue(response, 'UserName') || '',
      userId: this.parseXmlValue(response, 'UserId') || '',
      arn: this.parseXmlValue(response, 'Arn') || '',
      path: this.parseXmlValue(response, 'Path') || '',
      createDate: this.parseXmlValue(response, 'CreateDate') || '',
      passwordLastUsed: this.parseXmlValue(response, 'PasswordLastUsed'),
    };
  }

  async iamListRoles(): Promise<IAMRole[]> {
    const response = await this.request<string>('iam', 'GET', '/', {
      query: { Action: 'ListRoles', Version: '2010-05-08' },
    });

    const roles: IAMRole[] = [];
    const roleMatches = response.matchAll(/<member>([\s\S]*?RoleName[\s\S]*?)<\/member>/g);

    for (const match of roleMatches) {
      const roleXml = match[1];
      roles.push({
        roleName: this.parseXmlValue(roleXml, 'RoleName') || '',
        roleId: this.parseXmlValue(roleXml, 'RoleId') || '',
        arn: this.parseXmlValue(roleXml, 'Arn') || '',
        path: this.parseXmlValue(roleXml, 'Path') || '',
        createDate: this.parseXmlValue(roleXml, 'CreateDate') || '',
        description: this.parseXmlValue(roleXml, 'Description'),
      });
    }

    return roles;
  }

  async iamGetRole(roleName: string): Promise<IAMRole> {
    const response = await this.request<string>('iam', 'GET', '/', {
      query: { Action: 'GetRole', Version: '2010-05-08', RoleName: roleName },
    });

    return {
      roleName: this.parseXmlValue(response, 'RoleName') || '',
      roleId: this.parseXmlValue(response, 'RoleId') || '',
      arn: this.parseXmlValue(response, 'Arn') || '',
      path: this.parseXmlValue(response, 'Path') || '',
      createDate: this.parseXmlValue(response, 'CreateDate') || '',
      description: this.parseXmlValue(response, 'Description'),
      assumeRolePolicyDocument: this.parseXmlValue(response, 'AssumeRolePolicyDocument'),
    };
  }

  async iamListPolicies(onlyAttached?: boolean): Promise<IAMPolicy[]> {
    const query: Record<string, string> = { Action: 'ListPolicies', Version: '2010-05-08' };
    if (onlyAttached) {
      query.OnlyAttached = 'true';
    }

    const response = await this.request<string>('iam', 'GET', '/', { query });

    const policies: IAMPolicy[] = [];
    const policyMatches = response.matchAll(/<member>([\s\S]*?PolicyName[\s\S]*?)<\/member>/g);

    for (const match of policyMatches) {
      const policyXml = match[1];
      policies.push({
        policyName: this.parseXmlValue(policyXml, 'PolicyName') || '',
        policyId: this.parseXmlValue(policyXml, 'PolicyId') || '',
        arn: this.parseXmlValue(policyXml, 'Arn') || '',
        path: this.parseXmlValue(policyXml, 'Path') || '',
        createDate: this.parseXmlValue(policyXml, 'CreateDate') || '',
        updateDate: this.parseXmlValue(policyXml, 'UpdateDate') || '',
        defaultVersionId: this.parseXmlValue(policyXml, 'DefaultVersionId') || '',
        attachmentCount: Number.parseInt(this.parseXmlValue(policyXml, 'AttachmentCount') || '0', 10),
        isAttachable: this.parseXmlValue(policyXml, 'IsAttachable') === 'true',
        description: this.parseXmlValue(policyXml, 'Description'),
      });
    }

    return policies;
  }

  async iamGetPolicy(policyArn: string): Promise<IAMPolicy> {
    const response = await this.request<string>('iam', 'GET', '/', {
      query: { Action: 'GetPolicy', Version: '2010-05-08', PolicyArn: policyArn },
    });

    return {
      policyName: this.parseXmlValue(response, 'PolicyName') || '',
      policyId: this.parseXmlValue(response, 'PolicyId') || '',
      arn: this.parseXmlValue(response, 'Arn') || '',
      path: this.parseXmlValue(response, 'Path') || '',
      createDate: this.parseXmlValue(response, 'CreateDate') || '',
      updateDate: this.parseXmlValue(response, 'UpdateDate') || '',
      defaultVersionId: this.parseXmlValue(response, 'DefaultVersionId') || '',
      attachmentCount: Number.parseInt(this.parseXmlValue(response, 'AttachmentCount') || '0', 10),
      isAttachable: this.parseXmlValue(response, 'IsAttachable') === 'true',
      description: this.parseXmlValue(response, 'Description'),
    };
  }

  async iamListGroups(): Promise<IAMGroup[]> {
    const response = await this.request<string>('iam', 'GET', '/', {
      query: { Action: 'ListGroups', Version: '2010-05-08' },
    });

    const groups: IAMGroup[] = [];
    const groupMatches = response.matchAll(/<member>([\s\S]*?GroupName[\s\S]*?)<\/member>/g);

    for (const match of groupMatches) {
      const groupXml = match[1];
      groups.push({
        groupName: this.parseXmlValue(groupXml, 'GroupName') || '',
        groupId: this.parseXmlValue(groupXml, 'GroupId') || '',
        arn: this.parseXmlValue(groupXml, 'Arn') || '',
        path: this.parseXmlValue(groupXml, 'Path') || '',
        createDate: this.parseXmlValue(groupXml, 'CreateDate') || '',
      });
    }

    return groups;
  }

  async iamListAccessKeys(userName: string): Promise<IAMAccessKey[]> {
    const response = await this.request<string>('iam', 'GET', '/', {
      query: { Action: 'ListAccessKeys', Version: '2010-05-08', UserName: userName },
    });

    const keys: IAMAccessKey[] = [];
    const keyMatches = response.matchAll(/<member>([\s\S]*?AccessKeyId[\s\S]*?)<\/member>/g);

    for (const match of keyMatches) {
      const keyXml = match[1];
      keys.push({
        accessKeyId: this.parseXmlValue(keyXml, 'AccessKeyId') || '',
        status: (this.parseXmlValue(keyXml, 'Status') || 'Active') as 'Active' | 'Inactive',
        createDate: this.parseXmlValue(keyXml, 'CreateDate') || '',
        userName: this.parseXmlValue(keyXml, 'UserName') || '',
      });
    }

    return keys;
  }

  async iamListAttachedUserPolicies(userName: string): Promise<IAMAttachedPolicy[]> {
    const response = await this.request<string>('iam', 'GET', '/', {
      query: { Action: 'ListAttachedUserPolicies', Version: '2010-05-08', UserName: userName },
    });

    const policies: IAMAttachedPolicy[] = [];
    const policyMatches = response.matchAll(/<member>([\s\S]*?PolicyArn[\s\S]*?)<\/member>/g);

    for (const match of policyMatches) {
      const policyXml = match[1];
      policies.push({
        policyName: this.parseXmlValue(policyXml, 'PolicyName') || '',
        policyArn: this.parseXmlValue(policyXml, 'PolicyArn') || '',
      });
    }

    return policies;
  }

  async iamListAttachedRolePolicies(roleName: string): Promise<IAMAttachedPolicy[]> {
    const response = await this.request<string>('iam', 'GET', '/', {
      query: { Action: 'ListAttachedRolePolicies', Version: '2010-05-08', RoleName: roleName },
    });

    const policies: IAMAttachedPolicy[] = [];
    const policyMatches = response.matchAll(/<member>([\s\S]*?PolicyArn[\s\S]*?)<\/member>/g);

    for (const match of policyMatches) {
      const policyXml = match[1];
      policies.push({
        policyName: this.parseXmlValue(policyXml, 'PolicyName') || '',
        policyArn: this.parseXmlValue(policyXml, 'PolicyArn') || '',
      });
    }

    return policies;
  }

  async iamListGroupsForUser(userName: string): Promise<IAMGroupForUser[]> {
    const response = await this.request<string>('iam', 'GET', '/', {
      query: { Action: 'ListGroupsForUser', Version: '2010-05-08', UserName: userName },
    });

    const groups: IAMGroupForUser[] = [];
    const groupMatches = response.matchAll(/<member>([\s\S]*?GroupName[\s\S]*?)<\/member>/g);

    for (const match of groupMatches) {
      const groupXml = match[1];
      groups.push({
        groupName: this.parseXmlValue(groupXml, 'GroupName') || '',
        groupId: this.parseXmlValue(groupXml, 'GroupId') || '',
        arn: this.parseXmlValue(groupXml, 'Arn') || '',
        path: this.parseXmlValue(groupXml, 'Path') || '',
        createDate: this.parseXmlValue(groupXml, 'CreateDate') || '',
      });
    }

    return groups;
  }

  async iamListMfaDevices(userName?: string): Promise<IAMMfaDevice[]> {
    const query: Record<string, string> = { Action: 'ListMFADevices', Version: '2010-05-08' };
    if (userName) {
      query.UserName = userName;
    }

    const response = await this.request<string>('iam', 'GET', '/', { query });

    const devices: IAMMfaDevice[] = [];
    const deviceMatches = response.matchAll(/<member>([\s\S]*?SerialNumber[\s\S]*?)<\/member>/g);

    for (const match of deviceMatches) {
      const deviceXml = match[1];
      devices.push({
        serialNumber: this.parseXmlValue(deviceXml, 'SerialNumber') || '',
        userName: this.parseXmlValue(deviceXml, 'UserName') || '',
        enableDate: this.parseXmlValue(deviceXml, 'EnableDate') || '',
      });
    }

    return devices;
  }

  async iamListInstanceProfiles(): Promise<IAMInstanceProfile[]> {
    const response = await this.request<string>('iam', 'GET', '/', {
      query: { Action: 'ListInstanceProfiles', Version: '2010-05-08' },
    });

    const profiles: IAMInstanceProfile[] = [];
    const profileMatches = response.matchAll(/<member>([\s\S]*?InstanceProfileName[\s\S]*?)<\/member>/g);

    for (const match of profileMatches) {
      const profileXml = match[1];

      const roles: Array<{ roleName: string; roleId: string; arn: string }> = [];
      const roleMatches = profileXml.matchAll(/<Roles>[\s\S]*?<member>([\s\S]*?)<\/member>[\s\S]*?<\/Roles>/g);
      for (const roleMatch of roleMatches) {
        const roleXml = roleMatch[1];
        roles.push({
          roleName: this.parseXmlValue(roleXml, 'RoleName') || '',
          roleId: this.parseXmlValue(roleXml, 'RoleId') || '',
          arn: this.parseXmlValue(roleXml, 'Arn') || '',
        });
      }

      profiles.push({
        instanceProfileName: this.parseXmlValue(profileXml, 'InstanceProfileName') || '',
        instanceProfileId: this.parseXmlValue(profileXml, 'InstanceProfileId') || '',
        arn: this.parseXmlValue(profileXml, 'Arn') || '',
        path: this.parseXmlValue(profileXml, 'Path') || '',
        createDate: this.parseXmlValue(profileXml, 'CreateDate') || '',
        roles,
      });
    }

    return profiles;
  }

  async iamGetInstanceProfile(instanceProfileName: string): Promise<IAMInstanceProfile> {
    const response = await this.request<string>('iam', 'GET', '/', {
      query: { Action: 'GetInstanceProfile', Version: '2010-05-08', InstanceProfileName: instanceProfileName },
    });

    const roles: Array<{ roleName: string; roleId: string; arn: string }> = [];
    const roleMatches = response.matchAll(/<Roles>[\s\S]*?<member>([\s\S]*?)<\/member>[\s\S]*?<\/Roles>/g);
    for (const roleMatch of roleMatches) {
      const roleXml = roleMatch[1];
      roles.push({
        roleName: this.parseXmlValue(roleXml, 'RoleName') || '',
        roleId: this.parseXmlValue(roleXml, 'RoleId') || '',
        arn: this.parseXmlValue(roleXml, 'Arn') || '',
      });
    }

    return {
      instanceProfileName: this.parseXmlValue(response, 'InstanceProfileName') || '',
      instanceProfileId: this.parseXmlValue(response, 'InstanceProfileId') || '',
      arn: this.parseXmlValue(response, 'Arn') || '',
      path: this.parseXmlValue(response, 'Path') || '',
      createDate: this.parseXmlValue(response, 'CreateDate') || '',
      roles,
    };
  }

  async iamCreateUser(userName: string): Promise<IAMUser> {
    const response = await this.request<string>('iam', 'GET', '/', {
      query: { Action: 'CreateUser', Version: '2010-05-08', UserName: userName },
    });

    return {
      userName: this.parseXmlValue(response, 'UserName') || '',
      userId: this.parseXmlValue(response, 'UserId') || '',
      arn: this.parseXmlValue(response, 'Arn') || '',
      path: this.parseXmlValue(response, 'Path') || '/',
      createDate: this.parseXmlValue(response, 'CreateDate') || '',
    };
  }

  async iamDeleteUser(userName: string): Promise<void> {
    await this.request<string>('iam', 'GET', '/', {
      query: { Action: 'DeleteUser', Version: '2010-05-08', UserName: userName },
    });
  }

  async iamCreateRole(roleName: string, assumeRolePolicyDocument: string, description?: string): Promise<IAMRole> {
    const query: Record<string, string> = {
      Action: 'CreateRole',
      Version: '2010-05-08',
      RoleName: roleName,
      AssumeRolePolicyDocument: assumeRolePolicyDocument,
    };
    if (description) query.Description = description;

    const response = await this.request<string>('iam', 'GET', '/', { query });

    return {
      roleName: this.parseXmlValue(response, 'RoleName') || '',
      roleId: this.parseXmlValue(response, 'RoleId') || '',
      arn: this.parseXmlValue(response, 'Arn') || '',
      path: this.parseXmlValue(response, 'Path') || '/',
      createDate: this.parseXmlValue(response, 'CreateDate') || '',
      description: this.parseXmlValue(response, 'Description'),
      assumeRolePolicyDocument: this.parseXmlValue(response, 'AssumeRolePolicyDocument'),
    };
  }

  async iamDeleteRole(roleName: string): Promise<void> {
    await this.request<string>('iam', 'GET', '/', {
      query: { Action: 'DeleteRole', Version: '2010-05-08', RoleName: roleName },
    });
  }

  async iamAttachUserPolicy(userName: string, policyArn: string): Promise<void> {
    await this.request<string>('iam', 'GET', '/', {
      query: { Action: 'AttachUserPolicy', Version: '2010-05-08', UserName: userName, PolicyArn: policyArn },
    });
  }

  async iamDetachUserPolicy(userName: string, policyArn: string): Promise<void> {
    await this.request<string>('iam', 'GET', '/', {
      query: { Action: 'DetachUserPolicy', Version: '2010-05-08', UserName: userName, PolicyArn: policyArn },
    });
  }

  async iamAttachRolePolicy(roleName: string, policyArn: string): Promise<void> {
    await this.request<string>('iam', 'GET', '/', {
      query: { Action: 'AttachRolePolicy', Version: '2010-05-08', RoleName: roleName, PolicyArn: policyArn },
    });
  }

  async iamDetachRolePolicy(roleName: string, policyArn: string): Promise<void> {
    await this.request<string>('iam', 'GET', '/', {
      query: { Action: 'DetachRolePolicy', Version: '2010-05-08', RoleName: roleName, PolicyArn: policyArn },
    });
  }

  async iamCreateAccessKey(userName: string): Promise<{ accessKeyId: string; secretAccessKey: string }> {
    const response = await this.request<string>('iam', 'GET', '/', {
      query: { Action: 'CreateAccessKey', Version: '2010-05-08', UserName: userName },
    });

    return {
      accessKeyId: this.parseXmlValue(response, 'AccessKeyId') || '',
      secretAccessKey: this.parseXmlValue(response, 'SecretAccessKey') || '',
    };
  }

  async iamDeleteAccessKey(userName: string, accessKeyId: string): Promise<void> {
    await this.request<string>('iam', 'GET', '/', {
      query: { Action: 'DeleteAccessKey', Version: '2010-05-08', UserName: userName, AccessKeyId: accessKeyId },
    });
  }

  async iamUpdateAccessKey(userName: string, accessKeyId: string, status: 'Active' | 'Inactive'): Promise<void> {
    await this.request<string>('iam', 'GET', '/', {
      query: { Action: 'UpdateAccessKey', Version: '2010-05-08', UserName: userName, AccessKeyId: accessKeyId, Status: status },
    });
  }

  async iamCreatePolicy(policyName: string, policyDocument: string, description?: string): Promise<IAMPolicy> {
    const query: Record<string, string> = {
      Action: 'CreatePolicy',
      Version: '2010-05-08',
      PolicyName: policyName,
      PolicyDocument: policyDocument,
    };
    if (description) query.Description = description;
    const response = await this.request<string>('iam', 'GET', '/', { query });
    const policyXml = response.match(/<Policy>([\s\S]*?)<\/Policy>/)?.[1] || '';
    return {
      policyName: this.parseXmlValue(policyXml, 'PolicyName') || '',
      policyId: this.parseXmlValue(policyXml, 'PolicyId') || '',
      arn: this.parseXmlValue(policyXml, 'Arn') || '',
      path: this.parseXmlValue(policyXml, 'Path') || '/',
      defaultVersionId: this.parseXmlValue(policyXml, 'DefaultVersionId') || 'v1',
      attachmentCount: Number.parseInt(this.parseXmlValue(policyXml, 'AttachmentCount') || '0', 10),
      isAttachable: this.parseXmlValue(policyXml, 'IsAttachable') === 'true',
      description: this.parseXmlValue(policyXml, 'Description'),
      createDate: this.parseXmlValue(policyXml, 'CreateDate') || '',
      updateDate: this.parseXmlValue(policyXml, 'UpdateDate') || '',
    };
  }

  async iamDeletePolicy(policyArn: string): Promise<void> {
    await this.request<string>('iam', 'GET', '/', {
      query: { Action: 'DeletePolicy', Version: '2010-05-08', PolicyArn: policyArn },
    });
  }

  async iamGetPolicyVersion(policyArn: string, versionId: string): Promise<{ document: string; versionId: string; isDefaultVersion: boolean; createDate?: string }> {
    const response = await this.request<string>('iam', 'GET', '/', {
      query: { Action: 'GetPolicyVersion', Version: '2010-05-08', PolicyArn: policyArn, VersionId: versionId },
    });
    const versionXml = response.match(/<PolicyVersion>([\s\S]*?)<\/PolicyVersion>/)?.[1] || '';
    return {
      document: decodeURIComponent(this.parseXmlValue(versionXml, 'Document') || ''),
      versionId: this.parseXmlValue(versionXml, 'VersionId') || '',
      isDefaultVersion: this.parseXmlValue(versionXml, 'IsDefaultVersion') === 'true',
      createDate: this.parseXmlValue(versionXml, 'CreateDate'),
    };
  }

  async iamListPolicyVersions(policyArn: string): Promise<Array<{ versionId: string; isDefaultVersion: boolean; createDate?: string }>> {
    const response = await this.request<string>('iam', 'GET', '/', {
      query: { Action: 'ListPolicyVersions', Version: '2010-05-08', PolicyArn: policyArn },
    });
    const versions: Array<{ versionId: string; isDefaultVersion: boolean; createDate?: string }> = [];
    const memberMatches = response.matchAll(/<member>([\s\S]*?)<\/member>/g);
    for (const match of memberMatches) {
      const xml = match[1];
      versions.push({
        versionId: this.parseXmlValue(xml, 'VersionId') || '',
        isDefaultVersion: this.parseXmlValue(xml, 'IsDefaultVersion') === 'true',
        createDate: this.parseXmlValue(xml, 'CreateDate'),
      });
    }
    return versions;
  }

  async iamCreatePolicyVersion(policyArn: string, policyDocument: string, setAsDefault?: boolean): Promise<{ versionId: string }> {
    const query: Record<string, string> = {
      Action: 'CreatePolicyVersion',
      Version: '2010-05-08',
      PolicyArn: policyArn,
      PolicyDocument: policyDocument,
    };
    if (setAsDefault) query.SetAsDefault = 'true';
    const response = await this.request<string>('iam', 'GET', '/', { query });
    return {
      versionId: this.parseXmlValue(response, 'VersionId') || '',
    };
  }

  async iamDeletePolicyVersion(policyArn: string, versionId: string): Promise<void> {
    await this.request<string>('iam', 'GET', '/', {
      query: { Action: 'DeletePolicyVersion', Version: '2010-05-08', PolicyArn: policyArn, VersionId: versionId },
    });
  }

  async iamAddUserToGroup(groupName: string, userName: string): Promise<void> {
    await this.request<string>('iam', 'GET', '/', {
      query: { Action: 'AddUserToGroup', Version: '2010-05-08', GroupName: groupName, UserName: userName },
    });
  }

  async iamRemoveUserFromGroup(groupName: string, userName: string): Promise<void> {
    await this.request<string>('iam', 'GET', '/', {
      query: { Action: 'RemoveUserFromGroup', Version: '2010-05-08', GroupName: groupName, UserName: userName },
    });
  }

  async iamCreateGroup(groupName: string): Promise<IAMGroup> {
    const response = await this.request<string>('iam', 'GET', '/', {
      query: { Action: 'CreateGroup', Version: '2010-05-08', GroupName: groupName },
    });
    const groupXml = response.match(/<Group>([\s\S]*?)<\/Group>/)?.[1] || '';
    return {
      groupName: this.parseXmlValue(groupXml, 'GroupName') || '',
      groupId: this.parseXmlValue(groupXml, 'GroupId') || '',
      arn: this.parseXmlValue(groupXml, 'Arn') || '',
      path: this.parseXmlValue(groupXml, 'Path') || '/',
      createDate: this.parseXmlValue(groupXml, 'CreateDate') || '',
    };
  }

  async iamDeleteGroup(groupName: string): Promise<void> {
    await this.request<string>('iam', 'GET', '/', {
      query: { Action: 'DeleteGroup', Version: '2010-05-08', GroupName: groupName },
    });
  }

  async iamTagUser(userName: string, tags: Array<{ key: string; value: string }>): Promise<void> {
    const query: Record<string, string> = {
      Action: 'TagUser',
      Version: '2010-05-08',
      UserName: userName,
    };
    tags.forEach((tag, i) => {
      query[`Tags.member.${i + 1}.Key`] = tag.key;
      query[`Tags.member.${i + 1}.Value`] = tag.value;
    });
    await this.request<string>('iam', 'GET', '/', { query });
  }

  async iamUntagUser(userName: string, tagKeys: string[]): Promise<void> {
    const query: Record<string, string> = {
      Action: 'UntagUser',
      Version: '2010-05-08',
      UserName: userName,
    };
    tagKeys.forEach((key, i) => {
      query[`TagKeys.member.${i + 1}`] = key;
    });
    await this.request<string>('iam', 'GET', '/', { query });
  }

  async iamTagRole(roleName: string, tags: Array<{ key: string; value: string }>): Promise<void> {
    const query: Record<string, string> = {
      Action: 'TagRole',
      Version: '2010-05-08',
      RoleName: roleName,
    };
    tags.forEach((tag, i) => {
      query[`Tags.member.${i + 1}.Key`] = tag.key;
      query[`Tags.member.${i + 1}.Value`] = tag.value;
    });
    await this.request<string>('iam', 'GET', '/', { query });
  }

  async iamUntagRole(roleName: string, tagKeys: string[]): Promise<void> {
    const query: Record<string, string> = {
      Action: 'UntagRole',
      Version: '2010-05-08',
      RoleName: roleName,
    };
    tagKeys.forEach((key, i) => {
      query[`TagKeys.member.${i + 1}`] = key;
    });
    await this.request<string>('iam', 'GET', '/', { query });
  }

  // ===========================================================================
  // CloudWatch
  // ===========================================================================

  async cloudwatchListMetrics(namespace?: string): Promise<Array<{ namespace: string; metricName: string; dimensions: Array<{ name: string; value: string }> }>> {
    const query: Record<string, string> = {
      Action: 'ListMetrics',
      Version: '2010-08-01',
    };
    if (namespace) {
      query.Namespace = namespace;
    }

    const response = await this.request<string>('monitoring', 'GET', '/', { query });

    const metrics: Array<{ namespace: string; metricName: string; dimensions: Array<{ name: string; value: string }> }> = [];
    const metricMatches = response.matchAll(/<member>([\s\S]*?MetricName[\s\S]*?)<\/member>/g);

    for (const match of metricMatches) {
      const metricXml = match[1];

      const dimensions: Array<{ name: string; value: string }> = [];
      const dimMatches = metricXml.matchAll(/<Dimensions>[\s\S]*?<member>([\s\S]*?)<\/member>[\s\S]*?<\/Dimensions>/g);
      for (const dimMatch of dimMatches) {
        dimensions.push({
          name: this.parseXmlValue(dimMatch[1], 'Name') || '',
          value: this.parseXmlValue(dimMatch[1], 'Value') || '',
        });
      }

      metrics.push({
        namespace: this.parseXmlValue(metricXml, 'Namespace') || '',
        metricName: this.parseXmlValue(metricXml, 'MetricName') || '',
        dimensions,
      });
    }

    return metrics;
  }

  async cloudwatchGetMetricStatistics(params: {
    namespace: string;
    metricName: string;
    dimensions?: Array<{ name: string; value: string }>;
    startTime: string;
    endTime: string;
    period: number;
    statistics: string[];
  }): Promise<CloudWatchMetricDatapoint[]> {
    const query: Record<string, string> = {
      Action: 'GetMetricStatistics',
      Version: '2010-08-01',
      Namespace: params.namespace,
      MetricName: params.metricName,
      StartTime: params.startTime,
      EndTime: params.endTime,
      Period: String(params.period),
    };

    params.statistics.forEach((stat, i) => {
      query[`Statistics.member.${i + 1}`] = stat;
    });

    if (params.dimensions) {
      params.dimensions.forEach((dim, i) => {
        query[`Dimensions.member.${i + 1}.Name`] = dim.name;
        query[`Dimensions.member.${i + 1}.Value`] = dim.value;
      });
    }

    const response = await this.request<string>('monitoring', 'GET', '/', { query });

    const datapoints: CloudWatchMetricDatapoint[] = [];
    const dpMatches = response.matchAll(/<member>([\s\S]*?Timestamp[\s\S]*?)<\/member>/g);

    for (const match of dpMatches) {
      const dpXml = match[1];
      datapoints.push({
        timestamp: this.parseXmlValue(dpXml, 'Timestamp') || '',
        average: this.parseXmlValue(dpXml, 'Average') ? Number.parseFloat(this.parseXmlValue(dpXml, 'Average')!) : undefined,
        sum: this.parseXmlValue(dpXml, 'Sum') ? Number.parseFloat(this.parseXmlValue(dpXml, 'Sum')!) : undefined,
        minimum: this.parseXmlValue(dpXml, 'Minimum') ? Number.parseFloat(this.parseXmlValue(dpXml, 'Minimum')!) : undefined,
        maximum: this.parseXmlValue(dpXml, 'Maximum') ? Number.parseFloat(this.parseXmlValue(dpXml, 'Maximum')!) : undefined,
        sampleCount: this.parseXmlValue(dpXml, 'SampleCount') ? Number.parseFloat(this.parseXmlValue(dpXml, 'SampleCount')!) : undefined,
        unit: this.parseXmlValue(dpXml, 'Unit'),
      });
    }

    return datapoints;
  }

  async cloudwatchDescribeAlarms(alarmNames?: string[]): Promise<CloudWatchAlarm[]> {
    const query: Record<string, string> = {
      Action: 'DescribeAlarms',
      Version: '2010-08-01',
    };

    if (alarmNames) {
      alarmNames.forEach((name, i) => {
        query[`AlarmNames.member.${i + 1}`] = name;
      });
    }

    const response = await this.request<string>('monitoring', 'GET', '/', { query });

    const alarms: CloudWatchAlarm[] = [];
    const alarmMatches = response.matchAll(/<member>([\s\S]*?AlarmName[\s\S]*?)<\/member>/g);

    for (const match of alarmMatches) {
      const alarmXml = match[1];

      const dimensions: Array<{ name: string; value: string }> = [];
      const dimMatches = alarmXml.matchAll(/<Dimensions>[\s\S]*?<member>([\s\S]*?)<\/member>[\s\S]*?<\/Dimensions>/g);
      for (const dimMatch of dimMatches) {
        dimensions.push({
          name: this.parseXmlValue(dimMatch[1], 'Name') || '',
          value: this.parseXmlValue(dimMatch[1], 'Value') || '',
        });
      }

      const alarmActions: string[] = [];
      const actionMatches = alarmXml.matchAll(/<AlarmActions>[\s\S]*?<member>([^<]+)<\/member>[\s\S]*?<\/AlarmActions>/g);
      for (const actionMatch of actionMatches) {
        alarmActions.push(actionMatch[1]);
      }

      alarms.push({
        alarmName: this.parseXmlValue(alarmXml, 'AlarmName') || '',
        alarmArn: this.parseXmlValue(alarmXml, 'AlarmArn') || '',
        stateValue: (this.parseXmlValue(alarmXml, 'StateValue') || 'INSUFFICIENT_DATA') as 'OK' | 'ALARM' | 'INSUFFICIENT_DATA',
        stateReason: this.parseXmlValue(alarmXml, 'StateReason'),
        metricName: this.parseXmlValue(alarmXml, 'MetricName') || '',
        namespace: this.parseXmlValue(alarmXml, 'Namespace') || '',
        statistic: this.parseXmlValue(alarmXml, 'Statistic') || '',
        period: Number.parseInt(this.parseXmlValue(alarmXml, 'Period') || '0', 10),
        threshold: Number.parseFloat(this.parseXmlValue(alarmXml, 'Threshold') || '0'),
        comparisonOperator: this.parseXmlValue(alarmXml, 'ComparisonOperator') || '',
        evaluationPeriods: Number.parseInt(this.parseXmlValue(alarmXml, 'EvaluationPeriods') || '0', 10),
        actionsEnabled: this.parseXmlValue(alarmXml, 'ActionsEnabled') === 'true',
        alarmActions: alarmActions.length > 0 ? alarmActions : undefined,
        dimensions: dimensions.length > 0 ? dimensions : undefined,
      });
    }

    return alarms;
  }

  async cloudwatchSetAlarmState(alarmName: string, stateValue: string, stateReason: string): Promise<void> {
    await this.request<string>('monitoring', 'GET', '/', {
      query: {
        Action: 'SetAlarmState',
        Version: '2010-08-01',
        AlarmName: alarmName,
        StateValue: stateValue,
        StateReason: stateReason,
      },
    });
  }

  async cloudwatchPutMetricData(params: CloudWatchPutMetricDataParams): Promise<void> {
    const query: Record<string, string> = {
      Action: 'PutMetricData',
      Version: '2010-08-01',
      Namespace: params.namespace,
    };

    params.metricData.forEach((metric, i) => {
      const prefix = `MetricData.member.${i + 1}`;
      query[`${prefix}.MetricName`] = metric.metricName;
      if (metric.value !== undefined) {
        query[`${prefix}.Value`] = String(metric.value);
      }
      if (metric.unit) {
        query[`${prefix}.Unit`] = metric.unit;
      }
      if (metric.timestamp) {
        query[`${prefix}.Timestamp`] = metric.timestamp;
      }
      if (metric.dimensions) {
        metric.dimensions.forEach((dim, j) => {
          query[`${prefix}.Dimensions.member.${j + 1}.Name`] = dim.name;
          query[`${prefix}.Dimensions.member.${j + 1}.Value`] = dim.value;
        });
      }
    });

    await this.request<string>('monitoring', 'POST', '/', { query });
  }

  async cloudwatchPutMetricAlarm(params: {
    alarmName: string;
    namespace: string;
    metricName: string;
    statistic: string;
    period: number;
    evaluationPeriods: number;
    threshold: number;
    comparisonOperator: string;
    dimensions?: Array<{ name: string; value: string }>;
    alarmDescription?: string;
    alarmActions?: string[];
    okActions?: string[];
    insufficientDataActions?: string[];
    treatMissingData?: string;
  }): Promise<void> {
    const query: Record<string, string> = {
      Action: 'PutMetricAlarm',
      Version: '2010-08-01',
      AlarmName: params.alarmName,
      Namespace: params.namespace,
      MetricName: params.metricName,
      Statistic: params.statistic,
      Period: String(params.period),
      EvaluationPeriods: String(params.evaluationPeriods),
      Threshold: String(params.threshold),
      ComparisonOperator: params.comparisonOperator,
    };

    if (params.alarmDescription) {
      query.AlarmDescription = params.alarmDescription;
    }
    if (params.treatMissingData) {
      query.TreatMissingData = params.treatMissingData;
    }
    if (params.dimensions) {
      params.dimensions.forEach((dim, i) => {
        query[`Dimensions.member.${i + 1}.Name`] = dim.name;
        query[`Dimensions.member.${i + 1}.Value`] = dim.value;
      });
    }
    if (params.alarmActions) {
      params.alarmActions.forEach((action, i) => {
        query[`AlarmActions.member.${i + 1}`] = action;
      });
    }
    if (params.okActions) {
      params.okActions.forEach((action, i) => {
        query[`OKActions.member.${i + 1}`] = action;
      });
    }
    if (params.insufficientDataActions) {
      params.insufficientDataActions.forEach((action, i) => {
        query[`InsufficientDataActions.member.${i + 1}`] = action;
      });
    }

    await this.request<string>('monitoring', 'POST', '/', { query });
  }

  async cloudwatchDeleteAlarms(alarmNames: string[]): Promise<void> {
    const query: Record<string, string> = {
      Action: 'DeleteAlarms',
      Version: '2010-08-01',
    };

    alarmNames.forEach((name, i) => {
      query[`AlarmNames.member.${i + 1}`] = name;
    });

    await this.request<string>('monitoring', 'POST', '/', { query });
  }

  async cloudwatchEnableAlarmActions(alarmNames: string[]): Promise<void> {
    const query: Record<string, string> = {
      Action: 'EnableAlarmActions',
      Version: '2010-08-01',
    };

    alarmNames.forEach((name, i) => {
      query[`AlarmNames.member.${i + 1}`] = name;
    });

    await this.request<string>('monitoring', 'POST', '/', { query });
  }

  async cloudwatchDisableAlarmActions(alarmNames: string[]): Promise<void> {
    const query: Record<string, string> = {
      Action: 'DisableAlarmActions',
      Version: '2010-08-01',
    };

    alarmNames.forEach((name, i) => {
      query[`AlarmNames.member.${i + 1}`] = name;
    });

    await this.request<string>('monitoring', 'POST', '/', { query });
  }

  // ===========================================================================
  // CloudWatch Logs
  // ===========================================================================

  async cloudwatchLogsDescribeLogGroups(prefix?: string): Promise<CloudWatchLogGroup[]> {
    const body: Record<string, unknown> = {};
    if (prefix) {
      body.logGroupNamePrefix = prefix;
    }

    const response = await this.request<{ logGroups: Array<Record<string, unknown>> }>(
      'logs',
      'POST',
      '/',
      {
        body: JSON.stringify(body),
        headers: {
          'content-type': 'application/x-amz-json-1.1',
          'x-amz-target': 'Logs_20140328.DescribeLogGroups',
        },
      }
    );

    return (response.logGroups || []).map((g) => ({
      logGroupName: g.logGroupName as string,
      arn: g.arn as string | undefined,
      creationTime: g.creationTime as number | undefined,
      storedBytes: g.storedBytes as number | undefined,
      retentionInDays: g.retentionInDays as number | undefined,
    }));
  }

  async cloudwatchLogsDescribeLogStreams(logGroupName: string): Promise<CloudWatchLogStream[]> {
    const response = await this.request<{ logStreams: Array<Record<string, unknown>> }>(
      'logs',
      'POST',
      '/',
      {
        body: JSON.stringify({ logGroupName, orderBy: 'LastEventTime', descending: true }),
        headers: {
          'content-type': 'application/x-amz-json-1.1',
          'x-amz-target': 'Logs_20140328.DescribeLogStreams',
        },
      }
    );

    return (response.logStreams || []).map((s) => ({
      logStreamName: s.logStreamName as string,
      creationTime: s.creationTime as number | undefined,
      firstEventTimestamp: s.firstEventTimestamp as number | undefined,
      lastEventTimestamp: s.lastEventTimestamp as number | undefined,
      lastIngestionTime: s.lastIngestionTime as number | undefined,
      storedBytes: s.storedBytes as number | undefined,
    }));
  }

  async cloudwatchLogsGetLogEvents(
    logGroupName: string,
    logStreamName: string,
    params?: { startTime?: number; endTime?: number; limit?: number }
  ): Promise<CloudWatchLogEvent[]> {
    const body: Record<string, unknown> = {
      logGroupName,
      logStreamName,
      startFromHead: false,
    };

    if (params?.startTime) body.startTime = params.startTime;
    if (params?.endTime) body.endTime = params.endTime;
    if (params?.limit) body.limit = params.limit;

    const response = await this.request<{ events: Array<Record<string, unknown>> }>(
      'logs',
      'POST',
      '/',
      {
        body: JSON.stringify(body),
        headers: {
          'content-type': 'application/x-amz-json-1.1',
          'x-amz-target': 'Logs_20140328.GetLogEvents',
        },
      }
    );

    return (response.events || []).map((e) => ({
      timestamp: e.timestamp as number,
      message: e.message as string,
      ingestionTime: e.ingestionTime as number | undefined,
    }));
  }

  async cloudwatchLogsFilterLogEvents(
    logGroupName: string,
    params?: {
      filterPattern?: string;
      startTime?: number;
      endTime?: number;
      limit?: number;
      logStreamNames?: string[];
    }
  ): Promise<CloudWatchFilteredLogEvent[]> {
    const body: Record<string, unknown> = { logGroupName };

    if (params?.filterPattern) body.filterPattern = params.filterPattern;
    if (params?.startTime) body.startTime = params.startTime;
    if (params?.endTime) body.endTime = params.endTime;
    if (params?.limit) body.limit = params.limit;
    if (params?.logStreamNames) body.logStreamNames = params.logStreamNames;

    const response = await this.request<{ events: Array<Record<string, unknown>> }>(
      'logs',
      'POST',
      '/',
      {
        body: JSON.stringify(body),
        headers: {
          'content-type': 'application/x-amz-json-1.1',
          'x-amz-target': 'Logs_20140328.FilterLogEvents',
        },
      }
    );

    return (response.events || []).map((e) => ({
      logStreamName: e.logStreamName as string,
      timestamp: e.timestamp as number,
      message: e.message as string,
      ingestionTime: e.ingestionTime as number | undefined,
      eventId: e.eventId as string | undefined,
    }));
  }

  async cloudwatchLogsCreateLogGroup(logGroupName: string, tags?: Record<string, string>): Promise<void> {
    const body: Record<string, unknown> = { logGroupName };
    if (tags) {
      body.tags = tags;
    }

    await this.request<Record<string, unknown>>(
      'logs',
      'POST',
      '/',
      {
        body: JSON.stringify(body),
        headers: {
          'content-type': 'application/x-amz-json-1.1',
          'x-amz-target': 'Logs_20140328.CreateLogGroup',
        },
      }
    );
  }

  async cloudwatchLogsDeleteLogGroup(logGroupName: string): Promise<void> {
    await this.request<Record<string, unknown>>(
      'logs',
      'POST',
      '/',
      {
        body: JSON.stringify({ logGroupName }),
        headers: {
          'content-type': 'application/x-amz-json-1.1',
          'x-amz-target': 'Logs_20140328.DeleteLogGroup',
        },
      }
    );
  }

  async cloudwatchLogsPutRetentionPolicy(logGroupName: string, retentionInDays: number): Promise<void> {
    await this.request<Record<string, unknown>>(
      'logs',
      'POST',
      '/',
      {
        body: JSON.stringify({ logGroupName, retentionInDays }),
        headers: {
          'content-type': 'application/x-amz-json-1.1',
          'x-amz-target': 'Logs_20140328.PutRetentionPolicy',
        },
      }
    );
  }

  async cloudwatchLogsDeleteRetentionPolicy(logGroupName: string): Promise<void> {
    await this.request<Record<string, unknown>>(
      'logs',
      'POST',
      '/',
      {
        body: JSON.stringify({ logGroupName }),
        headers: {
          'content-type': 'application/x-amz-json-1.1',
          'x-amz-target': 'Logs_20140328.DeleteRetentionPolicy',
        },
      }
    );
  }

  async cloudwatchLogsCreateLogStream(logGroupName: string, logStreamName: string): Promise<void> {
    await this.request<Record<string, unknown>>(
      'logs',
      'POST',
      '/',
      {
        body: JSON.stringify({ logGroupName, logStreamName }),
        headers: {
          'content-type': 'application/x-amz-json-1.1',
          'x-amz-target': 'Logs_20140328.CreateLogStream',
        },
      }
    );
  }

  async cloudwatchLogsDeleteLogStream(logGroupName: string, logStreamName: string): Promise<void> {
    await this.request<Record<string, unknown>>(
      'logs',
      'POST',
      '/',
      {
        body: JSON.stringify({ logGroupName, logStreamName }),
        headers: {
          'content-type': 'application/x-amz-json-1.1',
          'x-amz-target': 'Logs_20140328.DeleteLogStream',
        },
      }
    );
  }

  async cloudwatchLogsPutLogEvents(
    logGroupName: string,
    logStreamName: string,
    logEvents: Array<{ timestamp: number; message: string }>,
    sequenceToken?: string
  ): Promise<{ nextSequenceToken?: string }> {
    const body: Record<string, unknown> = {
      logGroupName,
      logStreamName,
      logEvents,
    };
    if (sequenceToken) body.sequenceToken = sequenceToken;

    const response = await this.request<{ nextSequenceToken?: string }>(
      'logs',
      'POST',
      '/',
      {
        body: JSON.stringify(body),
        headers: {
          'content-type': 'application/x-amz-json-1.1',
          'x-amz-target': 'Logs_20140328.PutLogEvents',
        },
      }
    );

    return { nextSequenceToken: response.nextSequenceToken };
  }

  // ===========================================================================
  // DynamoDB
  // ===========================================================================

  async dynamodbListTables(): Promise<string[]> {
    const response = await this.request<{ TableNames: string[] }>('dynamodb', 'POST', '/', {
      body: JSON.stringify({}),
      headers: {
        'content-type': 'application/x-amz-json-1.0',
        'x-amz-target': 'DynamoDB_20120810.ListTables',
      },
    });

    return response.TableNames || [];
  }

  private parseDynamoDBTable(t: Record<string, unknown>): DynamoDBTable {
    return {
      tableName: (t.TableName as string) || '',
      tableArn: (t.TableArn as string) || '',
      tableStatus: (t.TableStatus as string) || '',
      creationDateTime: t.CreationDateTime as string,
      itemCount: t.ItemCount as number | undefined,
      tableSizeBytes: t.TableSizeBytes as number | undefined,
      keySchema: t.KeySchema ? (t.KeySchema as Array<{ AttributeName: string; KeyType: 'HASH' | 'RANGE' }>).map((k) => ({
        attributeName: k.AttributeName,
        keyType: k.KeyType,
      })) : [],
      attributeDefinitions: t.AttributeDefinitions ? (t.AttributeDefinitions as Array<{ AttributeName: string; AttributeType: 'S' | 'N' | 'B' }>).map((a) => ({
        attributeName: a.AttributeName,
        attributeType: a.AttributeType,
      })) : [],
      billingModeSummary: t.BillingModeSummary
        ? { billingMode: (t.BillingModeSummary as { BillingMode: 'PROVISIONED' | 'PAY_PER_REQUEST' }).BillingMode }
        : undefined,
      provisionedThroughput: t.ProvisionedThroughput
        ? {
            readCapacityUnits: (t.ProvisionedThroughput as { ReadCapacityUnits: number }).ReadCapacityUnits,
            writeCapacityUnits: (t.ProvisionedThroughput as { WriteCapacityUnits: number }).WriteCapacityUnits,
          }
        : undefined,
    };
  }

  async dynamodbDescribeTable(tableName: string): Promise<DynamoDBTable> {
    const response = await this.request<{ Table: Record<string, unknown> }>('dynamodb', 'POST', '/', {
      body: JSON.stringify({ TableName: tableName }),
      headers: {
        'content-type': 'application/x-amz-json-1.0',
        'x-amz-target': 'DynamoDB_20120810.DescribeTable',
      },
    });
    return this.parseDynamoDBTable(response.Table);
  }

  async dynamodbQuery(params: DynamoDBQueryParams): Promise<{ items: DynamoDBItem[]; lastEvaluatedKey?: Record<string, unknown> }> {
    const body: Record<string, unknown> = {
      TableName: params.tableName,
      KeyConditionExpression: params.keyConditionExpression,
      ExpressionAttributeValues: params.expressionAttributeValues,
    };

    if (params.expressionAttributeNames) body.ExpressionAttributeNames = params.expressionAttributeNames;
    if (params.filterExpression) body.FilterExpression = params.filterExpression;
    if (params.limit) body.Limit = params.limit;
    if (params.scanIndexForward !== undefined) body.ScanIndexForward = params.scanIndexForward;
    if (params.exclusiveStartKey) body.ExclusiveStartKey = params.exclusiveStartKey;
    if (params.indexName) body.IndexName = params.indexName;

    const response = await this.request<{ Items: DynamoDBItem[]; LastEvaluatedKey?: Record<string, unknown> }>(
      'dynamodb',
      'POST',
      '/',
      {
        body: JSON.stringify(body),
        headers: {
          'content-type': 'application/x-amz-json-1.0',
          'x-amz-target': 'DynamoDB_20120810.Query',
        },
      }
    );

    return {
      items: response.Items || [],
      lastEvaluatedKey: response.LastEvaluatedKey,
    };
  }

  async dynamodbScan(params: DynamoDBScanParams): Promise<{ items: DynamoDBItem[]; lastEvaluatedKey?: Record<string, unknown> }> {
    const body: Record<string, unknown> = {
      TableName: params.tableName,
    };

    if (params.filterExpression) body.FilterExpression = params.filterExpression;
    if (params.expressionAttributeValues) body.ExpressionAttributeValues = params.expressionAttributeValues;
    if (params.expressionAttributeNames) body.ExpressionAttributeNames = params.expressionAttributeNames;
    if (params.limit) body.Limit = params.limit;
    if (params.exclusiveStartKey) body.ExclusiveStartKey = params.exclusiveStartKey;
    if (params.indexName) body.IndexName = params.indexName;

    const response = await this.request<{ Items: DynamoDBItem[]; LastEvaluatedKey?: Record<string, unknown> }>(
      'dynamodb',
      'POST',
      '/',
      {
        body: JSON.stringify(body),
        headers: {
          'content-type': 'application/x-amz-json-1.0',
          'x-amz-target': 'DynamoDB_20120810.Scan',
        },
      }
    );

    return {
      items: response.Items || [],
      lastEvaluatedKey: response.LastEvaluatedKey,
    };
  }

  async dynamodbGetItem(params: DynamoDBGetItemParams): Promise<DynamoDBItem | null> {
    const body: Record<string, unknown> = {
      TableName: params.tableName,
      Key: params.key,
    };

    if (params.consistentRead) body.ConsistentRead = params.consistentRead;
    if (params.projectionExpression) body.ProjectionExpression = params.projectionExpression;
    if (params.expressionAttributeNames) body.ExpressionAttributeNames = params.expressionAttributeNames;

    const response = await this.request<{ Item?: DynamoDBItem }>('dynamodb', 'POST', '/', {
      body: JSON.stringify(body),
      headers: {
        'content-type': 'application/x-amz-json-1.0',
        'x-amz-target': 'DynamoDB_20120810.GetItem',
      },
    });

    return response.Item || null;
  }

  async dynamodbPutItem(params: DynamoDBPutItemParams): Promise<void> {
    const body: Record<string, unknown> = {
      TableName: params.tableName,
      Item: params.item,
    };

    if (params.conditionExpression) body.ConditionExpression = params.conditionExpression;
    if (params.expressionAttributeValues) body.ExpressionAttributeValues = params.expressionAttributeValues;
    if (params.expressionAttributeNames) body.ExpressionAttributeNames = params.expressionAttributeNames;

    await this.request<void>('dynamodb', 'POST', '/', {
      body: JSON.stringify(body),
      headers: {
        'content-type': 'application/x-amz-json-1.0',
        'x-amz-target': 'DynamoDB_20120810.PutItem',
      },
    });
  }

  async dynamodbDeleteItem(params: DynamoDBDeleteItemParams): Promise<void> {
    const body: Record<string, unknown> = {
      TableName: params.tableName,
      Key: params.key,
    };

    if (params.conditionExpression) body.ConditionExpression = params.conditionExpression;
    if (params.expressionAttributeValues) body.ExpressionAttributeValues = params.expressionAttributeValues;
    if (params.expressionAttributeNames) body.ExpressionAttributeNames = params.expressionAttributeNames;

    await this.request<void>('dynamodb', 'POST', '/', {
      body: JSON.stringify(body),
      headers: {
        'content-type': 'application/x-amz-json-1.0',
        'x-amz-target': 'DynamoDB_20120810.DeleteItem',
      },
    });
  }

  async dynamodbUpdateItem(params: DynamoDBUpdateItemParams): Promise<void> {
    const body: Record<string, unknown> = {
      TableName: params.tableName,
      Key: params.key,
      UpdateExpression: params.updateExpression,
    };

    if (params.expressionAttributeValues) body.ExpressionAttributeValues = params.expressionAttributeValues;
    if (params.expressionAttributeNames) body.ExpressionAttributeNames = params.expressionAttributeNames;
    if (params.conditionExpression) body.ConditionExpression = params.conditionExpression;

    await this.request<void>('dynamodb', 'POST', '/', {
      body: JSON.stringify(body),
      headers: {
        'content-type': 'application/x-amz-json-1.0',
        'x-amz-target': 'DynamoDB_20120810.UpdateItem',
      },
    });
  }

  async dynamodbBatchGetItem(
    params: DynamoDBBatchGetItemParams
  ): Promise<{ responses: Record<string, DynamoDBItem[]>; unprocessedKeys?: Record<string, unknown> }> {
    const requestItems: Record<string, unknown> = {};

    for (const [tableName, tableParams] of Object.entries(params.requestItems)) {
      const tableRequest: Record<string, unknown> = {
        Keys: tableParams.keys,
      };
      if (tableParams.projectionExpression) tableRequest.ProjectionExpression = tableParams.projectionExpression;
      if (tableParams.expressionAttributeNames) tableRequest.ExpressionAttributeNames = tableParams.expressionAttributeNames;
      if (tableParams.consistentRead !== undefined) tableRequest.ConsistentRead = tableParams.consistentRead;
      requestItems[tableName] = tableRequest;
    }

    const response = await this.request<{
      Responses?: Record<string, Array<Record<string, unknown>>>;
      UnprocessedKeys?: Record<string, unknown>;
    }>('dynamodb', 'POST', '/', {
      body: JSON.stringify({ RequestItems: requestItems }),
      headers: {
        'content-type': 'application/x-amz-json-1.0',
        'x-amz-target': 'DynamoDB_20120810.BatchGetItem',
      },
    });

    const responses: Record<string, DynamoDBItem[]> = {};
    for (const [tableName, items] of Object.entries(response.Responses || {})) {
      responses[tableName] = items as DynamoDBItem[];
    }

    return {
      responses,
      unprocessedKeys: response.UnprocessedKeys,
    };
  }

  async dynamodbBatchWriteItem(
    params: DynamoDBBatchWriteItemParams
  ): Promise<{ unprocessedItems?: Record<string, unknown> }> {
    const requestItems: Record<string, unknown[]> = {};

    for (const [tableName, requests] of Object.entries(params.requestItems)) {
      requestItems[tableName] = requests.map((req) => {
        if ('putRequest' in req) {
          return { PutRequest: { Item: req.putRequest.item } };
        } else {
          return { DeleteRequest: { Key: req.deleteRequest.key } };
        }
      });
    }

    const response = await this.request<{
      UnprocessedItems?: Record<string, unknown>;
    }>('dynamodb', 'POST', '/', {
      body: JSON.stringify({ RequestItems: requestItems }),
      headers: {
        'content-type': 'application/x-amz-json-1.0',
        'x-amz-target': 'DynamoDB_20120810.BatchWriteItem',
      },
    });

    return {
      unprocessedItems: response.UnprocessedItems,
    };
  }

  async dynamodbCreateTable(params: {
    tableName: string;
    keySchema: Array<{ attributeName: string; keyType: 'HASH' | 'RANGE' }>;
    attributeDefinitions: Array<{ attributeName: string; attributeType: 'S' | 'N' | 'B' }>;
    billingMode?: 'PROVISIONED' | 'PAY_PER_REQUEST';
    provisionedThroughput?: { readCapacityUnits: number; writeCapacityUnits: number };
  }): Promise<DynamoDBTable> {
    const body: Record<string, unknown> = {
      TableName: params.tableName,
      KeySchema: params.keySchema.map((k) => ({
        AttributeName: k.attributeName,
        KeyType: k.keyType,
      })),
      AttributeDefinitions: params.attributeDefinitions.map((a) => ({
        AttributeName: a.attributeName,
        AttributeType: a.attributeType,
      })),
      BillingMode: params.billingMode || 'PAY_PER_REQUEST',
    };

    if (params.provisionedThroughput) {
      body.ProvisionedThroughput = {
        ReadCapacityUnits: params.provisionedThroughput.readCapacityUnits,
        WriteCapacityUnits: params.provisionedThroughput.writeCapacityUnits,
      };
    }

    const response = await this.request<{ TableDescription: Record<string, unknown> }>(
      'dynamodb',
      'POST',
      '/',
      {
        body: JSON.stringify(body),
        headers: {
          'content-type': 'application/x-amz-json-1.0',
          'x-amz-target': 'DynamoDB_20120810.CreateTable',
        },
      }
    );

    const t = response.TableDescription;
    return {
      tableName: t.TableName as string,
      tableArn: t.TableArn as string,
      tableStatus: t.TableStatus as string,
      creationDateTime: t.CreationDateTime as string,
      keySchema: (t.KeySchema as Array<{ AttributeName: string; KeyType: 'HASH' | 'RANGE' }>).map((k) => ({
        attributeName: k.AttributeName,
        keyType: k.KeyType,
      })),
      attributeDefinitions: (t.AttributeDefinitions as Array<{ AttributeName: string; AttributeType: 'S' | 'N' | 'B' }>).map((a) => ({
        attributeName: a.AttributeName,
        attributeType: a.AttributeType,
      })),
    };
  }

  async dynamodbDeleteTable(tableName: string): Promise<void> {
    await this.request<void>('dynamodb', 'POST', '/', {
      body: JSON.stringify({ TableName: tableName }),
      headers: {
        'content-type': 'application/x-amz-json-1.0',
        'x-amz-target': 'DynamoDB_20120810.DeleteTable',
      },
    });
  }

  async dynamodbUpdateTimeToLive(tableName: string, attributeName: string, enabled: boolean): Promise<void> {
    await this.request<void>('dynamodb', 'POST', '/', {
      body: JSON.stringify({
        TableName: tableName,
        TimeToLiveSpecification: {
          AttributeName: attributeName,
          Enabled: enabled,
        },
      }),
      headers: {
        'content-type': 'application/x-amz-json-1.0',
        'x-amz-target': 'DynamoDB_20120810.UpdateTimeToLive',
      },
    });
  }

  async dynamodbDescribeTimeToLive(tableName: string): Promise<{ attributeName?: string; status: string }> {
    const response = await this.request<{ TimeToLiveDescription?: { AttributeName?: string; TimeToLiveStatus?: string } }>('dynamodb', 'POST', '/', {
      body: JSON.stringify({ TableName: tableName }),
      headers: {
        'content-type': 'application/x-amz-json-1.0',
        'x-amz-target': 'DynamoDB_20120810.DescribeTimeToLive',
      },
    });
    return {
      attributeName: response.TimeToLiveDescription?.AttributeName,
      status: response.TimeToLiveDescription?.TimeToLiveStatus || 'DISABLED',
    };
  }

  async dynamodbCreateBackup(tableName: string, backupName: string): Promise<{ backupArn: string; backupName: string; backupStatus: string; tableArn: string }> {
    const response = await this.request<{ BackupDetails?: { BackupArn?: string; BackupName?: string; BackupStatus?: string; TableArn?: string } }>('dynamodb', 'POST', '/', {
      body: JSON.stringify({ TableName: tableName, BackupName: backupName }),
      headers: {
        'content-type': 'application/x-amz-json-1.0',
        'x-amz-target': 'DynamoDB_20120810.CreateBackup',
      },
    });
    return {
      backupArn: response.BackupDetails?.BackupArn || '',
      backupName: response.BackupDetails?.BackupName || '',
      backupStatus: response.BackupDetails?.BackupStatus || '',
      tableArn: response.BackupDetails?.TableArn || '',
    };
  }

  async dynamodbListBackups(tableName?: string): Promise<Array<{ backupArn: string; backupName: string; backupStatus: string; tableName: string; backupCreationDateTime?: string }>> {
    const body: Record<string, unknown> = {};
    if (tableName) body.TableName = tableName;

    const response = await this.request<{ BackupSummaries?: Array<{ BackupArn?: string; BackupName?: string; BackupStatus?: string; TableName?: string; BackupCreationDateTime?: number }> }>('dynamodb', 'POST', '/', {
      body: JSON.stringify(body),
      headers: {
        'content-type': 'application/x-amz-json-1.0',
        'x-amz-target': 'DynamoDB_20120810.ListBackups',
      },
    });
    return (response.BackupSummaries || []).map((b) => ({
      backupArn: b.BackupArn || '',
      backupName: b.BackupName || '',
      backupStatus: b.BackupStatus || '',
      tableName: b.TableName || '',
      backupCreationDateTime: b.BackupCreationDateTime ? new Date(b.BackupCreationDateTime * 1000).toISOString() : undefined,
    }));
  }

  async dynamodbDescribeBackup(backupArn: string): Promise<{ backupArn: string; backupName: string; backupStatus: string; tableName: string; backupCreationDateTime?: string; backupSizeBytes?: number }> {
    const response = await this.request<{ BackupDescription?: { BackupDetails?: { BackupArn?: string; BackupName?: string; BackupStatus?: string; BackupCreationDateTime?: number; BackupSizeBytes?: number }; SourceTableDetails?: { TableName?: string } } }>('dynamodb', 'POST', '/', {
      body: JSON.stringify({ BackupArn: backupArn }),
      headers: {
        'content-type': 'application/x-amz-json-1.0',
        'x-amz-target': 'DynamoDB_20120810.DescribeBackup',
      },
    });
    return {
      backupArn: response.BackupDescription?.BackupDetails?.BackupArn || '',
      backupName: response.BackupDescription?.BackupDetails?.BackupName || '',
      backupStatus: response.BackupDescription?.BackupDetails?.BackupStatus || '',
      tableName: response.BackupDescription?.SourceTableDetails?.TableName || '',
      backupCreationDateTime: response.BackupDescription?.BackupDetails?.BackupCreationDateTime ? new Date(response.BackupDescription.BackupDetails.BackupCreationDateTime * 1000).toISOString() : undefined,
      backupSizeBytes: response.BackupDescription?.BackupDetails?.BackupSizeBytes,
    };
  }

  async dynamodbDeleteBackup(backupArn: string): Promise<void> {
    await this.request<void>('dynamodb', 'POST', '/', {
      body: JSON.stringify({ BackupArn: backupArn }),
      headers: {
        'content-type': 'application/x-amz-json-1.0',
        'x-amz-target': 'DynamoDB_20120810.DeleteBackup',
      },
    });
  }

  async dynamodbRestoreTableFromBackup(targetTableName: string, backupArn: string): Promise<DynamoDBTable> {
    const response = await this.request<{ TableDescription?: unknown }>('dynamodb', 'POST', '/', {
      body: JSON.stringify({ TargetTableName: targetTableName, BackupArn: backupArn }),
      headers: {
        'content-type': 'application/x-amz-json-1.0',
        'x-amz-target': 'DynamoDB_20120810.RestoreTableFromBackup',
      },
    });
    return this.parseDynamoDBTable((response.TableDescription || {}) as Record<string, unknown>);
  }

  async dynamodbEnableContinuousBackups(tableName: string): Promise<void> {
    await this.request<void>('dynamodb', 'POST', '/', {
      body: JSON.stringify({
        TableName: tableName,
        PointInTimeRecoverySpecification: { PointInTimeRecoveryEnabled: true },
      }),
      headers: {
        'content-type': 'application/x-amz-json-1.0',
        'x-amz-target': 'DynamoDB_20120810.UpdateContinuousBackups',
      },
    });
  }

  async dynamodbDescribeContinuousBackups(tableName: string): Promise<{ pointInTimeRecoveryStatus: string; earliestRestorableDateTime?: string; latestRestorableDateTime?: string }> {
    const response = await this.request<{ ContinuousBackupsDescription?: { PointInTimeRecoveryDescription?: { PointInTimeRecoveryStatus?: string; EarliestRestorableDateTime?: number; LatestRestorableDateTime?: number } } }>('dynamodb', 'POST', '/', {
      body: JSON.stringify({ TableName: tableName }),
      headers: {
        'content-type': 'application/x-amz-json-1.0',
        'x-amz-target': 'DynamoDB_20120810.DescribeContinuousBackups',
      },
    });
    const pitr = response.ContinuousBackupsDescription?.PointInTimeRecoveryDescription;
    return {
      pointInTimeRecoveryStatus: pitr?.PointInTimeRecoveryStatus || 'DISABLED',
      earliestRestorableDateTime: pitr?.EarliestRestorableDateTime ? new Date(pitr.EarliestRestorableDateTime * 1000).toISOString() : undefined,
      latestRestorableDateTime: pitr?.LatestRestorableDateTime ? new Date(pitr.LatestRestorableDateTime * 1000).toISOString() : undefined,
    };
  }

  async dynamodbRestoreTableToPointInTime(sourceTableName: string, targetTableName: string, restoreDateTime?: Date): Promise<DynamoDBTable> {
    const body: Record<string, unknown> = {
      SourceTableName: sourceTableName,
      TargetTableName: targetTableName,
    };
    if (restoreDateTime) {
      body.RestoreDateTime = Math.floor(restoreDateTime.getTime() / 1000);
    } else {
      body.UseLatestRestorableTime = true;
    }
    const response = await this.request<{ TableDescription?: unknown }>('dynamodb', 'POST', '/', {
      body: JSON.stringify(body),
      headers: {
        'content-type': 'application/x-amz-json-1.0',
        'x-amz-target': 'DynamoDB_20120810.RestoreTableToPointInTime',
      },
    });
    return this.parseDynamoDBTable((response.TableDescription || {}) as Record<string, unknown>);
  }

  async dynamodbUpdateTable(tableName: string, params: { provisionedThroughput?: { readCapacityUnits: number; writeCapacityUnits: number }; billingMode?: 'PROVISIONED' | 'PAY_PER_REQUEST' }): Promise<DynamoDBTable> {
    const body: Record<string, unknown> = { TableName: tableName };
    if (params.provisionedThroughput) {
      body.ProvisionedThroughput = {
        ReadCapacityUnits: params.provisionedThroughput.readCapacityUnits,
        WriteCapacityUnits: params.provisionedThroughput.writeCapacityUnits,
      };
    }
    if (params.billingMode) {
      body.BillingMode = params.billingMode;
    }
    const response = await this.request<{ TableDescription?: unknown }>('dynamodb', 'POST', '/', {
      body: JSON.stringify(body),
      headers: {
        'content-type': 'application/x-amz-json-1.0',
        'x-amz-target': 'DynamoDB_20120810.UpdateTable',
      },
    });
    return this.parseDynamoDBTable((response.TableDescription || {}) as Record<string, unknown>);
  }

  async dynamodbListGlobalTables(): Promise<Array<{ globalTableName: string; replicationGroup: Array<{ regionName: string }> }>> {
    const response = await this.request<{ GlobalTables?: Array<Record<string, unknown>> }>('dynamodb', 'POST', '/', {
      body: JSON.stringify({}),
      headers: {
        'content-type': 'application/x-amz-json-1.0',
        'x-amz-target': 'DynamoDB_20120810.ListGlobalTables',
      },
    });
    return (response.GlobalTables || []).map((gt) => ({
      globalTableName: gt.GlobalTableName as string,
      replicationGroup: ((gt.ReplicationGroup as Array<Record<string, unknown>>) || []).map((r) => ({
        regionName: r.RegionName as string,
      })),
    }));
  }

  async dynamodbDescribeGlobalTable(globalTableName: string): Promise<{ globalTableName: string; replicationGroup: Array<{ regionName: string }>; globalTableStatus: string; creationDateTime?: string }> {
    const response = await this.request<{ GlobalTableDescription?: Record<string, unknown> }>('dynamodb', 'POST', '/', {
      body: JSON.stringify({ GlobalTableName: globalTableName }),
      headers: {
        'content-type': 'application/x-amz-json-1.0',
        'x-amz-target': 'DynamoDB_20120810.DescribeGlobalTable',
      },
    });
    const gt = response.GlobalTableDescription || {};
    return {
      globalTableName: gt.GlobalTableName as string,
      replicationGroup: ((gt.ReplicationGroup as Array<Record<string, unknown>>) || []).map((r) => ({
        regionName: r.RegionName as string,
      })),
      globalTableStatus: gt.GlobalTableStatus as string,
      creationDateTime: gt.CreationDateTime as string | undefined,
    };
  }

  async dynamodbTagResource(resourceArn: string, tags: Array<{ key: string; value: string }>): Promise<void> {
    await this.request<Record<string, unknown>>('dynamodb', 'POST', '/', {
      body: JSON.stringify({
        ResourceArn: resourceArn,
        Tags: tags.map((t) => ({ Key: t.key, Value: t.value })),
      }),
      headers: {
        'content-type': 'application/x-amz-json-1.0',
        'x-amz-target': 'DynamoDB_20120810.TagResource',
      },
    });
  }

  async dynamodbUntagResource(resourceArn: string, tagKeys: string[]): Promise<void> {
    await this.request<Record<string, unknown>>('dynamodb', 'POST', '/', {
      body: JSON.stringify({
        ResourceArn: resourceArn,
        TagKeys: tagKeys,
      }),
      headers: {
        'content-type': 'application/x-amz-json-1.0',
        'x-amz-target': 'DynamoDB_20120810.UntagResource',
      },
    });
  }

  async dynamodbListTagsOfResource(resourceArn: string): Promise<Array<{ key: string; value: string }>> {
    const response = await this.request<{ Tags?: Array<Record<string, string>> }>('dynamodb', 'POST', '/', {
      body: JSON.stringify({ ResourceArn: resourceArn }),
      headers: {
        'content-type': 'application/x-amz-json-1.0',
        'x-amz-target': 'DynamoDB_20120810.ListTagsOfResource',
      },
    });
    return (response.Tags || []).map((t) => ({
      key: t.Key,
      value: t.Value,
    }));
  }

  async dynamodbDescribeTableReplicaAutoScaling(tableName: string): Promise<{ tableName: string; replicas: Array<{ regionName: string; globalSecondaryIndexes?: Array<{ indexName: string; indexStatus: string }> }> }> {
    const response = await this.request<{ TableAutoScalingDescription?: Record<string, unknown> }>('dynamodb', 'POST', '/', {
      body: JSON.stringify({ TableName: tableName }),
      headers: {
        'content-type': 'application/x-amz-json-1.0',
        'x-amz-target': 'DynamoDB_20120810.DescribeTableReplicaAutoScaling',
      },
    });
    const desc = response.TableAutoScalingDescription || {};
    const replicas = (desc.Replicas as Array<Record<string, unknown>>) || [];
    return {
      tableName: desc.TableName as string || tableName,
      replicas: replicas.map((r) => ({
        regionName: r.RegionName as string,
        globalSecondaryIndexes: r.GlobalSecondaryIndexes ? (r.GlobalSecondaryIndexes as Array<Record<string, unknown>>).map((gsi) => ({
          indexName: gsi.IndexName as string,
          indexStatus: gsi.IndexStatus as string,
        })) : undefined,
      })),
    };
  }

  async dynamodbDescribeLimits(): Promise<{ accountMaxReadCapacityUnits: number; accountMaxWriteCapacityUnits: number; tableMaxReadCapacityUnits: number; tableMaxWriteCapacityUnits: number }> {
    const response = await this.request<Record<string, number>>('dynamodb', 'POST', '/', {
      body: JSON.stringify({}),
      headers: {
        'content-type': 'application/x-amz-json-1.0',
        'x-amz-target': 'DynamoDB_20120810.DescribeLimits',
      },
    });
    return {
      accountMaxReadCapacityUnits: response.AccountMaxReadCapacityUnits || 0,
      accountMaxWriteCapacityUnits: response.AccountMaxWriteCapacityUnits || 0,
      tableMaxReadCapacityUnits: response.TableMaxReadCapacityUnits || 0,
      tableMaxWriteCapacityUnits: response.TableMaxWriteCapacityUnits || 0,
    };
  }

  // ===========================================================================
  // SQS
  // ===========================================================================

  async sqsListQueues(): Promise<string[]> {
    const response = await this.request<string>('sqs', 'GET', '/', {
      query: { Action: 'ListQueues', Version: '2012-11-05' },
    });

    const urls: string[] = [];
    const urlMatches = response.matchAll(/<QueueUrl>([^<]+)<\/QueueUrl>/g);
    for (const match of urlMatches) {
      urls.push(match[1]);
    }

    return urls;
  }

  async sqsGetQueueAttributes(queueUrl: string): Promise<SQSQueue> {
    const response = await this.request<string>('sqs', 'GET', '/', {
      query: {
        Action: 'GetQueueAttributes',
        Version: '2012-11-05',
        QueueUrl: queueUrl,
        'AttributeName.1': 'All',
      },
    });

    const getAttribute = (name: string): string | undefined => {
      const match = response.match(new RegExp(`<Name>${name}</Name>\\s*<Value>([^<]*)</Value>`));
      return match ? match[1] : undefined;
    };

    return {
      queueUrl,
      queueArn: getAttribute('QueueArn'),
      approximateNumberOfMessages: getAttribute('ApproximateNumberOfMessages')
        ? Number.parseInt(getAttribute('ApproximateNumberOfMessages')!, 10)
        : undefined,
      approximateNumberOfMessagesNotVisible: getAttribute('ApproximateNumberOfMessagesNotVisible')
        ? Number.parseInt(getAttribute('ApproximateNumberOfMessagesNotVisible')!, 10)
        : undefined,
      approximateNumberOfMessagesDelayed: getAttribute('ApproximateNumberOfMessagesDelayed')
        ? Number.parseInt(getAttribute('ApproximateNumberOfMessagesDelayed')!, 10)
        : undefined,
      visibilityTimeout: getAttribute('VisibilityTimeout')
        ? Number.parseInt(getAttribute('VisibilityTimeout')!, 10)
        : undefined,
      maximumMessageSize: getAttribute('MaximumMessageSize')
        ? Number.parseInt(getAttribute('MaximumMessageSize')!, 10)
        : undefined,
      messageRetentionPeriod: getAttribute('MessageRetentionPeriod')
        ? Number.parseInt(getAttribute('MessageRetentionPeriod')!, 10)
        : undefined,
      delaySeconds: getAttribute('DelaySeconds')
        ? Number.parseInt(getAttribute('DelaySeconds')!, 10)
        : undefined,
    };
  }

  async sqsSendMessage(params: SQSSendMessageParams): Promise<{ messageId: string }> {
    const query: Record<string, string> = {
      Action: 'SendMessage',
      Version: '2012-11-05',
      QueueUrl: params.queueUrl,
      MessageBody: params.messageBody,
    };

    if (params.delaySeconds !== undefined) {
      query.DelaySeconds = String(params.delaySeconds);
    }

    const response = await this.request<string>('sqs', 'GET', '/', { query });

    return {
      messageId: this.parseXmlValue(response, 'MessageId') || '',
    };
  }

  async sqsReceiveMessage(params: SQSReceiveMessageParams): Promise<SQSMessage[]> {
    const query: Record<string, string> = {
      Action: 'ReceiveMessage',
      Version: '2012-11-05',
      QueueUrl: params.queueUrl,
    };

    if (params.maxNumberOfMessages) query.MaxNumberOfMessages = String(params.maxNumberOfMessages);
    if (params.visibilityTimeout) query.VisibilityTimeout = String(params.visibilityTimeout);
    if (params.waitTimeSeconds) query.WaitTimeSeconds = String(params.waitTimeSeconds);

    const response = await this.request<string>('sqs', 'GET', '/', { query });

    const messages: SQSMessage[] = [];
    const msgMatches = response.matchAll(/<Message>([\s\S]*?)<\/Message>/g);

    for (const match of msgMatches) {
      const msgXml = match[1];
      messages.push({
        messageId: this.parseXmlValue(msgXml, 'MessageId') || '',
        receiptHandle: this.parseXmlValue(msgXml, 'ReceiptHandle') || '',
        body: this.parseXmlValue(msgXml, 'Body') || '',
        md5OfBody: this.parseXmlValue(msgXml, 'MD5OfBody') || '',
      });
    }

    return messages;
  }

  async sqsDeleteMessage(queueUrl: string, receiptHandle: string): Promise<void> {
    await this.request<string>('sqs', 'GET', '/', {
      query: {
        Action: 'DeleteMessage',
        Version: '2012-11-05',
        QueueUrl: queueUrl,
        ReceiptHandle: receiptHandle,
      },
    });
  }

  async sqsPurgeQueue(queueUrl: string): Promise<void> {
    await this.request<string>('sqs', 'GET', '/', {
      query: {
        Action: 'PurgeQueue',
        Version: '2012-11-05',
        QueueUrl: queueUrl,
      },
    });
  }

  async sqsCreateQueue(params: SQSCreateQueueParams): Promise<{ queueUrl: string }> {
    const query: Record<string, string> = {
      Action: 'CreateQueue',
      Version: '2012-11-05',
      QueueName: params.queueName,
    };

    let attrIndex = 1;
    if (params.attributes) {
      if (params.attributes.delaySeconds !== undefined) {
        query[`Attribute.${attrIndex}.Name`] = 'DelaySeconds';
        query[`Attribute.${attrIndex}.Value`] = String(params.attributes.delaySeconds);
        attrIndex++;
      }
      if (params.attributes.maximumMessageSize !== undefined) {
        query[`Attribute.${attrIndex}.Name`] = 'MaximumMessageSize';
        query[`Attribute.${attrIndex}.Value`] = String(params.attributes.maximumMessageSize);
        attrIndex++;
      }
      if (params.attributes.messageRetentionPeriod !== undefined) {
        query[`Attribute.${attrIndex}.Name`] = 'MessageRetentionPeriod';
        query[`Attribute.${attrIndex}.Value`] = String(params.attributes.messageRetentionPeriod);
        attrIndex++;
      }
      if (params.attributes.visibilityTimeout !== undefined) {
        query[`Attribute.${attrIndex}.Name`] = 'VisibilityTimeout';
        query[`Attribute.${attrIndex}.Value`] = String(params.attributes.visibilityTimeout);
        attrIndex++;
      }
      if (params.attributes.fifoQueue) {
        query[`Attribute.${attrIndex}.Name`] = 'FifoQueue';
        query[`Attribute.${attrIndex}.Value`] = 'true';
        attrIndex++;
      }
      if (params.attributes.contentBasedDeduplication) {
        query[`Attribute.${attrIndex}.Name`] = 'ContentBasedDeduplication';
        query[`Attribute.${attrIndex}.Value`] = 'true';
      }
    }

    const response = await this.request<string>('sqs', 'GET', '/', { query });
    return {
      queueUrl: this.parseXmlValue(response, 'QueueUrl') || '',
    };
  }

  async sqsDeleteQueue(queueUrl: string): Promise<void> {
    await this.request<string>('sqs', 'GET', '/', {
      query: {
        Action: 'DeleteQueue',
        Version: '2012-11-05',
        QueueUrl: queueUrl,
      },
    });
  }

  async sqsGetQueueUrl(queueName: string): Promise<string> {
    const response = await this.request<string>('sqs', 'GET', '/', {
      query: {
        Action: 'GetQueueUrl',
        Version: '2012-11-05',
        QueueName: queueName,
      },
    });
    return this.parseXmlValue(response, 'QueueUrl') || '';
  }

  async sqsSetQueueAttributes(queueUrl: string, attributes: Record<string, string>): Promise<void> {
    const query: Record<string, string> = {
      Action: 'SetQueueAttributes',
      Version: '2012-11-05',
      QueueUrl: queueUrl,
    };

    let i = 1;
    for (const [name, value] of Object.entries(attributes)) {
      query[`Attribute.${i}.Name`] = name;
      query[`Attribute.${i}.Value`] = value;
      i++;
    }

    await this.request<string>('sqs', 'GET', '/', { query });
  }

  async sqsTagQueue(queueUrl: string, tags: Record<string, string>): Promise<void> {
    const query: Record<string, string> = {
      Action: 'TagQueue',
      Version: '2012-11-05',
      QueueUrl: queueUrl,
    };

    let i = 1;
    for (const [key, value] of Object.entries(tags)) {
      query[`Tag.${i}.Key`] = key;
      query[`Tag.${i}.Value`] = value;
      i++;
    }

    await this.request<string>('sqs', 'GET', '/', { query });
  }

  async sqsListQueueTags(queueUrl: string): Promise<Record<string, string>> {
    const response = await this.request<string>('sqs', 'GET', '/', {
      query: {
        Action: 'ListQueueTags',
        Version: '2012-11-05',
        QueueUrl: queueUrl,
      },
    });

    const tags: Record<string, string> = {};
    const tagMatches = response.matchAll(/<entry><key>([^<]+)<\/key><value>([^<]+)<\/value><\/entry>/g);

    for (const match of tagMatches) {
      tags[match[1]] = match[2];
    }

    return tags;
  }

  async sqsUntagQueue(queueUrl: string, tagKeys: string[]): Promise<void> {
    const query: Record<string, string> = {
      Action: 'UntagQueue',
      Version: '2012-11-05',
      QueueUrl: queueUrl,
    };
    tagKeys.forEach((key, i) => {
      query[`TagKey.${i + 1}`] = key;
    });
    await this.request<string>('sqs', 'GET', '/', { query });
  }

  async sqsSendMessageBatch(queueUrl: string, entries: Array<{ id: string; messageBody: string; delaySeconds?: number }>): Promise<{ successful: Array<{ id: string; messageId: string }>; failed: Array<{ id: string; code: string; message: string }> }> {
    const query: Record<string, string> = {
      Action: 'SendMessageBatch',
      Version: '2012-11-05',
      QueueUrl: queueUrl,
    };
    entries.forEach((entry, i) => {
      query[`SendMessageBatchRequestEntry.${i + 1}.Id`] = entry.id;
      query[`SendMessageBatchRequestEntry.${i + 1}.MessageBody`] = entry.messageBody;
      if (entry.delaySeconds !== undefined) {
        query[`SendMessageBatchRequestEntry.${i + 1}.DelaySeconds`] = String(entry.delaySeconds);
      }
    });
    const response = await this.request<string>('sqs', 'GET', '/', { query });

    const successful: Array<{ id: string; messageId: string }> = [];
    const failed: Array<{ id: string; code: string; message: string }> = [];

    const successMatches = response.matchAll(/<SendMessageBatchResultEntry>([\s\S]*?)<\/SendMessageBatchResultEntry>/g);
    for (const match of successMatches) {
      successful.push({
        id: this.parseXmlValue(match[1], 'Id') || '',
        messageId: this.parseXmlValue(match[1], 'MessageId') || '',
      });
    }

    const failedMatches = response.matchAll(/<BatchResultErrorEntry>([\s\S]*?)<\/BatchResultErrorEntry>/g);
    for (const match of failedMatches) {
      failed.push({
        id: this.parseXmlValue(match[1], 'Id') || '',
        code: this.parseXmlValue(match[1], 'Code') || '',
        message: this.parseXmlValue(match[1], 'Message') || '',
      });
    }

    return { successful, failed };
  }

  async sqsDeleteMessageBatch(queueUrl: string, entries: Array<{ id: string; receiptHandle: string }>): Promise<{ successful: Array<{ id: string }>; failed: Array<{ id: string; code: string; message: string }> }> {
    const query: Record<string, string> = {
      Action: 'DeleteMessageBatch',
      Version: '2012-11-05',
      QueueUrl: queueUrl,
    };
    entries.forEach((entry, i) => {
      query[`DeleteMessageBatchRequestEntry.${i + 1}.Id`] = entry.id;
      query[`DeleteMessageBatchRequestEntry.${i + 1}.ReceiptHandle`] = entry.receiptHandle;
    });
    const response = await this.request<string>('sqs', 'GET', '/', { query });

    const successful: Array<{ id: string }> = [];
    const failed: Array<{ id: string; code: string; message: string }> = [];

    const successMatches = response.matchAll(/<DeleteMessageBatchResultEntry>([\s\S]*?)<\/DeleteMessageBatchResultEntry>/g);
    for (const match of successMatches) {
      successful.push({ id: this.parseXmlValue(match[1], 'Id') || '' });
    }

    const failedMatches = response.matchAll(/<BatchResultErrorEntry>([\s\S]*?)<\/BatchResultErrorEntry>/g);
    for (const match of failedMatches) {
      failed.push({
        id: this.parseXmlValue(match[1], 'Id') || '',
        code: this.parseXmlValue(match[1], 'Code') || '',
        message: this.parseXmlValue(match[1], 'Message') || '',
      });
    }

    return { successful, failed };
  }

  async sqsChangeMessageVisibility(queueUrl: string, receiptHandle: string, visibilityTimeout: number): Promise<void> {
    await this.request<string>('sqs', 'GET', '/', {
      query: {
        Action: 'ChangeMessageVisibility',
        Version: '2012-11-05',
        QueueUrl: queueUrl,
        ReceiptHandle: receiptHandle,
        VisibilityTimeout: String(visibilityTimeout),
      },
    });
  }

  async sqsChangeMessageVisibilityBatch(queueUrl: string, entries: Array<{ id: string; receiptHandle: string; visibilityTimeout: number }>): Promise<{ successful: Array<{ id: string }>; failed: Array<{ id: string; code: string; message: string }> }> {
    const query: Record<string, string> = {
      Action: 'ChangeMessageVisibilityBatch',
      Version: '2012-11-05',
      QueueUrl: queueUrl,
    };
    entries.forEach((entry, i) => {
      query[`ChangeMessageVisibilityBatchRequestEntry.${i + 1}.Id`] = entry.id;
      query[`ChangeMessageVisibilityBatchRequestEntry.${i + 1}.ReceiptHandle`] = entry.receiptHandle;
      query[`ChangeMessageVisibilityBatchRequestEntry.${i + 1}.VisibilityTimeout`] = String(entry.visibilityTimeout);
    });
    const response = await this.request<string>('sqs', 'GET', '/', { query });

    const successful: Array<{ id: string }> = [];
    const failed: Array<{ id: string; code: string; message: string }> = [];

    const successMatches = response.matchAll(/<ChangeMessageVisibilityBatchResultEntry>([\s\S]*?)<\/ChangeMessageVisibilityBatchResultEntry>/g);
    for (const match of successMatches) {
      successful.push({ id: this.parseXmlValue(match[1], 'Id') || '' });
    }

    const failedMatches = response.matchAll(/<BatchResultErrorEntry>([\s\S]*?)<\/BatchResultErrorEntry>/g);
    for (const match of failedMatches) {
      failed.push({
        id: this.parseXmlValue(match[1], 'Id') || '',
        code: this.parseXmlValue(match[1], 'Code') || '',
        message: this.parseXmlValue(match[1], 'Message') || '',
      });
    }

    return { successful, failed };
  }

  async sqsListDeadLetterSourceQueues(queueUrl: string): Promise<string[]> {
    const response = await this.request<string>('sqs', 'GET', '/', {
      query: {
        Action: 'ListDeadLetterSourceQueues',
        Version: '2012-11-05',
        QueueUrl: queueUrl,
      },
    });

    const queues: string[] = [];
    const queueMatches = response.matchAll(/<QueueUrl>([^<]+)<\/QueueUrl>/g);
    for (const match of queueMatches) {
      queues.push(match[1]);
    }
    return queues;
  }

  // ===========================================================================
  // SNS
  // ===========================================================================

  async snsListTopics(): Promise<SNSTopic[]> {
    const response = await this.request<string>('sns', 'GET', '/', {
      query: { Action: 'ListTopics', Version: '2010-03-31' },
    });

    const topics: SNSTopic[] = [];
    const topicMatches = response.matchAll(/<TopicArn>([^<]+)<\/TopicArn>/g);

    for (const match of topicMatches) {
      topics.push({
        topicArn: match[1],
      });
    }

    return topics;
  }

  async snsListSubscriptions(topicArn?: string): Promise<SNSSubscription[]> {
    const query: Record<string, string> = {
      Action: topicArn ? 'ListSubscriptionsByTopic' : 'ListSubscriptions',
      Version: '2010-03-31',
    };

    if (topicArn) {
      query.TopicArn = topicArn;
    }

    const response = await this.request<string>('sns', 'GET', '/', { query });

    const subscriptions: SNSSubscription[] = [];
    const subMatches = response.matchAll(/<member>([\s\S]*?SubscriptionArn[\s\S]*?)<\/member>/g);

    for (const match of subMatches) {
      const subXml = match[1];
      subscriptions.push({
        subscriptionArn: this.parseXmlValue(subXml, 'SubscriptionArn') || '',
        topicArn: this.parseXmlValue(subXml, 'TopicArn') || '',
        protocol: this.parseXmlValue(subXml, 'Protocol') || '',
        endpoint: this.parseXmlValue(subXml, 'Endpoint') || '',
        owner: this.parseXmlValue(subXml, 'Owner') || '',
      });
    }

    return subscriptions;
  }

  async snsPublish(params: SNSPublishParams): Promise<{ messageId: string }> {
    const query: Record<string, string> = {
      Action: 'Publish',
      Version: '2010-03-31',
      Message: params.message,
    };

    if (params.topicArn) query.TopicArn = params.topicArn;
    if (params.targetArn) query.TargetArn = params.targetArn;
    if (params.subject) query.Subject = params.subject;

    const response = await this.request<string>('sns', 'GET', '/', { query });

    return {
      messageId: this.parseXmlValue(response, 'MessageId') || '',
    };
  }

  async snsGetTopicAttributes(topicArn: string): Promise<SNSTopicAttributes> {
    const response = await this.request<string>('sns', 'GET', '/', {
      query: { Action: 'GetTopicAttributes', Version: '2010-03-31', TopicArn: topicArn },
    });

    const getAttribute = (name: string): string | undefined => {
      const match = response.match(new RegExp(`<key>${name}</key>\\s*<value>([^<]*)</value>`));
      return match ? match[1] : undefined;
    };

    return {
      topicArn,
      displayName: getAttribute('DisplayName'),
      owner: getAttribute('Owner'),
      policy: getAttribute('Policy'),
      subscriptionsConfirmed: getAttribute('SubscriptionsConfirmed')
        ? parseInt(getAttribute('SubscriptionsConfirmed')!, 10)
        : undefined,
      subscriptionsPending: getAttribute('SubscriptionsPending')
        ? parseInt(getAttribute('SubscriptionsPending')!, 10)
        : undefined,
      subscriptionsDeleted: getAttribute('SubscriptionsDeleted')
        ? parseInt(getAttribute('SubscriptionsDeleted')!, 10)
        : undefined,
      effectiveDeliveryPolicy: getAttribute('EffectiveDeliveryPolicy'),
      kmsMasterKeyId: getAttribute('KmsMasterKeyId'),
    };
  }

  async snsSubscribe(topicArn: string, protocol: string, endpoint: string): Promise<{ subscriptionArn: string }> {
    const response = await this.request<string>('sns', 'GET', '/', {
      query: {
        Action: 'Subscribe',
        Version: '2010-03-31',
        TopicArn: topicArn,
        Protocol: protocol,
        Endpoint: endpoint,
      },
    });

    return {
      subscriptionArn: this.parseXmlValue(response, 'SubscriptionArn') || 'pending confirmation',
    };
  }

  async snsCreateTopic(params: SNSCreateTopicParams): Promise<{ topicArn: string }> {
    const query: Record<string, string> = {
      Action: 'CreateTopic',
      Version: '2010-03-31',
      Name: params.name,
    };

    let attrIndex = 1;
    if (params.attributes) {
      if (params.attributes.displayName) {
        query[`Attributes.entry.${attrIndex}.key`] = 'DisplayName';
        query[`Attributes.entry.${attrIndex}.value`] = params.attributes.displayName;
        attrIndex++;
      }
      if (params.attributes.kmsMasterKeyId) {
        query[`Attributes.entry.${attrIndex}.key`] = 'KmsMasterKeyId';
        query[`Attributes.entry.${attrIndex}.value`] = params.attributes.kmsMasterKeyId;
        attrIndex++;
      }
      if (params.attributes.fifoTopic) {
        query[`Attributes.entry.${attrIndex}.key`] = 'FifoTopic';
        query[`Attributes.entry.${attrIndex}.value`] = 'true';
        attrIndex++;
      }
      if (params.attributes.contentBasedDeduplication) {
        query[`Attributes.entry.${attrIndex}.key`] = 'ContentBasedDeduplication';
        query[`Attributes.entry.${attrIndex}.value`] = 'true';
      }
    }

    const response = await this.request<string>('sns', 'GET', '/', { query });
    return {
      topicArn: this.parseXmlValue(response, 'TopicArn') || '',
    };
  }

  async snsDeleteTopic(topicArn: string): Promise<void> {
    await this.request<string>('sns', 'GET', '/', {
      query: {
        Action: 'DeleteTopic',
        Version: '2010-03-31',
        TopicArn: topicArn,
      },
    });
  }

  async snsUnsubscribe(subscriptionArn: string): Promise<void> {
    await this.request<string>('sns', 'GET', '/', {
      query: {
        Action: 'Unsubscribe',
        Version: '2010-03-31',
        SubscriptionArn: subscriptionArn,
      },
    });
  }

  async snsSetTopicAttributes(
    topicArn: string,
    attributeName: string,
    attributeValue: string
  ): Promise<void> {
    await this.request<string>('sns', 'GET', '/', {
      query: {
        Action: 'SetTopicAttributes',
        Version: '2010-03-31',
        TopicArn: topicArn,
        AttributeName: attributeName,
        AttributeValue: attributeValue,
      },
    });
  }

  async snsTagResource(
    resourceArn: string,
    tags: Array<{ key: string; value: string }>
  ): Promise<void> {
    const query: Record<string, string> = {
      Action: 'TagResource',
      Version: '2010-03-31',
      ResourceArn: resourceArn,
    };

    tags.forEach((tag, i) => {
      query[`Tags.member.${i + 1}.Key`] = tag.key;
      query[`Tags.member.${i + 1}.Value`] = tag.value;
    });

    await this.request<string>('sns', 'GET', '/', { query });
  }

  async snsListTagsForResource(resourceArn: string): Promise<Array<{ key: string; value: string }>> {
    const response = await this.request<string>('sns', 'GET', '/', {
      query: {
        Action: 'ListTagsForResource',
        Version: '2010-03-31',
        ResourceArn: resourceArn,
      },
    });

    const tags: Array<{ key: string; value: string }> = [];
    const tagMatches = response.matchAll(/<member>([\s\S]*?)<\/member>/g);

    for (const match of tagMatches) {
      const tagXml = match[1];
      const key = this.parseXmlValue(tagXml, 'Key');
      const value = this.parseXmlValue(tagXml, 'Value');
      if (key) {
        tags.push({ key, value: value || '' });
      }
    }

    return tags;
  }

  async snsConfirmSubscription(topicArn: string, token: string): Promise<{ subscriptionArn: string }> {
    const response = await this.request<string>('sns', 'GET', '/', {
      query: {
        Action: 'ConfirmSubscription',
        Version: '2010-03-31',
        TopicArn: topicArn,
        Token: token,
      },
    });
    return {
      subscriptionArn: this.parseXmlValue(response, 'SubscriptionArn') || '',
    };
  }

  async snsGetSubscriptionAttributes(subscriptionArn: string): Promise<Record<string, string>> {
    const response = await this.request<string>('sns', 'GET', '/', {
      query: {
        Action: 'GetSubscriptionAttributes',
        Version: '2010-03-31',
        SubscriptionArn: subscriptionArn,
      },
    });
    const attributes: Record<string, string> = {};
    const entryMatches = response.matchAll(/<entry>([\s\S]*?)<\/entry>/g);
    for (const match of entryMatches) {
      const entryXml = match[1];
      const key = this.parseXmlValue(entryXml, 'key');
      const value = this.parseXmlValue(entryXml, 'value');
      if (key) {
        attributes[key] = value || '';
      }
    }
    return attributes;
  }

  async snsSetSubscriptionAttributes(subscriptionArn: string, attributeName: string, attributeValue: string): Promise<void> {
    await this.request<string>('sns', 'GET', '/', {
      query: {
        Action: 'SetSubscriptionAttributes',
        Version: '2010-03-31',
        SubscriptionArn: subscriptionArn,
        AttributeName: attributeName,
        AttributeValue: attributeValue,
      },
    });
  }

  async snsUntagResource(resourceArn: string, tagKeys: string[]): Promise<void> {
    const query: Record<string, string> = {
      Action: 'UntagResource',
      Version: '2010-03-31',
      ResourceArn: resourceArn,
    };
    tagKeys.forEach((key, i) => {
      query[`TagKeys.member.${i + 1}`] = key;
    });
    await this.request<string>('sns', 'GET', '/', { query });
  }

  async snsPublishBatch(topicArn: string, entries: Array<{ id: string; message: string; subject?: string }>): Promise<{ successful: Array<{ id: string; messageId: string }>; failed: Array<{ id: string; code: string; message: string }> }> {
    const query: Record<string, string> = {
      Action: 'PublishBatch',
      Version: '2010-03-31',
      TopicArn: topicArn,
    };
    entries.forEach((entry, i) => {
      query[`PublishBatchRequestEntries.member.${i + 1}.Id`] = entry.id;
      query[`PublishBatchRequestEntries.member.${i + 1}.Message`] = entry.message;
      if (entry.subject) {
        query[`PublishBatchRequestEntries.member.${i + 1}.Subject`] = entry.subject;
      }
    });
    const response = await this.request<string>('sns', 'GET', '/', { query });

    const successful: Array<{ id: string; messageId: string }> = [];
    const failed: Array<{ id: string; code: string; message: string }> = [];

    const successMatches = response.matchAll(/<Successful>([\s\S]*?)<\/Successful>/g);
    for (const match of successMatches) {
      const memberMatches = match[1].matchAll(/<member>([\s\S]*?)<\/member>/g);
      for (const memberMatch of memberMatches) {
        const xml = memberMatch[1];
        successful.push({
          id: this.parseXmlValue(xml, 'Id') || '',
          messageId: this.parseXmlValue(xml, 'MessageId') || '',
        });
      }
    }

    const failedMatches = response.matchAll(/<Failed>([\s\S]*?)<\/Failed>/g);
    for (const match of failedMatches) {
      const memberMatches = match[1].matchAll(/<member>([\s\S]*?)<\/member>/g);
      for (const memberMatch of memberMatches) {
        const xml = memberMatch[1];
        failed.push({
          id: this.parseXmlValue(xml, 'Id') || '',
          code: this.parseXmlValue(xml, 'Code') || '',
          message: this.parseXmlValue(xml, 'Message') || '',
        });
      }
    }

    return { successful, failed };
  }

  // ===========================================================================
  // Secrets Manager
  // ===========================================================================

  async secretsListSecrets(): Promise<SecretInfo[]> {
    const response = await this.request<{ SecretList: Array<Record<string, unknown>> }>(
      'secretsmanager',
      'POST',
      '/',
      {
        body: JSON.stringify({}),
        headers: {
          'content-type': 'application/x-amz-json-1.1',
          'x-amz-target': 'secretsmanager.ListSecrets',
        },
      }
    );

    return (response.SecretList || []).map((s) => ({
      arn: s.ARN as string,
      name: s.Name as string,
      description: s.Description as string | undefined,
      lastChangedDate: s.LastChangedDate as string | undefined,
      lastAccessedDate: s.LastAccessedDate as string | undefined,
      lastRotatedDate: s.LastRotatedDate as string | undefined,
      rotationEnabled: s.RotationEnabled as boolean | undefined,
    }));
  }

  async secretsGetSecretValue(secretId: string): Promise<SecretValue> {
    const response = await this.request<Record<string, unknown>>('secretsmanager', 'POST', '/', {
      body: JSON.stringify({ SecretId: secretId }),
      headers: {
        'content-type': 'application/x-amz-json-1.1',
        'x-amz-target': 'secretsmanager.GetSecretValue',
      },
    });

    return {
      arn: response.ARN as string,
      name: response.Name as string,
      versionId: response.VersionId as string | undefined,
      secretString: response.SecretString as string | undefined,
      secretBinary: response.SecretBinary as string | undefined,
      versionStages: response.VersionStages as string[] | undefined,
      createdDate: response.CreatedDate as string | undefined,
    };
  }

  async secretsDescribeSecret(secretId: string): Promise<SecretInfo> {
    const response = await this.request<Record<string, unknown>>('secretsmanager', 'POST', '/', {
      body: JSON.stringify({ SecretId: secretId }),
      headers: {
        'content-type': 'application/x-amz-json-1.1',
        'x-amz-target': 'secretsmanager.DescribeSecret',
      },
    });

    return {
      arn: response.ARN as string,
      name: response.Name as string,
      description: response.Description as string | undefined,
      lastChangedDate: response.LastChangedDate as string | undefined,
      lastAccessedDate: response.LastAccessedDate as string | undefined,
      lastRotatedDate: response.LastRotatedDate as string | undefined,
      rotationEnabled: response.RotationEnabled as boolean | undefined,
    };
  }

  async secretsCreateSecret(params: SecretsCreateSecretParams): Promise<{ arn: string; name: string; versionId?: string }> {
    const body: Record<string, unknown> = {
      Name: params.name,
    };

    if (params.secretString) body.SecretString = params.secretString;
    if (params.description) body.Description = params.description;
    if (params.kmsKeyId) body.KmsKeyId = params.kmsKeyId;
    if (params.tags) {
      body.Tags = params.tags.map((t) => ({ Key: t.key, Value: t.value }));
    }

    const response = await this.request<Record<string, unknown>>('secretsmanager', 'POST', '/', {
      body: JSON.stringify(body),
      headers: {
        'content-type': 'application/x-amz-json-1.1',
        'x-amz-target': 'secretsmanager.CreateSecret',
      },
    });

    return {
      arn: response.ARN as string,
      name: response.Name as string,
      versionId: response.VersionId as string | undefined,
    };
  }

  async secretsUpdateSecret(secretId: string, secretString: string): Promise<{ arn: string; name: string; versionId?: string }> {
    const response = await this.request<Record<string, unknown>>('secretsmanager', 'POST', '/', {
      body: JSON.stringify({
        SecretId: secretId,
        SecretString: secretString,
      }),
      headers: {
        'content-type': 'application/x-amz-json-1.1',
        'x-amz-target': 'secretsmanager.UpdateSecret',
      },
    });

    return {
      arn: response.ARN as string,
      name: response.Name as string,
      versionId: response.VersionId as string | undefined,
    };
  }

  async secretsDeleteSecret(secretId: string, forceDeleteWithoutRecovery?: boolean): Promise<{ arn: string; name: string; deletionDate?: string }> {
    const body: Record<string, unknown> = { SecretId: secretId };
    if (forceDeleteWithoutRecovery) {
      body.ForceDeleteWithoutRecovery = true;
    }

    const response = await this.request<Record<string, unknown>>('secretsmanager', 'POST', '/', {
      body: JSON.stringify(body),
      headers: {
        'content-type': 'application/x-amz-json-1.1',
        'x-amz-target': 'secretsmanager.DeleteSecret',
      },
    });

    return {
      arn: response.ARN as string,
      name: response.Name as string,
      deletionDate: response.DeletionDate as string | undefined,
    };
  }

  async secretsRestoreSecret(secretId: string): Promise<{ arn: string; name: string }> {
    const response = await this.request<Record<string, unknown>>('secretsmanager', 'POST', '/', {
      body: JSON.stringify({ SecretId: secretId }),
      headers: {
        'content-type': 'application/x-amz-json-1.1',
        'x-amz-target': 'secretsmanager.RestoreSecret',
      },
    });

    return {
      arn: response.ARN as string,
      name: response.Name as string,
    };
  }

  async secretsRotateSecret(secretId: string, rotationLambdaARN?: string): Promise<{ arn: string; name: string; versionId?: string }> {
    const body: Record<string, unknown> = { SecretId: secretId };
    if (rotationLambdaARN) {
      body.RotationLambdaARN = rotationLambdaARN;
    }

    const response = await this.request<Record<string, unknown>>('secretsmanager', 'POST', '/', {
      body: JSON.stringify(body),
      headers: {
        'content-type': 'application/x-amz-json-1.1',
        'x-amz-target': 'secretsmanager.RotateSecret',
      },
    });

    return {
      arn: response.ARN as string,
      name: response.Name as string,
      versionId: response.VersionId as string | undefined,
    };
  }

  async secretsPutSecretValue(secretId: string, secretString: string, versionStages?: string[]): Promise<{ arn: string; name: string; versionId: string }> {
    const body: Record<string, unknown> = {
      SecretId: secretId,
      SecretString: secretString,
    };
    if (versionStages) {
      body.VersionStages = versionStages;
    }

    const response = await this.request<Record<string, unknown>>('secretsmanager', 'POST', '/', {
      body: JSON.stringify(body),
      headers: {
        'content-type': 'application/x-amz-json-1.1',
        'x-amz-target': 'secretsmanager.PutSecretValue',
      },
    });

    return {
      arn: response.ARN as string,
      name: response.Name as string,
      versionId: response.VersionId as string,
    };
  }

  async secretsTagResource(secretId: string, tags: Array<{ key: string; value: string }>): Promise<void> {
    await this.request<void>('secretsmanager', 'POST', '/', {
      body: JSON.stringify({
        SecretId: secretId,
        Tags: tags.map((t) => ({ Key: t.key, Value: t.value })),
      }),
      headers: {
        'content-type': 'application/x-amz-json-1.1',
        'x-amz-target': 'secretsmanager.TagResource',
      },
    });
  }

  async secretsUntagResource(secretId: string, tagKeys: string[]): Promise<void> {
    await this.request<void>('secretsmanager', 'POST', '/', {
      body: JSON.stringify({
        SecretId: secretId,
        TagKeys: tagKeys,
      }),
      headers: {
        'content-type': 'application/x-amz-json-1.1',
        'x-amz-target': 'secretsmanager.UntagResource',
      },
    });
  }

  async secretsGetResourcePolicy(secretId: string): Promise<{ arn: string; name: string; resourcePolicy?: string }> {
    const response = await this.request<Record<string, unknown>>('secretsmanager', 'POST', '/', {
      body: JSON.stringify({ SecretId: secretId }),
      headers: {
        'content-type': 'application/x-amz-json-1.1',
        'x-amz-target': 'secretsmanager.GetResourcePolicy',
      },
    });
    return {
      arn: response.ARN as string,
      name: response.Name as string,
      resourcePolicy: response.ResourcePolicy as string | undefined,
    };
  }

  async secretsPutResourcePolicy(secretId: string, resourcePolicy: string): Promise<{ arn: string; name: string }> {
    const response = await this.request<Record<string, unknown>>('secretsmanager', 'POST', '/', {
      body: JSON.stringify({
        SecretId: secretId,
        ResourcePolicy: resourcePolicy,
      }),
      headers: {
        'content-type': 'application/x-amz-json-1.1',
        'x-amz-target': 'secretsmanager.PutResourcePolicy',
      },
    });
    return {
      arn: response.ARN as string,
      name: response.Name as string,
    };
  }

  async secretsDeleteResourcePolicy(secretId: string): Promise<{ arn: string; name: string }> {
    const response = await this.request<Record<string, unknown>>('secretsmanager', 'POST', '/', {
      body: JSON.stringify({ SecretId: secretId }),
      headers: {
        'content-type': 'application/x-amz-json-1.1',
        'x-amz-target': 'secretsmanager.DeleteResourcePolicy',
      },
    });
    return {
      arn: response.ARN as string,
      name: response.Name as string,
    };
  }

  async secretsCancelRotateSecret(secretId: string): Promise<{ arn: string; name: string }> {
    const response = await this.request<Record<string, unknown>>('secretsmanager', 'POST', '/', {
      body: JSON.stringify({ SecretId: secretId }),
      headers: {
        'content-type': 'application/x-amz-json-1.1',
        'x-amz-target': 'secretsmanager.CancelRotateSecret',
      },
    });
    return {
      arn: response.ARN as string,
      name: response.Name as string,
    };
  }

  async secretsListSecretVersionIds(secretId: string): Promise<Array<{ versionId: string; versionStages?: string[]; createdDate?: string }>> {
    const response = await this.request<{ Versions?: Array<{ VersionId?: string; VersionStages?: string[]; CreatedDate?: number }> }>('secretsmanager', 'POST', '/', {
      body: JSON.stringify({ SecretId: secretId }),
      headers: {
        'content-type': 'application/x-amz-json-1.1',
        'x-amz-target': 'secretsmanager.ListSecretVersionIds',
      },
    });
    return (response.Versions || []).map((v) => ({
      versionId: v.VersionId || '',
      versionStages: v.VersionStages,
      createdDate: v.CreatedDate ? new Date(v.CreatedDate * 1000).toISOString() : undefined,
    }));
  }

  async secretsUpdateSecretVersionStage(secretId: string, versionStage: string, moveToVersionId?: string, removeFromVersionId?: string): Promise<{ arn: string; name: string }> {
    const body: Record<string, unknown> = {
      SecretId: secretId,
      VersionStage: versionStage,
    };
    if (moveToVersionId) body.MoveToVersionId = moveToVersionId;
    if (removeFromVersionId) body.RemoveFromVersionId = removeFromVersionId;

    const response = await this.request<Record<string, unknown>>('secretsmanager', 'POST', '/', {
      body: JSON.stringify(body),
      headers: {
        'content-type': 'application/x-amz-json-1.1',
        'x-amz-target': 'secretsmanager.UpdateSecretVersionStage',
      },
    });
    return {
      arn: response.ARN as string,
      name: response.Name as string,
    };
  }

  // ===========================================================================
  // Route53
  // ===========================================================================

  async route53ListHostedZones(): Promise<Route53HostedZone[]> {
    const response = await this.request<string>('route53', 'GET', '/2013-04-01/hostedzone');

    const zones: Route53HostedZone[] = [];
    const zoneMatches = response.matchAll(/<HostedZone>([\s\S]*?)<\/HostedZone>/g);

    for (const match of zoneMatches) {
      const zoneXml = match[1];
      const configMatch = zoneXml.match(/<Config>([\s\S]*?)<\/Config>/);

      zones.push({
        id: this.parseXmlValue(zoneXml, 'Id')?.replace('/hostedzone/', '') || '',
        name: this.parseXmlValue(zoneXml, 'Name') || '',
        resourceRecordSetCount: this.parseXmlValue(zoneXml, 'ResourceRecordSetCount')
          ? Number.parseInt(this.parseXmlValue(zoneXml, 'ResourceRecordSetCount')!, 10)
          : undefined,
        callerReference: this.parseXmlValue(zoneXml, 'CallerReference') || '',
        config: configMatch
          ? {
              privateZone: this.parseXmlValue(configMatch[1], 'PrivateZone') === 'true',
              comment: this.parseXmlValue(configMatch[1], 'Comment'),
            }
          : undefined,
      });
    }

    return zones;
  }

  async route53ListResourceRecordSets(hostedZoneId: string): Promise<Route53RecordSet[]> {
    const response = await this.request<string>(
      'route53',
      'GET',
      `/2013-04-01/hostedzone/${hostedZoneId}/rrset`
    );

    const records: Route53RecordSet[] = [];
    const recordMatches = response.matchAll(/<ResourceRecordSet>([\s\S]*?)<\/ResourceRecordSet>/g);

    for (const match of recordMatches) {
      const recordXml = match[1];

      const resourceRecords: Array<{ value: string }> = [];
      const rrMatches = recordXml.matchAll(/<ResourceRecord>[\s\S]*?<Value>([^<]+)<\/Value>[\s\S]*?<\/ResourceRecord>/g);
      for (const rrMatch of rrMatches) {
        resourceRecords.push({ value: rrMatch[1] });
      }

      const aliasMatch = recordXml.match(/<AliasTarget>([\s\S]*?)<\/AliasTarget>/);

      records.push({
        name: this.parseXmlValue(recordXml, 'Name') || '',
        type: this.parseXmlValue(recordXml, 'Type') || '',
        ttl: this.parseXmlValue(recordXml, 'TTL')
          ? Number.parseInt(this.parseXmlValue(recordXml, 'TTL')!, 10)
          : undefined,
        resourceRecords: resourceRecords.length > 0 ? resourceRecords : undefined,
        aliasTarget: aliasMatch
          ? {
              hostedZoneId: this.parseXmlValue(aliasMatch[1], 'HostedZoneId') || '',
              dnsName: this.parseXmlValue(aliasMatch[1], 'DNSName') || '',
              evaluateTargetHealth: this.parseXmlValue(aliasMatch[1], 'EvaluateTargetHealth') === 'true',
            }
          : undefined,
        setIdentifier: this.parseXmlValue(recordXml, 'SetIdentifier'),
        weight: this.parseXmlValue(recordXml, 'Weight')
          ? Number.parseInt(this.parseXmlValue(recordXml, 'Weight')!, 10)
          : undefined,
        region: this.parseXmlValue(recordXml, 'Region'),
        healthCheckId: this.parseXmlValue(recordXml, 'HealthCheckId'),
      });
    }

    return records;
  }

  async route53ChangeResourceRecordSets(
    hostedZoneId: string,
    changes: Array<{
      action: 'CREATE' | 'DELETE' | 'UPSERT';
      resourceRecordSet: {
        name: string;
        type: string;
        ttl?: number;
        resourceRecords?: Array<{ value: string }>;
      };
    }>
  ): Promise<Route53ChangeInfo> {
    const changesXml = changes
      .map((change) => {
        let recordSetXml = `<Name>${change.resourceRecordSet.name}</Name><Type>${change.resourceRecordSet.type}</Type>`;
        if (change.resourceRecordSet.ttl !== undefined) {
          recordSetXml += `<TTL>${change.resourceRecordSet.ttl}</TTL>`;
        }
        if (change.resourceRecordSet.resourceRecords) {
          recordSetXml += `<ResourceRecords>${change.resourceRecordSet.resourceRecords
            .map((rr) => `<ResourceRecord><Value>${rr.value}</Value></ResourceRecord>`)
            .join('')}</ResourceRecords>`;
        }
        return `<Change><Action>${change.action}</Action><ResourceRecordSet>${recordSetXml}</ResourceRecordSet></Change>`;
      })
      .join('');

    const requestBody = `<?xml version="1.0" encoding="UTF-8"?>
<ChangeResourceRecordSetsRequest xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
  <ChangeBatch>
    <Changes>${changesXml}</Changes>
  </ChangeBatch>
</ChangeResourceRecordSetsRequest>`;

    const response = await this.request<string>(
      'route53',
      'POST',
      `/2013-04-01/hostedzone/${hostedZoneId}/rrset`,
      {
        body: requestBody,
        headers: { 'content-type': 'application/xml' },
      }
    );

    return {
      id: this.parseXmlValue(response, 'Id')?.replace('/change/', '') || '',
      status: this.parseXmlValue(response, 'Status') || '',
      submittedAt: this.parseXmlValue(response, 'SubmittedAt') || '',
    };
  }

  async route53ListHealthChecks(): Promise<Route53HealthCheck[]> {
    const response = await this.request<string>('route53', 'GET', '/2013-04-01/healthcheck');

    const healthChecks: Route53HealthCheck[] = [];
    const hcMatches = response.matchAll(/<HealthCheck>([\s\S]*?)<\/HealthCheck>/g);

    for (const match of hcMatches) {
      const hcXml = match[1];
      const configMatch = hcXml.match(/<HealthCheckConfig>([\s\S]*?)<\/HealthCheckConfig>/);

      healthChecks.push({
        id: this.parseXmlValue(hcXml, 'Id') || '',
        callerReference: this.parseXmlValue(hcXml, 'CallerReference') || '',
        healthCheckVersion: parseInt(this.parseXmlValue(hcXml, 'HealthCheckVersion') || '1', 10),
        healthCheckConfig: configMatch
          ? {
              ipAddress: this.parseXmlValue(configMatch[1], 'IPAddress'),
              port: this.parseXmlValue(configMatch[1], 'Port')
                ? parseInt(this.parseXmlValue(configMatch[1], 'Port')!, 10)
                : undefined,
              type: this.parseXmlValue(configMatch[1], 'Type') || '',
              resourcePath: this.parseXmlValue(configMatch[1], 'ResourcePath'),
              fullyQualifiedDomainName: this.parseXmlValue(configMatch[1], 'FullyQualifiedDomainName'),
              requestInterval: this.parseXmlValue(configMatch[1], 'RequestInterval')
                ? parseInt(this.parseXmlValue(configMatch[1], 'RequestInterval')!, 10)
                : undefined,
              failureThreshold: this.parseXmlValue(configMatch[1], 'FailureThreshold')
                ? parseInt(this.parseXmlValue(configMatch[1], 'FailureThreshold')!, 10)
                : undefined,
            }
          : { type: '' },
      });
    }

    return healthChecks;
  }

  async route53GetHostedZone(hostedZoneId: string): Promise<Route53HostedZone> {
    // Remove /hostedzone/ prefix if present
    const zoneId = hostedZoneId.replace('/hostedzone/', '');
    const response = await this.request<string>('route53', 'GET', `/2013-04-01/hostedzone/${zoneId}`);

    return {
      id: this.parseXmlValue(response, 'Id') || '',
      name: this.parseXmlValue(response, 'Name') || '',
      resourceRecordSetCount: this.parseXmlValue(response, 'ResourceRecordSetCount')
        ? parseInt(this.parseXmlValue(response, 'ResourceRecordSetCount')!, 10)
        : undefined,
      callerReference: this.parseXmlValue(response, 'CallerReference') || '',
      config: {
        privateZone: this.parseXmlValue(response, 'PrivateZone') === 'true',
        comment: this.parseXmlValue(response, 'Comment'),
      },
    };
  }

  async route53CreateHostedZone(
    name: string,
    callerReference: string,
    comment?: string,
    privateZone?: boolean,
    vpcId?: string,
    vpcRegion?: string
  ): Promise<{ hostedZone: Route53HostedZone; changeInfo: Route53ChangeInfo }> {
    let body = `<?xml version="1.0" encoding="UTF-8"?>
<CreateHostedZoneRequest xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
  <Name>${name}</Name>
  <CallerReference>${callerReference}</CallerReference>`;

    if (comment || privateZone !== undefined) {
      body += '<HostedZoneConfig>';
      if (comment) body += `<Comment>${comment}</Comment>`;
      if (privateZone !== undefined) body += `<PrivateZone>${privateZone}</PrivateZone>`;
      body += '</HostedZoneConfig>';
    }

    if (vpcId && vpcRegion) {
      body += `<VPC><VPCId>${vpcId}</VPCId><VPCRegion>${vpcRegion}</VPCRegion></VPC>`;
    }

    body += '</CreateHostedZoneRequest>';

    const response = await this.request<string>('route53', 'POST', '/2013-04-01/hostedzone', {
      body,
      headers: { 'content-type': 'application/xml' },
    });

    // Parse HostedZone section
    const hostedZoneMatch = response.match(/<HostedZone>([\s\S]*?)<\/HostedZone>/);
    const hostedZoneXml = hostedZoneMatch ? hostedZoneMatch[1] : response;

    const hostedZone: Route53HostedZone = {
      id: this.parseXmlValue(hostedZoneXml, 'Id') || '',
      name: this.parseXmlValue(hostedZoneXml, 'Name') || '',
      callerReference: this.parseXmlValue(hostedZoneXml, 'CallerReference') || '',
      config: {
        privateZone: this.parseXmlValue(hostedZoneXml, 'PrivateZone') === 'true',
        comment: this.parseXmlValue(hostedZoneXml, 'Comment'),
      },
    };

    // Parse ChangeInfo section
    const changeInfoMatch = response.match(/<ChangeInfo>([\s\S]*?)<\/ChangeInfo>/);
    const changeInfoXml = changeInfoMatch ? changeInfoMatch[1] : response;

    const changeInfo: Route53ChangeInfo = {
      id: this.parseXmlValue(changeInfoXml, 'Id') || '',
      status: this.parseXmlValue(changeInfoXml, 'Status') || '',
      submittedAt: this.parseXmlValue(changeInfoXml, 'SubmittedAt') || '',
    };

    return { hostedZone, changeInfo };
  }

  async route53DeleteHostedZone(hostedZoneId: string): Promise<Route53ChangeInfo> {
    // Remove /hostedzone/ prefix if present
    const zoneId = hostedZoneId.replace('/hostedzone/', '');
    const response = await this.request<string>('route53', 'DELETE', `/2013-04-01/hostedzone/${zoneId}`);

    return {
      id: this.parseXmlValue(response, 'Id') || '',
      status: this.parseXmlValue(response, 'Status') || '',
      submittedAt: this.parseXmlValue(response, 'SubmittedAt') || '',
    };
  }

  async route53GetHealthCheck(healthCheckId: string): Promise<Route53HealthCheck> {
    const response = await this.request<string>('route53', 'GET', `/2013-04-01/healthcheck/${healthCheckId}`);

    const configMatch = response.match(/<HealthCheckConfig>([\s\S]*?)<\/HealthCheckConfig>/);

    return {
      id: this.parseXmlValue(response, 'Id') || '',
      callerReference: this.parseXmlValue(response, 'CallerReference') || '',
      healthCheckVersion: parseInt(this.parseXmlValue(response, 'HealthCheckVersion') || '1', 10),
      healthCheckConfig: configMatch
        ? {
            ipAddress: this.parseXmlValue(configMatch[1], 'IPAddress'),
            port: this.parseXmlValue(configMatch[1], 'Port')
              ? parseInt(this.parseXmlValue(configMatch[1], 'Port')!, 10)
              : undefined,
            type: this.parseXmlValue(configMatch[1], 'Type') || '',
            resourcePath: this.parseXmlValue(configMatch[1], 'ResourcePath'),
            fullyQualifiedDomainName: this.parseXmlValue(configMatch[1], 'FullyQualifiedDomainName'),
            requestInterval: this.parseXmlValue(configMatch[1], 'RequestInterval')
              ? parseInt(this.parseXmlValue(configMatch[1], 'RequestInterval')!, 10)
              : undefined,
            failureThreshold: this.parseXmlValue(configMatch[1], 'FailureThreshold')
              ? parseInt(this.parseXmlValue(configMatch[1], 'FailureThreshold')!, 10)
              : undefined,
          }
        : { type: '' },
    };
  }

  async route53CreateHealthCheck(
    callerReference: string,
    config: {
      ipAddress?: string;
      port?: number;
      type: string;
      resourcePath?: string;
      fullyQualifiedDomainName?: string;
      requestInterval?: number;
      failureThreshold?: number;
    }
  ): Promise<Route53HealthCheck> {
    let body = `<?xml version="1.0" encoding="UTF-8"?>
<CreateHealthCheckRequest xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
  <CallerReference>${callerReference}</CallerReference>
  <HealthCheckConfig>
    <Type>${config.type}</Type>`;

    if (config.ipAddress) body += `<IPAddress>${config.ipAddress}</IPAddress>`;
    if (config.port !== undefined) body += `<Port>${config.port}</Port>`;
    if (config.resourcePath) body += `<ResourcePath>${config.resourcePath}</ResourcePath>`;
    if (config.fullyQualifiedDomainName) body += `<FullyQualifiedDomainName>${config.fullyQualifiedDomainName}</FullyQualifiedDomainName>`;
    if (config.requestInterval !== undefined) body += `<RequestInterval>${config.requestInterval}</RequestInterval>`;
    if (config.failureThreshold !== undefined) body += `<FailureThreshold>${config.failureThreshold}</FailureThreshold>`;

    body += '</HealthCheckConfig></CreateHealthCheckRequest>';

    const response = await this.request<string>('route53', 'POST', '/2013-04-01/healthcheck', {
      body,
      headers: { 'content-type': 'application/xml' },
    });

    const configMatch = response.match(/<HealthCheckConfig>([\s\S]*?)<\/HealthCheckConfig>/);

    return {
      id: this.parseXmlValue(response, 'Id') || '',
      callerReference: this.parseXmlValue(response, 'CallerReference') || '',
      healthCheckVersion: parseInt(this.parseXmlValue(response, 'HealthCheckVersion') || '1', 10),
      healthCheckConfig: configMatch
        ? {
            ipAddress: this.parseXmlValue(configMatch[1], 'IPAddress'),
            port: this.parseXmlValue(configMatch[1], 'Port')
              ? parseInt(this.parseXmlValue(configMatch[1], 'Port')!, 10)
              : undefined,
            type: this.parseXmlValue(configMatch[1], 'Type') || '',
            resourcePath: this.parseXmlValue(configMatch[1], 'ResourcePath'),
            fullyQualifiedDomainName: this.parseXmlValue(configMatch[1], 'FullyQualifiedDomainName'),
            requestInterval: this.parseXmlValue(configMatch[1], 'RequestInterval')
              ? parseInt(this.parseXmlValue(configMatch[1], 'RequestInterval')!, 10)
              : undefined,
            failureThreshold: this.parseXmlValue(configMatch[1], 'FailureThreshold')
              ? parseInt(this.parseXmlValue(configMatch[1], 'FailureThreshold')!, 10)
              : undefined,
          }
        : { type: '' },
    };
  }

  async route53DeleteHealthCheck(healthCheckId: string): Promise<void> {
    await this.request<string>('route53', 'DELETE', `/2013-04-01/healthcheck/${healthCheckId}`);
  }

  async route53GetChange(changeId: string): Promise<Route53ChangeInfo> {
    // Remove /change/ prefix if present
    const id = changeId.replace('/change/', '');
    const response = await this.request<string>('route53', 'GET', `/2013-04-01/change/${id}`);

    return {
      id: this.parseXmlValue(response, 'Id') || '',
      status: this.parseXmlValue(response, 'Status') || '',
      submittedAt: this.parseXmlValue(response, 'SubmittedAt') || '',
    };
  }

  // ===========================================================================
  // CloudFront
  // ===========================================================================

  async cloudfrontListDistributions(): Promise<CloudFrontDistribution[]> {
    const response = await this.request<string>('cloudfront', 'GET', '/2020-05-31/distribution');

    const distributions: CloudFrontDistribution[] = [];
    const distMatches = response.matchAll(/<DistributionSummary>([\s\S]*?)<\/DistributionSummary>/g);

    for (const match of distMatches) {
      const distXml = match[1];

      const origins: CloudFrontDistribution['origins'] = [];
      const originMatches = distXml.matchAll(/<Origin>([\s\S]*?)<\/Origin>/g);
      for (const originMatch of originMatches) {
        const originXml = originMatch[1];
        origins.push({
          id: this.parseXmlValue(originXml, 'Id') || '',
          domainName: this.parseXmlValue(originXml, 'DomainName') || '',
          originPath: this.parseXmlValue(originXml, 'OriginPath'),
        });
      }

      const aliases: string[] = [];
      const aliasMatches = distXml.matchAll(/<Aliases>[\s\S]*?<Items>[\s\S]*?<CNAME>([^<]+)<\/CNAME>[\s\S]*?<\/Items>[\s\S]*?<\/Aliases>/g);
      for (const aliasMatch of aliasMatches) {
        aliases.push(aliasMatch[1]);
      }

      distributions.push({
        id: this.parseXmlValue(distXml, 'Id') || '',
        arn: this.parseXmlValue(distXml, 'ARN') || '',
        status: this.parseXmlValue(distXml, 'Status') || '',
        domainName: this.parseXmlValue(distXml, 'DomainName') || '',
        enabled: this.parseXmlValue(distXml, 'Enabled') === 'true',
        lastModifiedTime: this.parseXmlValue(distXml, 'LastModifiedTime') || '',
        origins,
        defaultCacheBehavior: {
          targetOriginId: '',
          viewerProtocolPolicy: '',
          allowedMethods: [],
          cachedMethods: [],
        },
        aliases: aliases.length > 0 ? aliases : undefined,
        priceClass: this.parseXmlValue(distXml, 'PriceClass') || '',
        comment: this.parseXmlValue(distXml, 'Comment'),
      });
    }

    return distributions;
  }

  async cloudfrontGetDistribution(id: string): Promise<CloudFrontDistribution> {
    const response = await this.request<string>('cloudfront', 'GET', `/2020-05-31/distribution/${id}`);

    const origins: CloudFrontDistribution['origins'] = [];
    const originMatches = response.matchAll(/<Origin>([\s\S]*?)<\/Origin>/g);
    for (const originMatch of originMatches) {
      const originXml = originMatch[1];
      origins.push({
        id: this.parseXmlValue(originXml, 'Id') || '',
        domainName: this.parseXmlValue(originXml, 'DomainName') || '',
        originPath: this.parseXmlValue(originXml, 'OriginPath'),
      });
    }

    return {
      id: this.parseXmlValue(response, 'Id') || '',
      arn: this.parseXmlValue(response, 'ARN') || '',
      status: this.parseXmlValue(response, 'Status') || '',
      domainName: this.parseXmlValue(response, 'DomainName') || '',
      enabled: this.parseXmlValue(response, 'Enabled') === 'true',
      lastModifiedTime: this.parseXmlValue(response, 'LastModifiedTime') || '',
      origins,
      defaultCacheBehavior: {
        targetOriginId: '',
        viewerProtocolPolicy: '',
        allowedMethods: [],
        cachedMethods: [],
      },
      priceClass: this.parseXmlValue(response, 'PriceClass') || '',
      comment: this.parseXmlValue(response, 'Comment'),
    };
  }

  async cloudfrontCreateInvalidation(
    distributionId: string,
    paths: string[],
    callerReference?: string
  ): Promise<CloudFrontInvalidation> {
    const ref = callerReference || `inv-${Date.now()}`;
    const body = `<?xml version="1.0" encoding="UTF-8"?>
<InvalidationBatch xmlns="http://cloudfront.amazonaws.com/doc/2020-05-31/">
  <Paths>
    <Quantity>${paths.length}</Quantity>
    <Items>
      ${paths.map((p) => `<Path>${p}</Path>`).join('\n      ')}
    </Items>
  </Paths>
  <CallerReference>${ref}</CallerReference>
</InvalidationBatch>`;

    const response = await this.request<string>(
      'cloudfront',
      'POST',
      `/2020-05-31/distribution/${distributionId}/invalidation`,
      {
        body,
        headers: { 'content-type': 'application/xml' },
      }
    );

    const pathsMatch = response.match(/<Items>([\s\S]*?)<\/Items>/);
    const parsedPaths: string[] = [];
    if (pathsMatch) {
      const pathMatches = pathsMatch[1].matchAll(/<Path>(.*?)<\/Path>/g);
      for (const match of pathMatches) {
        parsedPaths.push(match[1]);
      }
    }

    return {
      id: this.parseXmlValue(response, 'Id') || '',
      status: this.parseXmlValue(response, 'Status') || '',
      createTime: this.parseXmlValue(response, 'CreateTime') || '',
      paths: parsedPaths,
    };
  }

  async cloudfrontListInvalidations(distributionId: string): Promise<CloudFrontInvalidationSummary[]> {
    const response = await this.request<string>(
      'cloudfront',
      'GET',
      `/2020-05-31/distribution/${distributionId}/invalidation`
    );

    const invalidations: CloudFrontInvalidationSummary[] = [];
    const matches = response.matchAll(/<InvalidationSummary>([\s\S]*?)<\/InvalidationSummary>/g);

    for (const match of matches) {
      const invXml = match[1];
      invalidations.push({
        id: this.parseXmlValue(invXml, 'Id') || '',
        status: this.parseXmlValue(invXml, 'Status') || '',
        createTime: this.parseXmlValue(invXml, 'CreateTime') || '',
      });
    }

    return invalidations;
  }

  async cloudfrontGetInvalidation(
    distributionId: string,
    invalidationId: string
  ): Promise<CloudFrontInvalidation> {
    const response = await this.request<string>(
      'cloudfront',
      'GET',
      `/2020-05-31/distribution/${distributionId}/invalidation/${invalidationId}`
    );

    const pathsMatch = response.match(/<Items>([\s\S]*?)<\/Items>/);
    const paths: string[] = [];
    if (pathsMatch) {
      const pathMatches = pathsMatch[1].matchAll(/<Path>(.*?)<\/Path>/g);
      for (const match of pathMatches) {
        paths.push(match[1]);
      }
    }

    return {
      id: this.parseXmlValue(response, 'Id') || '',
      status: this.parseXmlValue(response, 'Status') || '',
      createTime: this.parseXmlValue(response, 'CreateTime') || '',
      paths,
    };
  }

  async cloudfrontListTagsForResource(resourceArn: string): Promise<Array<{ key: string; value: string }>> {
    const response = await this.request<string>(
      'cloudfront',
      'GET',
      `/2020-05-31/tagging?Resource=${encodeURIComponent(resourceArn)}`
    );
    const tags: Array<{ key: string; value: string }> = [];
    const itemMatches = response.matchAll(/<Item>([\s\S]*?)<\/Item>/g);
    for (const match of itemMatches) {
      const xml = match[1];
      const key = this.parseXmlValue(xml, 'Key');
      const value = this.parseXmlValue(xml, 'Value');
      if (key) {
        tags.push({ key, value: value || '' });
      }
    }
    return tags;
  }

  async cloudfrontTagResource(resourceArn: string, tags: Array<{ key: string; value: string }>): Promise<void> {
    const tagsXml = tags.map((t) => `<Item><Key>${t.key}</Key><Value>${t.value}</Value></Item>`).join('');
    const body = `<?xml version="1.0" encoding="UTF-8"?><Tags xmlns="http://cloudfront.amazonaws.com/doc/2020-05-31/"><Items>${tagsXml}</Items></Tags>`;
    await this.request<string>(
      'cloudfront',
      'POST',
      `/2020-05-31/tagging?Operation=Tag&Resource=${encodeURIComponent(resourceArn)}`,
      { body, headers: { 'content-type': 'application/xml' } }
    );
  }

  async cloudfrontUntagResource(resourceArn: string, tagKeys: string[]): Promise<void> {
    const keysXml = tagKeys.map((k) => `<Key>${k}</Key>`).join('');
    const body = `<?xml version="1.0" encoding="UTF-8"?><TagKeys xmlns="http://cloudfront.amazonaws.com/doc/2020-05-31/"><Items>${keysXml}</Items></TagKeys>`;
    await this.request<string>(
      'cloudfront',
      'POST',
      `/2020-05-31/tagging?Operation=Untag&Resource=${encodeURIComponent(resourceArn)}`,
      { body, headers: { 'content-type': 'application/xml' } }
    );
  }

  // ===========================================================================
  // ECS
  // ===========================================================================

  async ecsListClusters(): Promise<string[]> {
    const response = await this.request<{ clusterArns: string[] }>('ecs', 'POST', '/', {
      body: JSON.stringify({}),
      headers: {
        'content-type': 'application/x-amz-json-1.1',
        'x-amz-target': 'AmazonEC2ContainerServiceV20141113.ListClusters',
      },
    });

    return response.clusterArns || [];
  }

  async ecsDescribeClusters(clusterArns: string[]): Promise<ECSCluster[]> {
    const response = await this.request<{ clusters: Array<Record<string, unknown>> }>(
      'ecs',
      'POST',
      '/',
      {
        body: JSON.stringify({ clusters: clusterArns }),
        headers: {
          'content-type': 'application/x-amz-json-1.1',
          'x-amz-target': 'AmazonEC2ContainerServiceV20141113.DescribeClusters',
        },
      }
    );

    return (response.clusters || []).map((c) => ({
      clusterArn: c.clusterArn as string,
      clusterName: c.clusterName as string,
      status: c.status as string,
      registeredContainerInstancesCount: c.registeredContainerInstancesCount as number,
      runningTasksCount: c.runningTasksCount as number,
      pendingTasksCount: c.pendingTasksCount as number,
      activeServicesCount: c.activeServicesCount as number,
      capacityProviders: c.capacityProviders as string[] | undefined,
    }));
  }

  async ecsListServices(clusterArn: string): Promise<string[]> {
    const response = await this.request<{ serviceArns: string[] }>('ecs', 'POST', '/', {
      body: JSON.stringify({ cluster: clusterArn }),
      headers: {
        'content-type': 'application/x-amz-json-1.1',
        'x-amz-target': 'AmazonEC2ContainerServiceV20141113.ListServices',
      },
    });

    return response.serviceArns || [];
  }

  async ecsDescribeServices(clusterArn: string, serviceArns: string[]): Promise<ECSService[]> {
    const response = await this.request<{ services: Array<Record<string, unknown>> }>(
      'ecs',
      'POST',
      '/',
      {
        body: JSON.stringify({ cluster: clusterArn, services: serviceArns }),
        headers: {
          'content-type': 'application/x-amz-json-1.1',
          'x-amz-target': 'AmazonEC2ContainerServiceV20141113.DescribeServices',
        },
      }
    );

    return (response.services || []).map((s) => ({
      serviceArn: s.serviceArn as string,
      serviceName: s.serviceName as string,
      clusterArn: s.clusterArn as string,
      status: s.status as string,
      desiredCount: s.desiredCount as number,
      runningCount: s.runningCount as number,
      pendingCount: s.pendingCount as number,
      launchType: s.launchType as string | undefined,
      taskDefinition: s.taskDefinition as string,
    }));
  }

  async ecsListTasks(clusterArn: string, serviceName?: string): Promise<string[]> {
    const body: Record<string, unknown> = { cluster: clusterArn };
    if (serviceName) body.serviceName = serviceName;

    const response = await this.request<{ taskArns: string[] }>('ecs', 'POST', '/', {
      body: JSON.stringify(body),
      headers: {
        'content-type': 'application/x-amz-json-1.1',
        'x-amz-target': 'AmazonEC2ContainerServiceV20141113.ListTasks',
      },
    });

    return response.taskArns || [];
  }

  async ecsDescribeTasks(clusterArn: string, taskArns: string[]): Promise<ECSTask[]> {
    const response = await this.request<{ tasks: Array<Record<string, unknown>> }>(
      'ecs',
      'POST',
      '/',
      {
        body: JSON.stringify({ cluster: clusterArn, tasks: taskArns }),
        headers: {
          'content-type': 'application/x-amz-json-1.1',
          'x-amz-target': 'AmazonEC2ContainerServiceV20141113.DescribeTasks',
        },
      }
    );

    return (response.tasks || []).map((t) => ({
      taskArn: t.taskArn as string,
      taskDefinitionArn: t.taskDefinitionArn as string,
      clusterArn: t.clusterArn as string,
      lastStatus: t.lastStatus as string,
      desiredStatus: t.desiredStatus as string,
      cpu: t.cpu as string | undefined,
      memory: t.memory as string | undefined,
      launchType: t.launchType as string | undefined,
      startedAt: t.startedAt as string | undefined,
      stoppedAt: t.stoppedAt as string | undefined,
      stoppedReason: t.stoppedReason as string | undefined,
      containers: ((t.containers || []) as Array<Record<string, unknown>>).map((c) => ({
        containerArn: c.containerArn as string,
        name: c.name as string,
        lastStatus: c.lastStatus as string,
        exitCode: c.exitCode as number | undefined,
        networkInterfaces: c.networkInterfaces as Array<{
          attachmentId: string;
          privateIpv4Address: string;
        }> | undefined,
      })),
    }));
  }

  async ecsDescribeTaskDefinition(taskDefinition: string): Promise<ECSTaskDefinition> {
    const response = await this.request<{ taskDefinition: Record<string, unknown> }>(
      'ecs',
      'POST',
      '/',
      {
        body: JSON.stringify({ taskDefinition }),
        headers: {
          'content-type': 'application/x-amz-json-1.1',
          'x-amz-target': 'AmazonEC2ContainerServiceV20141113.DescribeTaskDefinition',
        },
      }
    );

    const td = response.taskDefinition;
    return {
      taskDefinitionArn: td.taskDefinitionArn as string,
      family: td.family as string,
      revision: td.revision as number,
      status: td.status as string,
      networkMode: td.networkMode as string | undefined,
      requiresCompatibilities: td.requiresCompatibilities as string[] | undefined,
      cpu: td.cpu as string | undefined,
      memory: td.memory as string | undefined,
      containerDefinitions: ((td.containerDefinitions || []) as Array<Record<string, unknown>>).map(
        (c) => ({
          name: c.name as string,
          image: c.image as string,
          cpu: c.cpu as number | undefined,
          memory: c.memory as number | undefined,
          essential: c.essential as boolean | undefined,
          portMappings: c.portMappings as Array<{
            containerPort: number;
            hostPort?: number;
            protocol?: string;
          }> | undefined,
          environment: c.environment as Array<{ name: string; value: string }> | undefined,
        })
      ),
    };
  }

  async ecsListTaskDefinitions(familyPrefix?: string): Promise<string[]> {
    const body: Record<string, unknown> = {};
    if (familyPrefix) {
      body.familyPrefix = familyPrefix;
    }

    const response = await this.request<{ taskDefinitionArns: string[] }>(
      'ecs',
      'POST',
      '/',
      {
        body: JSON.stringify(body),
        headers: {
          'content-type': 'application/x-amz-json-1.1',
          'x-amz-target': 'AmazonEC2ContainerServiceV20141113.ListTaskDefinitions',
        },
      }
    );

    return response.taskDefinitionArns || [];
  }

  async ecsUpdateService(
    clusterArn: string,
    serviceName: string,
    params: { desiredCount?: number; taskDefinition?: string; forceNewDeployment?: boolean }
  ): Promise<ECSService> {
    const body: Record<string, unknown> = {
      cluster: clusterArn,
      service: serviceName,
    };

    if (params.desiredCount !== undefined) body.desiredCount = params.desiredCount;
    if (params.taskDefinition) body.taskDefinition = params.taskDefinition;
    if (params.forceNewDeployment) body.forceNewDeployment = params.forceNewDeployment;

    const response = await this.request<{ service: Record<string, unknown> }>(
      'ecs',
      'POST',
      '/',
      {
        body: JSON.stringify(body),
        headers: {
          'content-type': 'application/x-amz-json-1.1',
          'x-amz-target': 'AmazonEC2ContainerServiceV20141113.UpdateService',
        },
      }
    );

    const s = response.service;
    return {
      serviceArn: s.serviceArn as string,
      serviceName: s.serviceName as string,
      clusterArn: s.clusterArn as string,
      status: s.status as string,
      desiredCount: s.desiredCount as number,
      runningCount: s.runningCount as number,
      pendingCount: s.pendingCount as number,
      launchType: s.launchType as string | undefined,
      taskDefinition: s.taskDefinition as string,
      deploymentConfiguration: s.deploymentConfiguration as { maximumPercent: number; minimumHealthyPercent: number } | undefined,
      loadBalancers: s.loadBalancers as Array<{
        targetGroupArn: string;
        containerName: string;
        containerPort: number;
      }> | undefined,
    };
  }

  async ecsRunTask(
    clusterArn: string,
    taskDefinition: string,
    params?: { count?: number; launchType?: string; networkConfiguration?: ECSNetworkConfiguration }
  ): Promise<ECSTask[]> {
    const body: Record<string, unknown> = {
      cluster: clusterArn,
      taskDefinition,
      count: params?.count || 1,
    };

    if (params?.launchType) body.launchType = params.launchType;
    if (params?.networkConfiguration) body.networkConfiguration = params.networkConfiguration;

    const response = await this.request<{ tasks: Array<Record<string, unknown>> }>(
      'ecs',
      'POST',
      '/',
      {
        body: JSON.stringify(body),
        headers: {
          'content-type': 'application/x-amz-json-1.1',
          'x-amz-target': 'AmazonEC2ContainerServiceV20141113.RunTask',
        },
      }
    );

    return (response.tasks || []).map((t) => ({
      taskArn: t.taskArn as string,
      taskDefinitionArn: t.taskDefinitionArn as string,
      clusterArn: t.clusterArn as string,
      lastStatus: t.lastStatus as string,
      desiredStatus: t.desiredStatus as string,
      cpu: t.cpu as string | undefined,
      memory: t.memory as string | undefined,
      launchType: t.launchType as string | undefined,
      startedAt: t.startedAt as string | undefined,
      containers: ((t.containers as Array<Record<string, unknown>>) || []).map((c) => ({
        containerArn: c.containerArn as string,
        name: c.name as string,
        lastStatus: c.lastStatus as string,
        exitCode: c.exitCode as number | undefined,
        networkInterfaces: c.networkInterfaces as Array<{ attachmentId: string; privateIpv4Address: string }> | undefined,
      })),
    }));
  }

  async ecsStopTask(clusterArn: string, taskArn: string, reason?: string): Promise<ECSTask> {
    const body: Record<string, unknown> = {
      cluster: clusterArn,
      task: taskArn,
    };

    if (reason) body.reason = reason;

    const response = await this.request<{ task: Record<string, unknown> }>(
      'ecs',
      'POST',
      '/',
      {
        body: JSON.stringify(body),
        headers: {
          'content-type': 'application/x-amz-json-1.1',
          'x-amz-target': 'AmazonEC2ContainerServiceV20141113.StopTask',
        },
      }
    );

    const t = response.task;
    return {
      taskArn: t.taskArn as string,
      taskDefinitionArn: t.taskDefinitionArn as string,
      clusterArn: t.clusterArn as string,
      lastStatus: t.lastStatus as string,
      desiredStatus: t.desiredStatus as string,
      cpu: t.cpu as string | undefined,
      memory: t.memory as string | undefined,
      launchType: t.launchType as string | undefined,
      stoppedAt: t.stoppedAt as string | undefined,
      stoppedReason: t.stoppedReason as string | undefined,
      containers: ((t.containers as Array<Record<string, unknown>>) || []).map((c) => ({
        containerArn: c.containerArn as string,
        name: c.name as string,
        lastStatus: c.lastStatus as string,
        exitCode: c.exitCode as number | undefined,
        networkInterfaces: c.networkInterfaces as Array<{ attachmentId: string; privateIpv4Address: string }> | undefined,
      })),
    };
  }

  async ecsDeleteService(clusterArn: string, serviceName: string, force?: boolean): Promise<ECSService> {
    const body: Record<string, unknown> = {
      cluster: clusterArn,
      service: serviceName,
    };
    if (force !== undefined) body.force = force;

    const response = await this.request<{ service: Record<string, unknown> }>('ecs', 'POST', '/', {
      body: JSON.stringify(body),
      headers: {
        'content-type': 'application/x-amz-json-1.1',
        'x-amz-target': 'AmazonEC2ContainerServiceV20141113.DeleteService',
      },
    });

    const s = response.service;
    return {
      serviceArn: s.serviceArn as string,
      serviceName: s.serviceName as string,
      clusterArn: s.clusterArn as string,
      status: s.status as string,
      desiredCount: s.desiredCount as number,
      runningCount: s.runningCount as number,
      pendingCount: s.pendingCount as number,
      taskDefinition: s.taskDefinition as string,
      launchType: s.launchType as string | undefined,
    };
  }

  async ecsDeregisterTaskDefinition(taskDefinition: string): Promise<ECSTaskDefinition> {
    const response = await this.request<{ taskDefinition: Record<string, unknown> }>('ecs', 'POST', '/', {
      body: JSON.stringify({ taskDefinition }),
      headers: {
        'content-type': 'application/x-amz-json-1.1',
        'x-amz-target': 'AmazonEC2ContainerServiceV20141113.DeregisterTaskDefinition',
      },
    });

    const td = response.taskDefinition;
    return {
      taskDefinitionArn: td.taskDefinitionArn as string,
      family: td.family as string,
      revision: td.revision as number,
      status: td.status as string,
      cpu: td.cpu as string | undefined,
      memory: td.memory as string | undefined,
      requiresCompatibilities: td.requiresCompatibilities as string[] | undefined,
      networkMode: td.networkMode as string | undefined,
      containerDefinitions: ((td.containerDefinitions as Array<Record<string, unknown>>) || []).map((c) => ({
        name: c.name as string,
        image: c.image as string,
        cpu: c.cpu as number | undefined,
        memory: c.memory as number | undefined,
        essential: c.essential as boolean | undefined,
        portMappings: c.portMappings as Array<{ containerPort: number; hostPort?: number; protocol?: string }> | undefined,
        environment: c.environment as Array<{ name: string; value: string }> | undefined,
      })),
    };
  }

  async ecsListContainerInstances(clusterArn: string): Promise<string[]> {
    const response = await this.request<{ containerInstanceArns?: string[] }>('ecs', 'POST', '/', {
      body: JSON.stringify({ cluster: clusterArn }),
      headers: {
        'content-type': 'application/x-amz-json-1.1',
        'x-amz-target': 'AmazonEC2ContainerServiceV20141113.ListContainerInstances',
      },
    });
    return response.containerInstanceArns || [];
  }

  async ecsDescribeContainerInstances(clusterArn: string, containerInstanceArns: string[]): Promise<Array<{ containerInstanceArn: string; ec2InstanceId?: string; status: string; runningTasksCount: number; pendingTasksCount: number; agentConnected: boolean; registeredAt?: string }>> {
    const response = await this.request<{ containerInstances?: Array<Record<string, unknown>> }>('ecs', 'POST', '/', {
      body: JSON.stringify({ cluster: clusterArn, containerInstances: containerInstanceArns }),
      headers: {
        'content-type': 'application/x-amz-json-1.1',
        'x-amz-target': 'AmazonEC2ContainerServiceV20141113.DescribeContainerInstances',
      },
    });
    return (response.containerInstances || []).map((ci) => ({
      containerInstanceArn: ci.containerInstanceArn as string,
      ec2InstanceId: ci.ec2InstanceId as string | undefined,
      status: ci.status as string,
      runningTasksCount: ci.runningTasksCount as number,
      pendingTasksCount: ci.pendingTasksCount as number,
      agentConnected: ci.agentConnected as boolean,
      registeredAt: ci.registeredAt as string | undefined,
    }));
  }

  async ecsCreateCluster(clusterName: string): Promise<ECSCluster> {
    const response = await this.request<{ cluster: Record<string, unknown> }>('ecs', 'POST', '/', {
      body: JSON.stringify({ clusterName }),
      headers: {
        'content-type': 'application/x-amz-json-1.1',
        'x-amz-target': 'AmazonEC2ContainerServiceV20141113.CreateCluster',
      },
    });
    const c = response.cluster;
    return {
      clusterArn: c.clusterArn as string,
      clusterName: c.clusterName as string,
      status: c.status as string,
      registeredContainerInstancesCount: (c.registeredContainerInstancesCount as number) || 0,
      runningTasksCount: (c.runningTasksCount as number) || 0,
      pendingTasksCount: (c.pendingTasksCount as number) || 0,
      activeServicesCount: (c.activeServicesCount as number) || 0,
    };
  }

  async ecsDeleteCluster(clusterArn: string): Promise<ECSCluster> {
    const response = await this.request<{ cluster: Record<string, unknown> }>('ecs', 'POST', '/', {
      body: JSON.stringify({ cluster: clusterArn }),
      headers: {
        'content-type': 'application/x-amz-json-1.1',
        'x-amz-target': 'AmazonEC2ContainerServiceV20141113.DeleteCluster',
      },
    });
    const c = response.cluster;
    return {
      clusterArn: c.clusterArn as string,
      clusterName: c.clusterName as string,
      status: c.status as string,
      registeredContainerInstancesCount: (c.registeredContainerInstancesCount as number) || 0,
      runningTasksCount: (c.runningTasksCount as number) || 0,
      pendingTasksCount: (c.pendingTasksCount as number) || 0,
      activeServicesCount: (c.activeServicesCount as number) || 0,
    };
  }

  async ecsCreateService(clusterArn: string, serviceName: string, taskDefinition: string, desiredCount: number, launchType?: string, networkConfiguration?: ECSNetworkConfiguration): Promise<ECSService> {
    const body: Record<string, unknown> = {
      cluster: clusterArn,
      serviceName,
      taskDefinition,
      desiredCount,
    };
    if (launchType) body.launchType = launchType;
    if (networkConfiguration) body.networkConfiguration = networkConfiguration;

    const response = await this.request<{ service: Record<string, unknown> }>('ecs', 'POST', '/', {
      body: JSON.stringify(body),
      headers: {
        'content-type': 'application/x-amz-json-1.1',
        'x-amz-target': 'AmazonEC2ContainerServiceV20141113.CreateService',
      },
    });
    const s = response.service;
    return {
      serviceArn: s.serviceArn as string,
      serviceName: s.serviceName as string,
      clusterArn: s.clusterArn as string,
      taskDefinition: s.taskDefinition as string,
      desiredCount: s.desiredCount as number,
      runningCount: (s.runningCount as number) || 0,
      pendingCount: (s.pendingCount as number) || 0,
      status: s.status as string,
      launchType: s.launchType as string | undefined,
    };
  }

  async ecsTagResource(resourceArn: string, tags: Array<{ key: string; value: string }>): Promise<void> {
    await this.request<Record<string, unknown>>('ecs', 'POST', '/', {
      body: JSON.stringify({ resourceArn, tags }),
      headers: {
        'content-type': 'application/x-amz-json-1.1',
        'x-amz-target': 'AmazonEC2ContainerServiceV20141113.TagResource',
      },
    });
  }

  async ecsUntagResource(resourceArn: string, tagKeys: string[]): Promise<void> {
    await this.request<Record<string, unknown>>('ecs', 'POST', '/', {
      body: JSON.stringify({ resourceArn, tagKeys }),
      headers: {
        'content-type': 'application/x-amz-json-1.1',
        'x-amz-target': 'AmazonEC2ContainerServiceV20141113.UntagResource',
      },
    });
  }

  async ecsListTagsForResource(resourceArn: string): Promise<Array<{ key: string; value: string }>> {
    const response = await this.request<{ tags?: Array<{ key: string; value: string }> }>('ecs', 'POST', '/', {
      body: JSON.stringify({ resourceArn }),
      headers: {
        'content-type': 'application/x-amz-json-1.1',
        'x-amz-target': 'AmazonEC2ContainerServiceV20141113.ListTagsForResource',
      },
    });
    return response.tags || [];
  }

  async ecsListTaskDefinitionFamilies(familyPrefix?: string): Promise<string[]> {
    const body: Record<string, unknown> = {};
    if (familyPrefix) body.familyPrefix = familyPrefix;

    const response = await this.request<{ families?: string[] }>('ecs', 'POST', '/', {
      body: JSON.stringify(body),
      headers: {
        'content-type': 'application/x-amz-json-1.1',
        'x-amz-target': 'AmazonEC2ContainerServiceV20141113.ListTaskDefinitionFamilies',
      },
    });
    return response.families || [];
  }

  async ecsUpdateContainerInstancesState(clusterArn: string, containerInstanceArns: string[], status: 'ACTIVE' | 'DRAINING'): Promise<Array<{ containerInstanceArn: string; status: string }>> {
    const response = await this.request<{ containerInstances?: Array<Record<string, unknown>> }>('ecs', 'POST', '/', {
      body: JSON.stringify({ cluster: clusterArn, containerInstances: containerInstanceArns, status }),
      headers: {
        'content-type': 'application/x-amz-json-1.1',
        'x-amz-target': 'AmazonEC2ContainerServiceV20141113.UpdateContainerInstancesState',
      },
    });
    return (response.containerInstances || []).map((ci) => ({
      containerInstanceArn: ci.containerInstanceArn as string,
      status: ci.status as string,
    }));
  }

  // ===========================================================================
  // RDS
  // ===========================================================================

  async rdsDescribeDBInstances(dbInstanceIdentifier?: string): Promise<RDSInstance[]> {
    const query: Record<string, string> = {
      Action: 'DescribeDBInstances',
      Version: '2014-10-31',
    };

    if (dbInstanceIdentifier) {
      query.DBInstanceIdentifier = dbInstanceIdentifier;
    }

    const response = await this.request<string>('rds', 'GET', '/', { query });

    const instances: RDSInstance[] = [];
    const instanceMatches = response.matchAll(/<DBInstance>([\s\S]*?)<\/DBInstance>/g);

    for (const match of instanceMatches) {
      const instanceXml = match[1];

      const vpcSecurityGroups: Array<{ vpcSecurityGroupId: string; status: string }> = [];
      const sgMatches = instanceXml.matchAll(/<VpcSecurityGroupMembership>([\s\S]*?)<\/VpcSecurityGroupMembership>/g);
      for (const sgMatch of sgMatches) {
        vpcSecurityGroups.push({
          vpcSecurityGroupId: this.parseXmlValue(sgMatch[1], 'VpcSecurityGroupId') || '',
          status: this.parseXmlValue(sgMatch[1], 'Status') || '',
        });
      }

      const endpointMatch = instanceXml.match(/<Endpoint>([\s\S]*?)<\/Endpoint>/);
      const subnetGroupMatch = instanceXml.match(/<DBSubnetGroup>([\s\S]*?)<\/DBSubnetGroup>/);

      const tags: Array<{ key: string; value: string }> = [];
      const tagMatches = instanceXml.matchAll(/<Tag>([\s\S]*?)<\/Tag>/g);
      for (const tagMatch of tagMatches) {
        tags.push({
          key: this.parseXmlValue(tagMatch[1], 'Key') || '',
          value: this.parseXmlValue(tagMatch[1], 'Value') || '',
        });
      }

      instances.push({
        dbInstanceIdentifier: this.parseXmlValue(instanceXml, 'DBInstanceIdentifier') || '',
        dbInstanceArn: this.parseXmlValue(instanceXml, 'DBInstanceArn') || '',
        dbInstanceClass: this.parseXmlValue(instanceXml, 'DBInstanceClass') || '',
        engine: this.parseXmlValue(instanceXml, 'Engine') || '',
        engineVersion: this.parseXmlValue(instanceXml, 'EngineVersion') || '',
        dbInstanceStatus: this.parseXmlValue(instanceXml, 'DBInstanceStatus') || '',
        masterUsername: this.parseXmlValue(instanceXml, 'MasterUsername') || '',
        endpoint: endpointMatch
          ? {
              address: this.parseXmlValue(endpointMatch[1], 'Address') || '',
              port: Number.parseInt(this.parseXmlValue(endpointMatch[1], 'Port') || '0', 10),
              hostedZoneId: this.parseXmlValue(endpointMatch[1], 'HostedZoneId') || '',
            }
          : undefined,
        allocatedStorage: Number.parseInt(this.parseXmlValue(instanceXml, 'AllocatedStorage') || '0', 10),
        storageType: this.parseXmlValue(instanceXml, 'StorageType') || '',
        multiAZ: this.parseXmlValue(instanceXml, 'MultiAZ') === 'true',
        availabilityZone: this.parseXmlValue(instanceXml, 'AvailabilityZone'),
        vpcSecurityGroups,
        dbSubnetGroup: subnetGroupMatch
          ? {
              dbSubnetGroupName: this.parseXmlValue(subnetGroupMatch[1], 'DBSubnetGroupName') || '',
              dbSubnetGroupDescription: this.parseXmlValue(subnetGroupMatch[1], 'DBSubnetGroupDescription') || '',
              vpcId: this.parseXmlValue(subnetGroupMatch[1], 'VpcId') || '',
            }
          : undefined,
        publiclyAccessible: this.parseXmlValue(instanceXml, 'PubliclyAccessible') === 'true',
        storageEncrypted: this.parseXmlValue(instanceXml, 'StorageEncrypted') === 'true',
        instanceCreateTime: this.parseXmlValue(instanceXml, 'InstanceCreateTime'),
        backupRetentionPeriod: this.parseXmlValue(instanceXml, 'BackupRetentionPeriod')
          ? Number.parseInt(this.parseXmlValue(instanceXml, 'BackupRetentionPeriod')!, 10)
          : undefined,
        tags: tags.length > 0 ? tags : undefined,
      });
    }

    return instances;
  }

  async rdsDescribeDBClusters(dbClusterIdentifier?: string): Promise<RDSCluster[]> {
    const query: Record<string, string> = {
      Action: 'DescribeDBClusters',
      Version: '2014-10-31',
    };

    if (dbClusterIdentifier) {
      query.DBClusterIdentifier = dbClusterIdentifier;
    }

    const response = await this.request<string>('rds', 'GET', '/', { query });

    const clusters: RDSCluster[] = [];
    const clusterMatches = response.matchAll(/<DBCluster>([\s\S]*?)<\/DBCluster>/g);

    for (const match of clusterMatches) {
      const clusterXml = match[1];

      const vpcSecurityGroups: Array<{ vpcSecurityGroupId: string; status: string }> = [];
      const sgMatches = clusterXml.matchAll(/<VpcSecurityGroupMembership>([\s\S]*?)<\/VpcSecurityGroupMembership>/g);
      for (const sgMatch of sgMatches) {
        vpcSecurityGroups.push({
          vpcSecurityGroupId: this.parseXmlValue(sgMatch[1], 'VpcSecurityGroupId') || '',
          status: this.parseXmlValue(sgMatch[1], 'Status') || '',
        });
      }

      const clusterMembers: Array<{
        dbInstanceIdentifier: string;
        isClusterWriter: boolean;
        dbClusterParameterGroupStatus: string;
      }> = [];
      const memberMatches = clusterXml.matchAll(/<DBClusterMember>([\s\S]*?)<\/DBClusterMember>/g);
      for (const memberMatch of memberMatches) {
        clusterMembers.push({
          dbInstanceIdentifier: this.parseXmlValue(memberMatch[1], 'DBInstanceIdentifier') || '',
          isClusterWriter: this.parseXmlValue(memberMatch[1], 'IsClusterWriter') === 'true',
          dbClusterParameterGroupStatus: this.parseXmlValue(memberMatch[1], 'DBClusterParameterGroupStatus') || '',
        });
      }

      clusters.push({
        dbClusterIdentifier: this.parseXmlValue(clusterXml, 'DBClusterIdentifier') || '',
        dbClusterArn: this.parseXmlValue(clusterXml, 'DBClusterArn') || '',
        engine: this.parseXmlValue(clusterXml, 'Engine') || '',
        engineVersion: this.parseXmlValue(clusterXml, 'EngineVersion') || '',
        status: this.parseXmlValue(clusterXml, 'Status') || '',
        endpoint: this.parseXmlValue(clusterXml, 'Endpoint'),
        readerEndpoint: this.parseXmlValue(clusterXml, 'ReaderEndpoint'),
        port: Number.parseInt(this.parseXmlValue(clusterXml, 'Port') || '0', 10),
        masterUsername: this.parseXmlValue(clusterXml, 'MasterUsername') || '',
        allocatedStorage: this.parseXmlValue(clusterXml, 'AllocatedStorage')
          ? Number.parseInt(this.parseXmlValue(clusterXml, 'AllocatedStorage')!, 10)
          : undefined,
        multiAZ: this.parseXmlValue(clusterXml, 'MultiAZ') === 'true',
        clusterMembers,
        vpcSecurityGroups,
        storageEncrypted: this.parseXmlValue(clusterXml, 'StorageEncrypted') === 'true',
        clusterCreateTime: this.parseXmlValue(clusterXml, 'ClusterCreateTime'),
        backupRetentionPeriod: this.parseXmlValue(clusterXml, 'BackupRetentionPeriod')
          ? Number.parseInt(this.parseXmlValue(clusterXml, 'BackupRetentionPeriod')!, 10)
          : undefined,
      });
    }

    return clusters;
  }

  async rdsDescribeDBSnapshots(dbInstanceIdentifier?: string): Promise<RDSSnapshot[]> {
    const query: Record<string, string> = {
      Action: 'DescribeDBSnapshots',
      Version: '2014-10-31',
    };

    if (dbInstanceIdentifier) {
      query.DBInstanceIdentifier = dbInstanceIdentifier;
    }

    const response = await this.request<string>('rds', 'GET', '/', { query });

    const snapshots: RDSSnapshot[] = [];
    const snapshotMatches = response.matchAll(/<DBSnapshot>([\s\S]*?)<\/DBSnapshot>/g);

    for (const match of snapshotMatches) {
      const snapshotXml = match[1];

      snapshots.push({
        dbSnapshotIdentifier: this.parseXmlValue(snapshotXml, 'DBSnapshotIdentifier') || '',
        dbSnapshotArn: this.parseXmlValue(snapshotXml, 'DBSnapshotArn') || '',
        dbInstanceIdentifier: this.parseXmlValue(snapshotXml, 'DBInstanceIdentifier') || '',
        snapshotType: this.parseXmlValue(snapshotXml, 'SnapshotType') || '',
        status: this.parseXmlValue(snapshotXml, 'Status') || '',
        engine: this.parseXmlValue(snapshotXml, 'Engine') || '',
        engineVersion: this.parseXmlValue(snapshotXml, 'EngineVersion') || '',
        allocatedStorage: Number.parseInt(this.parseXmlValue(snapshotXml, 'AllocatedStorage') || '0', 10),
        snapshotCreateTime: this.parseXmlValue(snapshotXml, 'SnapshotCreateTime'),
        encrypted: this.parseXmlValue(snapshotXml, 'Encrypted') === 'true',
        percentProgress: this.parseXmlValue(snapshotXml, 'PercentProgress')
          ? Number.parseInt(this.parseXmlValue(snapshotXml, 'PercentProgress')!, 10)
          : undefined,
      });
    }

    return snapshots;
  }

  async rdsDescribeDBParameterGroups(dbParameterGroupName?: string): Promise<RDSDBParameterGroup[]> {
    const query: Record<string, string> = {
      Action: 'DescribeDBParameterGroups',
      Version: '2014-10-31',
    };

    if (dbParameterGroupName) {
      query.DBParameterGroupName = dbParameterGroupName;
    }

    const response = await this.request<string>('rds', 'GET', '/', { query });

    const groups: RDSDBParameterGroup[] = [];
    const groupMatches = response.matchAll(/<DBParameterGroup>([\s\S]*?)<\/DBParameterGroup>/g);

    for (const match of groupMatches) {
      const groupXml = match[1];
      groups.push({
        dbParameterGroupName: this.parseXmlValue(groupXml, 'DBParameterGroupName') || '',
        dbParameterGroupFamily: this.parseXmlValue(groupXml, 'DBParameterGroupFamily') || '',
        description: this.parseXmlValue(groupXml, 'Description') || '',
        dbParameterGroupArn: this.parseXmlValue(groupXml, 'DBParameterGroupArn'),
      });
    }

    return groups;
  }

  async rdsDescribeDBSubnetGroups(dbSubnetGroupName?: string): Promise<RDSDBSubnetGroup[]> {
    const query: Record<string, string> = {
      Action: 'DescribeDBSubnetGroups',
      Version: '2014-10-31',
    };

    if (dbSubnetGroupName) {
      query.DBSubnetGroupName = dbSubnetGroupName;
    }

    const response = await this.request<string>('rds', 'GET', '/', { query });

    const groups: RDSDBSubnetGroup[] = [];
    const groupMatches = response.matchAll(/<DBSubnetGroup>([\s\S]*?)<\/DBSubnetGroup>/g);

    for (const match of groupMatches) {
      const groupXml = match[1];

      const subnets: RDSDBSubnetGroup['subnets'] = [];
      const subnetMatches = groupXml.matchAll(/<Subnet>([\s\S]*?)<\/Subnet>/g);
      for (const subnetMatch of subnetMatches) {
        const subnetXml = subnetMatch[1];
        const azMatch = subnetXml.match(/<SubnetAvailabilityZone>([\s\S]*?)<\/SubnetAvailabilityZone>/);
        subnets.push({
          subnetIdentifier: this.parseXmlValue(subnetXml, 'SubnetIdentifier') || '',
          subnetAvailabilityZone: azMatch
            ? { name: this.parseXmlValue(azMatch[1], 'Name') || '' }
            : undefined,
          subnetStatus: this.parseXmlValue(subnetXml, 'SubnetStatus'),
        });
      }

      groups.push({
        dbSubnetGroupName: this.parseXmlValue(groupXml, 'DBSubnetGroupName') || '',
        dbSubnetGroupDescription: this.parseXmlValue(groupXml, 'DBSubnetGroupDescription') || '',
        vpcId: this.parseXmlValue(groupXml, 'VpcId') || '',
        subnetGroupStatus: this.parseXmlValue(groupXml, 'SubnetGroupStatus') || '',
        subnets,
        dbSubnetGroupArn: this.parseXmlValue(groupXml, 'DBSubnetGroupArn'),
      });
    }

    return groups;
  }

  async rdsCreateDBSnapshot(
    dbInstanceIdentifier: string,
    dbSnapshotIdentifier: string
  ): Promise<RDSSnapshot> {
    const query: Record<string, string> = {
      Action: 'CreateDBSnapshot',
      Version: '2014-10-31',
      DBInstanceIdentifier: dbInstanceIdentifier,
      DBSnapshotIdentifier: dbSnapshotIdentifier,
    };

    const response = await this.request<string>('rds', 'GET', '/', { query });

    return {
      dbSnapshotIdentifier: this.parseXmlValue(response, 'DBSnapshotIdentifier') || dbSnapshotIdentifier,
      dbSnapshotArn: this.parseXmlValue(response, 'DBSnapshotArn') || '',
      dbInstanceIdentifier: this.parseXmlValue(response, 'DBInstanceIdentifier') || dbInstanceIdentifier,
      snapshotCreateTime: this.parseXmlValue(response, 'SnapshotCreateTime'),
      engine: this.parseXmlValue(response, 'Engine') || '',
      engineVersion: this.parseXmlValue(response, 'EngineVersion') || '',
      status: this.parseXmlValue(response, 'Status') || 'creating',
      snapshotType: this.parseXmlValue(response, 'SnapshotType') || 'manual',
      percentProgress: parseInt(this.parseXmlValue(response, 'PercentProgress') || '0', 10),
      encrypted: this.parseXmlValue(response, 'Encrypted') === 'true',
      allocatedStorage: parseInt(this.parseXmlValue(response, 'AllocatedStorage') || '0', 10),
    };
  }

  async rdsDeleteDBSnapshot(dbSnapshotIdentifier: string): Promise<void> {
    const query: Record<string, string> = {
      Action: 'DeleteDBSnapshot',
      Version: '2014-10-31',
      DBSnapshotIdentifier: dbSnapshotIdentifier,
    };

    await this.request<string>('rds', 'GET', '/', { query });
  }

  async rdsStartDBInstance(dbInstanceIdentifier: string): Promise<RDSInstance> {
    const query: Record<string, string> = {
      Action: 'StartDBInstance',
      Version: '2014-10-31',
      DBInstanceIdentifier: dbInstanceIdentifier,
    };

    const response = await this.request<string>('rds', 'GET', '/', { query });

    return {
      dbInstanceIdentifier: this.parseXmlValue(response, 'DBInstanceIdentifier') || dbInstanceIdentifier,
      dbInstanceArn: this.parseXmlValue(response, 'DBInstanceArn') || '',
      dbInstanceClass: this.parseXmlValue(response, 'DBInstanceClass') || '',
      engine: this.parseXmlValue(response, 'Engine') || '',
      dbInstanceStatus: this.parseXmlValue(response, 'DBInstanceStatus') || 'starting',
      endpoint: {
        address: this.parseXmlValue(response, 'Address') || '',
        port: parseInt(this.parseXmlValue(response, 'Port') || '0', 10),
        hostedZoneId: this.parseXmlValue(response, 'HostedZoneId') || '',
      },
      availabilityZone: this.parseXmlValue(response, 'AvailabilityZone'),
      multiAZ: this.parseXmlValue(response, 'MultiAZ') === 'true',
      engineVersion: this.parseXmlValue(response, 'EngineVersion') || '',
      masterUsername: this.parseXmlValue(response, 'MasterUsername') || '',
      allocatedStorage: parseInt(this.parseXmlValue(response, 'AllocatedStorage') || '0', 10),
      storageType: this.parseXmlValue(response, 'StorageType') || '',
      storageEncrypted: this.parseXmlValue(response, 'StorageEncrypted') === 'true',
      vpcSecurityGroups: [],
      publiclyAccessible: this.parseXmlValue(response, 'PubliclyAccessible') === 'true',
    };
  }

  async rdsStopDBInstance(
    dbInstanceIdentifier: string,
    dbSnapshotIdentifier?: string
  ): Promise<RDSInstance> {
    const query: Record<string, string> = {
      Action: 'StopDBInstance',
      Version: '2014-10-31',
      DBInstanceIdentifier: dbInstanceIdentifier,
    };

    if (dbSnapshotIdentifier) {
      query.DBSnapshotIdentifier = dbSnapshotIdentifier;
    }

    const response = await this.request<string>('rds', 'GET', '/', { query });

    return {
      dbInstanceIdentifier: this.parseXmlValue(response, 'DBInstanceIdentifier') || dbInstanceIdentifier,
      dbInstanceArn: this.parseXmlValue(response, 'DBInstanceArn') || '',
      dbInstanceClass: this.parseXmlValue(response, 'DBInstanceClass') || '',
      engine: this.parseXmlValue(response, 'Engine') || '',
      dbInstanceStatus: this.parseXmlValue(response, 'DBInstanceStatus') || 'stopping',
      endpoint: {
        address: this.parseXmlValue(response, 'Address') || '',
        port: parseInt(this.parseXmlValue(response, 'Port') || '0', 10),
        hostedZoneId: this.parseXmlValue(response, 'HostedZoneId') || '',
      },
      availabilityZone: this.parseXmlValue(response, 'AvailabilityZone'),
      multiAZ: this.parseXmlValue(response, 'MultiAZ') === 'true',
      engineVersion: this.parseXmlValue(response, 'EngineVersion') || '',
      masterUsername: this.parseXmlValue(response, 'MasterUsername') || '',
      allocatedStorage: parseInt(this.parseXmlValue(response, 'AllocatedStorage') || '0', 10),
      storageType: this.parseXmlValue(response, 'StorageType') || '',
      storageEncrypted: this.parseXmlValue(response, 'StorageEncrypted') === 'true',
      vpcSecurityGroups: [],
      publiclyAccessible: this.parseXmlValue(response, 'PubliclyAccessible') === 'true',
    };
  }

  async rdsRebootDBInstance(
    dbInstanceIdentifier: string,
    forceFailover?: boolean
  ): Promise<RDSInstance> {
    const query: Record<string, string> = {
      Action: 'RebootDBInstance',
      Version: '2014-10-31',
      DBInstanceIdentifier: dbInstanceIdentifier,
    };

    if (forceFailover !== undefined) {
      query.ForceFailover = forceFailover.toString();
    }

    const response = await this.request<string>('rds', 'GET', '/', { query });

    return {
      dbInstanceIdentifier: this.parseXmlValue(response, 'DBInstanceIdentifier') || dbInstanceIdentifier,
      dbInstanceArn: this.parseXmlValue(response, 'DBInstanceArn') || '',
      dbInstanceClass: this.parseXmlValue(response, 'DBInstanceClass') || '',
      engine: this.parseXmlValue(response, 'Engine') || '',
      dbInstanceStatus: this.parseXmlValue(response, 'DBInstanceStatus') || 'rebooting',
      endpoint: {
        address: this.parseXmlValue(response, 'Address') || '',
        port: parseInt(this.parseXmlValue(response, 'Port') || '0', 10),
        hostedZoneId: this.parseXmlValue(response, 'HostedZoneId') || '',
      },
      availabilityZone: this.parseXmlValue(response, 'AvailabilityZone'),
      multiAZ: this.parseXmlValue(response, 'MultiAZ') === 'true',
      engineVersion: this.parseXmlValue(response, 'EngineVersion') || '',
      masterUsername: this.parseXmlValue(response, 'MasterUsername') || '',
      allocatedStorage: parseInt(this.parseXmlValue(response, 'AllocatedStorage') || '0', 10),
      storageType: this.parseXmlValue(response, 'StorageType') || '',
      storageEncrypted: this.parseXmlValue(response, 'StorageEncrypted') === 'true',
      vpcSecurityGroups: [],
      publiclyAccessible: this.parseXmlValue(response, 'PubliclyAccessible') === 'true',
    };
  }

  async rdsDeleteDBInstance(
    dbInstanceIdentifier: string,
    skipFinalSnapshot?: boolean,
    finalSnapshotIdentifier?: string
  ): Promise<RDSInstance> {
    const query: Record<string, string> = {
      Action: 'DeleteDBInstance',
      Version: '2014-10-31',
      DBInstanceIdentifier: dbInstanceIdentifier,
    };

    if (skipFinalSnapshot !== undefined) {
      query.SkipFinalSnapshot = skipFinalSnapshot.toString();
    }
    if (finalSnapshotIdentifier) {
      query.FinalDBSnapshotIdentifier = finalSnapshotIdentifier;
    }

    const response = await this.request<string>('rds', 'GET', '/', { query });

    return {
      dbInstanceIdentifier: this.parseXmlValue(response, 'DBInstanceIdentifier') || dbInstanceIdentifier,
      dbInstanceArn: this.parseXmlValue(response, 'DBInstanceArn') || '',
      dbInstanceClass: this.parseXmlValue(response, 'DBInstanceClass') || '',
      engine: this.parseXmlValue(response, 'Engine') || '',
      dbInstanceStatus: this.parseXmlValue(response, 'DBInstanceStatus') || 'deleting',
      endpoint: {
        address: this.parseXmlValue(response, 'Address') || '',
        port: parseInt(this.parseXmlValue(response, 'Port') || '0', 10),
        hostedZoneId: this.parseXmlValue(response, 'HostedZoneId') || '',
      },
      availabilityZone: this.parseXmlValue(response, 'AvailabilityZone'),
      multiAZ: this.parseXmlValue(response, 'MultiAZ') === 'true',
      engineVersion: this.parseXmlValue(response, 'EngineVersion') || '',
      masterUsername: this.parseXmlValue(response, 'MasterUsername') || '',
      allocatedStorage: parseInt(this.parseXmlValue(response, 'AllocatedStorage') || '0', 10),
      storageType: this.parseXmlValue(response, 'StorageType') || '',
      storageEncrypted: this.parseXmlValue(response, 'StorageEncrypted') === 'true',
      vpcSecurityGroups: [],
      publiclyAccessible: this.parseXmlValue(response, 'PubliclyAccessible') === 'true',
    };
  }

  async rdsModifyDBInstance(
    dbInstanceIdentifier: string,
    params: {
      dbInstanceClass?: string;
      allocatedStorage?: number;
      masterUserPassword?: string;
      backupRetentionPeriod?: number;
      multiAZ?: boolean;
      applyImmediately?: boolean;
    }
  ): Promise<RDSInstance> {
    const query: Record<string, string> = {
      Action: 'ModifyDBInstance',
      Version: '2014-10-31',
      DBInstanceIdentifier: dbInstanceIdentifier,
    };

    if (params.dbInstanceClass) query.DBInstanceClass = params.dbInstanceClass;
    if (params.allocatedStorage !== undefined) query.AllocatedStorage = params.allocatedStorage.toString();
    if (params.masterUserPassword) query.MasterUserPassword = params.masterUserPassword;
    if (params.backupRetentionPeriod !== undefined) query.BackupRetentionPeriod = params.backupRetentionPeriod.toString();
    if (params.multiAZ !== undefined) query.MultiAZ = params.multiAZ.toString();
    if (params.applyImmediately !== undefined) query.ApplyImmediately = params.applyImmediately.toString();

    const response = await this.request<string>('rds', 'GET', '/', { query });

    return {
      dbInstanceIdentifier: this.parseXmlValue(response, 'DBInstanceIdentifier') || dbInstanceIdentifier,
      dbInstanceArn: this.parseXmlValue(response, 'DBInstanceArn') || '',
      dbInstanceClass: this.parseXmlValue(response, 'DBInstanceClass') || '',
      engine: this.parseXmlValue(response, 'Engine') || '',
      dbInstanceStatus: this.parseXmlValue(response, 'DBInstanceStatus') || 'modifying',
      endpoint: {
        address: this.parseXmlValue(response, 'Address') || '',
        port: parseInt(this.parseXmlValue(response, 'Port') || '0', 10),
        hostedZoneId: this.parseXmlValue(response, 'HostedZoneId') || '',
      },
      availabilityZone: this.parseXmlValue(response, 'AvailabilityZone'),
      multiAZ: this.parseXmlValue(response, 'MultiAZ') === 'true',
      engineVersion: this.parseXmlValue(response, 'EngineVersion') || '',
      masterUsername: this.parseXmlValue(response, 'MasterUsername') || '',
      allocatedStorage: parseInt(this.parseXmlValue(response, 'AllocatedStorage') || '0', 10),
      storageType: this.parseXmlValue(response, 'StorageType') || '',
      storageEncrypted: this.parseXmlValue(response, 'StorageEncrypted') === 'true',
      vpcSecurityGroups: [],
      publiclyAccessible: this.parseXmlValue(response, 'PubliclyAccessible') === 'true',
    };
  }

  async rdsDescribeDBClusterSnapshots(dbClusterIdentifier?: string): Promise<Array<{ dbClusterSnapshotIdentifier: string; dbClusterIdentifier: string; snapshotType: string; status: string; engine: string; engineVersion?: string; snapshotCreateTime?: string; allocatedStorage?: number; storageEncrypted: boolean }>> {
    const query: Record<string, string> = {
      Action: 'DescribeDBClusterSnapshots',
      Version: '2014-10-31',
    };
    if (dbClusterIdentifier) query.DBClusterIdentifier = dbClusterIdentifier;

    const response = await this.request<string>('rds', 'GET', '/', { query });
    const snapshots: Array<{ dbClusterSnapshotIdentifier: string; dbClusterIdentifier: string; snapshotType: string; status: string; engine: string; engineVersion?: string; snapshotCreateTime?: string; allocatedStorage?: number; storageEncrypted: boolean }> = [];

    const snapshotMatches = response.matchAll(/<DBClusterSnapshot>([\s\S]*?)<\/DBClusterSnapshot>/g);
    for (const match of snapshotMatches) {
      const xml = match[1];
      snapshots.push({
        dbClusterSnapshotIdentifier: this.parseXmlValue(xml, 'DBClusterSnapshotIdentifier') || '',
        dbClusterIdentifier: this.parseXmlValue(xml, 'DBClusterIdentifier') || '',
        snapshotType: this.parseXmlValue(xml, 'SnapshotType') || '',
        status: this.parseXmlValue(xml, 'Status') || '',
        engine: this.parseXmlValue(xml, 'Engine') || '',
        engineVersion: this.parseXmlValue(xml, 'EngineVersion'),
        snapshotCreateTime: this.parseXmlValue(xml, 'SnapshotCreateTime'),
        allocatedStorage: this.parseXmlValue(xml, 'AllocatedStorage') ? parseInt(this.parseXmlValue(xml, 'AllocatedStorage')!, 10) : undefined,
        storageEncrypted: this.parseXmlValue(xml, 'StorageEncrypted') === 'true',
      });
    }
    return snapshots;
  }

  async rdsCreateDBClusterSnapshot(dbClusterIdentifier: string, dbClusterSnapshotIdentifier: string): Promise<{ dbClusterSnapshotIdentifier: string; dbClusterIdentifier: string; status: string }> {
    const response = await this.request<string>('rds', 'GET', '/', {
      query: {
        Action: 'CreateDBClusterSnapshot',
        Version: '2014-10-31',
        DBClusterIdentifier: dbClusterIdentifier,
        DBClusterSnapshotIdentifier: dbClusterSnapshotIdentifier,
      },
    });
    return {
      dbClusterSnapshotIdentifier: this.parseXmlValue(response, 'DBClusterSnapshotIdentifier') || dbClusterSnapshotIdentifier,
      dbClusterIdentifier: this.parseXmlValue(response, 'DBClusterIdentifier') || dbClusterIdentifier,
      status: this.parseXmlValue(response, 'Status') || 'creating',
    };
  }

  async rdsDeleteDBClusterSnapshot(dbClusterSnapshotIdentifier: string): Promise<void> {
    await this.request<string>('rds', 'GET', '/', {
      query: {
        Action: 'DeleteDBClusterSnapshot',
        Version: '2014-10-31',
        DBClusterSnapshotIdentifier: dbClusterSnapshotIdentifier,
      },
    });
  }

  async rdsDescribeDBSecurityGroups(dbSecurityGroupName?: string): Promise<Array<{ dbSecurityGroupName: string; dbSecurityGroupDescription: string; ownerId: string; vpcId?: string }>> {
    const query: Record<string, string> = {
      Action: 'DescribeDBSecurityGroups',
      Version: '2014-10-31',
    };
    if (dbSecurityGroupName) query.DBSecurityGroupName = dbSecurityGroupName;

    const response = await this.request<string>('rds', 'GET', '/', { query });
    const groups: Array<{ dbSecurityGroupName: string; dbSecurityGroupDescription: string; ownerId: string; vpcId?: string }> = [];

    const groupMatches = response.matchAll(/<DBSecurityGroup>([\s\S]*?)<\/DBSecurityGroup>/g);
    for (const match of groupMatches) {
      const xml = match[1];
      groups.push({
        dbSecurityGroupName: this.parseXmlValue(xml, 'DBSecurityGroupName') || '',
        dbSecurityGroupDescription: this.parseXmlValue(xml, 'DBSecurityGroupDescription') || '',
        ownerId: this.parseXmlValue(xml, 'OwnerId') || '',
        vpcId: this.parseXmlValue(xml, 'VpcId'),
      });
    }
    return groups;
  }

  async rdsDescribeOptionGroups(optionGroupName?: string): Promise<Array<{ optionGroupName: string; optionGroupDescription: string; engineName: string; majorEngineVersion: string; vpcId?: string }>> {
    const query: Record<string, string> = {
      Action: 'DescribeOptionGroups',
      Version: '2014-10-31',
    };
    if (optionGroupName) query.OptionGroupName = optionGroupName;

    const response = await this.request<string>('rds', 'GET', '/', { query });
    const groups: Array<{ optionGroupName: string; optionGroupDescription: string; engineName: string; majorEngineVersion: string; vpcId?: string }> = [];

    const groupMatches = response.matchAll(/<OptionGroup>([\s\S]*?)<\/OptionGroup>/g);
    for (const match of groupMatches) {
      const xml = match[1];
      groups.push({
        optionGroupName: this.parseXmlValue(xml, 'OptionGroupName') || '',
        optionGroupDescription: this.parseXmlValue(xml, 'OptionGroupDescription') || '',
        engineName: this.parseXmlValue(xml, 'EngineName') || '',
        majorEngineVersion: this.parseXmlValue(xml, 'MajorEngineVersion') || '',
        vpcId: this.parseXmlValue(xml, 'VpcId'),
      });
    }
    return groups;
  }

  async rdsDescribeDBEngineVersions(engine?: string): Promise<Array<{ engine: string; engineVersion: string; dbEngineDescription: string; dbEngineVersionDescription: string; validUpgradeTarget?: string[] }>> {
    const query: Record<string, string> = {
      Action: 'DescribeDBEngineVersions',
      Version: '2014-10-31',
    };
    if (engine) query.Engine = engine;

    const response = await this.request<string>('rds', 'GET', '/', { query });
    const versions: Array<{ engine: string; engineVersion: string; dbEngineDescription: string; dbEngineVersionDescription: string; validUpgradeTarget?: string[] }> = [];

    const versionMatches = response.matchAll(/<DBEngineVersion>([\s\S]*?)<\/DBEngineVersion>/g);
    for (const match of versionMatches) {
      const xml = match[1];
      const targets: string[] = [];
      const targetMatches = xml.matchAll(/<UpgradeTarget>[\s\S]*?<EngineVersion>([^<]+)<\/EngineVersion>[\s\S]*?<\/UpgradeTarget>/g);
      for (const tm of targetMatches) {
        targets.push(tm[1]);
      }
      versions.push({
        engine: this.parseXmlValue(xml, 'Engine') || '',
        engineVersion: this.parseXmlValue(xml, 'EngineVersion') || '',
        dbEngineDescription: this.parseXmlValue(xml, 'DBEngineDescription') || '',
        dbEngineVersionDescription: this.parseXmlValue(xml, 'DBEngineVersionDescription') || '',
        validUpgradeTarget: targets.length > 0 ? targets : undefined,
      });
    }
    return versions;
  }

  async rdsDescribeOrderableDBInstanceOptions(engine: string): Promise<Array<{ dbInstanceClass: string; engine: string; engineVersion: string; storageType: string; supportsStorageEncryption: boolean; supportsIAMDatabaseAuthentication: boolean }>> {
    const response = await this.request<string>('rds', 'GET', '/', {
      query: {
        Action: 'DescribeOrderableDBInstanceOptions',
        Version: '2014-10-31',
        Engine: engine,
      },
    });
    const options: Array<{ dbInstanceClass: string; engine: string; engineVersion: string; storageType: string; supportsStorageEncryption: boolean; supportsIAMDatabaseAuthentication: boolean }> = [];

    const optionMatches = response.matchAll(/<OrderableDBInstanceOption>([\s\S]*?)<\/OrderableDBInstanceOption>/g);
    for (const match of optionMatches) {
      const xml = match[1];
      options.push({
        dbInstanceClass: this.parseXmlValue(xml, 'DBInstanceClass') || '',
        engine: this.parseXmlValue(xml, 'Engine') || '',
        engineVersion: this.parseXmlValue(xml, 'EngineVersion') || '',
        storageType: this.parseXmlValue(xml, 'StorageType') || '',
        supportsStorageEncryption: this.parseXmlValue(xml, 'SupportsStorageEncryption') === 'true',
        supportsIAMDatabaseAuthentication: this.parseXmlValue(xml, 'SupportsIAMDatabaseAuthentication') === 'true',
      });
    }
    return options;
  }

  async rdsDescribeEvents(params?: { sourceType?: string; sourceIdentifier?: string; duration?: number }): Promise<Array<{ sourceIdentifier: string; sourceType: string; message: string; date: string }>> {
    const query: Record<string, string> = {
      Action: 'DescribeEvents',
      Version: '2014-10-31',
    };
    if (params?.sourceType) query.SourceType = params.sourceType;
    if (params?.sourceIdentifier) query.SourceIdentifier = params.sourceIdentifier;
    if (params?.duration !== undefined) query.Duration = params.duration.toString();

    const response = await this.request<string>('rds', 'GET', '/', { query });
    const events: Array<{ sourceIdentifier: string; sourceType: string; message: string; date: string }> = [];

    const eventMatches = response.matchAll(/<Event>([\s\S]*?)<\/Event>/g);
    for (const match of eventMatches) {
      const xml = match[1];
      events.push({
        sourceIdentifier: this.parseXmlValue(xml, 'SourceIdentifier') || '',
        sourceType: this.parseXmlValue(xml, 'SourceType') || '',
        message: this.parseXmlValue(xml, 'Message') || '',
        date: this.parseXmlValue(xml, 'Date') || '',
      });
    }
    return events;
  }

  async rdsDescribePendingMaintenanceActions(resourceIdentifier?: string): Promise<Array<{ resourceIdentifier: string; pendingMaintenanceActionDetails: Array<{ action: string; autoAppliedAfterDate?: string; currentApplyDate?: string; description: string }> }>> {
    const query: Record<string, string> = {
      Action: 'DescribePendingMaintenanceActions',
      Version: '2014-10-31',
    };
    if (resourceIdentifier) query.ResourceIdentifier = resourceIdentifier;

    const response = await this.request<string>('rds', 'GET', '/', { query });
    const resources: Array<{ resourceIdentifier: string; pendingMaintenanceActionDetails: Array<{ action: string; autoAppliedAfterDate?: string; currentApplyDate?: string; description: string }> }> = [];

    const resourceMatches = response.matchAll(/<ResourcePendingMaintenanceActions>([\s\S]*?)<\/ResourcePendingMaintenanceActions>/g);
    for (const match of resourceMatches) {
      const xml = match[1];
      const actions: Array<{ action: string; autoAppliedAfterDate?: string; currentApplyDate?: string; description: string }> = [];
      const actionMatches = xml.matchAll(/<PendingMaintenanceAction>([\s\S]*?)<\/PendingMaintenanceAction>/g);
      for (const am of actionMatches) {
        actions.push({
          action: this.parseXmlValue(am[1], 'Action') || '',
          autoAppliedAfterDate: this.parseXmlValue(am[1], 'AutoAppliedAfterDate'),
          currentApplyDate: this.parseXmlValue(am[1], 'CurrentApplyDate'),
          description: this.parseXmlValue(am[1], 'Description') || '',
        });
      }
      resources.push({
        resourceIdentifier: this.parseXmlValue(xml, 'ResourceIdentifier') || '',
        pendingMaintenanceActionDetails: actions,
      });
    }
    return resources;
  }

  async rdsAddTagsToResource(resourceArn: string, tags: Array<{ key: string; value: string }>): Promise<void> {
    const query: Record<string, string> = {
      Action: 'AddTagsToResource',
      Version: '2014-10-31',
      ResourceName: resourceArn,
    };
    tags.forEach((tag, i) => {
      query[`Tags.Tag.${i + 1}.Key`] = tag.key;
      query[`Tags.Tag.${i + 1}.Value`] = tag.value;
    });
    await this.request<string>('rds', 'GET', '/', { query });
  }

  async rdsRemoveTagsFromResource(resourceArn: string, tagKeys: string[]): Promise<void> {
    const query: Record<string, string> = {
      Action: 'RemoveTagsFromResource',
      Version: '2014-10-31',
      ResourceName: resourceArn,
    };
    tagKeys.forEach((key, i) => {
      query[`TagKeys.member.${i + 1}`] = key;
    });
    await this.request<string>('rds', 'GET', '/', { query });
  }

  async rdsListTagsForResource(resourceArn: string): Promise<Array<{ key: string; value: string }>> {
    const response = await this.request<string>('rds', 'GET', '/', {
      query: {
        Action: 'ListTagsForResource',
        Version: '2014-10-31',
        ResourceName: resourceArn,
      },
    });
    const tags: Array<{ key: string; value: string }> = [];
    const tagMatches = response.matchAll(/<Tag>([\s\S]*?)<\/Tag>/g);
    for (const match of tagMatches) {
      const xml = match[1];
      tags.push({
        key: this.parseXmlValue(xml, 'Key') || '',
        value: this.parseXmlValue(xml, 'Value') || '',
      });
    }
    return tags;
  }

  async rdsRestoreDBInstanceFromDBSnapshot(dbInstanceIdentifier: string, dbSnapshotIdentifier: string, dbInstanceClass?: string): Promise<RDSInstance> {
    const query: Record<string, string> = {
      Action: 'RestoreDBInstanceFromDBSnapshot',
      Version: '2014-10-31',
      DBInstanceIdentifier: dbInstanceIdentifier,
      DBSnapshotIdentifier: dbSnapshotIdentifier,
    };
    if (dbInstanceClass) query.DBInstanceClass = dbInstanceClass;

    const response = await this.request<string>('rds', 'GET', '/', { query });
    return {
      dbInstanceIdentifier: this.parseXmlValue(response, 'DBInstanceIdentifier') || dbInstanceIdentifier,
      dbInstanceArn: this.parseXmlValue(response, 'DBInstanceArn') || '',
      dbInstanceClass: this.parseXmlValue(response, 'DBInstanceClass') || '',
      engine: this.parseXmlValue(response, 'Engine') || '',
      dbInstanceStatus: this.parseXmlValue(response, 'DBInstanceStatus') || 'creating',
      endpoint: {
        address: this.parseXmlValue(response, 'Address') || '',
        port: parseInt(this.parseXmlValue(response, 'Port') || '0', 10),
        hostedZoneId: this.parseXmlValue(response, 'HostedZoneId') || '',
      },
      availabilityZone: this.parseXmlValue(response, 'AvailabilityZone'),
      multiAZ: this.parseXmlValue(response, 'MultiAZ') === 'true',
      engineVersion: this.parseXmlValue(response, 'EngineVersion') || '',
      masterUsername: this.parseXmlValue(response, 'MasterUsername') || '',
      allocatedStorage: parseInt(this.parseXmlValue(response, 'AllocatedStorage') || '0', 10),
      storageType: this.parseXmlValue(response, 'StorageType') || '',
      storageEncrypted: this.parseXmlValue(response, 'StorageEncrypted') === 'true',
      vpcSecurityGroups: [],
      publiclyAccessible: this.parseXmlValue(response, 'PubliclyAccessible') === 'true',
    };
  }

  async rdsCopyDBSnapshot(sourceSnapshotIdentifier: string, targetSnapshotIdentifier: string): Promise<{ dbSnapshotIdentifier: string; status: string }> {
    const response = await this.request<string>('rds', 'GET', '/', {
      query: {
        Action: 'CopyDBSnapshot',
        Version: '2014-10-31',
        SourceDBSnapshotIdentifier: sourceSnapshotIdentifier,
        TargetDBSnapshotIdentifier: targetSnapshotIdentifier,
      },
    });
    return {
      dbSnapshotIdentifier: this.parseXmlValue(response, 'DBSnapshotIdentifier') || targetSnapshotIdentifier,
      status: this.parseXmlValue(response, 'Status') || 'copying',
    };
  }

  // ===========================================================================
  // EKS
  // ===========================================================================

  async eksListClusters(): Promise<string[]> {
    const response = await this.request<{ clusters: string[] }>('eks', 'GET', '/clusters', {
      headers: { 'content-type': 'application/json' },
    });

    return response.clusters || [];
  }

  async eksDescribeCluster(name: string): Promise<EKSCluster> {
    const response = await this.request<{ cluster: Record<string, unknown> }>(
      'eks',
      'GET',
      `/clusters/${encodeURIComponent(name)}`,
      { headers: { 'content-type': 'application/json' } }
    );

    const c = response.cluster;
    const vpcConfig = c.resourcesVpcConfig as Record<string, unknown> | undefined;

    return {
      name: c.name as string,
      arn: c.arn as string,
      createdAt: c.createdAt as string | undefined,
      version: c.version as string,
      endpoint: c.endpoint as string | undefined,
      roleArn: c.roleArn as string,
      status: c.status as string,
      certificateAuthority: c.certificateAuthority as { data: string } | undefined,
      platformVersion: c.platformVersion as string | undefined,
      tags: c.tags as Record<string, string> | undefined,
      resourcesVpcConfig: vpcConfig
        ? {
            subnetIds: (vpcConfig.subnetIds as string[]) || [],
            securityGroupIds: (vpcConfig.securityGroupIds as string[]) || [],
            clusterSecurityGroupId: vpcConfig.clusterSecurityGroupId as string | undefined,
            vpcId: vpcConfig.vpcId as string | undefined,
            endpointPublicAccess: vpcConfig.endpointPublicAccess as boolean,
            endpointPrivateAccess: vpcConfig.endpointPrivateAccess as boolean,
            publicAccessCidrs: vpcConfig.publicAccessCidrs as string[] | undefined,
          }
        : undefined,
    };
  }

  async eksListNodegroups(clusterName: string): Promise<string[]> {
    const response = await this.request<{ nodegroups: string[] }>(
      'eks',
      'GET',
      `/clusters/${encodeURIComponent(clusterName)}/node-groups`,
      { headers: { 'content-type': 'application/json' } }
    );

    return response.nodegroups || [];
  }

  async eksDescribeNodegroup(clusterName: string, nodegroupName: string): Promise<EKSNodegroup> {
    const response = await this.request<{ nodegroup: Record<string, unknown> }>(
      'eks',
      'GET',
      `/clusters/${encodeURIComponent(clusterName)}/node-groups/${encodeURIComponent(nodegroupName)}`,
      { headers: { 'content-type': 'application/json' } }
    );

    const n = response.nodegroup;
    const scaling = n.scalingConfig as Record<string, unknown> | undefined;

    return {
      nodegroupName: n.nodegroupName as string,
      nodegroupArn: n.nodegroupArn as string,
      clusterName: n.clusterName as string,
      version: n.version as string | undefined,
      releaseVersion: n.releaseVersion as string | undefined,
      createdAt: n.createdAt as string | undefined,
      modifiedAt: n.modifiedAt as string | undefined,
      status: n.status as string,
      capacityType: n.capacityType as string | undefined,
      scalingConfig: scaling
        ? {
            minSize: scaling.minSize as number,
            maxSize: scaling.maxSize as number,
            desiredSize: scaling.desiredSize as number,
          }
        : undefined,
      instanceTypes: n.instanceTypes as string[] | undefined,
      subnets: (n.subnets as string[]) || [],
      amiType: n.amiType as string | undefined,
      nodeRole: n.nodeRole as string,
      labels: n.labels as Record<string, string> | undefined,
      tags: n.tags as Record<string, string> | undefined,
    };
  }

  async eksListFargateProfiles(clusterName: string): Promise<string[]> {
    const response = await this.request<{ fargateProfileNames: string[] }>(
      'eks',
      'GET',
      `/clusters/${encodeURIComponent(clusterName)}/fargate-profiles`,
      { headers: { 'content-type': 'application/json' } }
    );

    return response.fargateProfileNames || [];
  }

  async eksDescribeFargateProfile(clusterName: string, fargateProfileName: string): Promise<EKSFargateProfile> {
    const response = await this.request<{ fargateProfile: Record<string, unknown> }>(
      'eks',
      'GET',
      `/clusters/${encodeURIComponent(clusterName)}/fargate-profiles/${encodeURIComponent(fargateProfileName)}`,
      { headers: { 'content-type': 'application/json' } }
    );

    const f = response.fargateProfile;
    const selectors = (f.selectors as Array<Record<string, unknown>>) || [];

    return {
      fargateProfileName: f.fargateProfileName as string,
      fargateProfileArn: f.fargateProfileArn as string,
      clusterName: f.clusterName as string,
      createdAt: f.createdAt as string | undefined,
      podExecutionRoleArn: f.podExecutionRoleArn as string,
      subnets: (f.subnets as string[]) || [],
      selectors: selectors.map((s) => ({
        namespace: s.namespace as string,
        labels: s.labels as Record<string, string> | undefined,
      })),
      status: f.status as string,
      tags: f.tags as Record<string, string> | undefined,
    };
  }

  async eksListAddons(clusterName: string): Promise<string[]> {
    const response = await this.request<{ addons?: string[] }>(
      'eks',
      'GET',
      `/clusters/${encodeURIComponent(clusterName)}/addons`,
      { headers: { 'content-type': 'application/json' } }
    );

    return response.addons || [];
  }

  async eksDescribeAddon(clusterName: string, addonName: string): Promise<EKSAddon> {
    const response = await this.request<{ addon: Record<string, unknown> }>(
      'eks',
      'GET',
      `/clusters/${encodeURIComponent(clusterName)}/addons/${encodeURIComponent(addonName)}`,
      { headers: { 'content-type': 'application/json' } }
    );

    const a = response.addon;
    const health = a.health as Record<string, unknown> | undefined;
    const issues = health?.issues as Array<Record<string, unknown>> | undefined;

    return {
      addonName: a.addonName as string,
      clusterName: a.clusterName as string,
      status: a.status as string,
      addonVersion: a.addonVersion as string,
      addonArn: a.addonArn as string | undefined,
      createdAt: a.createdAt as string | undefined,
      modifiedAt: a.modifiedAt as string | undefined,
      serviceAccountRoleArn: a.serviceAccountRoleArn as string | undefined,
      tags: a.tags as Record<string, string> | undefined,
      health: health ? {
        issues: issues?.map((i) => ({
          code: i.code as string,
          message: i.message as string,
          resourceIds: i.resourceIds as string[] | undefined,
        })),
      } : undefined,
    };
  }

  async eksListIdentityProviderConfigs(clusterName: string): Promise<Array<{ type: string; name: string }>> {
    const response = await this.request<{ identityProviderConfigs?: Array<{ type: string; name: string }> }>(
      'eks',
      'GET',
      `/clusters/${encodeURIComponent(clusterName)}/identity-provider-configs`,
      { headers: { 'content-type': 'application/json' } }
    );

    return response.identityProviderConfigs || [];
  }

  async eksDescribeIdentityProviderConfig(clusterName: string, type: string, name: string): Promise<EKSIdentityProviderConfig> {
    const response = await this.request<{ identityProviderConfig: Record<string, unknown> }>(
      'eks',
      'POST',
      `/clusters/${encodeURIComponent(clusterName)}/identity-provider-configs/describe`,
      {
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          identityProviderConfig: { type, name },
        }),
      }
    );

    const c = response.identityProviderConfig;
    const oidc = c.oidc as Record<string, unknown> | undefined;

    return {
      type: type,
      name: name,
      clusterName: clusterName,
      identityProviderConfigArn: c.identityProviderConfigArn as string | undefined,
      status: c.status as string | undefined,
      oidc: oidc ? {
        identityProviderConfigName: oidc.identityProviderConfigName as string,
        issuerUrl: oidc.issuerUrl as string,
        clientId: oidc.clientId as string,
        usernamePrefix: oidc.usernamePrefix as string | undefined,
        usernameClaim: oidc.usernameClaim as string | undefined,
        groupsPrefix: oidc.groupsPrefix as string | undefined,
        groupsClaim: oidc.groupsClaim as string | undefined,
        requiredClaims: oidc.requiredClaims as Record<string, string> | undefined,
      } : undefined,
      tags: c.tags as Record<string, string> | undefined,
    };
  }

  async eksUpdateNodegroupConfig(clusterName: string, nodegroupName: string, scalingConfig?: { minSize?: number; maxSize?: number; desiredSize?: number }): Promise<{ updateId: string; status: string }> {
    const body: Record<string, unknown> = {};
    if (scalingConfig) {
      body.scalingConfig = scalingConfig;
    }

    const response = await this.request<{ update: { id: string; status: string } }>(
      'eks',
      'POST',
      `/clusters/${encodeURIComponent(clusterName)}/node-groups/${encodeURIComponent(nodegroupName)}/update-config`,
      {
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify(body),
      }
    );

    return {
      updateId: response.update.id,
      status: response.update.status,
    };
  }

  async eksTagResource(resourceArn: string, tags: Record<string, string>): Promise<void> {
    await this.request<Record<string, unknown>>('eks', 'POST', '/tags/' + encodeURIComponent(resourceArn), {
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ tags }),
    });
  }

  async eksUntagResource(resourceArn: string, tagKeys: string[]): Promise<void> {
    await this.request<Record<string, unknown>>('eks', 'DELETE', '/tags/' + encodeURIComponent(resourceArn), {
      query: { tagKeys: tagKeys.join(',') },
      headers: { 'content-type': 'application/json' },
    });
  }

  async eksListUpdates(clusterName: string, nodegroupName?: string, addonName?: string): Promise<string[]> {
    let path = `/clusters/${encodeURIComponent(clusterName)}/updates`;
    if (nodegroupName) {
      path = `/clusters/${encodeURIComponent(clusterName)}/node-groups/${encodeURIComponent(nodegroupName)}/updates`;
    } else if (addonName) {
      path = `/clusters/${encodeURIComponent(clusterName)}/addons/${encodeURIComponent(addonName)}/updates`;
    }
    const response = await this.request<{ updateIds?: string[] }>('eks', 'GET', path, {
      headers: { 'content-type': 'application/json' },
    });
    return response.updateIds || [];
  }

  async eksDescribeUpdate(clusterName: string, updateId: string, nodegroupName?: string, addonName?: string): Promise<{ id: string; status: string; type: string; createdAt?: string; errors?: Array<{ errorCode: string; errorMessage: string }> }> {
    let path = `/clusters/${encodeURIComponent(clusterName)}/updates/${encodeURIComponent(updateId)}`;
    const query: Record<string, string> = {};
    if (nodegroupName) {
      query.nodegroupName = nodegroupName;
    }
    if (addonName) {
      query.addonName = addonName;
    }
    const response = await this.request<{ update: Record<string, unknown> }>('eks', 'GET', path, {
      query: Object.keys(query).length > 0 ? query : undefined,
      headers: { 'content-type': 'application/json' },
    });
    const u = response.update;
    const errors = u.errors as Array<Record<string, unknown>> | undefined;
    return {
      id: u.id as string,
      status: u.status as string,
      type: u.type as string,
      createdAt: u.createdAt as string | undefined,
      errors: errors?.map((e) => ({
        errorCode: e.errorCode as string,
        errorMessage: e.errorMessage as string,
      })),
    };
  }

  // ===========================================================================
  // CloudFormation
  // ===========================================================================

  async cfnListStacks(statusFilter?: string[]): Promise<Array<{ stackId: string; stackName: string; stackStatus: string; creationTime: string; lastUpdatedTime?: string; templateDescription?: string }>> {
    const query: Record<string, string> = {
      Action: 'ListStacks',
      Version: '2010-05-15',
    };
    if (statusFilter) {
      statusFilter.forEach((status, i) => {
        query[`StackStatusFilter.member.${i + 1}`] = status;
      });
    }
    const response = await this.request<string>('cloudformation', 'GET', '/', { query });

    const stacks: Array<{ stackId: string; stackName: string; stackStatus: string; creationTime: string; lastUpdatedTime?: string; templateDescription?: string }> = [];
    const memberMatches = response.matchAll(/<member>([\s\S]*?)<\/member>/g);
    for (const match of memberMatches) {
      const xml = match[1];
      stacks.push({
        stackId: this.parseXmlValue(xml, 'StackId') || '',
        stackName: this.parseXmlValue(xml, 'StackName') || '',
        stackStatus: this.parseXmlValue(xml, 'StackStatus') || '',
        creationTime: this.parseXmlValue(xml, 'CreationTime') || '',
        lastUpdatedTime: this.parseXmlValue(xml, 'LastUpdatedTime'),
        templateDescription: this.parseXmlValue(xml, 'TemplateDescription'),
      });
    }
    return stacks;
  }

  async cfnDescribeStack(stackName: string): Promise<{ stackId: string; stackName: string; stackStatus: string; stackStatusReason?: string; creationTime: string; lastUpdatedTime?: string; parameters?: Array<{ key: string; value: string }>; outputs?: Array<{ key: string; value: string; description?: string; exportName?: string }>; tags?: Array<{ key: string; value: string }> }> {
    const response = await this.request<string>('cloudformation', 'GET', '/', {
      query: { Action: 'DescribeStacks', Version: '2010-05-15', StackName: stackName },
    });

    const stackXml = response.match(/<member>([\s\S]*?)<\/member>/)?.[1] || '';
    const parameters: Array<{ key: string; value: string }> = [];
    const paramMatches = stackXml.matchAll(/<Parameters>[\s\S]*?<member>([\s\S]*?)<\/member>[\s\S]*?<\/Parameters>/g);
    for (const match of paramMatches) {
      const xml = match[1];
      parameters.push({
        key: this.parseXmlValue(xml, 'ParameterKey') || '',
        value: this.parseXmlValue(xml, 'ParameterValue') || '',
      });
    }

    const outputs: Array<{ key: string; value: string; description?: string; exportName?: string }> = [];
    const outputMatches = stackXml.matchAll(/<Outputs>[\s\S]*?<member>([\s\S]*?)<\/member>[\s\S]*?<\/Outputs>/g);
    for (const match of outputMatches) {
      const xml = match[1];
      outputs.push({
        key: this.parseXmlValue(xml, 'OutputKey') || '',
        value: this.parseXmlValue(xml, 'OutputValue') || '',
        description: this.parseXmlValue(xml, 'Description'),
        exportName: this.parseXmlValue(xml, 'ExportName'),
      });
    }

    const tags: Array<{ key: string; value: string }> = [];
    const tagMatches = stackXml.matchAll(/<Tags>[\s\S]*?<member>([\s\S]*?)<\/member>[\s\S]*?<\/Tags>/g);
    for (const match of tagMatches) {
      const xml = match[1];
      tags.push({
        key: this.parseXmlValue(xml, 'Key') || '',
        value: this.parseXmlValue(xml, 'Value') || '',
      });
    }

    return {
      stackId: this.parseXmlValue(stackXml, 'StackId') || '',
      stackName: this.parseXmlValue(stackXml, 'StackName') || '',
      stackStatus: this.parseXmlValue(stackXml, 'StackStatus') || '',
      stackStatusReason: this.parseXmlValue(stackXml, 'StackStatusReason'),
      creationTime: this.parseXmlValue(stackXml, 'CreationTime') || '',
      lastUpdatedTime: this.parseXmlValue(stackXml, 'LastUpdatedTime'),
      parameters: parameters.length > 0 ? parameters : undefined,
      outputs: outputs.length > 0 ? outputs : undefined,
      tags: tags.length > 0 ? tags : undefined,
    };
  }

  async cfnGetTemplate(stackName: string): Promise<{ templateBody: string }> {
    const response = await this.request<string>('cloudformation', 'GET', '/', {
      query: { Action: 'GetTemplate', Version: '2010-05-15', StackName: stackName },
    });
    return {
      templateBody: this.parseXmlValue(response, 'TemplateBody') || '',
    };
  }

  async cfnListStackResources(stackName: string): Promise<Array<{ logicalResourceId: string; physicalResourceId?: string; resourceType: string; resourceStatus: string; lastUpdatedTimestamp?: string }>> {
    const response = await this.request<string>('cloudformation', 'GET', '/', {
      query: { Action: 'ListStackResources', Version: '2010-05-15', StackName: stackName },
    });

    const resources: Array<{ logicalResourceId: string; physicalResourceId?: string; resourceType: string; resourceStatus: string; lastUpdatedTimestamp?: string }> = [];
    const memberMatches = response.matchAll(/<member>([\s\S]*?)<\/member>/g);
    for (const match of memberMatches) {
      const xml = match[1];
      resources.push({
        logicalResourceId: this.parseXmlValue(xml, 'LogicalResourceId') || '',
        physicalResourceId: this.parseXmlValue(xml, 'PhysicalResourceId'),
        resourceType: this.parseXmlValue(xml, 'ResourceType') || '',
        resourceStatus: this.parseXmlValue(xml, 'ResourceStatus') || '',
        lastUpdatedTimestamp: this.parseXmlValue(xml, 'LastUpdatedTimestamp'),
      });
    }
    return resources;
  }

  async cfnDescribeStackEvents(stackName: string): Promise<Array<{ eventId: string; stackName: string; logicalResourceId?: string; physicalResourceId?: string; resourceType?: string; resourceStatus?: string; resourceStatusReason?: string; timestamp: string }>> {
    const response = await this.request<string>('cloudformation', 'GET', '/', {
      query: { Action: 'DescribeStackEvents', Version: '2010-05-15', StackName: stackName },
    });

    const events: Array<{ eventId: string; stackName: string; logicalResourceId?: string; physicalResourceId?: string; resourceType?: string; resourceStatus?: string; resourceStatusReason?: string; timestamp: string }> = [];
    const memberMatches = response.matchAll(/<member>([\s\S]*?)<\/member>/g);
    for (const match of memberMatches) {
      const xml = match[1];
      events.push({
        eventId: this.parseXmlValue(xml, 'EventId') || '',
        stackName: this.parseXmlValue(xml, 'StackName') || '',
        logicalResourceId: this.parseXmlValue(xml, 'LogicalResourceId'),
        physicalResourceId: this.parseXmlValue(xml, 'PhysicalResourceId'),
        resourceType: this.parseXmlValue(xml, 'ResourceType'),
        resourceStatus: this.parseXmlValue(xml, 'ResourceStatus'),
        resourceStatusReason: this.parseXmlValue(xml, 'ResourceStatusReason'),
        timestamp: this.parseXmlValue(xml, 'Timestamp') || '',
      });
    }
    return events;
  }

  async cfnCreateStack(params: { stackName: string; templateBody?: string; templateUrl?: string; parameters?: Array<{ key: string; value: string }>; capabilities?: string[]; tags?: Array<{ key: string; value: string }> }): Promise<{ stackId: string }> {
    const query: Record<string, string> = {
      Action: 'CreateStack',
      Version: '2010-05-15',
      StackName: params.stackName,
    };
    if (params.templateBody) query.TemplateBody = params.templateBody;
    if (params.templateUrl) query.TemplateURL = params.templateUrl;
    if (params.parameters) {
      params.parameters.forEach((p, i) => {
        query[`Parameters.member.${i + 1}.ParameterKey`] = p.key;
        query[`Parameters.member.${i + 1}.ParameterValue`] = p.value;
      });
    }
    if (params.capabilities) {
      params.capabilities.forEach((c, i) => {
        query[`Capabilities.member.${i + 1}`] = c;
      });
    }
    if (params.tags) {
      params.tags.forEach((t, i) => {
        query[`Tags.member.${i + 1}.Key`] = t.key;
        query[`Tags.member.${i + 1}.Value`] = t.value;
      });
    }
    const response = await this.request<string>('cloudformation', 'GET', '/', { query });
    return {
      stackId: this.parseXmlValue(response, 'StackId') || '',
    };
  }

  async cfnUpdateStack(params: { stackName: string; templateBody?: string; templateUrl?: string; parameters?: Array<{ key: string; value: string }>; capabilities?: string[] }): Promise<{ stackId: string }> {
    const query: Record<string, string> = {
      Action: 'UpdateStack',
      Version: '2010-05-15',
      StackName: params.stackName,
    };
    if (params.templateBody) query.TemplateBody = params.templateBody;
    if (params.templateUrl) query.TemplateURL = params.templateUrl;
    if (params.parameters) {
      params.parameters.forEach((p, i) => {
        query[`Parameters.member.${i + 1}.ParameterKey`] = p.key;
        query[`Parameters.member.${i + 1}.ParameterValue`] = p.value;
      });
    }
    if (params.capabilities) {
      params.capabilities.forEach((c, i) => {
        query[`Capabilities.member.${i + 1}`] = c;
      });
    }
    const response = await this.request<string>('cloudformation', 'GET', '/', { query });
    return {
      stackId: this.parseXmlValue(response, 'StackId') || '',
    };
  }

  async cfnDeleteStack(stackName: string): Promise<void> {
    await this.request<string>('cloudformation', 'GET', '/', {
      query: { Action: 'DeleteStack', Version: '2010-05-15', StackName: stackName },
    });
  }

  async cfnListChangeSets(stackName: string): Promise<Array<{ changeSetId: string; changeSetName: string; status: string; statusReason?: string; executionStatus: string; creationTime: string }>> {
    const response = await this.request<string>('cloudformation', 'GET', '/', {
      query: { Action: 'ListChangeSets', Version: '2010-05-15', StackName: stackName },
    });

    const changeSets: Array<{ changeSetId: string; changeSetName: string; status: string; statusReason?: string; executionStatus: string; creationTime: string }> = [];
    const memberMatches = response.matchAll(/<member>([\s\S]*?)<\/member>/g);
    for (const match of memberMatches) {
      const xml = match[1];
      changeSets.push({
        changeSetId: this.parseXmlValue(xml, 'ChangeSetId') || '',
        changeSetName: this.parseXmlValue(xml, 'ChangeSetName') || '',
        status: this.parseXmlValue(xml, 'Status') || '',
        statusReason: this.parseXmlValue(xml, 'StatusReason'),
        executionStatus: this.parseXmlValue(xml, 'ExecutionStatus') || '',
        creationTime: this.parseXmlValue(xml, 'CreationTime') || '',
      });
    }
    return changeSets;
  }

  async cfnDescribeChangeSet(stackName: string, changeSetName: string): Promise<{ changeSetId: string; changeSetName: string; stackName: string; status: string; statusReason?: string; executionStatus: string; changes?: Array<{ resourceChange: { action: string; logicalResourceId: string; physicalResourceId?: string; resourceType: string; replacement?: string } }> }> {
    const response = await this.request<string>('cloudformation', 'GET', '/', {
      query: { Action: 'DescribeChangeSet', Version: '2010-05-15', StackName: stackName, ChangeSetName: changeSetName },
    });

    const changes: Array<{ resourceChange: { action: string; logicalResourceId: string; physicalResourceId?: string; resourceType: string; replacement?: string } }> = [];
    const changeMatches = response.matchAll(/<member>([\s\S]*?)<ResourceChange>([\s\S]*?)<\/ResourceChange>[\s\S]*?<\/member>/g);
    for (const match of changeMatches) {
      const xml = match[2];
      changes.push({
        resourceChange: {
          action: this.parseXmlValue(xml, 'Action') || '',
          logicalResourceId: this.parseXmlValue(xml, 'LogicalResourceId') || '',
          physicalResourceId: this.parseXmlValue(xml, 'PhysicalResourceId'),
          resourceType: this.parseXmlValue(xml, 'ResourceType') || '',
          replacement: this.parseXmlValue(xml, 'Replacement'),
        },
      });
    }

    return {
      changeSetId: this.parseXmlValue(response, 'ChangeSetId') || '',
      changeSetName: this.parseXmlValue(response, 'ChangeSetName') || '',
      stackName: this.parseXmlValue(response, 'StackName') || '',
      status: this.parseXmlValue(response, 'Status') || '',
      statusReason: this.parseXmlValue(response, 'StatusReason'),
      executionStatus: this.parseXmlValue(response, 'ExecutionStatus') || '',
      changes: changes.length > 0 ? changes : undefined,
    };
  }

  async cfnCreateChangeSet(params: { stackName: string; changeSetName: string; templateBody?: string; templateUrl?: string; parameters?: Array<{ key: string; value: string }>; capabilities?: string[]; changeSetType?: 'CREATE' | 'UPDATE' }): Promise<{ changeSetId: string; stackId: string }> {
    const query: Record<string, string> = {
      Action: 'CreateChangeSet',
      Version: '2010-05-15',
      StackName: params.stackName,
      ChangeSetName: params.changeSetName,
    };
    if (params.templateBody) query.TemplateBody = params.templateBody;
    if (params.templateUrl) query.TemplateURL = params.templateUrl;
    if (params.changeSetType) query.ChangeSetType = params.changeSetType;
    if (params.parameters) {
      params.parameters.forEach((p, i) => {
        query[`Parameters.member.${i + 1}.ParameterKey`] = p.key;
        query[`Parameters.member.${i + 1}.ParameterValue`] = p.value;
      });
    }
    if (params.capabilities) {
      params.capabilities.forEach((c, i) => {
        query[`Capabilities.member.${i + 1}`] = c;
      });
    }
    const response = await this.request<string>('cloudformation', 'GET', '/', { query });
    return {
      changeSetId: this.parseXmlValue(response, 'Id') || '',
      stackId: this.parseXmlValue(response, 'StackId') || '',
    };
  }

  async cfnExecuteChangeSet(stackName: string, changeSetName: string): Promise<void> {
    await this.request<string>('cloudformation', 'GET', '/', {
      query: { Action: 'ExecuteChangeSet', Version: '2010-05-15', StackName: stackName, ChangeSetName: changeSetName },
    });
  }

  async cfnDeleteChangeSet(stackName: string, changeSetName: string): Promise<void> {
    await this.request<string>('cloudformation', 'GET', '/', {
      query: { Action: 'DeleteChangeSet', Version: '2010-05-15', StackName: stackName, ChangeSetName: changeSetName },
    });
  }

  async cfnValidateTemplate(templateBody?: string, templateUrl?: string): Promise<{ parameters?: Array<{ parameterKey: string; defaultValue?: string; noEcho?: boolean; description?: string }>; description?: string; capabilities?: string[] }> {
    const query: Record<string, string> = {
      Action: 'ValidateTemplate',
      Version: '2010-05-15',
    };
    if (templateBody) query.TemplateBody = templateBody;
    if (templateUrl) query.TemplateURL = templateUrl;
    const response = await this.request<string>('cloudformation', 'GET', '/', { query });

    const parameters: Array<{ parameterKey: string; defaultValue?: string; noEcho?: boolean; description?: string }> = [];
    const paramMatches = response.matchAll(/<member>([\s\S]*?)<\/member>/g);
    for (const match of paramMatches) {
      const xml = match[1];
      if (xml.includes('<ParameterKey>')) {
        parameters.push({
          parameterKey: this.parseXmlValue(xml, 'ParameterKey') || '',
          defaultValue: this.parseXmlValue(xml, 'DefaultValue'),
          noEcho: this.parseXmlValue(xml, 'NoEcho') === 'true',
          description: this.parseXmlValue(xml, 'Description'),
        });
      }
    }

    const capabilities: string[] = [];
    const capMatches = response.matchAll(/<Capabilities>[\s\S]*?<member>([^<]+)<\/member>[\s\S]*?<\/Capabilities>/g);
    for (const match of capMatches) {
      capabilities.push(match[1]);
    }

    return {
      parameters: parameters.length > 0 ? parameters : undefined,
      description: this.parseXmlValue(response, 'Description'),
      capabilities: capabilities.length > 0 ? capabilities : undefined,
    };
  }
}

// =============================================================================
// Factory Function
// =============================================================================

/**
 * Create an AWS client instance with tenant-specific credentials.
 *
 * @param credentials - AWS credentials parsed from request headers
 */
export function createAwsClient(credentials: AwsCredentials): AwsClient {
  return new AwsClientImpl(credentials);
}
