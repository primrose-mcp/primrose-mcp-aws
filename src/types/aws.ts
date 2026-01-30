/**
 * AWS Entity Types
 *
 * Type definitions for AWS service responses.
 */

// =============================================================================
// Common Types
// =============================================================================

export interface PaginationParams {
  /** Maximum number of items to return */
  maxResults?: number;
  /** Pagination token from previous response */
  nextToken?: string;
}

export interface PaginatedResponse<T> {
  items: T[];
  count: number;
  nextToken?: string;
  hasMore: boolean;
}

export type ResponseFormat = 'json' | 'markdown';

// =============================================================================
// STS Types
// =============================================================================

export interface CallerIdentity {
  userId: string;
  account: string;
  arn: string;
}

export interface STSCredentials {
  accessKeyId: string;
  secretAccessKey: string;
  sessionToken: string;
  expiration: string;
}

export interface STSAssumedRoleUser {
  assumedRoleId: string;
  arn: string;
}

// =============================================================================
// S3 Types
// =============================================================================

export interface S3Bucket {
  name: string;
  creationDate: string;
}

export interface S3Object {
  key: string;
  size: number;
  lastModified: string;
  etag?: string;
  storageClass?: string;
}

export interface S3ListObjectsParams {
  bucket: string;
  prefix?: string;
  delimiter?: string;
  maxKeys?: number;
  continuationToken?: string;
}

export interface S3ListObjectsResponse {
  objects: S3Object[];
  commonPrefixes: string[];
  isTruncated: boolean;
  nextContinuationToken?: string;
}

export interface S3GetObjectParams {
  bucket: string;
  key: string;
}

export interface S3PutObjectParams {
  bucket: string;
  key: string;
  body: string;
  contentType?: string;
}

export interface S3DeleteObjectParams {
  bucket: string;
  key: string;
}

export interface S3CopyObjectParams {
  sourceBucket: string;
  sourceKey: string;
  destinationBucket: string;
  destinationKey: string;
}

export interface S3HeadObjectResponse {
  contentLength: number;
  contentType?: string;
  etag?: string;
  lastModified?: string;
  metadata?: Record<string, string>;
  storageClass?: string;
  versionId?: string;
}

export interface S3BucketVersioning {
  status?: 'Enabled' | 'Suspended';
  mfaDelete?: 'Enabled' | 'Disabled';
}

export interface S3BucketPolicy {
  policy: string;
}

export interface S3CorsRule {
  allowedHeaders?: string[];
  allowedMethods: string[];
  allowedOrigins: string[];
  exposeHeaders?: string[];
  maxAgeSeconds?: number;
}

export interface S3LifecycleRule {
  id?: string;
  status: 'Enabled' | 'Disabled';
  prefix?: string;
  expiration?: {
    days?: number;
    date?: string;
    expiredObjectDeleteMarker?: boolean;
  };
  transitions?: Array<{
    days?: number;
    date?: string;
    storageClass: string;
  }>;
  noncurrentVersionExpiration?: {
    noncurrentDays?: number;
  };
}

export interface S3BucketTagging {
  tagSet: Array<{ key: string; value: string }>;
}

export interface S3BucketEncryption {
  rules: Array<{
    applyServerSideEncryptionByDefault?: {
      sseAlgorithm: 'AES256' | 'aws:kms';
      kmsMasterKeyId?: string;
    };
    bucketKeyEnabled?: boolean;
  }>;
}

export interface S3WebsiteConfiguration {
  indexDocument?: string;
  errorDocument?: string;
  redirectAllRequestsTo?: {
    hostName: string;
    protocol?: 'http' | 'https';
  };
  routingRules?: Array<{
    condition?: {
      httpErrorCodeReturnedEquals?: string;
      keyPrefixEquals?: string;
    };
    redirect: {
      hostName?: string;
      httpRedirectCode?: string;
      protocol?: 'http' | 'https';
      replaceKeyPrefixWith?: string;
      replaceKeyWith?: string;
    };
  }>;
}

export interface S3ObjectTagging {
  tagSet: Array<{ key: string; value: string }>;
}

// =============================================================================
// EC2 Types
// =============================================================================

export interface EC2Instance {
  instanceId: string;
  instanceType: string;
  state: string;
  publicIpAddress?: string;
  privateIpAddress?: string;
  launchTime: string;
  availabilityZone?: string;
  vpcId?: string;
  subnetId?: string;
  securityGroups: Array<{ groupId: string; groupName: string }>;
  tags: Array<{ key: string; value: string }>;
}

export interface EC2SecurityGroup {
  groupId: string;
  groupName: string;
  description: string;
  vpcId?: string;
  ingressRules: EC2SecurityGroupRule[];
  egressRules: EC2SecurityGroupRule[];
  tags: Array<{ key: string; value: string }>;
}

export interface EC2SecurityGroupRule {
  protocol: string;
  fromPort?: number;
  toPort?: number;
  cidrIpv4?: string;
  cidrIpv6?: string;
  sourceSecurityGroupId?: string;
  description?: string;
}

export interface EC2Volume {
  volumeId: string;
  size: number;
  volumeType: string;
  state: string;
  availabilityZone: string;
  encrypted: boolean;
  iops?: number;
  attachments: Array<{
    instanceId: string;
    device: string;
    state: string;
  }>;
  tags: Array<{ key: string; value: string }>;
}

export interface EC2Vpc {
  vpcId: string;
  cidrBlock: string;
  state: string;
  isDefault: boolean;
  tags: Array<{ key: string; value: string }>;
}

export interface EC2Subnet {
  subnetId: string;
  vpcId: string;
  cidrBlock: string;
  availabilityZone: string;
  availableIpAddressCount: number;
  mapPublicIpOnLaunch: boolean;
  tags: Array<{ key: string; value: string }>;
}

export interface EC2Image {
  imageId: string;
  name: string;
  description?: string;
  state: string;
  architecture: string;
  platform?: string;
  creationDate?: string;
  ownerId: string;
  public: boolean;
  tags: Array<{ key: string; value: string }>;
}

export interface EC2KeyPair {
  keyName: string;
  keyPairId: string;
  keyFingerprint: string;
  tags: Array<{ key: string; value: string }>;
}

export interface EC2Snapshot {
  snapshotId: string;
  volumeId: string;
  state: string;
  progress: string;
  startTime: string;
  volumeSize: number;
  description?: string;
  ownerId: string;
  encrypted: boolean;
  tags: Array<{ key: string; value: string }>;
}

export interface EC2NatGateway {
  natGatewayId: string;
  vpcId: string;
  subnetId: string;
  state: string;
  connectivityType: string;
  natGatewayAddresses: Array<{
    allocationId?: string;
    networkInterfaceId?: string;
    privateIp?: string;
    publicIp?: string;
  }>;
  createTime: string;
  tags: Array<{ key: string; value: string }>;
}

export interface EC2LaunchTemplate {
  launchTemplateId: string;
  launchTemplateName: string;
  createTime: string;
  createdBy: string;
  defaultVersionNumber: number;
  latestVersionNumber: number;
  tags: Array<{ key: string; value: string }>;
}

export interface EC2ElasticIp {
  publicIp: string;
  allocationId: string;
  domain: string;
  instanceId?: string;
  associationId?: string;
  networkInterfaceId?: string;
  privateIpAddress?: string;
  tags: Array<{ key: string; value: string }>;
}

export interface EC2AvailabilityZone {
  zoneName: string;
  zoneId: string;
  regionName: string;
  state: string;
  zoneType: string;
}

// =============================================================================
// Lambda Types
// =============================================================================

export interface LambdaFunction {
  functionName: string;
  functionArn: string;
  runtime?: string;
  handler: string;
  codeSize: number;
  memorySize: number;
  timeout: number;
  lastModified: string;
  description?: string;
  role: string;
  state?: string;
  stateReason?: string;
  environment?: Record<string, string>;
  tags?: Record<string, string>;
}

export interface LambdaInvokeParams {
  functionName: string;
  payload?: Record<string, unknown>;
  invocationType?: 'RequestResponse' | 'Event' | 'DryRun';
}

export interface LambdaInvokeResponse {
  statusCode: number;
  payload?: unknown;
  functionError?: string;
  executedVersion?: string;
  logResult?: string;
}

export interface LambdaAlias {
  name: string;
  functionVersion: string;
  description?: string;
  revisionId?: string;
}

export interface LambdaVersion {
  version: string;
  description?: string;
  revisionId?: string;
  lastModified?: string;
}

export interface LambdaEventSourceMapping {
  uuid: string;
  functionArn: string;
  eventSourceArn?: string;
  state: string;
  stateTransitionReason?: string;
  batchSize?: number;
  maximumBatchingWindowInSeconds?: number;
  lastModified?: string;
  startingPosition?: string;
}

export interface LambdaLayer {
  layerName: string;
  layerArn: string;
  latestMatchingVersion?: {
    layerVersionArn: string;
    version: number;
    description?: string;
    compatibleRuntimes?: string[];
    createdDate?: string;
  };
}

export interface LambdaLayerVersion {
  layerVersionArn: string;
  version: number;
  description?: string;
  createdDate?: string;
  compatibleRuntimes?: string[];
  compatibleArchitectures?: string[];
}

// =============================================================================
// IAM Types
// =============================================================================

export interface IAMUser {
  userName: string;
  userId: string;
  arn: string;
  path: string;
  createDate: string;
  passwordLastUsed?: string;
  tags?: Array<{ key: string; value: string }>;
}

export interface IAMRole {
  roleName: string;
  roleId: string;
  arn: string;
  path: string;
  createDate: string;
  description?: string;
  assumeRolePolicyDocument?: string;
  maxSessionDuration?: number;
  tags?: Array<{ key: string; value: string }>;
}

export interface IAMPolicy {
  policyName: string;
  policyId: string;
  arn: string;
  path: string;
  createDate: string;
  updateDate: string;
  defaultVersionId: string;
  attachmentCount: number;
  isAttachable: boolean;
  description?: string;
}

export interface IAMGroup {
  groupName: string;
  groupId: string;
  arn: string;
  path: string;
  createDate: string;
}

export interface IAMAccessKey {
  accessKeyId: string;
  status: 'Active' | 'Inactive';
  createDate: string;
  userName: string;
}

export interface IAMAttachedPolicy {
  policyName: string;
  policyArn: string;
}

export interface IAMMfaDevice {
  serialNumber: string;
  userName: string;
  enableDate: string;
}

export interface IAMGroupForUser {
  groupName: string;
  groupId: string;
  arn: string;
  path: string;
  createDate: string;
}

export interface IAMInstanceProfile {
  instanceProfileName: string;
  instanceProfileId: string;
  arn: string;
  path: string;
  createDate: string;
  roles: Array<{ roleName: string; roleId: string; arn: string }>;
}

// =============================================================================
// CloudWatch Types
// =============================================================================

export interface CloudWatchMetric {
  namespace: string;
  metricName: string;
  dimensions?: Array<{ name: string; value: string }>;
}

export interface CloudWatchMetricDatapoint {
  timestamp: string;
  average?: number;
  sum?: number;
  minimum?: number;
  maximum?: number;
  sampleCount?: number;
  unit?: string;
}

export interface CloudWatchAlarm {
  alarmName: string;
  alarmArn: string;
  stateValue: 'OK' | 'ALARM' | 'INSUFFICIENT_DATA';
  stateReason?: string;
  metricName: string;
  namespace: string;
  statistic: string;
  period: number;
  threshold: number;
  comparisonOperator: string;
  evaluationPeriods: number;
  actionsEnabled: boolean;
  alarmActions?: string[];
  dimensions?: Array<{ name: string; value: string }>;
}

export interface CloudWatchLogGroup {
  logGroupName: string;
  arn?: string;
  creationTime?: number;
  storedBytes?: number;
  retentionInDays?: number;
}

export interface CloudWatchLogStream {
  logStreamName: string;
  creationTime?: number;
  firstEventTimestamp?: number;
  lastEventTimestamp?: number;
  lastIngestionTime?: number;
  storedBytes?: number;
}

export interface CloudWatchLogEvent {
  timestamp: number;
  message: string;
  ingestionTime?: number;
}

// =============================================================================
// DynamoDB Types
// =============================================================================

export interface DynamoDBTable {
  tableName: string;
  tableArn: string;
  tableStatus: string;
  creationDateTime: string;
  itemCount?: number;
  tableSizeBytes?: number;
  keySchema: Array<{ attributeName: string; keyType: 'HASH' | 'RANGE' }>;
  attributeDefinitions: Array<{ attributeName: string; attributeType: 'S' | 'N' | 'B' }>;
  billingModeSummary?: {
    billingMode: 'PROVISIONED' | 'PAY_PER_REQUEST';
  };
  provisionedThroughput?: {
    readCapacityUnits: number;
    writeCapacityUnits: number;
  };
}

export interface DynamoDBItem {
  [key: string]: unknown;
}

export interface DynamoDBQueryParams {
  tableName: string;
  keyConditionExpression: string;
  expressionAttributeValues: Record<string, unknown>;
  expressionAttributeNames?: Record<string, string>;
  filterExpression?: string;
  limit?: number;
  scanIndexForward?: boolean;
  exclusiveStartKey?: Record<string, unknown>;
  indexName?: string;
}

export interface DynamoDBScanParams {
  tableName: string;
  filterExpression?: string;
  expressionAttributeValues?: Record<string, unknown>;
  expressionAttributeNames?: Record<string, string>;
  limit?: number;
  exclusiveStartKey?: Record<string, unknown>;
  indexName?: string;
}

export interface DynamoDBPutItemParams {
  tableName: string;
  item: Record<string, unknown>;
  conditionExpression?: string;
  expressionAttributeValues?: Record<string, unknown>;
  expressionAttributeNames?: Record<string, string>;
}

export interface DynamoDBGetItemParams {
  tableName: string;
  key: Record<string, unknown>;
  consistentRead?: boolean;
  projectionExpression?: string;
  expressionAttributeNames?: Record<string, string>;
}

export interface DynamoDBDeleteItemParams {
  tableName: string;
  key: Record<string, unknown>;
  conditionExpression?: string;
  expressionAttributeValues?: Record<string, unknown>;
  expressionAttributeNames?: Record<string, string>;
}

export interface DynamoDBUpdateItemParams {
  tableName: string;
  key: Record<string, unknown>;
  updateExpression: string;
  expressionAttributeValues?: Record<string, unknown>;
  expressionAttributeNames?: Record<string, string>;
  conditionExpression?: string;
}

export interface DynamoDBBatchGetItemParams {
  requestItems: Record<
    string,
    {
      keys: Array<Record<string, unknown>>;
      projectionExpression?: string;
      expressionAttributeNames?: Record<string, string>;
      consistentRead?: boolean;
    }
  >;
}

export interface DynamoDBBatchWriteItemParams {
  requestItems: Record<
    string,
    Array<
      | { putRequest: { item: Record<string, unknown> } }
      | { deleteRequest: { key: Record<string, unknown> } }
    >
  >;
}

// =============================================================================
// SQS Types
// =============================================================================

export interface SQSQueue {
  queueUrl: string;
  queueArn?: string;
  approximateNumberOfMessages?: number;
  approximateNumberOfMessagesNotVisible?: number;
  approximateNumberOfMessagesDelayed?: number;
  createdTimestamp?: string;
  visibilityTimeout?: number;
  maximumMessageSize?: number;
  messageRetentionPeriod?: number;
  delaySeconds?: number;
}

export interface SQSMessage {
  messageId: string;
  receiptHandle: string;
  body: string;
  md5OfBody: string;
  attributes?: Record<string, string>;
  messageAttributes?: Record<string, { dataType: string; stringValue?: string; binaryValue?: string }>;
}

export interface SQSSendMessageParams {
  queueUrl: string;
  messageBody: string;
  delaySeconds?: number;
  messageAttributes?: Record<string, { dataType: string; stringValue?: string }>;
}

export interface SQSReceiveMessageParams {
  queueUrl: string;
  maxNumberOfMessages?: number;
  visibilityTimeout?: number;
  waitTimeSeconds?: number;
  attributeNames?: string[];
  messageAttributeNames?: string[];
}

// =============================================================================
// SNS Types
// =============================================================================

export interface SNSTopic {
  topicArn: string;
  displayName?: string;
  subscriptionsConfirmed?: number;
  subscriptionsPending?: number;
  subscriptionsDeleted?: number;
}

export interface SNSSubscription {
  subscriptionArn: string;
  topicArn: string;
  protocol: string;
  endpoint: string;
  owner: string;
}

export interface SNSPublishParams {
  topicArn?: string;
  targetArn?: string;
  message: string;
  subject?: string;
  messageAttributes?: Record<string, { dataType: string; stringValue?: string }>;
}

export interface SNSTopicAttributes {
  topicArn: string;
  displayName?: string;
  owner?: string;
  policy?: string;
  subscriptionsConfirmed?: number;
  subscriptionsPending?: number;
  subscriptionsDeleted?: number;
  effectiveDeliveryPolicy?: string;
  kmsMasterKeyId?: string;
}

// =============================================================================
// Secrets Manager Types
// =============================================================================

export interface SecretInfo {
  arn: string;
  name: string;
  description?: string;
  lastChangedDate?: string;
  lastAccessedDate?: string;
  lastRotatedDate?: string;
  rotationEnabled?: boolean;
  tags?: Array<{ key: string; value: string }>;
}

export interface SecretValue {
  arn: string;
  name: string;
  versionId?: string;
  secretString?: string;
  secretBinary?: string;
  versionStages?: string[];
  createdDate?: string;
}

// =============================================================================
// Route53 Types
// =============================================================================

export interface Route53HostedZone {
  id: string;
  name: string;
  resourceRecordSetCount?: number;
  callerReference: string;
  config?: {
    privateZone: boolean;
    comment?: string;
  };
}

export interface Route53RecordSet {
  name: string;
  type: string;
  ttl?: number;
  resourceRecords?: Array<{ value: string }>;
  aliasTarget?: {
    hostedZoneId: string;
    dnsName: string;
    evaluateTargetHealth: boolean;
  };
  setIdentifier?: string;
  weight?: number;
  region?: string;
  healthCheckId?: string;
}

// =============================================================================
// CloudFront Types
// =============================================================================

export interface CloudFrontDistribution {
  id: string;
  arn: string;
  status: string;
  domainName: string;
  enabled: boolean;
  lastModifiedTime: string;
  origins: Array<{
    id: string;
    domainName: string;
    originPath?: string;
    s3OriginConfig?: { originAccessIdentity: string };
    customOriginConfig?: {
      httpPort: number;
      httpsPort: number;
      originProtocolPolicy: string;
    };
  }>;
  defaultCacheBehavior: {
    targetOriginId: string;
    viewerProtocolPolicy: string;
    allowedMethods: string[];
    cachedMethods: string[];
  };
  aliases?: string[];
  priceClass: string;
  comment?: string;
}

export interface CloudFrontInvalidation {
  id: string;
  status: string;
  createTime: string;
  paths: string[];
}

export interface CloudFrontInvalidationSummary {
  id: string;
  status: string;
  createTime: string;
}

// =============================================================================
// ECS Types
// =============================================================================

export interface ECSCluster {
  clusterArn: string;
  clusterName: string;
  status: string;
  registeredContainerInstancesCount: number;
  runningTasksCount: number;
  pendingTasksCount: number;
  activeServicesCount: number;
  capacityProviders?: string[];
}

export interface ECSService {
  serviceArn: string;
  serviceName: string;
  clusterArn: string;
  status: string;
  desiredCount: number;
  runningCount: number;
  pendingCount: number;
  launchType?: string;
  taskDefinition: string;
  deploymentConfiguration?: {
    maximumPercent: number;
    minimumHealthyPercent: number;
  };
  loadBalancers?: Array<{
    targetGroupArn: string;
    containerName: string;
    containerPort: number;
  }>;
}

export interface ECSTask {
  taskArn: string;
  taskDefinitionArn: string;
  clusterArn: string;
  lastStatus: string;
  desiredStatus: string;
  cpu?: string;
  memory?: string;
  launchType?: string;
  startedAt?: string;
  stoppedAt?: string;
  stoppedReason?: string;
  containers: Array<{
    containerArn: string;
    name: string;
    lastStatus: string;
    exitCode?: number;
    networkInterfaces?: Array<{
      attachmentId: string;
      privateIpv4Address: string;
    }>;
  }>;
}

export interface ECSTaskDefinition {
  taskDefinitionArn: string;
  family: string;
  revision: number;
  status: string;
  networkMode?: string;
  requiresCompatibilities?: string[];
  cpu?: string;
  memory?: string;
  containerDefinitions: Array<{
    name: string;
    image: string;
    cpu?: number;
    memory?: number;
    essential?: boolean;
    portMappings?: Array<{
      containerPort: number;
      hostPort?: number;
      protocol?: string;
    }>;
    environment?: Array<{ name: string; value: string }>;
  }>;
}

export interface ECSNetworkConfiguration {
  awsvpcConfiguration?: {
    subnets: string[];
    securityGroups?: string[];
    assignPublicIp?: 'ENABLED' | 'DISABLED';
  };
}

// =============================================================================
// RDS Types
// =============================================================================

export interface RDSInstance {
  dbInstanceIdentifier: string;
  dbInstanceArn: string;
  dbInstanceClass: string;
  engine: string;
  engineVersion: string;
  dbInstanceStatus: string;
  masterUsername: string;
  endpoint?: {
    address: string;
    port: number;
    hostedZoneId: string;
  };
  allocatedStorage: number;
  storageType: string;
  multiAZ: boolean;
  availabilityZone?: string;
  vpcSecurityGroups: Array<{ vpcSecurityGroupId: string; status: string }>;
  dbSubnetGroup?: {
    dbSubnetGroupName: string;
    dbSubnetGroupDescription: string;
    vpcId: string;
  };
  publiclyAccessible: boolean;
  storageEncrypted: boolean;
  instanceCreateTime?: string;
  backupRetentionPeriod?: number;
  tags?: Array<{ key: string; value: string }>;
}

export interface RDSCluster {
  dbClusterIdentifier: string;
  dbClusterArn: string;
  engine: string;
  engineVersion: string;
  status: string;
  endpoint?: string;
  readerEndpoint?: string;
  port: number;
  masterUsername: string;
  allocatedStorage?: number;
  multiAZ: boolean;
  clusterMembers: Array<{
    dbInstanceIdentifier: string;
    isClusterWriter: boolean;
    dbClusterParameterGroupStatus: string;
  }>;
  vpcSecurityGroups: Array<{ vpcSecurityGroupId: string; status: string }>;
  storageEncrypted: boolean;
  clusterCreateTime?: string;
  backupRetentionPeriod?: number;
  tags?: Array<{ key: string; value: string }>;
}

export interface RDSSnapshot {
  dbSnapshotIdentifier: string;
  dbSnapshotArn: string;
  dbInstanceIdentifier: string;
  snapshotType: string;
  status: string;
  engine: string;
  engineVersion: string;
  allocatedStorage: number;
  snapshotCreateTime?: string;
  encrypted: boolean;
  percentProgress?: number;
}

// =============================================================================
// EKS Types
// =============================================================================

export interface EKSCluster {
  name: string;
  arn: string;
  createdAt?: string;
  version: string;
  endpoint?: string;
  roleArn: string;
  status: string;
  certificateAuthority?: { data: string };
  platformVersion?: string;
  tags?: Record<string, string>;
  resourcesVpcConfig?: {
    subnetIds: string[];
    securityGroupIds: string[];
    clusterSecurityGroupId?: string;
    vpcId?: string;
    endpointPublicAccess: boolean;
    endpointPrivateAccess: boolean;
    publicAccessCidrs?: string[];
  };
}

export interface EKSNodegroup {
  nodegroupName: string;
  nodegroupArn: string;
  clusterName: string;
  version?: string;
  releaseVersion?: string;
  createdAt?: string;
  modifiedAt?: string;
  status: string;
  capacityType?: string;
  scalingConfig?: {
    minSize: number;
    maxSize: number;
    desiredSize: number;
  };
  instanceTypes?: string[];
  subnets: string[];
  amiType?: string;
  nodeRole: string;
  labels?: Record<string, string>;
  tags?: Record<string, string>;
}

export interface EKSFargateProfile {
  fargateProfileName: string;
  fargateProfileArn: string;
  clusterName: string;
  createdAt?: string;
  podExecutionRoleArn: string;
  subnets: string[];
  selectors: Array<{
    namespace: string;
    labels?: Record<string, string>;
  }>;
  status: string;
  tags?: Record<string, string>;
}

export interface EKSAddon {
  addonName: string;
  clusterName: string;
  status: string;
  addonVersion: string;
  addonArn?: string;
  createdAt?: string;
  modifiedAt?: string;
  serviceAccountRoleArn?: string;
  tags?: Record<string, string>;
  health?: {
    issues?: Array<{
      code: string;
      message: string;
      resourceIds?: string[];
    }>;
  };
}

export interface EKSIdentityProviderConfig {
  type: string;
  name: string;
  clusterName?: string;
  identityProviderConfigArn?: string;
  status?: string;
  oidc?: {
    identityProviderConfigName: string;
    issuerUrl: string;
    clientId: string;
    usernamePrefix?: string;
    usernameClaim?: string;
    groupsPrefix?: string;
    groupsClaim?: string;
    requiredClaims?: Record<string, string>;
  };
  tags?: Record<string, string>;
}

// =============================================================================
// Additional RDS Types
// =============================================================================

export interface RDSDBParameterGroup {
  dbParameterGroupName: string;
  dbParameterGroupFamily: string;
  description: string;
  dbParameterGroupArn?: string;
}

export interface RDSDBSubnetGroup {
  dbSubnetGroupName: string;
  dbSubnetGroupDescription: string;
  vpcId: string;
  subnetGroupStatus: string;
  subnets: Array<{
    subnetIdentifier: string;
    subnetAvailabilityZone?: { name: string };
    subnetStatus?: string;
  }>;
  dbSubnetGroupArn?: string;
}

// =============================================================================
// Additional Route53 Types
// =============================================================================

export interface Route53HealthCheck {
  id: string;
  callerReference: string;
  healthCheckConfig: {
    ipAddress?: string;
    port?: number;
    type: string;
    resourcePath?: string;
    fullyQualifiedDomainName?: string;
    requestInterval?: number;
    failureThreshold?: number;
  };
  healthCheckVersion: number;
}

export interface Route53ChangeInfo {
  id: string;
  status: string;
  submittedAt: string;
}

// =============================================================================
// Additional CloudWatch Types
// =============================================================================

export interface CloudWatchPutMetricDataParams {
  namespace: string;
  metricData: Array<{
    metricName: string;
    value?: number;
    unit?: string;
    timestamp?: string;
    dimensions?: Array<{ name: string; value: string }>;
  }>;
}

export interface CloudWatchFilteredLogEvent {
  logStreamName: string;
  timestamp: number;
  message: string;
  ingestionTime?: number;
  eventId?: string;
}

// =============================================================================
// Additional SQS Types
// =============================================================================

export interface SQSCreateQueueParams {
  queueName: string;
  attributes?: {
    delaySeconds?: number;
    maximumMessageSize?: number;
    messageRetentionPeriod?: number;
    visibilityTimeout?: number;
    fifoQueue?: boolean;
    contentBasedDeduplication?: boolean;
  };
}

// =============================================================================
// Additional SNS Types
// =============================================================================

export interface SNSCreateTopicParams {
  name: string;
  attributes?: {
    displayName?: string;
    kmsMasterKeyId?: string;
    fifoTopic?: boolean;
    contentBasedDeduplication?: boolean;
  };
}

// =============================================================================
// Additional Secrets Manager Types
// =============================================================================

export interface SecretsCreateSecretParams {
  name: string;
  secretString?: string;
  description?: string;
  kmsKeyId?: string;
  tags?: Array<{ key: string; value: string }>;
}
