/**
 * Response Formatting Utilities for AWS MCP Server
 */

import type {
  CloudWatchAlarm,
  CloudWatchLogGroup,
  DynamoDBTable,
  EC2Instance,
  EC2SecurityGroup,
  EC2Volume,
  ECSCluster,
  ECSService,
  IAMPolicy,
  IAMRole,
  IAMUser,
  LambdaFunction,
  PaginatedResponse,
  RDSInstance,
  ResponseFormat,
  S3Bucket,
  S3Object,
  SecretInfo,
  SNSTopic,
  SQSQueue,
} from '../types/aws.js';
import { AwsApiError, formatErrorForLogging } from './errors.js';

/**
 * MCP tool response type
 */
export interface ToolResponse {
  [key: string]: unknown;
  content: Array<{ type: 'text'; text: string }>;
  isError?: boolean;
}

/**
 * Format a successful response
 */
export function formatResponse(
  data: unknown,
  format: ResponseFormat,
  entityType: string
): ToolResponse {
  if (format === 'markdown') {
    return {
      content: [{ type: 'text', text: formatAsMarkdown(data, entityType) }],
    };
  }
  return {
    content: [{ type: 'text', text: JSON.stringify(data, null, 2) }],
  };
}

/**
 * Format an error response
 */
export function formatError(error: unknown): ToolResponse {
  const errorInfo = formatErrorForLogging(error);

  let message: string;
  if (error instanceof AwsApiError) {
    message = `AWS Error [${error.code}]: ${error.message}`;
    if (error.retryable) {
      message += ' (retryable)';
    }
    if (error.requestId) {
      message += ` [RequestId: ${error.requestId}]`;
    }
  } else if (error instanceof Error) {
    message = `Error: ${error.message}`;
  } else {
    message = `Error: ${String(error)}`;
  }

  return {
    content: [
      {
        type: 'text',
        text: JSON.stringify({ error: message, details: errorInfo }, null, 2),
      },
    ],
    isError: true,
  };
}

/**
 * Format data as Markdown
 */
function formatAsMarkdown(data: unknown, entityType: string): string {
  if (isPaginatedResponse(data)) {
    return formatPaginatedAsMarkdown(data, entityType);
  }

  if (Array.isArray(data)) {
    return formatArrayAsMarkdown(data, entityType);
  }

  if (typeof data === 'object' && data !== null) {
    return formatObjectAsMarkdown(data as Record<string, unknown>, entityType);
  }

  return String(data);
}

/**
 * Type guard for paginated response
 */
function isPaginatedResponse(data: unknown): data is PaginatedResponse<unknown> {
  return (
    typeof data === 'object' &&
    data !== null &&
    'items' in data &&
    Array.isArray((data as PaginatedResponse<unknown>).items)
  );
}

/**
 * Format paginated response as Markdown
 */
function formatPaginatedAsMarkdown(data: PaginatedResponse<unknown>, entityType: string): string {
  const lines: string[] = [];

  lines.push(`## ${capitalize(entityType)}`);
  lines.push('');
  lines.push(`**Count:** ${data.count}`);

  if (data.hasMore) {
    lines.push(`**More available:** Yes${data.nextToken ? ` (token: \`${data.nextToken.substring(0, 20)}...\`)` : ''}`);
  }
  lines.push('');

  if (data.items.length === 0) {
    lines.push('_No items found._');
    return lines.join('\n');
  }

  // Format items based on entity type
  switch (entityType) {
    case 's3_buckets':
      lines.push(formatS3BucketsTable(data.items as S3Bucket[]));
      break;
    case 's3_objects':
      lines.push(formatS3ObjectsTable(data.items as S3Object[]));
      break;
    case 'ec2_instances':
      lines.push(formatEC2InstancesTable(data.items as EC2Instance[]));
      break;
    case 'ec2_security_groups':
      lines.push(formatEC2SecurityGroupsTable(data.items as EC2SecurityGroup[]));
      break;
    case 'ec2_volumes':
      lines.push(formatEC2VolumesTable(data.items as EC2Volume[]));
      break;
    case 'lambda_functions':
      lines.push(formatLambdaFunctionsTable(data.items as LambdaFunction[]));
      break;
    case 'iam_users':
      lines.push(formatIAMUsersTable(data.items as IAMUser[]));
      break;
    case 'iam_roles':
      lines.push(formatIAMRolesTable(data.items as IAMRole[]));
      break;
    case 'iam_policies':
      lines.push(formatIAMPoliciesTable(data.items as IAMPolicy[]));
      break;
    case 'dynamodb_tables':
      lines.push(formatDynamoDBTablesTable(data.items as DynamoDBTable[]));
      break;
    case 'cloudwatch_alarms':
      lines.push(formatCloudWatchAlarmsTable(data.items as CloudWatchAlarm[]));
      break;
    case 'cloudwatch_log_groups':
      lines.push(formatCloudWatchLogGroupsTable(data.items as CloudWatchLogGroup[]));
      break;
    case 'sqs_queues':
      lines.push(formatSQSQueuesTable(data.items as SQSQueue[]));
      break;
    case 'sns_topics':
      lines.push(formatSNSTopicsTable(data.items as SNSTopic[]));
      break;
    case 'secrets':
      lines.push(formatSecretsTable(data.items as SecretInfo[]));
      break;
    case 'ecs_clusters':
      lines.push(formatECSClustersTable(data.items as ECSCluster[]));
      break;
    case 'ecs_services':
      lines.push(formatECSServicesTable(data.items as ECSService[]));
      break;
    case 'rds_instances':
      lines.push(formatRDSInstancesTable(data.items as RDSInstance[]));
      break;
    default:
      lines.push(formatGenericTable(data.items));
  }

  return lines.join('\n');
}

// =============================================================================
// Entity-specific formatters
// =============================================================================

function formatS3BucketsTable(buckets: S3Bucket[]): string {
  const lines: string[] = [];
  lines.push('| Name | Creation Date |');
  lines.push('|---|---|');
  for (const bucket of buckets) {
    lines.push(`| ${bucket.name} | ${bucket.creationDate} |`);
  }
  return lines.join('\n');
}

function formatS3ObjectsTable(objects: S3Object[]): string {
  const lines: string[] = [];
  lines.push('| Key | Size | Last Modified | Storage Class |');
  lines.push('|---|---|---|---|');
  for (const obj of objects) {
    const size = formatBytes(obj.size);
    lines.push(`| ${obj.key} | ${size} | ${obj.lastModified} | ${obj.storageClass || 'STANDARD'} |`);
  }
  return lines.join('\n');
}

function formatEC2InstancesTable(instances: EC2Instance[]): string {
  const lines: string[] = [];
  lines.push('| Instance ID | Type | State | Public IP | Private IP | Name |');
  lines.push('|---|---|---|---|---|---|');
  for (const instance of instances) {
    const name = instance.tags.find((t) => t.key === 'Name')?.value || '-';
    lines.push(
      `| ${instance.instanceId} | ${instance.instanceType} | ${instance.state} | ${instance.publicIpAddress || '-'} | ${instance.privateIpAddress || '-'} | ${name} |`
    );
  }
  return lines.join('\n');
}

function formatEC2SecurityGroupsTable(groups: EC2SecurityGroup[]): string {
  const lines: string[] = [];
  lines.push('| Group ID | Name | Description | VPC ID | Inbound Rules | Outbound Rules |');
  lines.push('|---|---|---|---|---|---|');
  for (const group of groups) {
    lines.push(
      `| ${group.groupId} | ${group.groupName} | ${group.description} | ${group.vpcId || '-'} | ${group.ingressRules.length} | ${group.egressRules.length} |`
    );
  }
  return lines.join('\n');
}

function formatEC2VolumesTable(volumes: EC2Volume[]): string {
  const lines: string[] = [];
  lines.push('| Volume ID | Size | Type | State | AZ | Encrypted |');
  lines.push('|---|---|---|---|---|---|');
  for (const volume of volumes) {
    lines.push(
      `| ${volume.volumeId} | ${volume.size} GiB | ${volume.volumeType} | ${volume.state} | ${volume.availabilityZone} | ${volume.encrypted ? 'Yes' : 'No'} |`
    );
  }
  return lines.join('\n');
}

function formatLambdaFunctionsTable(functions: LambdaFunction[]): string {
  const lines: string[] = [];
  lines.push('| Function Name | Runtime | Memory | Timeout | Last Modified |');
  lines.push('|---|---|---|---|---|');
  for (const fn of functions) {
    lines.push(
      `| ${fn.functionName} | ${fn.runtime || '-'} | ${fn.memorySize} MB | ${fn.timeout}s | ${fn.lastModified} |`
    );
  }
  return lines.join('\n');
}

function formatIAMUsersTable(users: IAMUser[]): string {
  const lines: string[] = [];
  lines.push('| User Name | User ID | Created | Last Login |');
  lines.push('|---|---|---|---|');
  for (const user of users) {
    lines.push(
      `| ${user.userName} | ${user.userId} | ${user.createDate} | ${user.passwordLastUsed || 'Never'} |`
    );
  }
  return lines.join('\n');
}

function formatIAMRolesTable(roles: IAMRole[]): string {
  const lines: string[] = [];
  lines.push('| Role Name | Role ID | Created | Description |');
  lines.push('|---|---|---|---|');
  for (const role of roles) {
    lines.push(
      `| ${role.roleName} | ${role.roleId} | ${role.createDate} | ${role.description || '-'} |`
    );
  }
  return lines.join('\n');
}

function formatIAMPoliciesTable(policies: IAMPolicy[]): string {
  const lines: string[] = [];
  lines.push('| Policy Name | ARN | Attachments | Updated |');
  lines.push('|---|---|---|---|');
  for (const policy of policies) {
    lines.push(
      `| ${policy.policyName} | ${policy.arn} | ${policy.attachmentCount} | ${policy.updateDate} |`
    );
  }
  return lines.join('\n');
}

function formatDynamoDBTablesTable(tables: DynamoDBTable[]): string {
  const lines: string[] = [];
  lines.push('| Table Name | Status | Items | Size | Billing |');
  lines.push('|---|---|---|---|---|');
  for (const table of tables) {
    const size = table.tableSizeBytes ? formatBytes(table.tableSizeBytes) : '-';
    const billing = table.billingModeSummary?.billingMode || 'PROVISIONED';
    lines.push(
      `| ${table.tableName} | ${table.tableStatus} | ${table.itemCount || '-'} | ${size} | ${billing} |`
    );
  }
  return lines.join('\n');
}

function formatCloudWatchAlarmsTable(alarms: CloudWatchAlarm[]): string {
  const lines: string[] = [];
  lines.push('| Alarm Name | State | Metric | Namespace | Threshold |');
  lines.push('|---|---|---|---|---|');
  for (const alarm of alarms) {
    lines.push(
      `| ${alarm.alarmName} | ${alarm.stateValue} | ${alarm.metricName} | ${alarm.namespace} | ${alarm.threshold} |`
    );
  }
  return lines.join('\n');
}

function formatCloudWatchLogGroupsTable(groups: CloudWatchLogGroup[]): string {
  const lines: string[] = [];
  lines.push('| Log Group | Stored Bytes | Retention |');
  lines.push('|---|---|---|');
  for (const group of groups) {
    const size = group.storedBytes ? formatBytes(group.storedBytes) : '-';
    const retention = group.retentionInDays ? `${group.retentionInDays} days` : 'Never expire';
    lines.push(`| ${group.logGroupName} | ${size} | ${retention} |`);
  }
  return lines.join('\n');
}

function formatSQSQueuesTable(queues: SQSQueue[]): string {
  const lines: string[] = [];
  lines.push('| Queue URL | Messages | In Flight | Delayed |');
  lines.push('|---|---|---|---|');
  for (const queue of queues) {
    const queueName = queue.queueUrl.split('/').pop() || queue.queueUrl;
    lines.push(
      `| ${queueName} | ${queue.approximateNumberOfMessages || 0} | ${queue.approximateNumberOfMessagesNotVisible || 0} | ${queue.approximateNumberOfMessagesDelayed || 0} |`
    );
  }
  return lines.join('\n');
}

function formatSNSTopicsTable(topics: SNSTopic[]): string {
  const lines: string[] = [];
  lines.push('| Topic ARN | Display Name | Subscriptions |');
  lines.push('|---|---|---|');
  for (const topic of topics) {
    const topicName = topic.topicArn.split(':').pop() || topic.topicArn;
    lines.push(
      `| ${topicName} | ${topic.displayName || '-'} | ${topic.subscriptionsConfirmed || 0} |`
    );
  }
  return lines.join('\n');
}

function formatSecretsTable(secrets: SecretInfo[]): string {
  const lines: string[] = [];
  lines.push('| Name | Last Changed | Last Accessed | Rotation |');
  lines.push('|---|---|---|---|');
  for (const secret of secrets) {
    lines.push(
      `| ${secret.name} | ${secret.lastChangedDate || '-'} | ${secret.lastAccessedDate || '-'} | ${secret.rotationEnabled ? 'Enabled' : 'Disabled'} |`
    );
  }
  return lines.join('\n');
}

function formatECSClustersTable(clusters: ECSCluster[]): string {
  const lines: string[] = [];
  lines.push('| Cluster Name | Status | Services | Running Tasks | Pending Tasks |');
  lines.push('|---|---|---|---|---|');
  for (const cluster of clusters) {
    lines.push(
      `| ${cluster.clusterName} | ${cluster.status} | ${cluster.activeServicesCount} | ${cluster.runningTasksCount} | ${cluster.pendingTasksCount} |`
    );
  }
  return lines.join('\n');
}

function formatECSServicesTable(services: ECSService[]): string {
  const lines: string[] = [];
  lines.push('| Service Name | Status | Desired | Running | Pending |');
  lines.push('|---|---|---|---|---|');
  for (const service of services) {
    lines.push(
      `| ${service.serviceName} | ${service.status} | ${service.desiredCount} | ${service.runningCount} | ${service.pendingCount} |`
    );
  }
  return lines.join('\n');
}

function formatRDSInstancesTable(instances: RDSInstance[]): string {
  const lines: string[] = [];
  lines.push('| DB Identifier | Engine | Class | Status | Multi-AZ | Storage |');
  lines.push('|---|---|---|---|---|---|');
  for (const instance of instances) {
    lines.push(
      `| ${instance.dbInstanceIdentifier} | ${instance.engine} ${instance.engineVersion} | ${instance.dbInstanceClass} | ${instance.dbInstanceStatus} | ${instance.multiAZ ? 'Yes' : 'No'} | ${instance.allocatedStorage} GiB |`
    );
  }
  return lines.join('\n');
}

/**
 * Format a generic array as Markdown table
 */
function formatGenericTable(items: unknown[]): string {
  if (items.length === 0) return '_No items_';

  const first = items[0] as Record<string, unknown>;
  const keys = Object.keys(first).slice(0, 5);

  const lines: string[] = [];
  lines.push(`| ${keys.join(' | ')} |`);
  lines.push(`|${keys.map(() => '---').join('|')}|`);

  for (const item of items) {
    const record = item as Record<string, unknown>;
    const values = keys.map((k) => {
      const val = record[k];
      if (val === null || val === undefined) return '-';
      if (typeof val === 'object') return JSON.stringify(val).substring(0, 30) + '...';
      return String(val);
    });
    lines.push(`| ${values.join(' | ')} |`);
  }

  return lines.join('\n');
}

/**
 * Format an array as Markdown
 */
function formatArrayAsMarkdown(data: unknown[], entityType: string): string {
  return formatGenericTable(data);
}

/**
 * Format a single object as Markdown
 */
function formatObjectAsMarkdown(data: Record<string, unknown>, entityType: string): string {
  const lines: string[] = [];
  lines.push(`## ${capitalize(entityType.replace(/s$/, '').replace(/_/g, ' '))}`);
  lines.push('');

  for (const [key, value] of Object.entries(data)) {
    if (value === null || value === undefined) continue;

    if (typeof value === 'object') {
      lines.push(`**${formatKey(key)}:**`);
      lines.push('```json');
      lines.push(JSON.stringify(value, null, 2));
      lines.push('```');
    } else {
      lines.push(`**${formatKey(key)}:** ${value}`);
    }
  }

  return lines.join('\n');
}

/**
 * Capitalize first letter
 */
function capitalize(str: string): string {
  return str.charAt(0).toUpperCase() + str.slice(1);
}

/**
 * Format a key for display (camelCase/snake_case to Title Case)
 */
function formatKey(key: string): string {
  return key
    .replace(/_/g, ' ')
    .replace(/([A-Z])/g, ' $1')
    .replace(/^./, (str) => str.toUpperCase())
    .trim();
}

/**
 * Format bytes to human readable string
 */
function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${Number.parseFloat((bytes / Math.pow(k, i)).toFixed(2))} ${sizes[i]}`;
}
