/**
 * CloudWatch Tools
 *
 * MCP tools for Amazon CloudWatch operations (metrics, alarms, logs).
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { AwsClient } from '../client.js';
import { formatError, formatResponse } from '../utils/formatters.js';

export function registerCloudWatchTools(server: McpServer, client: AwsClient): void {
  // ===========================================================================
  // List Metrics
  // ===========================================================================
  server.tool(
    'aws_cloudwatch_list_metrics',
    `List available CloudWatch metrics.

Args:
  - namespace: Filter by namespace (e.g., 'AWS/EC2', 'AWS/Lambda')

Returns metrics with their namespaces, names, and dimensions.`,
    {
      namespace: z.string().optional().describe("Namespace filter (e.g., 'AWS/EC2')"),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ namespace, format }) => {
      try {
        const metrics = await client.cloudwatchListMetrics(namespace);
        return formatResponse(
          { items: metrics, count: metrics.length, hasMore: false },
          format,
          'cloudwatch_metrics'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Get Metric Statistics
  // ===========================================================================
  server.tool(
    'aws_cloudwatch_get_metric_statistics',
    `Get statistics for a CloudWatch metric.

Args:
  - namespace: The metric namespace (required, e.g., 'AWS/EC2')
  - metricName: The metric name (required, e.g., 'CPUUtilization')
  - dimensions: Array of {name, value} pairs for filtering
  - startTime: Start time in ISO 8601 format (required)
  - endTime: End time in ISO 8601 format (required)
  - period: The granularity in seconds (required, e.g., 300 for 5 minutes)
  - statistics: Array of statistics to retrieve (e.g., ['Average', 'Maximum'])

Returns datapoints with timestamps and requested statistics.`,
    {
      namespace: z.string().describe("Metric namespace (e.g., 'AWS/EC2')"),
      metricName: z.string().describe("Metric name (e.g., 'CPUUtilization')"),
      dimensions: z
        .array(z.object({ name: z.string(), value: z.string() }))
        .optional()
        .describe('Dimensions to filter by'),
      startTime: z.string().describe('Start time (ISO 8601)'),
      endTime: z.string().describe('End time (ISO 8601)'),
      period: z.number().int().min(60).describe('Period in seconds (min 60)'),
      statistics: z
        .array(z.enum(['Average', 'Sum', 'Minimum', 'Maximum', 'SampleCount']))
        .min(1)
        .describe('Statistics to retrieve'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ namespace, metricName, dimensions, startTime, endTime, period, statistics, format }) => {
      try {
        const datapoints = await client.cloudwatchGetMetricStatistics({
          namespace,
          metricName,
          dimensions,
          startTime,
          endTime,
          period,
          statistics,
        });
        return formatResponse(
          {
            namespace,
            metricName,
            items: datapoints,
            count: datapoints.length,
            hasMore: false,
          },
          format,
          'cloudwatch_datapoints'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Describe Alarms
  // ===========================================================================
  server.tool(
    'aws_cloudwatch_describe_alarms',
    `List CloudWatch alarms.

Args:
  - alarmNames: Optional array of alarm names to filter by

Returns alarms with their states, metrics, and thresholds.`,
    {
      alarmNames: z.array(z.string()).optional().describe('Filter by alarm names'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ alarmNames, format }) => {
      try {
        const alarms = await client.cloudwatchDescribeAlarms(alarmNames);
        return formatResponse(
          { items: alarms, count: alarms.length, hasMore: false },
          format,
          'cloudwatch_alarms'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Set Alarm State
  // ===========================================================================
  server.tool(
    'aws_cloudwatch_set_alarm_state',
    `Temporarily set the state of a CloudWatch alarm.

This is useful for testing alarm actions.

Args:
  - alarmName: The alarm name (required)
  - stateValue: The state to set ('OK', 'ALARM', 'INSUFFICIENT_DATA')
  - stateReason: The reason for the state change (required)

Returns confirmation of the state change.`,
    {
      alarmName: z.string().describe('Alarm name'),
      stateValue: z.enum(['OK', 'ALARM', 'INSUFFICIENT_DATA']).describe('State to set'),
      stateReason: z.string().describe('Reason for state change'),
    },
    async ({ alarmName, stateValue, stateReason }) => {
      try {
        await client.cloudwatchSetAlarmState(alarmName, stateValue, stateReason);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Alarm '${alarmName}' state set to ${stateValue}`,
                  alarmName,
                  stateValue,
                  stateReason,
                },
                null,
                2
              ),
            },
          ],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Put Metric Data
  // ===========================================================================
  server.tool(
    'aws_cloudwatch_put_metric_data',
    `Publish custom metrics to CloudWatch.

Args:
  - namespace: The metric namespace (required, e.g., 'MyApp/Metrics')
  - metricData: Array of metrics to publish

Each metric requires:
  - metricName: The metric name
  - value: The metric value (optional)
  - unit: The unit (optional, e.g., 'Count', 'Seconds', 'Bytes')
  - dimensions: Optional array of {name, value} pairs

Returns confirmation of the publish operation.`,
    {
      namespace: z.string().describe("Metric namespace (e.g., 'MyApp/Metrics')"),
      metricData: z.array(z.object({
        metricName: z.string().describe('Metric name'),
        value: z.number().optional().describe('Metric value'),
        unit: z.string().optional().describe("Unit (e.g., 'Count', 'Seconds')"),
        timestamp: z.string().optional().describe('Timestamp (ISO 8601)'),
        dimensions: z.array(z.object({ name: z.string(), value: z.string() })).optional().describe('Dimensions'),
      })).min(1).describe('Metrics to publish'),
    },
    async ({ namespace, metricData }) => {
      try {
        await client.cloudwatchPutMetricData({ namespace, metricData });
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Published ${metricData.length} metric(s) to namespace '${namespace}'`,
                  namespace,
                  metricCount: metricData.length,
                },
                null,
                2
              ),
            },
          ],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Describe Log Groups
  // ===========================================================================
  server.tool(
    'aws_cloudwatch_logs_describe_log_groups',
    `List CloudWatch Log Groups.

Args:
  - prefix: Filter by log group name prefix

Returns log groups with stored bytes and retention settings.`,
    {
      prefix: z.string().optional().describe('Log group name prefix'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ prefix, format }) => {
      try {
        const logGroups = await client.cloudwatchLogsDescribeLogGroups(prefix);
        return formatResponse(
          { items: logGroups, count: logGroups.length, hasMore: false },
          format,
          'cloudwatch_log_groups'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Describe Log Streams
  // ===========================================================================
  server.tool(
    'aws_cloudwatch_logs_describe_log_streams',
    `List log streams in a CloudWatch Log Group.

Args:
  - logGroupName: The log group name (required)

Returns log streams ordered by last event time.`,
    {
      logGroupName: z.string().describe('Log group name'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ logGroupName, format }) => {
      try {
        const logStreams = await client.cloudwatchLogsDescribeLogStreams(logGroupName);
        return formatResponse(
          { items: logStreams, count: logStreams.length, hasMore: false },
          format,
          'cloudwatch_log_streams'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Get Log Events
  // ===========================================================================
  server.tool(
    'aws_cloudwatch_logs_get_log_events',
    `Get log events from a CloudWatch Log Stream.

Args:
  - logGroupName: The log group name (required)
  - logStreamName: The log stream name (required)
  - startTime: Start time in milliseconds since epoch
  - endTime: End time in milliseconds since epoch
  - limit: Maximum number of events to return (default: 100)

Returns log events with timestamps and messages.`,
    {
      logGroupName: z.string().describe('Log group name'),
      logStreamName: z.string().describe('Log stream name'),
      startTime: z.number().optional().describe('Start time (epoch ms)'),
      endTime: z.number().optional().describe('End time (epoch ms)'),
      limit: z.number().int().min(1).max(10000).default(100).describe('Max events'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ logGroupName, logStreamName, startTime, endTime, limit, format }) => {
      try {
        const events = await client.cloudwatchLogsGetLogEvents(logGroupName, logStreamName, {
          startTime,
          endTime,
          limit,
        });
        return formatResponse(
          {
            logGroupName,
            logStreamName,
            items: events,
            count: events.length,
            hasMore: events.length === limit,
          },
          format,
          'cloudwatch_log_events'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Filter Log Events
  // ===========================================================================
  server.tool(
    'aws_cloudwatch_logs_filter_log_events',
    `Search and filter log events across multiple log streams.

Args:
  - logGroupName: The log group name (required)
  - filterPattern: CloudWatch Logs filter pattern (e.g., 'ERROR', '"exception"')
  - startTime: Start time in milliseconds since epoch
  - endTime: End time in milliseconds since epoch
  - limit: Maximum number of events to return (default: 100)
  - logStreamNames: Filter to specific log streams (optional)

Returns matching log events with stream names and timestamps.`,
    {
      logGroupName: z.string().describe('Log group name'),
      filterPattern: z.string().optional().describe("Filter pattern (e.g., 'ERROR')"),
      startTime: z.number().optional().describe('Start time (epoch ms)'),
      endTime: z.number().optional().describe('End time (epoch ms)'),
      limit: z.number().int().min(1).max(10000).default(100).describe('Max events'),
      logStreamNames: z.array(z.string()).optional().describe('Filter to specific streams'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ logGroupName, filterPattern, startTime, endTime, limit, logStreamNames, format }) => {
      try {
        const events = await client.cloudwatchLogsFilterLogEvents(logGroupName, {
          filterPattern,
          startTime,
          endTime,
          limit,
          logStreamNames,
        });
        return formatResponse(
          {
            logGroupName,
            filterPattern,
            items: events,
            count: events.length,
            hasMore: events.length === limit,
          },
          format,
          'cloudwatch_filtered_log_events'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Put Metric Alarm
  // ===========================================================================
  server.tool(
    'aws_cloudwatch_put_metric_alarm',
    `Create or update a CloudWatch metric alarm.

Args:
  - alarmName: The alarm name (required)
  - namespace: The metric namespace (required)
  - metricName: The metric name (required)
  - statistic: The statistic (Average, Sum, Minimum, Maximum, SampleCount)
  - period: The period in seconds (required)
  - evaluationPeriods: Number of periods to evaluate (required)
  - threshold: The threshold value (required)
  - comparisonOperator: Comparison operator (required)
  - dimensions: Optional metric dimensions
  - alarmDescription: Optional description
  - alarmActions: SNS topic ARNs to notify on ALARM
  - okActions: SNS topic ARNs to notify on OK
  - treatMissingData: How to treat missing data (missing, ignore, breaching, notBreaching)

Returns confirmation of alarm creation.`,
    {
      alarmName: z.string().describe('Alarm name'),
      namespace: z.string().describe('Metric namespace'),
      metricName: z.string().describe('Metric name'),
      statistic: z.enum(['Average', 'Sum', 'Minimum', 'Maximum', 'SampleCount']).describe('Statistic'),
      period: z.number().int().min(60).describe('Period in seconds'),
      evaluationPeriods: z.number().int().min(1).describe('Evaluation periods'),
      threshold: z.number().describe('Threshold value'),
      comparisonOperator: z.enum([
        'GreaterThanOrEqualToThreshold',
        'GreaterThanThreshold',
        'LessThanThreshold',
        'LessThanOrEqualToThreshold',
      ]).describe('Comparison operator'),
      dimensions: z.array(z.object({ name: z.string(), value: z.string() })).optional().describe('Dimensions'),
      alarmDescription: z.string().optional().describe('Alarm description'),
      alarmActions: z.array(z.string()).optional().describe('SNS topic ARNs for ALARM state'),
      okActions: z.array(z.string()).optional().describe('SNS topic ARNs for OK state'),
      insufficientDataActions: z.array(z.string()).optional().describe('SNS topic ARNs for INSUFFICIENT_DATA'),
      treatMissingData: z.enum(['missing', 'ignore', 'breaching', 'notBreaching']).optional().describe('How to treat missing data'),
    },
    async ({ alarmName, namespace, metricName, statistic, period, evaluationPeriods, threshold, comparisonOperator, dimensions, alarmDescription, alarmActions, okActions, insufficientDataActions, treatMissingData }) => {
      try {
        await client.cloudwatchPutMetricAlarm({
          alarmName,
          namespace,
          metricName,
          statistic,
          period,
          evaluationPeriods,
          threshold,
          comparisonOperator,
          dimensions,
          alarmDescription,
          alarmActions,
          okActions,
          insufficientDataActions,
          treatMissingData,
        });
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Alarm created/updated',
                  alarmName,
                  namespace,
                  metricName,
                },
                null,
                2
              ),
            },
          ],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Delete Alarms
  // ===========================================================================
  server.tool(
    'aws_cloudwatch_delete_alarms',
    `Delete CloudWatch alarms.

Args:
  - alarmNames: Array of alarm names to delete (required)

WARNING: This action cannot be undone.

Returns confirmation of deletion.`,
    {
      alarmNames: z.array(z.string()).min(1).describe('Alarm names to delete'),
    },
    async ({ alarmNames }) => {
      try {
        await client.cloudwatchDeleteAlarms(alarmNames);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Deleted ${alarmNames.length} alarm(s)`,
                  alarmNames,
                },
                null,
                2
              ),
            },
          ],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Enable Alarm Actions
  // ===========================================================================
  server.tool(
    'aws_cloudwatch_enable_alarm_actions',
    `Enable actions for CloudWatch alarms.

Args:
  - alarmNames: Array of alarm names (required)

Returns confirmation of action enablement.`,
    {
      alarmNames: z.array(z.string()).min(1).describe('Alarm names'),
    },
    async ({ alarmNames }) => {
      try {
        await client.cloudwatchEnableAlarmActions(alarmNames);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Enabled actions for ${alarmNames.length} alarm(s)`,
                  alarmNames,
                },
                null,
                2
              ),
            },
          ],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Disable Alarm Actions
  // ===========================================================================
  server.tool(
    'aws_cloudwatch_disable_alarm_actions',
    `Disable actions for CloudWatch alarms.

Useful for maintenance windows or to temporarily stop notifications.

Args:
  - alarmNames: Array of alarm names (required)

Returns confirmation of action disablement.`,
    {
      alarmNames: z.array(z.string()).min(1).describe('Alarm names'),
    },
    async ({ alarmNames }) => {
      try {
        await client.cloudwatchDisableAlarmActions(alarmNames);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Disabled actions for ${alarmNames.length} alarm(s)`,
                  alarmNames,
                },
                null,
                2
              ),
            },
          ],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Create Log Group
  // ===========================================================================
  server.tool(
    'aws_cloudwatch_logs_create_log_group',
    `Create a new CloudWatch Log Group.

Args:
  - logGroupName: The log group name (required)
  - tags: Optional tags as key-value pairs

Returns confirmation of creation.`,
    {
      logGroupName: z.string().describe('Log group name'),
      tags: z.record(z.string(), z.string()).optional().describe('Tags'),
    },
    async ({ logGroupName, tags }) => {
      try {
        await client.cloudwatchLogsCreateLogGroup(logGroupName, tags);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Log group created',
                  logGroupName,
                },
                null,
                2
              ),
            },
          ],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Delete Log Group
  // ===========================================================================
  server.tool(
    'aws_cloudwatch_logs_delete_log_group',
    `Delete a CloudWatch Log Group.

WARNING: This action permanently deletes the log group and all its log streams.

Args:
  - logGroupName: The log group name (required)

Returns confirmation of deletion.`,
    {
      logGroupName: z.string().describe('Log group name'),
    },
    async ({ logGroupName }) => {
      try {
        await client.cloudwatchLogsDeleteLogGroup(logGroupName);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Log group deleted',
                  logGroupName,
                },
                null,
                2
              ),
            },
          ],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Put Retention Policy
  // ===========================================================================
  server.tool(
    'aws_cloudwatch_logs_put_retention_policy',
    `Set the retention policy for a CloudWatch Log Group.

Args:
  - logGroupName: The log group name (required)
  - retentionInDays: Retention period in days (required)

Valid retention values: 1, 3, 5, 7, 14, 30, 60, 90, 120, 150, 180, 365, 400, 545, 731, 1096, 1827, 2192, 2557, 2922, 3288, 3653

Returns confirmation of policy update.`,
    {
      logGroupName: z.string().describe('Log group name'),
      retentionInDays: z.number().int().describe('Retention in days'),
    },
    async ({ logGroupName, retentionInDays }) => {
      try {
        await client.cloudwatchLogsPutRetentionPolicy(logGroupName, retentionInDays);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Retention policy set',
                  logGroupName,
                  retentionInDays,
                },
                null,
                2
              ),
            },
          ],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Delete Retention Policy
  // ===========================================================================
  server.tool(
    'aws_cloudwatch_logs_delete_retention_policy',
    `Remove the retention policy from a CloudWatch Log Group.

This causes logs to be retained indefinitely.

Args:
  - logGroupName: The log group name (required)

Returns confirmation of policy removal.`,
    {
      logGroupName: z.string().describe('Log group name'),
    },
    async ({ logGroupName }) => {
      try {
        await client.cloudwatchLogsDeleteRetentionPolicy(logGroupName);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Retention policy removed (logs retained indefinitely)',
                  logGroupName,
                },
                null,
                2
              ),
            },
          ],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Create Log Stream
  // ===========================================================================
  server.tool(
    'aws_cloudwatch_logs_create_log_stream',
    `Create a new log stream in a CloudWatch Log Group.

Args:
  - logGroupName: The log group name (required)
  - logStreamName: The log stream name (required)

Returns confirmation of stream creation.`,
    {
      logGroupName: z.string().describe('Log group name'),
      logStreamName: z.string().describe('Log stream name'),
    },
    async ({ logGroupName, logStreamName }) => {
      try {
        await client.cloudwatchLogsCreateLogStream(logGroupName, logStreamName);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Log stream created',
                  logGroupName,
                  logStreamName,
                },
                null,
                2
              ),
            },
          ],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Delete Log Stream
  // ===========================================================================
  server.tool(
    'aws_cloudwatch_logs_delete_log_stream',
    `Delete a log stream from a CloudWatch Log Group.

Args:
  - logGroupName: The log group name (required)
  - logStreamName: The log stream name (required)

WARNING: This permanently deletes all log events in the stream.

Returns confirmation of stream deletion.`,
    {
      logGroupName: z.string().describe('Log group name'),
      logStreamName: z.string().describe('Log stream name'),
    },
    async ({ logGroupName, logStreamName }) => {
      try {
        await client.cloudwatchLogsDeleteLogStream(logGroupName, logStreamName);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Log stream deleted',
                  logGroupName,
                  logStreamName,
                },
                null,
                2
              ),
            },
          ],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Put Log Events
  // ===========================================================================
  server.tool(
    'aws_cloudwatch_logs_put_log_events',
    `Write log events to a CloudWatch Log Stream.

Args:
  - logGroupName: The log group name (required)
  - logStreamName: The log stream name (required)
  - logEvents: Array of log events with timestamp and message (required)
  - sequenceToken: Sequence token for ordering (optional, not needed for new streams)

Each log event requires:
  - timestamp: Unix timestamp in milliseconds
  - message: The log message

Returns the next sequence token for subsequent writes.`,
    {
      logGroupName: z.string().describe('Log group name'),
      logStreamName: z.string().describe('Log stream name'),
      logEvents: z.array(z.object({
        timestamp: z.number().describe('Unix timestamp in milliseconds'),
        message: z.string().describe('Log message'),
      })).min(1).describe('Log events to write'),
      sequenceToken: z.string().optional().describe('Sequence token'),
    },
    async ({ logGroupName, logStreamName, logEvents, sequenceToken }) => {
      try {
        const result = await client.cloudwatchLogsPutLogEvents(logGroupName, logStreamName, logEvents, sequenceToken);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Log events written',
                  logGroupName,
                  logStreamName,
                  eventsWritten: logEvents.length,
                  nextSequenceToken: result.nextSequenceToken,
                },
                null,
                2
              ),
            },
          ],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );
}
