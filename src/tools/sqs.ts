/**
 * SQS Tools
 *
 * MCP tools for Amazon SQS operations.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { AwsClient } from '../client.js';
import { formatError, formatResponse } from '../utils/formatters.js';

export function registerSQSTools(server: McpServer, client: AwsClient): void {
  // ===========================================================================
  // List Queues
  // ===========================================================================
  server.tool(
    'aws_sqs_list_queues',
    `List all SQS queues in the region.

Returns queue URLs. Use get_queue_attributes for details.`,
    {
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ format }) => {
      try {
        const queues = await client.sqsListQueues();
        return formatResponse(
          { items: queues.map((q) => ({ queueUrl: q })), count: queues.length, hasMore: false },
          format,
          'sqs_queues'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Get Queue Attributes
  // ===========================================================================
  server.tool(
    'aws_sqs_get_queue_attributes',
    `Get attributes of an SQS queue.

Args:
  - queueUrl: The queue URL (required)

Returns queue configuration and message counts.`,
    {
      queueUrl: z.string().describe('SQS queue URL'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ queueUrl, format }) => {
      try {
        const queue = await client.sqsGetQueueAttributes(queueUrl);
        return formatResponse(queue, format, 'sqs_queue');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Send Message
  // ===========================================================================
  server.tool(
    'aws_sqs_send_message',
    `Send a message to an SQS queue.

Args:
  - queueUrl: The queue URL (required)
  - messageBody: The message content (required)
  - delaySeconds: Delay before message becomes visible (0-900)

Returns the message ID.`,
    {
      queueUrl: z.string().describe('SQS queue URL'),
      messageBody: z.string().describe('Message content'),
      delaySeconds: z.number().int().min(0).max(900).optional().describe('Delay in seconds'),
    },
    async ({ queueUrl, messageBody, delaySeconds }) => {
      try {
        const result = await client.sqsSendMessage({
          queueUrl,
          messageBody,
          delaySeconds,
        });
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Message sent',
                  messageId: result.messageId,
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
  // Receive Messages
  // ===========================================================================
  server.tool(
    'aws_sqs_receive_messages',
    `Receive messages from an SQS queue.

Args:
  - queueUrl: The queue URL (required)
  - maxNumberOfMessages: Max messages to receive (1-10, default: 1)
  - visibilityTimeout: How long to hide message (seconds)
  - waitTimeSeconds: Long polling timeout (0-20, default: 0)

Returns messages with bodies and receipt handles.
IMPORTANT: Messages must be deleted after processing.`,
    {
      queueUrl: z.string().describe('SQS queue URL'),
      maxNumberOfMessages: z.number().int().min(1).max(10).default(1).describe('Max messages'),
      visibilityTimeout: z.number().int().optional().describe('Visibility timeout (seconds)'),
      waitTimeSeconds: z.number().int().min(0).max(20).default(0).describe('Long poll timeout'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ queueUrl, maxNumberOfMessages, visibilityTimeout, waitTimeSeconds, format }) => {
      try {
        const messages = await client.sqsReceiveMessage({
          queueUrl,
          maxNumberOfMessages,
          visibilityTimeout,
          waitTimeSeconds,
        });
        return formatResponse(
          { items: messages, count: messages.length, hasMore: false },
          format,
          'sqs_messages'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Delete Message
  // ===========================================================================
  server.tool(
    'aws_sqs_delete_message',
    `Delete a message from an SQS queue.

Args:
  - queueUrl: The queue URL (required)
  - receiptHandle: The receipt handle from receive (required)

Returns confirmation of deletion.`,
    {
      queueUrl: z.string().describe('SQS queue URL'),
      receiptHandle: z.string().describe('Receipt handle from receive'),
    },
    async ({ queueUrl, receiptHandle }) => {
      try {
        await client.sqsDeleteMessage(queueUrl, receiptHandle);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Message deleted',
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
  // Purge Queue
  // ===========================================================================
  server.tool(
    'aws_sqs_purge_queue',
    `Delete all messages from an SQS queue.

WARNING: This action cannot be undone.

Args:
  - queueUrl: The queue URL (required)

Returns confirmation of the purge.`,
    {
      queueUrl: z.string().describe('SQS queue URL'),
    },
    async ({ queueUrl }) => {
      try {
        await client.sqsPurgeQueue(queueUrl);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Queue purged',
                  warning: 'All messages have been deleted',
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
  // Create Queue
  // ===========================================================================
  server.tool(
    'aws_sqs_create_queue',
    `Create a new SQS queue.

Args:
  - queueName: The queue name (required). For FIFO queues, must end with '.fifo'
  - attributes: Optional queue attributes
    - delaySeconds: Default delay for messages (0-900)
    - maximumMessageSize: Max message size in bytes (1024-262144)
    - messageRetentionPeriod: How long to retain messages in seconds (60-1209600)
    - visibilityTimeout: Default visibility timeout (0-43200)
    - fifoQueue: Whether this is a FIFO queue
    - contentBasedDeduplication: Enable content-based deduplication (FIFO only)

Returns the new queue URL.`,
    {
      queueName: z.string().describe('Queue name (end with .fifo for FIFO queues)'),
      attributes: z.object({
        delaySeconds: z.number().int().min(0).max(900).optional().describe('Delay seconds'),
        maximumMessageSize: z.number().int().min(1024).max(262144).optional().describe('Max message size'),
        messageRetentionPeriod: z.number().int().min(60).max(1209600).optional().describe('Retention period'),
        visibilityTimeout: z.number().int().min(0).max(43200).optional().describe('Visibility timeout'),
        fifoQueue: z.boolean().optional().describe('Create FIFO queue'),
        contentBasedDeduplication: z.boolean().optional().describe('Content-based deduplication'),
      }).optional().describe('Queue attributes'),
    },
    async ({ queueName, attributes }) => {
      try {
        const result = await client.sqsCreateQueue({ queueName, attributes });
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Queue created',
                  queueUrl: result.queueUrl,
                  queueName,
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
  // Delete Queue
  // ===========================================================================
  server.tool(
    'aws_sqs_delete_queue',
    `Delete an SQS queue.

WARNING: This action cannot be undone. All messages in the queue will be deleted.

Args:
  - queueUrl: The queue URL (required)

Returns confirmation of deletion.`,
    {
      queueUrl: z.string().describe('SQS queue URL'),
    },
    async ({ queueUrl }) => {
      try {
        await client.sqsDeleteQueue(queueUrl);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Queue deleted',
                  queueUrl,
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
  // Get Queue URL
  // ===========================================================================
  server.tool(
    'aws_sqs_get_queue_url',
    `Get the URL of an SQS queue by its name.

Args:
  - queueName: The queue name (required)

Returns the queue URL.`,
    {
      queueName: z.string().describe('Queue name'),
    },
    async ({ queueName }) => {
      try {
        const queueUrl = await client.sqsGetQueueUrl(queueName);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  queueName,
                  queueUrl,
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
  // Set Queue Attributes
  // ===========================================================================
  server.tool(
    'aws_sqs_set_queue_attributes',
    `Set attributes on an SQS queue.

Args:
  - queueUrl: The queue URL (required)
  - attributes: Attributes to set (required)

Supported attributes:
  - DelaySeconds: Message delay (0-900 seconds)
  - MaximumMessageSize: Max message size (1024-262144 bytes)
  - MessageRetentionPeriod: Retention (60-1209600 seconds)
  - VisibilityTimeout: Visibility timeout (0-43200 seconds)
  - Policy: Queue policy JSON
  - RedrivePolicy: Dead-letter queue config JSON

Returns confirmation of update.`,
    {
      queueUrl: z.string().describe('SQS queue URL'),
      attributes: z.record(z.string(), z.string()).describe('Attributes to set'),
    },
    async ({ queueUrl, attributes }) => {
      try {
        await client.sqsSetQueueAttributes(queueUrl, attributes);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Queue attributes updated',
                  queueUrl,
                  attributes: Object.keys(attributes),
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
  // Tag Queue
  // ===========================================================================
  server.tool(
    'aws_sqs_tag_queue',
    `Add or update tags on an SQS queue.

Args:
  - queueUrl: The queue URL (required)
  - tags: Tags to add (required)

Returns confirmation of tagging.`,
    {
      queueUrl: z.string().describe('SQS queue URL'),
      tags: z.record(z.string(), z.string()).describe('Tags to add'),
    },
    async ({ queueUrl, tags }) => {
      try {
        await client.sqsTagQueue(queueUrl, tags);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Queue tagged',
                  queueUrl,
                  tagsCount: Object.keys(tags).length,
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
  // List Queue Tags
  // ===========================================================================
  server.tool(
    'aws_sqs_list_queue_tags',
    `List tags on an SQS queue.

Args:
  - queueUrl: The queue URL (required)

Returns the queue tags.`,
    {
      queueUrl: z.string().describe('SQS queue URL'),
    },
    async ({ queueUrl }) => {
      try {
        const tags = await client.sqsListQueueTags(queueUrl);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  queueUrl,
                  tags,
                  tagsCount: Object.keys(tags).length,
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
  // Untag Queue
  // ===========================================================================
  server.tool(
    'aws_sqs_untag_queue',
    `Remove tags from an SQS queue.

Args:
  - queueUrl: The queue URL (required)
  - tagKeys: Array of tag keys to remove (required)

Returns confirmation of untagging.`,
    {
      queueUrl: z.string().describe('SQS queue URL'),
      tagKeys: z.array(z.string()).min(1).describe('Tag keys to remove'),
    },
    async ({ queueUrl, tagKeys }) => {
      try {
        await client.sqsUntagQueue(queueUrl, tagKeys);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Tags removed',
                  queueUrl,
                  tagKeysRemoved: tagKeys,
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
  // Send Message Batch
  // ===========================================================================
  server.tool(
    'aws_sqs_send_message_batch',
    `Send multiple messages to an SQS queue in a single request.

Args:
  - queueUrl: The queue URL (required)
  - entries: Array of message entries (required, max 10)
    - id: Unique identifier for tracking (required)
    - messageBody: Message content (required)
    - delaySeconds: Delay before message becomes visible (optional)

Returns successful and failed message results.`,
    {
      queueUrl: z.string().describe('SQS queue URL'),
      entries: z.array(z.object({
        id: z.string().describe('Message ID for tracking'),
        messageBody: z.string().describe('Message body'),
        delaySeconds: z.number().int().min(0).max(900).optional().describe('Delay in seconds'),
      })).min(1).max(10).describe('Message entries'),
    },
    async ({ queueUrl, entries }) => {
      try {
        const result = await client.sqsSendMessageBatch(queueUrl, entries);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Batch send completed: ${result.successful.length} succeeded, ${result.failed.length} failed`,
                  successful: result.successful,
                  failed: result.failed,
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
  // Delete Message Batch
  // ===========================================================================
  server.tool(
    'aws_sqs_delete_message_batch',
    `Delete multiple messages from an SQS queue in a single request.

Args:
  - queueUrl: The queue URL (required)
  - entries: Array of delete entries (required, max 10)
    - id: Unique identifier for tracking (required)
    - receiptHandle: Receipt handle from receive (required)

Returns successful and failed delete results.`,
    {
      queueUrl: z.string().describe('SQS queue URL'),
      entries: z.array(z.object({
        id: z.string().describe('Delete ID for tracking'),
        receiptHandle: z.string().describe('Receipt handle'),
      })).min(1).max(10).describe('Delete entries'),
    },
    async ({ queueUrl, entries }) => {
      try {
        const result = await client.sqsDeleteMessageBatch(queueUrl, entries);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Batch delete completed: ${result.successful.length} succeeded, ${result.failed.length} failed`,
                  successful: result.successful,
                  failed: result.failed,
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
  // Change Message Visibility
  // ===========================================================================
  server.tool(
    'aws_sqs_change_message_visibility',
    `Change the visibility timeout of a message.

Args:
  - queueUrl: The queue URL (required)
  - receiptHandle: Receipt handle from receive (required)
  - visibilityTimeout: New visibility timeout in seconds (required, 0-43200)

Use this to extend processing time or make a message immediately visible again.

Returns confirmation.`,
    {
      queueUrl: z.string().describe('SQS queue URL'),
      receiptHandle: z.string().describe('Receipt handle'),
      visibilityTimeout: z.number().int().min(0).max(43200).describe('Visibility timeout in seconds'),
    },
    async ({ queueUrl, receiptHandle, visibilityTimeout }) => {
      try {
        await client.sqsChangeMessageVisibility(queueUrl, receiptHandle, visibilityTimeout);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Message visibility timeout changed',
                  visibilityTimeout,
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
  // Change Message Visibility Batch
  // ===========================================================================
  server.tool(
    'aws_sqs_change_message_visibility_batch',
    `Change visibility timeout for multiple messages in a single request.

Args:
  - queueUrl: The queue URL (required)
  - entries: Array of visibility change entries (required, max 10)
    - id: Unique identifier for tracking (required)
    - receiptHandle: Receipt handle from receive (required)
    - visibilityTimeout: New visibility timeout in seconds (required)

Returns successful and failed results.`,
    {
      queueUrl: z.string().describe('SQS queue URL'),
      entries: z.array(z.object({
        id: z.string().describe('Entry ID for tracking'),
        receiptHandle: z.string().describe('Receipt handle'),
        visibilityTimeout: z.number().int().min(0).max(43200).describe('Visibility timeout'),
      })).min(1).max(10).describe('Visibility change entries'),
    },
    async ({ queueUrl, entries }) => {
      try {
        const result = await client.sqsChangeMessageVisibilityBatch(queueUrl, entries);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Batch visibility change: ${result.successful.length} succeeded, ${result.failed.length} failed`,
                  successful: result.successful,
                  failed: result.failed,
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
  // List Dead Letter Source Queues
  // ===========================================================================
  server.tool(
    'aws_sqs_list_dead_letter_source_queues',
    `List queues that have this queue configured as their dead-letter queue.

Args:
  - queueUrl: The dead-letter queue URL (required)

Returns URLs of source queues that send failed messages to this DLQ.`,
    {
      queueUrl: z.string().describe('Dead-letter queue URL'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ queueUrl, format }) => {
      try {
        const queues = await client.sqsListDeadLetterSourceQueues(queueUrl);
        return formatResponse(
          { items: queues.map((url) => ({ queueUrl: url })), count: queues.length, hasMore: false },
          format,
          'sqs_queues'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );
}
