/**
 * SNS Tools
 *
 * MCP tools for Amazon SNS operations.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { AwsClient } from '../client.js';
import { formatError, formatResponse } from '../utils/formatters.js';

export function registerSNSTools(server: McpServer, client: AwsClient): void {
  // ===========================================================================
  // List Topics
  // ===========================================================================
  server.tool(
    'aws_sns_list_topics',
    `List all SNS topics in the region.

Returns topic ARNs.`,
    {
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ format }) => {
      try {
        const topics = await client.snsListTopics();
        return formatResponse(
          { items: topics, count: topics.length, hasMore: false },
          format,
          'sns_topics'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // List Subscriptions
  // ===========================================================================
  server.tool(
    'aws_sns_list_subscriptions',
    `List SNS subscriptions.

Args:
  - topicArn: Filter by topic ARN (optional)

Returns subscriptions with endpoints and protocols.`,
    {
      topicArn: z.string().optional().describe('Filter by topic ARN'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ topicArn, format }) => {
      try {
        const subscriptions = await client.snsListSubscriptions(topicArn);
        return formatResponse(
          { items: subscriptions, count: subscriptions.length, hasMore: false },
          format,
          'sns_subscriptions'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Publish Message
  // ===========================================================================
  server.tool(
    'aws_sns_publish',
    `Publish a message to an SNS topic or endpoint.

Args:
  - topicArn: The topic ARN to publish to
  - targetArn: Alternative target ARN (e.g., for direct endpoint)
  - message: The message content (required)
  - subject: Subject for email endpoints

Returns the message ID.`,
    {
      topicArn: z.string().optional().describe('Topic ARN'),
      targetArn: z.string().optional().describe('Target ARN (alternative to topic)'),
      message: z.string().describe('Message content'),
      subject: z.string().optional().describe('Subject (for email)'),
    },
    async ({ topicArn, targetArn, message, subject }) => {
      try {
        const result = await client.snsPublish({
          topicArn,
          targetArn,
          message,
          subject,
        });
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Message published',
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
  // Get Topic Attributes
  // ===========================================================================
  server.tool(
    'aws_sns_get_topic_attributes',
    `Get attributes of an SNS topic.

Args:
  - topicArn: The topic ARN (required)

Returns topic configuration including subscriptions and delivery policy.`,
    {
      topicArn: z.string().describe('Topic ARN'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ topicArn, format }) => {
      try {
        const attrs = await client.snsGetTopicAttributes(topicArn);
        return formatResponse(attrs, format, 'sns_topic');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Subscribe
  // ===========================================================================
  server.tool(
    'aws_sns_subscribe',
    `Subscribe an endpoint to an SNS topic.

Args:
  - topicArn: The topic ARN (required)
  - protocol: The protocol (email, sms, sqs, lambda, http, https, application)
  - endpoint: The endpoint (email address, phone number, queue ARN, etc.)

Returns the subscription ARN (or 'pending confirmation' for email).`,
    {
      topicArn: z.string().describe('Topic ARN'),
      protocol: z.enum(['email', 'email-json', 'sms', 'sqs', 'lambda', 'http', 'https', 'application']).describe('Protocol'),
      endpoint: z.string().describe('Endpoint (varies by protocol)'),
    },
    async ({ topicArn, protocol, endpoint }) => {
      try {
        const result = await client.snsSubscribe(topicArn, protocol, endpoint);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Subscription created',
                  subscriptionArn: result.subscriptionArn,
                  note: result.subscriptionArn === 'pending confirmation'
                    ? 'Endpoint must confirm subscription before messages can be received'
                    : undefined,
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
  // Create Topic
  // ===========================================================================
  server.tool(
    'aws_sns_create_topic',
    `Create a new SNS topic.

Args:
  - name: The topic name (required). For FIFO topics, must end with '.fifo'
  - attributes: Optional topic attributes
    - displayName: Display name for the topic
    - kmsMasterKeyId: KMS key ID for encryption
    - fifoTopic: Whether this is a FIFO topic
    - contentBasedDeduplication: Enable content-based deduplication (FIFO only)

Returns the new topic ARN.`,
    {
      name: z.string().describe('Topic name (end with .fifo for FIFO topics)'),
      attributes: z.object({
        displayName: z.string().optional().describe('Display name'),
        kmsMasterKeyId: z.string().optional().describe('KMS key ID'),
        fifoTopic: z.boolean().optional().describe('Create FIFO topic'),
        contentBasedDeduplication: z.boolean().optional().describe('Content-based deduplication'),
      }).optional().describe('Topic attributes'),
    },
    async ({ name, attributes }) => {
      try {
        const result = await client.snsCreateTopic({ name, attributes });
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Topic created',
                  topicArn: result.topicArn,
                  name,
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
  // Delete Topic
  // ===========================================================================
  server.tool(
    'aws_sns_delete_topic',
    `Delete an SNS topic.

WARNING: This action cannot be undone.

Args:
  - topicArn: The topic ARN (required)

Returns confirmation of deletion.`,
    {
      topicArn: z.string().describe('Topic ARN'),
    },
    async ({ topicArn }) => {
      try {
        await client.snsDeleteTopic(topicArn);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Topic deleted',
                  topicArn,
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
  // Unsubscribe
  // ===========================================================================
  server.tool(
    'aws_sns_unsubscribe',
    `Unsubscribe an endpoint from an SNS topic.

Args:
  - subscriptionArn: The subscription ARN (required)

Returns confirmation of unsubscription.`,
    {
      subscriptionArn: z.string().describe('Subscription ARN'),
    },
    async ({ subscriptionArn }) => {
      try {
        await client.snsUnsubscribe(subscriptionArn);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Unsubscribed',
                  subscriptionArn,
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
  // Set Topic Attributes
  // ===========================================================================
  server.tool(
    'aws_sns_set_topic_attributes',
    `Set an attribute on an SNS topic.

Args:
  - topicArn: The topic ARN (required)
  - attributeName: The attribute name (required)
  - attributeValue: The attribute value (required)

Supported attributes:
  - DisplayName: Topic display name
  - Policy: Access policy JSON
  - DeliveryPolicy: Delivery retry policy JSON
  - KmsMasterKeyId: KMS key ID for encryption

Returns confirmation of update.`,
    {
      topicArn: z.string().describe('Topic ARN'),
      attributeName: z.string().describe('Attribute name'),
      attributeValue: z.string().describe('Attribute value'),
    },
    async ({ topicArn, attributeName, attributeValue }) => {
      try {
        await client.snsSetTopicAttributes(topicArn, attributeName, attributeValue);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Topic attribute updated',
                  topicArn,
                  attributeName,
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
  // Tag Resource
  // ===========================================================================
  server.tool(
    'aws_sns_tag_resource',
    `Add or update tags on an SNS resource (topic or subscription).

Args:
  - resourceArn: The resource ARN (required)
  - tags: Tags to add (required)

Returns confirmation of tagging.`,
    {
      resourceArn: z.string().describe('Resource ARN (topic or subscription)'),
      tags: z.array(z.object({
        key: z.string().describe('Tag key'),
        value: z.string().describe('Tag value'),
      })).min(1).describe('Tags to add'),
    },
    async ({ resourceArn, tags }) => {
      try {
        await client.snsTagResource(resourceArn, tags);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Resource tagged',
                  resourceArn,
                  tagsCount: tags.length,
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
  // List Tags For Resource
  // ===========================================================================
  server.tool(
    'aws_sns_list_tags_for_resource',
    `List tags on an SNS resource (topic or subscription).

Args:
  - resourceArn: The resource ARN (required)

Returns the resource tags.`,
    {
      resourceArn: z.string().describe('Resource ARN'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ resourceArn, format }) => {
      try {
        const tags = await client.snsListTagsForResource(resourceArn);
        return formatResponse(
          { items: tags, count: tags.length, hasMore: false },
          format,
          'sns_tags'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Confirm Subscription
  // ===========================================================================
  server.tool(
    'aws_sns_confirm_subscription',
    `Confirm a pending subscription using the token from the confirmation message.

Args:
  - topicArn: The topic ARN (required)
  - token: The confirmation token from the subscription message (required)

Returns the confirmed subscription ARN.`,
    {
      topicArn: z.string().describe('Topic ARN'),
      token: z.string().describe('Confirmation token'),
    },
    async ({ topicArn, token }) => {
      try {
        const result = await client.snsConfirmSubscription(topicArn, token);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Subscription confirmed',
                  subscriptionArn: result.subscriptionArn,
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
  // Get Subscription Attributes
  // ===========================================================================
  server.tool(
    'aws_sns_get_subscription_attributes',
    `Get attributes of an SNS subscription.

Args:
  - subscriptionArn: The subscription ARN (required)

Returns subscription attributes including delivery policy and filter policy.`,
    {
      subscriptionArn: z.string().describe('Subscription ARN'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ subscriptionArn, format }) => {
      try {
        const attrs = await client.snsGetSubscriptionAttributes(subscriptionArn);
        return formatResponse(attrs, format, 'sns_subscription');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Set Subscription Attributes
  // ===========================================================================
  server.tool(
    'aws_sns_set_subscription_attributes',
    `Set an attribute on an SNS subscription.

Args:
  - subscriptionArn: The subscription ARN (required)
  - attributeName: The attribute name (required)
  - attributeValue: The attribute value (required)

Supported attributes:
  - DeliveryPolicy: Delivery retry policy JSON
  - FilterPolicy: Message filter policy JSON
  - RawMessageDelivery: 'true' or 'false'
  - RedrivePolicy: Dead-letter queue policy JSON

Returns confirmation of update.`,
    {
      subscriptionArn: z.string().describe('Subscription ARN'),
      attributeName: z.string().describe('Attribute name'),
      attributeValue: z.string().describe('Attribute value'),
    },
    async ({ subscriptionArn, attributeName, attributeValue }) => {
      try {
        await client.snsSetSubscriptionAttributes(subscriptionArn, attributeName, attributeValue);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Subscription attribute updated',
                  subscriptionArn,
                  attributeName,
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
  // Untag Resource
  // ===========================================================================
  server.tool(
    'aws_sns_untag_resource',
    `Remove tags from an SNS resource (topic or subscription).

Args:
  - resourceArn: The resource ARN (required)
  - tagKeys: Array of tag keys to remove (required)

Returns confirmation of untagging.`,
    {
      resourceArn: z.string().describe('Resource ARN'),
      tagKeys: z.array(z.string()).min(1).describe('Tag keys to remove'),
    },
    async ({ resourceArn, tagKeys }) => {
      try {
        await client.snsUntagResource(resourceArn, tagKeys);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Tags removed',
                  resourceArn,
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
  // Publish Batch
  // ===========================================================================
  server.tool(
    'aws_sns_publish_batch',
    `Publish multiple messages to an SNS topic in a single request.

Args:
  - topicArn: The topic ARN (required)
  - entries: Array of message entries (required, max 10)
    - id: Unique identifier for the message (required)
    - message: Message content (required)
    - subject: Subject for email endpoints (optional)

Returns successful and failed message results.`,
    {
      topicArn: z.string().describe('Topic ARN'),
      entries: z.array(z.object({
        id: z.string().describe('Message ID'),
        message: z.string().describe('Message content'),
        subject: z.string().optional().describe('Subject (for email)'),
      })).min(1).max(10).describe('Message entries'),
    },
    async ({ topicArn, entries }) => {
      try {
        const result = await client.snsPublishBatch(topicArn, entries);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Batch publish completed: ${result.successful.length} succeeded, ${result.failed.length} failed`,
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
}
