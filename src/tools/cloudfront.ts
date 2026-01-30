/**
 * CloudFront Tools
 *
 * MCP tools for Amazon CloudFront CDN operations.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { AwsClient } from '../client.js';
import { formatError, formatResponse } from '../utils/formatters.js';

export function registerCloudFrontTools(server: McpServer, client: AwsClient): void {
  // ===========================================================================
  // List Distributions
  // ===========================================================================
  server.tool(
    'aws_cloudfront_list_distributions',
    `List all CloudFront distributions.

Returns distributions with IDs, domains, and status.`,
    {
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ format }) => {
      try {
        const distributions = await client.cloudfrontListDistributions();
        return formatResponse(
          { items: distributions, count: distributions.length, hasMore: false },
          format,
          'cloudfront_distributions'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Get Distribution
  // ===========================================================================
  server.tool(
    'aws_cloudfront_get_distribution',
    `Get details of a CloudFront distribution.

Args:
  - id: The distribution ID (required)

Returns distribution configuration including origins and behaviors.`,
    {
      id: z.string().describe('Distribution ID'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ id, format }) => {
      try {
        const distribution = await client.cloudfrontGetDistribution(id);
        return formatResponse(distribution, format, 'cloudfront_distribution');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Create Invalidation
  // ===========================================================================
  server.tool(
    'aws_cloudfront_create_invalidation',
    `Create a cache invalidation for a CloudFront distribution.

Args:
  - distributionId: The distribution ID (required)
  - paths: Array of paths to invalidate (required, e.g., ['/*'] or ['/images/*', '/index.html'])
  - callerReference: Unique identifier for this request (optional, auto-generated if not provided)

Returns the invalidation details including ID and status.`,
    {
      distributionId: z.string().describe('Distribution ID'),
      paths: z.array(z.string()).min(1).describe('Paths to invalidate'),
      callerReference: z.string().optional().describe('Unique identifier'),
    },
    async ({ distributionId, paths, callerReference }) => {
      try {
        const invalidation = await client.cloudfrontCreateInvalidation(distributionId, paths, callerReference);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Invalidation created',
                  invalidationId: invalidation.id,
                  status: invalidation.status,
                  createTime: invalidation.createTime,
                  paths: invalidation.paths,
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
  // List Invalidations
  // ===========================================================================
  server.tool(
    'aws_cloudfront_list_invalidations',
    `List cache invalidations for a CloudFront distribution.

Args:
  - distributionId: The distribution ID (required)

Returns list of invalidations with IDs and status.`,
    {
      distributionId: z.string().describe('Distribution ID'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ distributionId, format }) => {
      try {
        const invalidations = await client.cloudfrontListInvalidations(distributionId);
        return formatResponse(
          { items: invalidations, count: invalidations.length, hasMore: false },
          format,
          'cloudfront_invalidations'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Get Invalidation
  // ===========================================================================
  server.tool(
    'aws_cloudfront_get_invalidation',
    `Get details of a CloudFront cache invalidation.

Args:
  - distributionId: The distribution ID (required)
  - invalidationId: The invalidation ID (required)

Returns invalidation details including paths and status.`,
    {
      distributionId: z.string().describe('Distribution ID'),
      invalidationId: z.string().describe('Invalidation ID'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ distributionId, invalidationId, format }) => {
      try {
        const invalidation = await client.cloudfrontGetInvalidation(distributionId, invalidationId);
        return formatResponse(invalidation, format, 'cloudfront_invalidation');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // List Tags For Resource
  // ===========================================================================
  server.tool(
    'aws_cloudfront_list_tags_for_resource',
    `List tags on a CloudFront resource.

Args:
  - resourceArn: The CloudFront resource ARN (required)

Returns the resource tags.`,
    {
      resourceArn: z.string().describe('CloudFront resource ARN'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ resourceArn, format }) => {
      try {
        const tags = await client.cloudfrontListTagsForResource(resourceArn);
        return formatResponse(
          { items: tags, count: tags.length, hasMore: false },
          format,
          'cloudfront_tags'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Tag Resource
  // ===========================================================================
  server.tool(
    'aws_cloudfront_tag_resource',
    `Add or update tags on a CloudFront resource.

Args:
  - resourceArn: The CloudFront resource ARN (required)
  - tags: Array of tags to add (required)

Returns confirmation.`,
    {
      resourceArn: z.string().describe('CloudFront resource ARN'),
      tags: z.array(z.object({
        key: z.string().describe('Tag key'),
        value: z.string().describe('Tag value'),
      })).min(1).describe('Tags to add'),
    },
    async ({ resourceArn, tags }) => {
      try {
        await client.cloudfrontTagResource(resourceArn, tags);
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
  // Untag Resource
  // ===========================================================================
  server.tool(
    'aws_cloudfront_untag_resource',
    `Remove tags from a CloudFront resource.

Args:
  - resourceArn: The CloudFront resource ARN (required)
  - tagKeys: Array of tag keys to remove (required)

Returns confirmation.`,
    {
      resourceArn: z.string().describe('CloudFront resource ARN'),
      tagKeys: z.array(z.string()).min(1).describe('Tag keys to remove'),
    },
    async ({ resourceArn, tagKeys }) => {
      try {
        await client.cloudfrontUntagResource(resourceArn, tagKeys);
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
}
