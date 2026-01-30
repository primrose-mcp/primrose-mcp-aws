/**
 * S3 Tools
 *
 * MCP tools for Amazon S3 operations.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { AwsClient } from '../client.js';
import { formatError, formatResponse } from '../utils/formatters.js';

export function registerS3Tools(server: McpServer, client: AwsClient): void {
  // ===========================================================================
  // List Buckets
  // ===========================================================================
  server.tool(
    'aws_s3_list_buckets',
    `List all S3 buckets in the AWS account.

Returns a list of all S3 buckets with their names and creation dates.`,
    {
      format: z.enum(['json', 'markdown']).default('json').describe('Response format'),
    },
    async ({ format }) => {
      try {
        const buckets = await client.s3ListBuckets();
        return formatResponse(
          { items: buckets, count: buckets.length, hasMore: false },
          format,
          's3_buckets'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // List Objects
  // ===========================================================================
  server.tool(
    'aws_s3_list_objects',
    `List objects in an S3 bucket.

Args:
  - bucket: The bucket name (required)
  - prefix: Filter objects by prefix
  - delimiter: Delimiter for grouping (usually '/')
  - maxKeys: Maximum number of keys to return (default: 1000)
  - continuationToken: Token for pagination

Returns paginated list of objects with keys, sizes, and metadata.`,
    {
      bucket: z.string().describe('S3 bucket name'),
      prefix: z.string().optional().describe('Filter objects by prefix'),
      delimiter: z.string().optional().describe("Delimiter for grouping (e.g., '/')"),
      maxKeys: z.number().int().min(1).max(1000).default(100).describe('Maximum keys to return'),
      continuationToken: z.string().optional().describe('Pagination token'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ bucket, prefix, delimiter, maxKeys, continuationToken, format }) => {
      try {
        const result = await client.s3ListObjects({
          bucket,
          prefix,
          delimiter,
          maxKeys,
          continuationToken,
        });
        return formatResponse(
          {
            items: result.objects,
            count: result.objects.length,
            hasMore: result.isTruncated,
            nextToken: result.nextContinuationToken,
            commonPrefixes: result.commonPrefixes,
          },
          format,
          's3_objects'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Get Object
  // ===========================================================================
  server.tool(
    'aws_s3_get_object',
    `Get the contents of an S3 object.

Args:
  - bucket: The bucket name (required)
  - key: The object key (required)

Returns the object contents as text. Best for text files, JSON, etc.
For binary files, consider using presigned URLs instead.`,
    {
      bucket: z.string().describe('S3 bucket name'),
      key: z.string().describe('Object key (path)'),
    },
    async ({ bucket, key }) => {
      try {
        const content = await client.s3GetObject({ bucket, key });
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  bucket,
                  key,
                  content: content.substring(0, 50000), // Truncate large files
                  truncated: content.length > 50000,
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
  // Put Object
  // ===========================================================================
  server.tool(
    'aws_s3_put_object',
    `Upload an object to S3.

Args:
  - bucket: The bucket name (required)
  - key: The object key/path (required)
  - body: The content to upload (required)
  - contentType: MIME type (default: application/octet-stream)

Returns confirmation with the object's ETag.`,
    {
      bucket: z.string().describe('S3 bucket name'),
      key: z.string().describe('Object key (path)'),
      body: z.string().describe('Content to upload'),
      contentType: z.string().optional().describe('MIME type of the content'),
    },
    async ({ bucket, key, body, contentType }) => {
      try {
        const result = await client.s3PutObject({ bucket, key, body, contentType });
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Object uploaded to s3://${bucket}/${key}`,
                  etag: result.etag,
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
  // Delete Object
  // ===========================================================================
  server.tool(
    'aws_s3_delete_object',
    `Delete an object from S3.

Args:
  - bucket: The bucket name (required)
  - key: The object key (required)

Returns confirmation of deletion.`,
    {
      bucket: z.string().describe('S3 bucket name'),
      key: z.string().describe('Object key to delete'),
    },
    async ({ bucket, key }) => {
      try {
        await client.s3DeleteObject({ bucket, key });
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Deleted s3://${bucket}/${key}`,
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
  // Copy Object
  // ===========================================================================
  server.tool(
    'aws_s3_copy_object',
    `Copy an object within or between S3 buckets.

Args:
  - sourceBucket: Source bucket name (required)
  - sourceKey: Source object key (required)
  - destinationBucket: Destination bucket name (required)
  - destinationKey: Destination object key (required)

Returns confirmation of the copy operation.`,
    {
      sourceBucket: z.string().describe('Source bucket name'),
      sourceKey: z.string().describe('Source object key'),
      destinationBucket: z.string().describe('Destination bucket name'),
      destinationKey: z.string().describe('Destination object key'),
    },
    async ({ sourceBucket, sourceKey, destinationBucket, destinationKey }) => {
      try {
        await client.s3CopyObject({
          sourceBucket,
          sourceKey,
          destinationBucket,
          destinationKey,
        });
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Copied s3://${sourceBucket}/${sourceKey} to s3://${destinationBucket}/${destinationKey}`,
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
  // Get Bucket Location
  // ===========================================================================
  server.tool(
    'aws_s3_get_bucket_location',
    `Get the AWS region where an S3 bucket is located.

Args:
  - bucket: The bucket name (required)

Returns the region name (e.g., 'us-east-1', 'eu-west-1').`,
    {
      bucket: z.string().describe('S3 bucket name'),
    },
    async ({ bucket }) => {
      try {
        const location = await client.s3GetBucketLocation(bucket);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({ bucket, region: location }, null, 2),
            },
          ],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Head Object
  // ===========================================================================
  server.tool(
    'aws_s3_head_object',
    `Get metadata about an S3 object without downloading it.

Args:
  - bucket: The bucket name (required)
  - key: The object key (required)

Returns object metadata including size, content type, and last modified date.`,
    {
      bucket: z.string().describe('S3 bucket name'),
      key: z.string().describe('Object key (path)'),
    },
    async ({ bucket, key }) => {
      try {
        const metadata = await client.s3HeadObject(bucket, key);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({ bucket, key, ...metadata }, null, 2),
            },
          ],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Delete Objects (batch)
  // ===========================================================================
  server.tool(
    'aws_s3_delete_objects',
    `Delete multiple objects from S3 in a single request.

Args:
  - bucket: The bucket name (required)
  - keys: Array of object keys to delete (required, max 1000)

Returns list of deleted keys and any errors.`,
    {
      bucket: z.string().describe('S3 bucket name'),
      keys: z.array(z.string()).min(1).max(1000).describe('Object keys to delete'),
    },
    async ({ bucket, keys }) => {
      try {
        const result = await client.s3DeleteObjects(bucket, keys);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  bucket,
                  deletedCount: result.deleted.length,
                  errorCount: result.errors.length,
                  deleted: result.deleted,
                  errors: result.errors,
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
  // Get Bucket Versioning
  // ===========================================================================
  server.tool(
    'aws_s3_get_bucket_versioning',
    `Get the versioning configuration for an S3 bucket.

Args:
  - bucket: The bucket name (required)

Returns versioning status ('Enabled', 'Suspended', or not set).`,
    {
      bucket: z.string().describe('S3 bucket name'),
    },
    async ({ bucket }) => {
      try {
        const versioning = await client.s3GetBucketVersioning(bucket);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({ bucket, ...versioning }, null, 2),
            },
          ],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Create Bucket
  // ===========================================================================
  server.tool(
    'aws_s3_create_bucket',
    `Create a new S3 bucket.

Args:
  - bucket: The bucket name (required)
  - region: AWS region for the bucket (optional, uses client region if not specified)

Returns confirmation of bucket creation.`,
    {
      bucket: z.string().describe('S3 bucket name'),
      region: z.string().optional().describe('AWS region for the bucket'),
    },
    async ({ bucket, region }) => {
      try {
        await client.s3CreateBucket(bucket, region);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Bucket '${bucket}' created successfully`,
                  bucket,
                  region: region || 'default',
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
  // Delete Bucket
  // ===========================================================================
  server.tool(
    'aws_s3_delete_bucket',
    `Delete an S3 bucket.

Args:
  - bucket: The bucket name (required)

Note: The bucket must be empty before it can be deleted.
Returns confirmation of bucket deletion.`,
    {
      bucket: z.string().describe('S3 bucket name'),
    },
    async ({ bucket }) => {
      try {
        await client.s3DeleteBucket(bucket);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Bucket '${bucket}' deleted successfully`,
                  bucket,
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
  // Get Bucket Policy
  // ===========================================================================
  server.tool(
    'aws_s3_get_bucket_policy',
    `Get the bucket policy for an S3 bucket.

Args:
  - bucket: The bucket name (required)

Returns the bucket policy as a JSON string.`,
    {
      bucket: z.string().describe('S3 bucket name'),
    },
    async ({ bucket }) => {
      try {
        const policy = await client.s3GetBucketPolicy(bucket);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({ bucket, policy: JSON.parse(policy) }, null, 2),
            },
          ],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Put Bucket Policy
  // ===========================================================================
  server.tool(
    'aws_s3_put_bucket_policy',
    `Set the bucket policy for an S3 bucket.

Args:
  - bucket: The bucket name (required)
  - policy: The bucket policy as a JSON string (required)

Returns confirmation of policy update.`,
    {
      bucket: z.string().describe('S3 bucket name'),
      policy: z.string().describe('Bucket policy as JSON string'),
    },
    async ({ bucket, policy }) => {
      try {
        await client.s3PutBucketPolicy(bucket, policy);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Bucket policy set for '${bucket}'`,
                  bucket,
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
  // Delete Bucket Policy
  // ===========================================================================
  server.tool(
    'aws_s3_delete_bucket_policy',
    `Delete the bucket policy for an S3 bucket.

Args:
  - bucket: The bucket name (required)

Returns confirmation of policy deletion.`,
    {
      bucket: z.string().describe('S3 bucket name'),
    },
    async ({ bucket }) => {
      try {
        await client.s3DeleteBucketPolicy(bucket);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Bucket policy deleted for '${bucket}'`,
                  bucket,
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
  // Get Bucket CORS
  // ===========================================================================
  server.tool(
    'aws_s3_get_bucket_cors',
    `Get the CORS configuration for an S3 bucket.

Args:
  - bucket: The bucket name (required)

Returns the CORS rules configured for the bucket.`,
    {
      bucket: z.string().describe('S3 bucket name'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ bucket, format }) => {
      try {
        const rules = await client.s3GetBucketCors(bucket);
        return formatResponse(
          { items: rules, count: rules.length, hasMore: false },
          format,
          's3_cors_rules'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Put Bucket CORS
  // ===========================================================================
  server.tool(
    'aws_s3_put_bucket_cors',
    `Set the CORS configuration for an S3 bucket.

Args:
  - bucket: The bucket name (required)
  - rules: Array of CORS rules (required)

Each rule can include:
  - allowedOrigins: Array of allowed origins (required)
  - allowedMethods: Array of allowed HTTP methods (required)
  - allowedHeaders: Array of allowed headers (optional)
  - exposeHeaders: Array of headers to expose (optional)
  - maxAgeSeconds: Cache duration in seconds (optional)

Returns confirmation of CORS configuration update.`,
    {
      bucket: z.string().describe('S3 bucket name'),
      rules: z.array(z.object({
        allowedOrigins: z.array(z.string()).describe('Allowed origins'),
        allowedMethods: z.array(z.string()).describe('Allowed HTTP methods'),
        allowedHeaders: z.array(z.string()).optional().describe('Allowed headers'),
        exposeHeaders: z.array(z.string()).optional().describe('Headers to expose'),
        maxAgeSeconds: z.number().int().optional().describe('Cache duration in seconds'),
      })).min(1).describe('CORS rules'),
    },
    async ({ bucket, rules }) => {
      try {
        await client.s3PutBucketCors(bucket, rules);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `CORS configuration set for '${bucket}'`,
                  bucket,
                  rulesCount: rules.length,
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
  // Delete Bucket CORS
  // ===========================================================================
  server.tool(
    'aws_s3_delete_bucket_cors',
    `Delete the CORS configuration for an S3 bucket.

Args:
  - bucket: The bucket name (required)

Returns confirmation of CORS configuration deletion.`,
    {
      bucket: z.string().describe('S3 bucket name'),
    },
    async ({ bucket }) => {
      try {
        await client.s3DeleteBucketCors(bucket);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `CORS configuration deleted for '${bucket}'`,
                  bucket,
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
  // Get Bucket Tagging
  // ===========================================================================
  server.tool(
    'aws_s3_get_bucket_tagging',
    `Get the tags for an S3 bucket.

Args:
  - bucket: The bucket name (required)

Returns the tags configured for the bucket.`,
    {
      bucket: z.string().describe('S3 bucket name'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ bucket, format }) => {
      try {
        const tagging = await client.s3GetBucketTagging(bucket);
        return formatResponse(
          { items: tagging.tagSet, count: tagging.tagSet.length, hasMore: false },
          format,
          's3_bucket_tags'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Put Bucket Tagging
  // ===========================================================================
  server.tool(
    'aws_s3_put_bucket_tagging',
    `Set tags for an S3 bucket.

Args:
  - bucket: The bucket name (required)
  - tags: Array of tags with key and value (required)

Returns confirmation of tagging update.`,
    {
      bucket: z.string().describe('S3 bucket name'),
      tags: z.array(z.object({
        key: z.string().describe('Tag key'),
        value: z.string().describe('Tag value'),
      })).min(1).describe('Tags to set'),
    },
    async ({ bucket, tags }) => {
      try {
        await client.s3PutBucketTagging(bucket, tags);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Tags set for bucket '${bucket}'`,
                  bucket,
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
  // Delete Bucket Tagging
  // ===========================================================================
  server.tool(
    'aws_s3_delete_bucket_tagging',
    `Delete all tags from an S3 bucket.

Args:
  - bucket: The bucket name (required)

Returns confirmation of tagging deletion.`,
    {
      bucket: z.string().describe('S3 bucket name'),
    },
    async ({ bucket }) => {
      try {
        await client.s3DeleteBucketTagging(bucket);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Tags deleted for bucket '${bucket}'`,
                  bucket,
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
  // Put Bucket Versioning
  // ===========================================================================
  server.tool(
    'aws_s3_put_bucket_versioning',
    `Enable or suspend versioning for an S3 bucket.

Args:
  - bucket: The bucket name (required)
  - status: 'Enabled' or 'Suspended' (required)

Returns confirmation of versioning configuration update.`,
    {
      bucket: z.string().describe('S3 bucket name'),
      status: z.enum(['Enabled', 'Suspended']).describe('Versioning status'),
    },
    async ({ bucket, status }) => {
      try {
        await client.s3PutBucketVersioning(bucket, status);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Versioning ${status.toLowerCase()} for bucket '${bucket}'`,
                  bucket,
                  status,
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
  // Get Bucket Lifecycle Configuration
  // ===========================================================================
  server.tool(
    'aws_s3_get_bucket_lifecycle_configuration',
    `Get the lifecycle configuration for an S3 bucket.

Args:
  - bucket: The bucket name (required)

Returns lifecycle rules including expiration and transition settings.`,
    {
      bucket: z.string().describe('S3 bucket name'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ bucket, format }) => {
      try {
        const rules = await client.s3GetBucketLifecycleConfiguration(bucket);
        return formatResponse(
          { items: rules, count: rules.length, hasMore: false },
          format,
          's3_lifecycle_rules'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Put Bucket Lifecycle Configuration
  // ===========================================================================
  server.tool(
    'aws_s3_put_bucket_lifecycle_configuration',
    `Set the lifecycle configuration for an S3 bucket.

Args:
  - bucket: The bucket name (required)
  - rules: Array of lifecycle rules (required)

Each rule can include:
  - id: Rule identifier
  - status: 'Enabled' or 'Disabled'
  - prefix: Object key prefix for the rule
  - expiration: Object expiration settings
  - transitions: Storage class transitions

Returns confirmation of lifecycle configuration update.`,
    {
      bucket: z.string().describe('S3 bucket name'),
      rules: z.array(z.object({
        id: z.string().optional().describe('Rule identifier'),
        status: z.enum(['Enabled', 'Disabled']).describe('Rule status'),
        prefix: z.string().optional().describe('Object key prefix'),
        expiration: z.object({
          days: z.number().int().optional().describe('Days until expiration'),
          date: z.string().optional().describe('Expiration date (ISO 8601)'),
          expiredObjectDeleteMarker: z.boolean().optional().describe('Remove expired delete markers'),
        }).optional().describe('Expiration settings'),
        transitions: z.array(z.object({
          days: z.number().int().optional().describe('Days until transition'),
          date: z.string().optional().describe('Transition date (ISO 8601)'),
          storageClass: z.string().describe('Target storage class (e.g., GLACIER, INTELLIGENT_TIERING)'),
        })).optional().describe('Storage class transitions'),
        noncurrentVersionExpiration: z.object({
          noncurrentDays: z.number().int().optional().describe('Days until noncurrent version expiration'),
        }).optional().describe('Noncurrent version expiration settings'),
      })).min(1).describe('Lifecycle rules'),
    },
    async ({ bucket, rules }) => {
      try {
        await client.s3PutBucketLifecycleConfiguration(bucket, rules);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Lifecycle configuration set for bucket '${bucket}'`,
                  bucket,
                  rulesCount: rules.length,
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
  // Delete Bucket Lifecycle Configuration
  // ===========================================================================
  server.tool(
    'aws_s3_delete_bucket_lifecycle_configuration',
    `Delete the lifecycle configuration for an S3 bucket.

Args:
  - bucket: The bucket name (required)

Returns confirmation of lifecycle configuration deletion.`,
    {
      bucket: z.string().describe('S3 bucket name'),
    },
    async ({ bucket }) => {
      try {
        await client.s3DeleteBucketLifecycleConfiguration(bucket);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Lifecycle configuration deleted for bucket '${bucket}'`,
                  bucket,
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
  // Get Bucket Encryption
  // ===========================================================================
  server.tool(
    'aws_s3_get_bucket_encryption',
    `Get the server-side encryption configuration for an S3 bucket.

Args:
  - bucket: The bucket name (required)

Returns encryption rules including SSE algorithm and KMS key.`,
    {
      bucket: z.string().describe('S3 bucket name'),
    },
    async ({ bucket }) => {
      try {
        const encryption = await client.s3GetBucketEncryption(bucket);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({ bucket, ...encryption }, null, 2),
            },
          ],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Put Bucket Encryption
  // ===========================================================================
  server.tool(
    'aws_s3_put_bucket_encryption',
    `Set the server-side encryption configuration for an S3 bucket.

Args:
  - bucket: The bucket name (required)
  - sseAlgorithm: 'AES256' for S3-managed keys or 'aws:kms' for KMS (required)
  - kmsMasterKeyId: KMS key ID (required if sseAlgorithm is 'aws:kms')

Returns confirmation of encryption configuration update.`,
    {
      bucket: z.string().describe('S3 bucket name'),
      sseAlgorithm: z.enum(['AES256', 'aws:kms']).describe('Server-side encryption algorithm'),
      kmsMasterKeyId: z.string().optional().describe('KMS key ID or ARN (for aws:kms)'),
    },
    async ({ bucket, sseAlgorithm, kmsMasterKeyId }) => {
      try {
        await client.s3PutBucketEncryption(bucket, sseAlgorithm, kmsMasterKeyId);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Encryption configuration set for bucket '${bucket}'`,
                  bucket,
                  sseAlgorithm,
                  kmsMasterKeyId: kmsMasterKeyId || undefined,
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
  // Delete Bucket Encryption
  // ===========================================================================
  server.tool(
    'aws_s3_delete_bucket_encryption',
    `Delete the server-side encryption configuration for an S3 bucket.

Args:
  - bucket: The bucket name (required)

Returns confirmation of encryption configuration deletion.`,
    {
      bucket: z.string().describe('S3 bucket name'),
    },
    async ({ bucket }) => {
      try {
        await client.s3DeleteBucketEncryption(bucket);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Encryption configuration deleted for bucket '${bucket}'`,
                  bucket,
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
  // Get Bucket Website
  // ===========================================================================
  server.tool(
    'aws_s3_get_bucket_website',
    `Get the static website configuration for an S3 bucket.

Args:
  - bucket: The bucket name (required)

Returns website configuration including index and error documents.`,
    {
      bucket: z.string().describe('S3 bucket name'),
    },
    async ({ bucket }) => {
      try {
        const config = await client.s3GetBucketWebsite(bucket);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({ bucket, ...config }, null, 2),
            },
          ],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Put Bucket Website
  // ===========================================================================
  server.tool(
    'aws_s3_put_bucket_website',
    `Configure an S3 bucket for static website hosting.

Args:
  - bucket: The bucket name (required)
  - indexDocument: Default index document (e.g., 'index.html')
  - errorDocument: Error document (e.g., 'error.html')
  - redirectAllRequestsTo: Redirect all requests to another host (optional)

Returns confirmation of website configuration update.`,
    {
      bucket: z.string().describe('S3 bucket name'),
      indexDocument: z.string().optional().describe('Index document suffix (e.g., index.html)'),
      errorDocument: z.string().optional().describe('Error document key (e.g., error.html)'),
      redirectAllRequestsTo: z.object({
        hostName: z.string().describe('Host name to redirect to'),
        protocol: z.enum(['http', 'https']).optional().describe('Protocol for redirect'),
      }).optional().describe('Redirect all requests to another host'),
    },
    async ({ bucket, indexDocument, errorDocument, redirectAllRequestsTo }) => {
      try {
        await client.s3PutBucketWebsite(bucket, {
          indexDocument,
          errorDocument,
          redirectAllRequestsTo,
        });
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Website configuration set for bucket '${bucket}'`,
                  bucket,
                  indexDocument,
                  errorDocument,
                  redirectAllRequestsTo,
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
  // Delete Bucket Website
  // ===========================================================================
  server.tool(
    'aws_s3_delete_bucket_website',
    `Delete the static website configuration for an S3 bucket.

Args:
  - bucket: The bucket name (required)

Returns confirmation of website configuration deletion.`,
    {
      bucket: z.string().describe('S3 bucket name'),
    },
    async ({ bucket }) => {
      try {
        await client.s3DeleteBucketWebsite(bucket);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Website configuration deleted for bucket '${bucket}'`,
                  bucket,
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
  // Get Object Tagging
  // ===========================================================================
  server.tool(
    'aws_s3_get_object_tagging',
    `Get the tags for an S3 object.

Args:
  - bucket: The bucket name (required)
  - key: The object key (required)

Returns the tags configured for the object.`,
    {
      bucket: z.string().describe('S3 bucket name'),
      key: z.string().describe('Object key'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ bucket, key, format }) => {
      try {
        const tagging = await client.s3GetObjectTagging(bucket, key);
        return formatResponse(
          { items: tagging.tagSet, count: tagging.tagSet.length, hasMore: false },
          format,
          's3_object_tags'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Put Object Tagging
  // ===========================================================================
  server.tool(
    'aws_s3_put_object_tagging',
    `Set tags for an S3 object.

Args:
  - bucket: The bucket name (required)
  - key: The object key (required)
  - tags: Array of tags with key and value (required)

Returns confirmation of tagging update.`,
    {
      bucket: z.string().describe('S3 bucket name'),
      key: z.string().describe('Object key'),
      tags: z.array(z.object({
        key: z.string().describe('Tag key'),
        value: z.string().describe('Tag value'),
      })).min(1).describe('Tags to set'),
    },
    async ({ bucket, key, tags }) => {
      try {
        await client.s3PutObjectTagging(bucket, key, tags);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Tags set for object '${key}' in bucket '${bucket}'`,
                  bucket,
                  key,
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
  // Delete Object Tagging
  // ===========================================================================
  server.tool(
    'aws_s3_delete_object_tagging',
    `Delete all tags from an S3 object.

Args:
  - bucket: The bucket name (required)
  - key: The object key (required)

Returns confirmation of tagging deletion.`,
    {
      bucket: z.string().describe('S3 bucket name'),
      key: z.string().describe('Object key'),
    },
    async ({ bucket, key }) => {
      try {
        await client.s3DeleteObjectTagging(bucket, key);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Tags deleted for object '${key}' in bucket '${bucket}'`,
                  bucket,
                  key,
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
  // Get Bucket ACL
  // ===========================================================================
  server.tool(
    'aws_s3_get_bucket_acl',
    `Get the access control list (ACL) for a bucket.

Args:
  - bucket: The S3 bucket name (required)

Returns the bucket owner and grants.`,
    {
      bucket: z.string().describe('S3 bucket name'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ bucket, format }) => {
      try {
        const acl = await client.s3GetBucketAcl(bucket);
        return formatResponse(acl, format, 's3_bucket_acl');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Get Object ACL
  // ===========================================================================
  server.tool(
    'aws_s3_get_object_acl',
    `Get the access control list (ACL) for an object.

Args:
  - bucket: The S3 bucket name (required)
  - key: The object key (required)

Returns the object owner and grants.`,
    {
      bucket: z.string().describe('S3 bucket name'),
      key: z.string().describe('Object key'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ bucket, key, format }) => {
      try {
        const acl = await client.s3GetObjectAcl(bucket, key);
        return formatResponse(acl, format, 's3_object_acl');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // List Object Versions
  // ===========================================================================
  server.tool(
    'aws_s3_list_object_versions',
    `List object versions in a versioning-enabled bucket.

Args:
  - bucket: The S3 bucket name (required)
  - prefix: Filter objects by prefix (optional)

Returns versions and delete markers.`,
    {
      bucket: z.string().describe('S3 bucket name'),
      prefix: z.string().optional().describe('Object key prefix'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ bucket, prefix, format }) => {
      try {
        const result = await client.s3ListObjectVersions(bucket, prefix);
        return formatResponse(
          {
            versions: result.versions,
            deleteMarkers: result.deleteMarkers,
            versionsCount: result.versions.length,
            deleteMarkersCount: result.deleteMarkers.length,
          },
          format,
          's3_object_versions'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Get Bucket Logging
  // ===========================================================================
  server.tool(
    'aws_s3_get_bucket_logging',
    `Get the logging configuration for a bucket.

Args:
  - bucket: The S3 bucket name (required)

Returns the logging target bucket and prefix.`,
    {
      bucket: z.string().describe('S3 bucket name'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ bucket, format }) => {
      try {
        const logging = await client.s3GetBucketLogging(bucket);
        return formatResponse(
          {
            bucket,
            loggingEnabled: !!(logging.targetBucket),
            targetBucket: logging.targetBucket,
            targetPrefix: logging.targetPrefix,
          },
          format,
          's3_bucket_logging'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Put Bucket Logging
  // ===========================================================================
  server.tool(
    'aws_s3_put_bucket_logging',
    `Enable access logging for a bucket.

Args:
  - bucket: The S3 bucket name (required)
  - targetBucket: The bucket to store logs (required)
  - targetPrefix: Prefix for log files (optional)

Returns confirmation.`,
    {
      bucket: z.string().describe('S3 bucket name'),
      targetBucket: z.string().describe('Target bucket for logs'),
      targetPrefix: z.string().optional().describe('Log file prefix'),
    },
    async ({ bucket, targetBucket, targetPrefix }) => {
      try {
        await client.s3PutBucketLogging(bucket, targetBucket, targetPrefix);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Logging enabled for bucket '${bucket}'`,
                  targetBucket,
                  targetPrefix: targetPrefix || '',
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
  // Get Bucket Notification Configuration
  // ===========================================================================
  server.tool(
    'aws_s3_get_bucket_notification_configuration',
    `Get the notification configuration for a bucket.

Args:
  - bucket: The S3 bucket name (required)

Returns Lambda, SQS, and SNS notification configurations.`,
    {
      bucket: z.string().describe('S3 bucket name'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ bucket, format }) => {
      try {
        const config = await client.s3GetBucketNotificationConfiguration(bucket);
        return formatResponse(config, format, 's3_bucket_notifications');
      } catch (error) {
        return formatError(error);
      }
    }
  );
}
