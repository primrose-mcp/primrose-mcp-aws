/**
 * Secrets Manager Tools
 *
 * MCP tools for AWS Secrets Manager operations.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { AwsClient } from '../client.js';
import { formatError, formatResponse } from '../utils/formatters.js';

export function registerSecretsManagerTools(server: McpServer, client: AwsClient): void {
  // ===========================================================================
  // List Secrets
  // ===========================================================================
  server.tool(
    'aws_secrets_list_secrets',
    `List all secrets in Secrets Manager.

Returns secret metadata (not values). Use get_secret_value to retrieve values.`,
    {
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ format }) => {
      try {
        const secrets = await client.secretsListSecrets();
        return formatResponse(
          { items: secrets, count: secrets.length, hasMore: false },
          format,
          'secrets'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Get Secret Value
  // ===========================================================================
  server.tool(
    'aws_secrets_get_secret_value',
    `Get the value of a secret from Secrets Manager.

Args:
  - secretId: The secret name or ARN (required)

Returns the secret value (string or binary).
WARNING: This returns sensitive data. Handle with care.`,
    {
      secretId: z.string().describe('Secret name or ARN'),
    },
    async ({ secretId }) => {
      try {
        const secret = await client.secretsGetSecretValue(secretId);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  name: secret.name,
                  arn: secret.arn,
                  versionId: secret.versionId,
                  versionStages: secret.versionStages,
                  secretString: secret.secretString,
                  createdDate: secret.createdDate,
                  warning: 'This is sensitive data. Handle securely.',
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
  // Describe Secret
  // ===========================================================================
  server.tool(
    'aws_secrets_describe_secret',
    `Get metadata about a secret (without the value).

Args:
  - secretId: The secret name or ARN (required)

Returns secret metadata including rotation status and tags.`,
    {
      secretId: z.string().describe('Secret name or ARN'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ secretId, format }) => {
      try {
        const secret = await client.secretsDescribeSecret(secretId);
        return formatResponse(secret, format, 'secret');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Create Secret
  // ===========================================================================
  server.tool(
    'aws_secrets_create_secret',
    `Create a new secret in Secrets Manager.

Args:
  - name: The secret name (required)
  - secretString: The secret value (required for string secrets)
  - description: Optional description
  - kmsKeyId: Optional KMS key ID for encryption
  - tags: Optional tags as [{key, value}]

Returns the created secret ARN and name.`,
    {
      name: z.string().describe('Secret name'),
      secretString: z.string().optional().describe('Secret value (string)'),
      description: z.string().optional().describe('Description'),
      kmsKeyId: z.string().optional().describe('KMS key ID'),
      tags: z.array(z.object({ key: z.string(), value: z.string() })).optional().describe('Tags'),
    },
    async ({ name, secretString, description, kmsKeyId, tags }) => {
      try {
        const result = await client.secretsCreateSecret({
          name,
          secretString,
          description,
          kmsKeyId,
          tags,
        });
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Secret created',
                  arn: result.arn,
                  name: result.name,
                  versionId: result.versionId,
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
  // Update Secret
  // ===========================================================================
  server.tool(
    'aws_secrets_update_secret',
    `Update the value of an existing secret.

Args:
  - secretId: The secret name or ARN (required)
  - secretString: The new secret value (required)

Returns the updated secret ARN and version ID.`,
    {
      secretId: z.string().describe('Secret name or ARN'),
      secretString: z.string().describe('New secret value'),
    },
    async ({ secretId, secretString }) => {
      try {
        const result = await client.secretsUpdateSecret(secretId, secretString);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Secret updated',
                  arn: result.arn,
                  name: result.name,
                  versionId: result.versionId,
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
  // Delete Secret
  // ===========================================================================
  server.tool(
    'aws_secrets_delete_secret',
    `Delete a secret from Secrets Manager.

By default, secrets are scheduled for deletion after a recovery window.
Use forceDeleteWithoutRecovery to delete immediately (cannot be undone).

Args:
  - secretId: The secret name or ARN (required)
  - forceDeleteWithoutRecovery: Delete immediately without recovery window

Returns deletion confirmation with scheduled deletion date.`,
    {
      secretId: z.string().describe('Secret name or ARN'),
      forceDeleteWithoutRecovery: z.boolean().default(false).describe('Force immediate deletion'),
    },
    async ({ secretId, forceDeleteWithoutRecovery }) => {
      try {
        const result = await client.secretsDeleteSecret(secretId, forceDeleteWithoutRecovery);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: forceDeleteWithoutRecovery ? 'Secret deleted immediately' : 'Secret scheduled for deletion',
                  arn: result.arn,
                  name: result.name,
                  deletionDate: result.deletionDate,
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
  // Restore Secret
  // ===========================================================================
  server.tool(
    'aws_secrets_restore_secret',
    `Restore a previously deleted secret that is scheduled for deletion.

Args:
  - secretId: The secret name or ARN (required)

Returns the restored secret ARN and name.
Note: Only works for secrets that are scheduled for deletion, not immediately deleted.`,
    {
      secretId: z.string().describe('Secret name or ARN'),
    },
    async ({ secretId }) => {
      try {
        const result = await client.secretsRestoreSecret(secretId);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Secret restored',
                  arn: result.arn,
                  name: result.name,
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
  // Rotate Secret
  // ===========================================================================
  server.tool(
    'aws_secrets_rotate_secret',
    `Trigger immediate rotation of a secret.

Args:
  - secretId: The secret name or ARN (required)
  - rotationLambdaARN: ARN of the Lambda function for rotation (optional, uses existing if not specified)

Returns the rotated secret ARN, name, and new version ID.
Note: Requires rotation to be configured on the secret.`,
    {
      secretId: z.string().describe('Secret name or ARN'),
      rotationLambdaARN: z.string().optional().describe('Lambda ARN for rotation'),
    },
    async ({ secretId, rotationLambdaARN }) => {
      try {
        const result = await client.secretsRotateSecret(secretId, rotationLambdaARN);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Secret rotation initiated',
                  arn: result.arn,
                  name: result.name,
                  versionId: result.versionId,
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
  // Put Secret Value
  // ===========================================================================
  server.tool(
    'aws_secrets_put_secret_value',
    `Store a new secret value for an existing secret.

Creates a new version of the secret with the provided value. Unlike update_secret,
this does not modify the secret's metadata.

Args:
  - secretId: The secret name or ARN (required)
  - secretString: The new secret value (required)
  - versionStages: Version stages to attach (optional, defaults to AWSCURRENT)

Returns the secret ARN, name, and version ID of the new version.`,
    {
      secretId: z.string().describe('Secret name or ARN'),
      secretString: z.string().describe('New secret value'),
      versionStages: z.array(z.string()).optional().describe('Version stages'),
    },
    async ({ secretId, secretString, versionStages }) => {
      try {
        const result = await client.secretsPutSecretValue(secretId, secretString, versionStages);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Secret value stored',
                  arn: result.arn,
                  name: result.name,
                  versionId: result.versionId,
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
    'aws_secrets_tag_resource',
    `Add or update tags on a secret.

Args:
  - secretId: The secret name or ARN (required)
  - tags: Array of tags to add (required)

Returns confirmation.`,
    {
      secretId: z.string().describe('Secret name or ARN'),
      tags: z.array(z.object({
        key: z.string().describe('Tag key'),
        value: z.string().describe('Tag value'),
      })).min(1).describe('Tags to add'),
    },
    async ({ secretId, tags }) => {
      try {
        await client.secretsTagResource(secretId, tags);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Secret tagged',
                  secretId,
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
    'aws_secrets_untag_resource',
    `Remove tags from a secret.

Args:
  - secretId: The secret name or ARN (required)
  - tagKeys: Array of tag keys to remove (required)

Returns confirmation.`,
    {
      secretId: z.string().describe('Secret name or ARN'),
      tagKeys: z.array(z.string()).min(1).describe('Tag keys to remove'),
    },
    async ({ secretId, tagKeys }) => {
      try {
        await client.secretsUntagResource(secretId, tagKeys);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Tags removed',
                  secretId,
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
  // Get Resource Policy
  // ===========================================================================
  server.tool(
    'aws_secrets_get_resource_policy',
    `Get the resource-based policy attached to a secret.

Args:
  - secretId: The secret name or ARN (required)

Returns the policy JSON if one is attached.`,
    {
      secretId: z.string().describe('Secret name or ARN'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ secretId, format }) => {
      try {
        const result = await client.secretsGetResourcePolicy(secretId);
        return formatResponse(result, format, 'secret_policy');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Put Resource Policy
  // ===========================================================================
  server.tool(
    'aws_secrets_put_resource_policy',
    `Attach a resource-based policy to a secret.

Args:
  - secretId: The secret name or ARN (required)
  - resourcePolicy: The policy document as JSON string (required)

Returns confirmation.`,
    {
      secretId: z.string().describe('Secret name or ARN'),
      resourcePolicy: z.string().describe('Policy document JSON'),
    },
    async ({ secretId, resourcePolicy }) => {
      try {
        const result = await client.secretsPutResourcePolicy(secretId, resourcePolicy);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Resource policy attached',
                  arn: result.arn,
                  name: result.name,
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
  // Delete Resource Policy
  // ===========================================================================
  server.tool(
    'aws_secrets_delete_resource_policy',
    `Delete the resource-based policy from a secret.

Args:
  - secretId: The secret name or ARN (required)

Returns confirmation.`,
    {
      secretId: z.string().describe('Secret name or ARN'),
    },
    async ({ secretId }) => {
      try {
        const result = await client.secretsDeleteResourcePolicy(secretId);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Resource policy deleted',
                  arn: result.arn,
                  name: result.name,
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
  // Cancel Rotate Secret
  // ===========================================================================
  server.tool(
    'aws_secrets_cancel_rotate_secret',
    `Cancel an in-progress rotation for a secret.

Args:
  - secretId: The secret name or ARN (required)

Returns confirmation.`,
    {
      secretId: z.string().describe('Secret name or ARN'),
    },
    async ({ secretId }) => {
      try {
        const result = await client.secretsCancelRotateSecret(secretId);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Rotation cancelled',
                  arn: result.arn,
                  name: result.name,
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
  // List Secret Version IDs
  // ===========================================================================
  server.tool(
    'aws_secrets_list_secret_version_ids',
    `List all versions of a secret.

Args:
  - secretId: The secret name or ARN (required)

Returns version IDs, stages, and creation dates.`,
    {
      secretId: z.string().describe('Secret name or ARN'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ secretId, format }) => {
      try {
        const versions = await client.secretsListSecretVersionIds(secretId);
        return formatResponse(
          { items: versions, count: versions.length, hasMore: false },
          format,
          'secret_versions'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Update Secret Version Stage
  // ===========================================================================
  server.tool(
    'aws_secrets_update_secret_version_stage',
    `Move a staging label to a different version of a secret.

Args:
  - secretId: The secret name or ARN (required)
  - versionStage: The staging label to move (required)
  - moveToVersionId: Version ID to move the label to (optional)
  - removeFromVersionId: Version ID to remove the label from (optional)

Use this to promote a version to AWSCURRENT or manage custom labels.

Returns confirmation.`,
    {
      secretId: z.string().describe('Secret name or ARN'),
      versionStage: z.string().describe('Staging label to move'),
      moveToVersionId: z.string().optional().describe('Move label to this version'),
      removeFromVersionId: z.string().optional().describe('Remove label from this version'),
    },
    async ({ secretId, versionStage, moveToVersionId, removeFromVersionId }) => {
      try {
        const result = await client.secretsUpdateSecretVersionStage(secretId, versionStage, moveToVersionId, removeFromVersionId);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Version stage updated',
                  arn: result.arn,
                  name: result.name,
                  versionStage,
                  moveToVersionId,
                  removeFromVersionId,
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
