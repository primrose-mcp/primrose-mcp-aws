/**
 * STS Tools
 *
 * MCP tools for AWS Security Token Service operations.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { AwsClient } from '../client.js';
import { formatError } from '../utils/formatters.js';

export function registerSTSTools(server: McpServer, client: AwsClient): void {
  // ===========================================================================
  // Get Caller Identity
  // ===========================================================================
  server.tool(
    'aws_sts_get_caller_identity',
    `Get details about the IAM user or role whose credentials are used to call the operation.

Returns the AWS account ID, IAM user/role ARN, and unique identifier.`,
    {},
    async () => {
      try {
        const identity = await client.getCallerIdentity();
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  userId: identity.userId,
                  account: identity.account,
                  arn: identity.arn,
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
  // Assume Role
  // ===========================================================================
  server.tool(
    'aws_sts_assume_role',
    `Assume an IAM role and get temporary security credentials.

Args:
  - roleArn: The ARN of the role to assume (required)
  - roleSessionName: An identifier for the assumed role session (required)
  - durationSeconds: Duration of the session in seconds (optional, 900-43200, default 3600)
  - externalId: External ID for cross-account access (optional)

Returns temporary credentials including access key, secret key, and session token.`,
    {
      roleArn: z.string().describe('ARN of the role to assume'),
      roleSessionName: z.string().describe('Identifier for the session'),
      durationSeconds: z.number().int().min(900).max(43200).optional().describe('Session duration in seconds'),
      externalId: z.string().optional().describe('External ID for cross-account access'),
    },
    async ({ roleArn, roleSessionName, durationSeconds, externalId }) => {
      try {
        const credentials = await client.stsAssumeRole(roleArn, roleSessionName, durationSeconds, externalId);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Role assumed successfully',
                  credentials: {
                    accessKeyId: credentials.accessKeyId,
                    secretAccessKey: credentials.secretAccessKey,
                    sessionToken: credentials.sessionToken,
                    expiration: credentials.expiration,
                  },
                  warning: 'Store these credentials securely. They will expire at the specified time.',
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
  // Get Session Token
  // ===========================================================================
  server.tool(
    'aws_sts_get_session_token',
    `Get temporary security credentials for an IAM user.

Args:
  - durationSeconds: Duration of the session in seconds (optional, 900-129600, default 43200)

This is useful for MFA-protected API access. The credentials can be used to call AWS APIs.

Returns temporary credentials including access key, secret key, and session token.`,
    {
      durationSeconds: z.number().int().min(900).max(129600).optional().describe('Session duration in seconds'),
    },
    async ({ durationSeconds }) => {
      try {
        const credentials = await client.stsGetSessionToken(durationSeconds);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Session token obtained successfully',
                  credentials: {
                    accessKeyId: credentials.accessKeyId,
                    secretAccessKey: credentials.secretAccessKey,
                    sessionToken: credentials.sessionToken,
                    expiration: credentials.expiration,
                  },
                  warning: 'Store these credentials securely. They will expire at the specified time.',
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
  // Get Federation Token
  // ===========================================================================
  server.tool(
    'aws_sts_get_federation_token',
    `Get temporary security credentials for a federated user.

Args:
  - name: The name of the federated user (required, 2-32 characters)
  - durationSeconds: Duration of the session in seconds (optional, 900-129600, default 43200)
  - policy: An IAM policy in JSON format to limit permissions (optional)

This returns credentials with permissions that are the intersection of the IAM user's
permissions and the policy you specify.

Returns temporary credentials and federated user info.`,
    {
      name: z.string().min(2).max(32).describe('Name of the federated user'),
      durationSeconds: z.number().int().min(900).max(129600).optional().describe('Session duration in seconds'),
      policy: z.string().optional().describe('IAM policy in JSON format'),
    },
    async ({ name, durationSeconds, policy }) => {
      try {
        const result = await client.stsGetFederationToken(name, durationSeconds, policy);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Federation token obtained successfully',
                  credentials: {
                    accessKeyId: result.accessKeyId,
                    secretAccessKey: result.secretAccessKey,
                    sessionToken: result.sessionToken,
                    expiration: result.expiration,
                  },
                  federatedUser: result.federatedUser,
                  warning: 'Store these credentials securely. They will expire at the specified time.',
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
  // Decode Authorization Message
  // ===========================================================================
  server.tool(
    'aws_sts_decode_authorization_message',
    `Decode an encoded authorization failure message.

Args:
  - encodedMessage: The encoded message from an authorization failure (required)

When an AWS API call fails due to authorization, AWS sometimes returns an encoded
message. This operation decodes that message to show the details of what failed.

Returns the decoded authorization message as JSON.`,
    {
      encodedMessage: z.string().describe('The encoded authorization failure message'),
    },
    async ({ encodedMessage }) => {
      try {
        const decodedMessage = await client.stsDecodeAuthorizationMessage(encodedMessage);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  decodedMessage: JSON.parse(decodedMessage),
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
