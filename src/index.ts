/**
 * AWS MCP Server - Main Entry Point
 *
 * This file sets up the MCP server for AWS services using Cloudflare's Agents SDK.
 *
 * MULTI-TENANT ARCHITECTURE:
 * AWS credentials are passed via request headers, allowing a single deployment
 * to serve multiple AWS accounts.
 *
 * Required Headers:
 * - X-AWS-Access-Key-ID: AWS access key ID
 * - X-AWS-Secret-Access-Key: AWS secret access key
 *
 * Optional Headers:
 * - X-AWS-Region: AWS region (default: us-east-1)
 * - X-AWS-Session-Token: Session token for temporary credentials
 */

import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { McpAgent } from 'agents/mcp';
import { createAwsClient } from './client.js';
import {
  registerCloudFormationTools,
  registerCloudFrontTools,
  registerCloudWatchTools,
  registerDynamoDBTools,
  registerEC2Tools,
  registerECSTools,
  registerEKSTools,
  registerIAMTools,
  registerLambdaTools,
  registerRDSTools,
  registerRoute53Tools,
  registerS3Tools,
  registerSecretsManagerTools,
  registerSNSTools,
  registerSQSTools,
  registerSTSTools,
} from './tools/index.js';
import {
  type AwsCredentials,
  type Env,
  parseAwsCredentials,
  validateAwsCredentials,
} from './types/env.js';

// =============================================================================
// MCP Server Configuration
// =============================================================================

const SERVER_NAME = 'primrose-mcp-aws';
const SERVER_VERSION = '1.0.0';

// =============================================================================
// MCP Agent (Stateful - uses Durable Objects)
// =============================================================================

export class AwsMcpAgent extends McpAgent<Env> {
  server = new McpServer({
    name: SERVER_NAME,
    version: SERVER_VERSION,
  });

  async init() {
    throw new Error(
      'Stateful mode (McpAgent) is not supported for multi-tenant deployments. ' +
        'Use the stateless /mcp endpoint with AWS credential headers instead.'
    );
  }
}

// =============================================================================
// Stateless MCP Server
// =============================================================================

function createStatelessServer(credentials: AwsCredentials): McpServer {
  const server = new McpServer({
    name: SERVER_NAME,
    version: SERVER_VERSION,
  });

  const client = createAwsClient(credentials);

  // Register all AWS service tools
  registerS3Tools(server, client);
  registerEC2Tools(server, client);
  registerLambdaTools(server, client);
  registerIAMTools(server, client);
  registerCloudWatchTools(server, client);
  registerDynamoDBTools(server, client);
  registerSQSTools(server, client);
  registerSNSTools(server, client);
  registerSecretsManagerTools(server, client);
  registerRoute53Tools(server, client);
  registerCloudFrontTools(server, client);
  registerECSTools(server, client);
  registerRDSTools(server, client);
  registerEKSTools(server, client);
  registerSTSTools(server, client);
  registerCloudFormationTools(server, client);

  // Test connection tool
  server.tool(
    'aws_test_connection',
    `Test the connection to AWS and get caller identity.

Returns the AWS account ID, user ID, and ARN of the caller.`,
    {},
    async () => {
      try {
        const result = await client.testConnection();
        return {
          content: [{ type: 'text', text: JSON.stringify(result, null, 2) }],
        };
      } catch (error) {
        return {
          content: [
            {
              type: 'text',
              text: `Connection failed: ${error instanceof Error ? error.message : 'Unknown error'}`,
            },
          ],
          isError: true,
        };
      }
    }
  );

  // Get caller identity tool
  server.tool(
    'aws_get_caller_identity',
    `Get the identity of the AWS credentials being used.

Returns the AWS account ID, user ID, and ARN.`,
    {},
    async () => {
      try {
        const identity = await client.getCallerIdentity();
        return {
          content: [{ type: 'text', text: JSON.stringify(identity, null, 2) }],
        };
      } catch (error) {
        return {
          content: [
            {
              type: 'text',
              text: `Failed to get identity: ${error instanceof Error ? error.message : 'Unknown error'}`,
            },
          ],
          isError: true,
        };
      }
    }
  );

  return server;
}

// =============================================================================
// Worker Export
// =============================================================================

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    // Health check endpoint
    if (url.pathname === '/health') {
      return new Response(JSON.stringify({ status: 'ok', server: SERVER_NAME }), {
        headers: { 'Content-Type': 'application/json' },
      });
    }

    // MCP endpoint
    if (url.pathname === '/mcp' && request.method === 'POST') {
      const defaultRegion = env.DEFAULT_REGION || 'us-east-1';
      const credentials = parseAwsCredentials(request, defaultRegion);

      try {
        validateAwsCredentials(credentials);
      } catch (error) {
        return new Response(
          JSON.stringify({
            error: 'Unauthorized',
            message: error instanceof Error ? error.message : 'Invalid credentials',
            required_headers: ['X-AWS-Access-Key-ID', 'X-AWS-Secret-Access-Key'],
            optional_headers: ['X-AWS-Region', 'X-AWS-Session-Token'],
          }),
          {
            status: 401,
            headers: { 'Content-Type': 'application/json' },
          }
        );
      }

      const server = createStatelessServer(credentials);

      const { createMcpHandler } = await import('agents/mcp');
      const handler = createMcpHandler(server);
      return handler(request, env, ctx);
    }

    // SSE endpoint notice
    if (url.pathname === '/sse') {
      return new Response('SSE endpoint requires Durable Objects. Enable in wrangler.jsonc.', {
        status: 501,
      });
    }

    // Default response - API documentation
    return new Response(
      JSON.stringify({
        name: SERVER_NAME,
        version: SERVER_VERSION,
        description: 'Multi-tenant AWS MCP Server for Cloudflare Workers',
        endpoints: {
          mcp: '/mcp (POST) - Streamable HTTP MCP endpoint',
          health: '/health - Health check',
        },
        authentication: {
          description: 'Pass AWS credentials via request headers',
          required_headers: {
            'X-AWS-Access-Key-ID': 'AWS access key ID',
            'X-AWS-Secret-Access-Key': 'AWS secret access key',
          },
          optional_headers: {
            'X-AWS-Region': 'AWS region (default: us-east-1)',
            'X-AWS-Session-Token': 'Session token for temporary credentials',
          },
        },
        supported_services: [
          'S3 - Object storage',
          'EC2 - Virtual machines',
          'Lambda - Serverless functions',
          'IAM - Identity and access management',
          'STS - Security Token Service',
          'CloudWatch - Metrics, logs, and alarms',
          'DynamoDB - NoSQL database',
          'SQS - Message queues',
          'SNS - Pub/sub messaging',
          'Secrets Manager - Secret storage',
          'Route53 - DNS',
          'CloudFront - CDN',
          'ECS - Container orchestration',
          'EKS - Kubernetes service',
          'RDS - Relational databases',
        ],
      }),
      {
        headers: { 'Content-Type': 'application/json' },
      }
    );
  },
};
