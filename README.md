# AWS MCP Server

A Model Context Protocol (MCP) server that enables AI assistants to interact with Amazon Web Services. Manage S3, EC2, Lambda, IAM, DynamoDB, and 12+ other AWS services through a unified interface.

[![Primrose MCP](https://img.shields.io/badge/Primrose-MCP-6366f1)](https://primrose.dev/mcp/aws)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

**[View on Primrose](https://primrose.dev/mcp/aws)** | **[Documentation](https://primrose.dev/docs)**

---

## Features

- **S3** - Manage buckets and objects in Simple Storage Service
- **EC2** - Control virtual machines and networking
- **Lambda** - Deploy and manage serverless functions
- **IAM** - Configure users, roles, and policies
- **CloudWatch** - Monitor logs and metrics
- **DynamoDB** - Work with NoSQL tables and items
- **SQS** - Manage message queues
- **SNS** - Configure notifications and topics
- **Secrets Manager** - Store and retrieve secrets
- **Route 53** - Manage DNS records and hosted zones
- **CloudFront** - Configure CDN distributions
- **ECS** - Manage container services
- **RDS** - Work with relational databases
- **EKS** - Manage Kubernetes clusters
- **STS** - Handle temporary credentials
- **CloudFormation** - Deploy infrastructure as code

## Quick Start

### Using Primrose SDK (Recommended)

The fastest way to get started is with the [Primrose SDK](https://github.com/primrose-mcp/primrose-sdk), which handles authentication and provides tool definitions formatted for your LLM provider.

```bash
npm install primrose-mcp
```

```typescript
import { Primrose } from 'primrose-mcp';

const primrose = new Primrose({
  apiKey: 'prm_xxxxx',
  provider: 'anthropic', // or 'openai', 'google', 'amazon', etc.
});

// List available AWS tools
const tools = await primrose.listTools({ mcpServer: 'aws' });

// Call a tool
const result = await primrose.callTool('aws_s3_list_buckets', {
  format: 'json'
});
```

[Get your Primrose API key](https://primrose.dev) to start building.

### Manual Installation

If you prefer to self-host, you can deploy this MCP server directly to Cloudflare Workers.

```bash
git clone https://github.com/primrose-mcp/primrose-mcp-aws.git
cd primrose-mcp-aws
bun install
bun run deploy
```

## Configuration

This server uses a multi-tenant architecture where credentials are passed via request headers.

### Required Headers

| Header | Description |
|--------|-------------|
| `X-AWS-Access-Key-ID` | AWS access key ID |
| `X-AWS-Secret-Access-Key` | AWS secret access key |

### Optional Headers

| Header | Description |
|--------|-------------|
| `X-AWS-Region` | AWS region (default: `us-east-1`) |
| `X-AWS-Session-Token` | Session token for temporary credentials |

### Getting Credentials

1. Log in to the [AWS Console](https://console.aws.amazon.com/)
2. Navigate to IAM > Users > Your User > Security credentials
3. Create an access key pair
4. For production, use IAM roles with least-privilege permissions

## Available Tools

### S3
- `aws_s3_list_buckets` - List all S3 buckets
- `aws_s3_list_objects` - List objects in a bucket
- `aws_s3_get_object` - Get object content
- `aws_s3_put_object` - Upload an object
- `aws_s3_delete_object` - Delete an object

### EC2
- `aws_ec2_list_instances` - List EC2 instances
- `aws_ec2_get_instance` - Get instance details
- `aws_ec2_start_instance` - Start an instance
- `aws_ec2_stop_instance` - Stop an instance

### Lambda
- `aws_lambda_list_functions` - List Lambda functions
- `aws_lambda_get_function` - Get function details
- `aws_lambda_invoke` - Invoke a function

### IAM
- `aws_iam_list_users` - List IAM users
- `aws_iam_list_roles` - List IAM roles
- `aws_iam_get_policy` - Get policy details

### DynamoDB
- `aws_dynamodb_list_tables` - List DynamoDB tables
- `aws_dynamodb_get_item` - Get an item
- `aws_dynamodb_put_item` - Put an item
- `aws_dynamodb_query` - Query a table

### CloudWatch
- `aws_cloudwatch_get_metrics` - Get metric data
- `aws_cloudwatch_list_log_groups` - List log groups
- `aws_cloudwatch_get_log_events` - Get log events

## Development

```bash
bun run dev
bun run typecheck
bun run lint
bun run inspector
```

## Related Resources

- [Primrose SDK](https://github.com/primrose-mcp/primrose-sdk)
- [AWS Documentation](https://docs.aws.amazon.com/)
- [Model Context Protocol](https://modelcontextprotocol.io)

## License

MIT License - see [LICENSE](LICENSE) for details.
