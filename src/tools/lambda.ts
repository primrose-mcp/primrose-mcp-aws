/**
 * Lambda Tools
 *
 * MCP tools for AWS Lambda operations.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { AwsClient } from '../client.js';
import { formatError, formatResponse } from '../utils/formatters.js';

export function registerLambdaTools(server: McpServer, client: AwsClient): void {
  // ===========================================================================
  // List Functions
  // ===========================================================================
  server.tool(
    'aws_lambda_list_functions',
    `List all Lambda functions in the region.

Returns functions with name, runtime, memory, timeout, and last modified date.`,
    {
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ format }) => {
      try {
        const functions = await client.lambdaListFunctions();
        return formatResponse(
          { items: functions, count: functions.length, hasMore: false },
          format,
          'lambda_functions'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Get Function
  // ===========================================================================
  server.tool(
    'aws_lambda_get_function',
    `Get detailed information about a Lambda function.

Args:
  - functionName: The function name or ARN (required)

Returns full function configuration including environment variables and tags.`,
    {
      functionName: z.string().describe('Function name or ARN'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ functionName, format }) => {
      try {
        const func = await client.lambdaGetFunction(functionName);
        return formatResponse(func, format, 'lambda_function');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Invoke Function
  // ===========================================================================
  server.tool(
    'aws_lambda_invoke',
    `Invoke a Lambda function and get its response.

Args:
  - functionName: The function name or ARN (required)
  - payload: JSON payload to pass to the function
  - invocationType: 'RequestResponse' (sync), 'Event' (async), or 'DryRun'

Returns the function's response payload for sync invocations.`,
    {
      functionName: z.string().describe('Function name or ARN'),
      payload: z.record(z.string(), z.unknown()).optional().describe('JSON payload for the function'),
      invocationType: z
        .enum(['RequestResponse', 'Event', 'DryRun'])
        .default('RequestResponse')
        .describe('Invocation type'),
    },
    async ({ functionName, payload, invocationType }) => {
      try {
        const result = await client.lambdaInvoke({
          functionName,
          payload,
          invocationType,
        });
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  statusCode: result.statusCode,
                  functionName,
                  invocationType,
                  payload: result.payload,
                  functionError: result.functionError,
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
  // List Aliases
  // ===========================================================================
  server.tool(
    'aws_lambda_list_aliases',
    `List aliases for a Lambda function.

Args:
  - functionName: The function name or ARN (required)

Returns aliases with their versions and descriptions.`,
    {
      functionName: z.string().describe('Function name or ARN'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ functionName, format }) => {
      try {
        const aliases = await client.lambdaListAliases(functionName);
        return formatResponse(
          { items: aliases, count: aliases.length, hasMore: false },
          format,
          'lambda_aliases'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // List Versions
  // ===========================================================================
  server.tool(
    'aws_lambda_list_versions',
    `List published versions of a Lambda function.

Args:
  - functionName: The function name or ARN (required)

Returns version numbers with descriptions and modification dates.`,
    {
      functionName: z.string().describe('Function name or ARN'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ functionName, format }) => {
      try {
        const versions = await client.lambdaListVersions(functionName);
        return formatResponse(
          { items: versions, count: versions.length, hasMore: false },
          format,
          'lambda_versions'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // List Event Source Mappings
  // ===========================================================================
  server.tool(
    'aws_lambda_list_event_source_mappings',
    `List event source mappings for Lambda functions.

Args:
  - functionName: Filter by function name (optional)

Returns event source mappings with UUID, state, and batch settings.`,
    {
      functionName: z.string().optional().describe('Filter by function name'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ functionName, format }) => {
      try {
        const mappings = await client.lambdaListEventSourceMappings(functionName);
        return formatResponse(
          { items: mappings, count: mappings.length, hasMore: false },
          format,
          'lambda_event_source_mappings'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // List Layers
  // ===========================================================================
  server.tool(
    'aws_lambda_list_layers',
    `List Lambda layers available in the region.

Returns layer names and ARNs with latest version info.`,
    {
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ format }) => {
      try {
        const layers = await client.lambdaListLayers();
        return formatResponse(
          { items: layers, count: layers.length, hasMore: false },
          format,
          'lambda_layers'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // List Layer Versions
  // ===========================================================================
  server.tool(
    'aws_lambda_list_layer_versions',
    `List versions of a Lambda layer.

Args:
  - layerName: The layer name (required)

Returns layer versions with compatible runtimes and architectures.`,
    {
      layerName: z.string().describe('Layer name'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ layerName, format }) => {
      try {
        const versions = await client.lambdaListLayerVersions(layerName);
        return formatResponse(
          { items: versions, count: versions.length, hasMore: false },
          format,
          'lambda_layer_versions'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Get Function Concurrency
  // ===========================================================================
  server.tool(
    'aws_lambda_get_function_concurrency',
    `Get the reserved concurrency setting for a Lambda function.

Args:
  - functionName: The function name (required)

Returns the reserved concurrent executions count (if set).`,
    {
      functionName: z.string().describe('Function name'),
    },
    async ({ functionName }) => {
      try {
        const concurrency = await client.lambdaGetFunctionConcurrency(functionName);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  functionName,
                  reservedConcurrentExecutions: concurrency.reservedConcurrentExecutions ?? 'Not set (uses unreserved account concurrency)',
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
  // Publish Version
  // ===========================================================================
  server.tool(
    'aws_lambda_publish_version',
    `Publish a new version of a Lambda function.

Args:
  - functionName: The function name (required)
  - description: Version description (optional)

Returns the published version details.`,
    {
      functionName: z.string().describe('Function name'),
      description: z.string().optional().describe('Version description'),
    },
    async ({ functionName, description }) => {
      try {
        const version = await client.lambdaPublishVersion(functionName, description);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Version ${version.version} published for '${functionName}'`,
                  functionName,
                  version: version.version,
                  description: version.description,
                  revisionId: version.revisionId,
                  lastModified: version.lastModified,
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
  // Update Function Configuration
  // ===========================================================================
  server.tool(
    'aws_lambda_update_function_configuration',
    `Update the configuration of a Lambda function.

Args:
  - functionName: The function name (required)
  - description: New description (optional)
  - handler: New handler (optional)
  - memorySize: New memory size in MB (optional)
  - timeout: New timeout in seconds (optional)
  - runtime: New runtime (optional)
  - environment: New environment variables (optional)

Returns the updated function configuration.`,
    {
      functionName: z.string().describe('Function name'),
      description: z.string().optional().describe('Function description'),
      handler: z.string().optional().describe('Function handler'),
      memorySize: z.number().int().min(128).max(10240).optional().describe('Memory in MB'),
      timeout: z.number().int().min(1).max(900).optional().describe('Timeout in seconds'),
      runtime: z.string().optional().describe('Runtime (e.g., nodejs18.x, python3.11)'),
      environment: z.record(z.string(), z.string()).optional().describe('Environment variables'),
    },
    async ({ functionName, description, handler, memorySize, timeout, runtime, environment }) => {
      try {
        const func = await client.lambdaUpdateFunctionConfiguration(functionName, {
          description,
          handler,
          memorySize,
          timeout,
          runtime,
          environment,
        });
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Configuration updated for '${functionName}'`,
                  functionName: func.functionName,
                  functionArn: func.functionArn,
                  runtime: func.runtime,
                  handler: func.handler,
                  memorySize: func.memorySize,
                  timeout: func.timeout,
                  lastModified: func.lastModified,
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
  // Delete Function
  // ===========================================================================
  server.tool(
    'aws_lambda_delete_function',
    `Delete a Lambda function.

Args:
  - functionName: The function name (required)
  - qualifier: Version or alias to delete (optional, deletes all versions if not specified)

WARNING: This action is irreversible.

Returns confirmation of deletion.`,
    {
      functionName: z.string().describe('Function name'),
      qualifier: z.string().optional().describe('Version or alias to delete'),
    },
    async ({ functionName, qualifier }) => {
      try {
        await client.lambdaDeleteFunction(functionName, qualifier);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: qualifier
                    ? `Function '${functionName}' version/alias '${qualifier}' deleted`
                    : `Function '${functionName}' deleted`,
                  functionName,
                  qualifier,
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
  // Put Function Concurrency
  // ===========================================================================
  server.tool(
    'aws_lambda_put_function_concurrency',
    `Set reserved concurrency for a Lambda function.

Args:
  - functionName: The function name (required)
  - reservedConcurrency: Number of concurrent executions to reserve (required)

Returns confirmation of the concurrency setting.`,
    {
      functionName: z.string().describe('Function name'),
      reservedConcurrency: z.number().int().min(0).describe('Reserved concurrent executions'),
    },
    async ({ functionName, reservedConcurrency }) => {
      try {
        const result = await client.lambdaPutFunctionConcurrency(functionName, reservedConcurrency);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Reserved concurrency set to ${reservedConcurrency} for '${functionName}'`,
                  functionName,
                  reservedConcurrentExecutions: result.reservedConcurrentExecutions,
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
  // Delete Function Concurrency
  // ===========================================================================
  server.tool(
    'aws_lambda_delete_function_concurrency',
    `Remove reserved concurrency from a Lambda function.

Args:
  - functionName: The function name (required)

This allows the function to use unreserved account concurrency.

Returns confirmation of removal.`,
    {
      functionName: z.string().describe('Function name'),
    },
    async ({ functionName }) => {
      try {
        await client.lambdaDeleteFunctionConcurrency(functionName);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Reserved concurrency removed for '${functionName}'`,
                  functionName,
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
  // Get Event Source Mapping
  // ===========================================================================
  server.tool(
    'aws_lambda_get_event_source_mapping',
    `Get details of an event source mapping.

Args:
  - uuid: The event source mapping UUID (required)

Returns mapping details including state and batch settings.`,
    {
      uuid: z.string().describe('Event source mapping UUID'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ uuid, format }) => {
      try {
        const mapping = await client.lambdaGetEventSourceMapping(uuid);
        return formatResponse(mapping, format, 'lambda_event_source_mapping');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Create Event Source Mapping
  // ===========================================================================
  server.tool(
    'aws_lambda_create_event_source_mapping',
    `Create an event source mapping for a Lambda function.

Args:
  - eventSourceArn: ARN of the event source (SQS, DynamoDB, Kinesis) (required)
  - functionName: Function name or ARN (required)
  - batchSize: Number of records per batch (optional)
  - enabled: Whether the mapping is enabled (optional, default: true)
  - startingPosition: Starting position for stream (TRIM_HORIZON, LATEST) (optional)

Returns the created mapping details.`,
    {
      eventSourceArn: z.string().describe('Event source ARN'),
      functionName: z.string().describe('Function name or ARN'),
      batchSize: z.number().int().min(1).optional().describe('Batch size'),
      enabled: z.boolean().optional().describe('Enable the mapping'),
      startingPosition: z.enum(['TRIM_HORIZON', 'LATEST', 'AT_TIMESTAMP']).optional().describe('Starting position'),
    },
    async ({ eventSourceArn, functionName, batchSize, enabled, startingPosition }) => {
      try {
        const mapping = await client.lambdaCreateEventSourceMapping({
          eventSourceArn,
          functionName,
          batchSize,
          enabled,
          startingPosition,
        });
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Event source mapping created',
                  uuid: mapping.uuid,
                  functionArn: mapping.functionArn,
                  eventSourceArn: mapping.eventSourceArn,
                  state: mapping.state,
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
  // Update Event Source Mapping
  // ===========================================================================
  server.tool(
    'aws_lambda_update_event_source_mapping',
    `Update an event source mapping.

Args:
  - uuid: The event source mapping UUID (required)
  - functionName: New function name or ARN (optional)
  - batchSize: New batch size (optional)
  - enabled: Enable or disable the mapping (optional)

Returns the updated mapping details.`,
    {
      uuid: z.string().describe('Event source mapping UUID'),
      functionName: z.string().optional().describe('Function name or ARN'),
      batchSize: z.number().int().min(1).optional().describe('Batch size'),
      enabled: z.boolean().optional().describe('Enable/disable the mapping'),
    },
    async ({ uuid, functionName, batchSize, enabled }) => {
      try {
        const mapping = await client.lambdaUpdateEventSourceMapping(uuid, {
          functionName,
          batchSize,
          enabled,
        });
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Event source mapping updated',
                  uuid: mapping.uuid,
                  functionArn: mapping.functionArn,
                  state: mapping.state,
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
  // Delete Event Source Mapping
  // ===========================================================================
  server.tool(
    'aws_lambda_delete_event_source_mapping',
    `Delete an event source mapping.

Args:
  - uuid: The event source mapping UUID (required)

Returns confirmation of deletion.`,
    {
      uuid: z.string().describe('Event source mapping UUID'),
    },
    async ({ uuid }) => {
      try {
        await client.lambdaDeleteEventSourceMapping(uuid);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Event source mapping deleted',
                  uuid,
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
  // Create Alias
  // ===========================================================================
  server.tool(
    'aws_lambda_create_alias',
    `Create an alias for a Lambda function version.

Args:
  - functionName: The function name (required)
  - name: Alias name (required)
  - functionVersion: Version to point to (required)
  - description: Alias description (optional)

Returns the created alias details.`,
    {
      functionName: z.string().describe('Function name'),
      name: z.string().describe('Alias name'),
      functionVersion: z.string().describe('Function version'),
      description: z.string().optional().describe('Alias description'),
    },
    async ({ functionName, name, functionVersion, description }) => {
      try {
        const alias = await client.lambdaCreateAlias(functionName, name, functionVersion, description);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Alias '${name}' created for function '${functionName}'`,
                  functionName,
                  name: alias.name,
                  functionVersion: alias.functionVersion,
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
  // Update Alias
  // ===========================================================================
  server.tool(
    'aws_lambda_update_alias',
    `Update a Lambda function alias.

Args:
  - functionName: The function name (required)
  - name: Alias name (required)
  - functionVersion: New version to point to (optional)
  - description: New description (optional)

Returns the updated alias details.`,
    {
      functionName: z.string().describe('Function name'),
      name: z.string().describe('Alias name'),
      functionVersion: z.string().optional().describe('Function version'),
      description: z.string().optional().describe('Alias description'),
    },
    async ({ functionName, name, functionVersion, description }) => {
      try {
        const alias = await client.lambdaUpdateAlias(functionName, name, functionVersion, description);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Alias '${name}' updated for function '${functionName}'`,
                  functionName,
                  name: alias.name,
                  functionVersion: alias.functionVersion,
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
  // Delete Alias
  // ===========================================================================
  server.tool(
    'aws_lambda_delete_alias',
    `Delete a Lambda function alias.

Args:
  - functionName: The function name (required)
  - name: Alias name (required)

Returns confirmation of deletion.`,
    {
      functionName: z.string().describe('Function name'),
      name: z.string().describe('Alias name'),
    },
    async ({ functionName, name }) => {
      try {
        await client.lambdaDeleteAlias(functionName, name);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Alias '${name}' deleted for function '${functionName}'`,
                  functionName,
                  aliasName: name,
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
  // Add Permission
  // ===========================================================================
  server.tool(
    'aws_lambda_add_permission',
    `Add a permission to a Lambda function's resource-based policy.

Args:
  - functionName: The function name (required)
  - statementId: A unique identifier for the policy statement (required)
  - action: The Lambda action to allow (required, e.g., 'lambda:InvokeFunction')
  - principal: The principal to grant permission to (required, e.g., 's3.amazonaws.com')
  - sourceArn: ARN of the source triggering the function (optional)

Returns the policy statement.`,
    {
      functionName: z.string().describe('Function name'),
      statementId: z.string().describe('Statement ID'),
      action: z.string().describe('Lambda action (e.g., lambda:InvokeFunction)'),
      principal: z.string().describe('Principal (e.g., s3.amazonaws.com)'),
      sourceArn: z.string().optional().describe('Source ARN'),
    },
    async ({ functionName, statementId, action, principal, sourceArn }) => {
      try {
        const result = await client.lambdaAddPermission(functionName, statementId, action, principal, sourceArn);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Permission added',
                  functionName,
                  statementId,
                  statement: JSON.parse(result.statement),
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
  // Remove Permission
  // ===========================================================================
  server.tool(
    'aws_lambda_remove_permission',
    `Remove a permission from a Lambda function's resource-based policy.

Args:
  - functionName: The function name (required)
  - statementId: The statement ID to remove (required)

Returns confirmation of removal.`,
    {
      functionName: z.string().describe('Function name'),
      statementId: z.string().describe('Statement ID'),
    },
    async ({ functionName, statementId }) => {
      try {
        await client.lambdaRemovePermission(functionName, statementId);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Permission removed',
                  functionName,
                  statementId,
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
  // Get Policy
  // ===========================================================================
  server.tool(
    'aws_lambda_get_policy',
    `Get the resource-based policy for a Lambda function.

Args:
  - functionName: The function name (required)

Returns the function's policy document.`,
    {
      functionName: z.string().describe('Function name'),
    },
    async ({ functionName }) => {
      try {
        const result = await client.lambdaGetPolicy(functionName);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  functionName,
                  policy: JSON.parse(result.policy),
                  revisionId: result.revisionId,
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
    'aws_lambda_tag_resource',
    `Add tags to a Lambda function.

Args:
  - resourceArn: The function ARN (required)
  - tags: Key-value pairs of tags (required)

Returns confirmation of tagging.`,
    {
      resourceArn: z.string().describe('Function ARN'),
      tags: z.record(z.string(), z.string()).describe('Tags as key-value pairs'),
    },
    async ({ resourceArn, tags }) => {
      try {
        await client.lambdaTagResource(resourceArn, tags as Record<string, string>);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Tags added',
                  resourceArn,
                  tagsAdded: Object.keys(tags).length,
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
    'aws_lambda_untag_resource',
    `Remove tags from a Lambda function.

Args:
  - resourceArn: The function ARN (required)
  - tagKeys: Array of tag keys to remove (required)

Returns confirmation of tag removal.`,
    {
      resourceArn: z.string().describe('Function ARN'),
      tagKeys: z.array(z.string()).min(1).describe('Tag keys to remove'),
    },
    async ({ resourceArn, tagKeys }) => {
      try {
        await client.lambdaUntagResource(resourceArn, tagKeys);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Tags removed',
                  resourceArn,
                  tagsRemoved: tagKeys,
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
  // List Tags
  // ===========================================================================
  server.tool(
    'aws_lambda_list_tags',
    `List tags for a Lambda function.

Args:
  - resourceArn: The function ARN (required)

Returns the function's tags.`,
    {
      resourceArn: z.string().describe('Function ARN'),
    },
    async ({ resourceArn }) => {
      try {
        const tags = await client.lambdaListTags(resourceArn);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  resourceArn,
                  tags,
                  tagCount: Object.keys(tags).length,
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
