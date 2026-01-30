/**
 * CloudFormation Tools
 *
 * MCP tools for AWS CloudFormation stack and change set operations.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { AwsClient } from '../client.js';
import { formatError, formatResponse } from '../utils/formatters.js';

export function registerCloudFormationTools(server: McpServer, client: AwsClient): void {
  // ===========================================================================
  // List Stacks
  // ===========================================================================
  server.tool(
    'aws_cfn_list_stacks',
    `List CloudFormation stacks.

Args:
  - statusFilter: Filter by stack status (optional)

Common status values: CREATE_COMPLETE, UPDATE_COMPLETE, DELETE_IN_PROGRESS, ROLLBACK_COMPLETE

Returns stack summaries.`,
    {
      statusFilter: z.array(z.string()).optional().describe('Filter by status'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ statusFilter, format }) => {
      try {
        const stacks = await client.cfnListStacks(statusFilter);
        return formatResponse(
          { items: stacks, count: stacks.length, hasMore: false },
          format,
          'cfn_stacks'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Describe Stack
  // ===========================================================================
  server.tool(
    'aws_cfn_describe_stack',
    `Get details of a CloudFormation stack.

Args:
  - stackName: Stack name or ID (required)

Returns stack configuration, parameters, outputs, and tags.`,
    {
      stackName: z.string().describe('Stack name or ID'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ stackName, format }) => {
      try {
        const stack = await client.cfnDescribeStack(stackName);
        return formatResponse(stack, format, 'cfn_stack');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Get Template
  // ===========================================================================
  server.tool(
    'aws_cfn_get_template',
    `Get the template body of a CloudFormation stack.

Args:
  - stackName: Stack name or ID (required)

Returns the template in YAML or JSON format.`,
    {
      stackName: z.string().describe('Stack name or ID'),
    },
    async ({ stackName }) => {
      try {
        const template = await client.cfnGetTemplate(stackName);
        return {
          content: [
            {
              type: 'text',
              text: template.templateBody,
            },
          ],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // List Stack Resources
  // ===========================================================================
  server.tool(
    'aws_cfn_list_stack_resources',
    `List resources in a CloudFormation stack.

Args:
  - stackName: Stack name or ID (required)

Returns logical and physical resource IDs, types, and status.`,
    {
      stackName: z.string().describe('Stack name or ID'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ stackName, format }) => {
      try {
        const resources = await client.cfnListStackResources(stackName);
        return formatResponse(
          { items: resources, count: resources.length, hasMore: false },
          format,
          'cfn_resources'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Describe Stack Events
  // ===========================================================================
  server.tool(
    'aws_cfn_describe_stack_events',
    `Get events for a CloudFormation stack.

Args:
  - stackName: Stack name or ID (required)

Returns stack events including status changes and error messages.`,
    {
      stackName: z.string().describe('Stack name or ID'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ stackName, format }) => {
      try {
        const events = await client.cfnDescribeStackEvents(stackName);
        return formatResponse(
          { items: events, count: events.length, hasMore: false },
          format,
          'cfn_events'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Create Stack
  // ===========================================================================
  server.tool(
    'aws_cfn_create_stack',
    `Create a new CloudFormation stack.

Args:
  - stackName: Name for the stack (required)
  - templateBody: Template content (required if no templateUrl)
  - templateUrl: S3 URL for template (required if no templateBody)
  - parameters: Stack parameters (optional)
  - capabilities: Required capabilities like CAPABILITY_IAM (optional)
  - tags: Stack tags (optional)

Returns the stack ID.`,
    {
      stackName: z.string().describe('Stack name'),
      templateBody: z.string().optional().describe('Template body'),
      templateUrl: z.string().optional().describe('Template S3 URL'),
      parameters: z.array(z.object({
        key: z.string().describe('Parameter key'),
        value: z.string().describe('Parameter value'),
      })).optional().describe('Stack parameters'),
      capabilities: z.array(z.string()).optional().describe('Capabilities like CAPABILITY_IAM'),
      tags: z.array(z.object({
        key: z.string().describe('Tag key'),
        value: z.string().describe('Tag value'),
      })).optional().describe('Stack tags'),
    },
    async ({ stackName, templateBody, templateUrl, parameters, capabilities, tags }) => {
      try {
        const result = await client.cfnCreateStack({
          stackName,
          templateBody,
          templateUrl,
          parameters,
          capabilities,
          tags,
        });
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Stack '${stackName}' creation initiated`,
                  stackId: result.stackId,
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
  // Update Stack
  // ===========================================================================
  server.tool(
    'aws_cfn_update_stack',
    `Update an existing CloudFormation stack.

Args:
  - stackName: Stack name or ID (required)
  - templateBody: New template content (optional)
  - templateUrl: S3 URL for new template (optional)
  - parameters: Updated parameters (optional)
  - capabilities: Required capabilities (optional)

Returns the stack ID.`,
    {
      stackName: z.string().describe('Stack name or ID'),
      templateBody: z.string().optional().describe('New template body'),
      templateUrl: z.string().optional().describe('New template S3 URL'),
      parameters: z.array(z.object({
        key: z.string().describe('Parameter key'),
        value: z.string().describe('Parameter value'),
      })).optional().describe('Updated parameters'),
      capabilities: z.array(z.string()).optional().describe('Capabilities'),
    },
    async ({ stackName, templateBody, templateUrl, parameters, capabilities }) => {
      try {
        const result = await client.cfnUpdateStack({
          stackName,
          templateBody,
          templateUrl,
          parameters,
          capabilities,
        });
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Stack '${stackName}' update initiated`,
                  stackId: result.stackId,
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
  // Delete Stack
  // ===========================================================================
  server.tool(
    'aws_cfn_delete_stack',
    `Delete a CloudFormation stack.

Args:
  - stackName: Stack name or ID (required)

WARNING: This will delete all resources created by the stack.

Returns confirmation.`,
    {
      stackName: z.string().describe('Stack name or ID'),
    },
    async ({ stackName }) => {
      try {
        await client.cfnDeleteStack(stackName);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Stack '${stackName}' deletion initiated`,
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
  // List Change Sets
  // ===========================================================================
  server.tool(
    'aws_cfn_list_change_sets',
    `List change sets for a CloudFormation stack.

Args:
  - stackName: Stack name or ID (required)

Returns change set summaries.`,
    {
      stackName: z.string().describe('Stack name or ID'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ stackName, format }) => {
      try {
        const changeSets = await client.cfnListChangeSets(stackName);
        return formatResponse(
          { items: changeSets, count: changeSets.length, hasMore: false },
          format,
          'cfn_change_sets'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Describe Change Set
  // ===========================================================================
  server.tool(
    'aws_cfn_describe_change_set',
    `Get details of a CloudFormation change set.

Args:
  - stackName: Stack name or ID (required)
  - changeSetName: Change set name or ID (required)

Returns change set details including resource changes.`,
    {
      stackName: z.string().describe('Stack name or ID'),
      changeSetName: z.string().describe('Change set name or ID'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ stackName, changeSetName, format }) => {
      try {
        const changeSet = await client.cfnDescribeChangeSet(stackName, changeSetName);
        return formatResponse(changeSet, format, 'cfn_change_set');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Create Change Set
  // ===========================================================================
  server.tool(
    'aws_cfn_create_change_set',
    `Create a change set for a CloudFormation stack.

Args:
  - stackName: Stack name or ID (required)
  - changeSetName: Name for the change set (required)
  - templateBody: Template content (optional)
  - templateUrl: S3 URL for template (optional)
  - parameters: Stack parameters (optional)
  - capabilities: Required capabilities (optional)
  - changeSetType: 'CREATE' for new stack, 'UPDATE' for existing (optional)

Returns the change set ID.`,
    {
      stackName: z.string().describe('Stack name or ID'),
      changeSetName: z.string().describe('Change set name'),
      templateBody: z.string().optional().describe('Template body'),
      templateUrl: z.string().optional().describe('Template S3 URL'),
      parameters: z.array(z.object({
        key: z.string().describe('Parameter key'),
        value: z.string().describe('Parameter value'),
      })).optional().describe('Stack parameters'),
      capabilities: z.array(z.string()).optional().describe('Capabilities'),
      changeSetType: z.enum(['CREATE', 'UPDATE']).optional().describe('Change set type'),
    },
    async ({ stackName, changeSetName, templateBody, templateUrl, parameters, capabilities, changeSetType }) => {
      try {
        const result = await client.cfnCreateChangeSet({
          stackName,
          changeSetName,
          templateBody,
          templateUrl,
          parameters,
          capabilities,
          changeSetType,
        });
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Change set '${changeSetName}' created`,
                  changeSetId: result.changeSetId,
                  stackId: result.stackId,
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
  // Execute Change Set
  // ===========================================================================
  server.tool(
    'aws_cfn_execute_change_set',
    `Execute a CloudFormation change set.

Args:
  - stackName: Stack name or ID (required)
  - changeSetName: Change set name or ID (required)

This applies the changes in the change set to the stack.

Returns confirmation.`,
    {
      stackName: z.string().describe('Stack name or ID'),
      changeSetName: z.string().describe('Change set name or ID'),
    },
    async ({ stackName, changeSetName }) => {
      try {
        await client.cfnExecuteChangeSet(stackName, changeSetName);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Change set '${changeSetName}' execution initiated`,
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
  // Delete Change Set
  // ===========================================================================
  server.tool(
    'aws_cfn_delete_change_set',
    `Delete a CloudFormation change set.

Args:
  - stackName: Stack name or ID (required)
  - changeSetName: Change set name or ID (required)

Returns confirmation.`,
    {
      stackName: z.string().describe('Stack name or ID'),
      changeSetName: z.string().describe('Change set name or ID'),
    },
    async ({ stackName, changeSetName }) => {
      try {
        await client.cfnDeleteChangeSet(stackName, changeSetName);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Change set '${changeSetName}' deleted`,
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
  // Validate Template
  // ===========================================================================
  server.tool(
    'aws_cfn_validate_template',
    `Validate a CloudFormation template.

Args:
  - templateBody: Template content (required if no templateUrl)
  - templateUrl: S3 URL for template (required if no templateBody)

Returns template parameters, description, and required capabilities.`,
    {
      templateBody: z.string().optional().describe('Template body'),
      templateUrl: z.string().optional().describe('Template S3 URL'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ templateBody, templateUrl, format }) => {
      try {
        const result = await client.cfnValidateTemplate(templateBody, templateUrl);
        return formatResponse(
          {
            valid: true,
            ...result,
          },
          format,
          'cfn_template_validation'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );
}
