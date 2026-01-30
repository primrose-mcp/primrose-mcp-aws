/**
 * DynamoDB Tools
 *
 * MCP tools for Amazon DynamoDB operations.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { AwsClient } from '../client.js';
import { formatError, formatResponse } from '../utils/formatters.js';

export function registerDynamoDBTools(server: McpServer, client: AwsClient): void {
  // ===========================================================================
  // List Tables
  // ===========================================================================
  server.tool(
    'aws_dynamodb_list_tables',
    `List all DynamoDB tables in the region.

Returns table names. Use describe_table for details.`,
    {
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ format }) => {
      try {
        const tables = await client.dynamodbListTables();
        return formatResponse(
          { items: tables.map((t) => ({ tableName: t })), count: tables.length, hasMore: false },
          format,
          'dynamodb_tables'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Describe Table
  // ===========================================================================
  server.tool(
    'aws_dynamodb_describe_table',
    `Get detailed information about a DynamoDB table.

Args:
  - tableName: The table name (required)

Returns table schema, billing mode, and throughput configuration.`,
    {
      tableName: z.string().describe('DynamoDB table name'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ tableName, format }) => {
      try {
        const table = await client.dynamodbDescribeTable(tableName);
        return formatResponse(table, format, 'dynamodb_table');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Query
  // ===========================================================================
  server.tool(
    'aws_dynamodb_query',
    `Query items from a DynamoDB table using key conditions.

Args:
  - tableName: The table name (required)
  - keyConditionExpression: Key condition (e.g., 'PK = :pk')
  - expressionAttributeValues: Values for placeholders (e.g., {':pk': {'S': 'user#123'}})
  - expressionAttributeNames: Name substitutions for reserved words
  - filterExpression: Additional filter to apply after query
  - indexName: Name of GSI or LSI to query
  - limit: Maximum items to return
  - scanIndexForward: true for ascending, false for descending

Returns matching items.`,
    {
      tableName: z.string().describe('DynamoDB table name'),
      keyConditionExpression: z.string().describe("Key condition (e.g., 'PK = :pk')"),
      expressionAttributeValues: z.record(z.string(), z.unknown()).describe('Attribute values'),
      expressionAttributeNames: z.record(z.string(), z.string()).optional().describe('Attribute name substitutions'),
      filterExpression: z.string().optional().describe('Filter expression'),
      indexName: z.string().optional().describe('Secondary index name'),
      limit: z.number().int().min(1).optional().describe('Max items to return'),
      scanIndexForward: z.boolean().default(true).describe('Sort ascending (true) or descending (false)'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({
      tableName,
      keyConditionExpression,
      expressionAttributeValues,
      expressionAttributeNames,
      filterExpression,
      indexName,
      limit,
      scanIndexForward,
      format,
    }) => {
      try {
        const result = await client.dynamodbQuery({
          tableName,
          keyConditionExpression,
          expressionAttributeValues,
          expressionAttributeNames,
          filterExpression,
          indexName,
          limit,
          scanIndexForward,
        });
        return formatResponse(
          {
            items: result.items,
            count: result.items.length,
            hasMore: !!result.lastEvaluatedKey,
            lastEvaluatedKey: result.lastEvaluatedKey,
          },
          format,
          'dynamodb_items'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Scan
  // ===========================================================================
  server.tool(
    'aws_dynamodb_scan',
    `Scan all items in a DynamoDB table (expensive operation).

Use Query when possible. Scan reads every item in the table.

Args:
  - tableName: The table name (required)
  - filterExpression: Filter to apply (e.g., 'status = :s')
  - expressionAttributeValues: Values for placeholders
  - expressionAttributeNames: Name substitutions
  - indexName: Secondary index to scan
  - limit: Maximum items to return

Returns matching items.`,
    {
      tableName: z.string().describe('DynamoDB table name'),
      filterExpression: z.string().optional().describe('Filter expression'),
      expressionAttributeValues: z.record(z.string(), z.unknown()).optional().describe('Attribute values'),
      expressionAttributeNames: z.record(z.string(), z.string()).optional().describe('Attribute name substitutions'),
      indexName: z.string().optional().describe('Secondary index name'),
      limit: z.number().int().min(1).optional().describe('Max items to return'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({
      tableName,
      filterExpression,
      expressionAttributeValues,
      expressionAttributeNames,
      indexName,
      limit,
      format,
    }) => {
      try {
        const result = await client.dynamodbScan({
          tableName,
          filterExpression,
          expressionAttributeValues,
          expressionAttributeNames,
          indexName,
          limit,
        });
        return formatResponse(
          {
            items: result.items,
            count: result.items.length,
            hasMore: !!result.lastEvaluatedKey,
            lastEvaluatedKey: result.lastEvaluatedKey,
          },
          format,
          'dynamodb_items'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Get Item
  // ===========================================================================
  server.tool(
    'aws_dynamodb_get_item',
    `Get a single item from DynamoDB by its primary key.

Args:
  - tableName: The table name (required)
  - key: The primary key (e.g., {'PK': {'S': 'user#123'}, 'SK': {'S': 'profile'}})
  - consistentRead: Use strongly consistent read (default: false)
  - projectionExpression: Attributes to retrieve

Returns the item or null if not found.`,
    {
      tableName: z.string().describe('DynamoDB table name'),
      key: z.record(z.string(), z.unknown()).describe('Primary key'),
      consistentRead: z.boolean().default(false).describe('Use consistent read'),
      projectionExpression: z.string().optional().describe('Attributes to retrieve'),
      expressionAttributeNames: z.record(z.string(), z.string()).optional().describe('Attribute name substitutions'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ tableName, key, consistentRead, projectionExpression, expressionAttributeNames, format }) => {
      try {
        const item = await client.dynamodbGetItem({
          tableName,
          key,
          consistentRead,
          projectionExpression,
          expressionAttributeNames,
        });
        if (item) {
          return formatResponse(item, format, 'dynamodb_item');
        }
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify({ found: false, message: 'Item not found' }, null, 2),
            },
          ],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Put Item
  // ===========================================================================
  server.tool(
    'aws_dynamodb_put_item',
    `Put an item into a DynamoDB table.

Args:
  - tableName: The table name (required)
  - item: The item to put (must include primary key attributes)
  - conditionExpression: Condition for the put (e.g., 'attribute_not_exists(PK)')
  - expressionAttributeValues: Values for condition placeholders
  - expressionAttributeNames: Name substitutions

Returns confirmation of the put operation.`,
    {
      tableName: z.string().describe('DynamoDB table name'),
      item: z.record(z.string(), z.unknown()).describe('Item to put (with primary key)'),
      conditionExpression: z.string().optional().describe('Condition expression'),
      expressionAttributeValues: z.record(z.string(), z.unknown()).optional().describe('Attribute values'),
      expressionAttributeNames: z.record(z.string(), z.string()).optional().describe('Attribute name substitutions'),
    },
    async ({ tableName, item, conditionExpression, expressionAttributeValues, expressionAttributeNames }) => {
      try {
        await client.dynamodbPutItem({
          tableName,
          item,
          conditionExpression,
          expressionAttributeValues,
          expressionAttributeNames,
        });
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Item put into ${tableName}`,
                  tableName,
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
  // Delete Item
  // ===========================================================================
  server.tool(
    'aws_dynamodb_delete_item',
    `Delete an item from a DynamoDB table.

Args:
  - tableName: The table name (required)
  - key: The primary key of the item to delete
  - conditionExpression: Condition for the delete
  - expressionAttributeValues: Values for condition placeholders
  - expressionAttributeNames: Name substitutions

Returns confirmation of the delete operation.`,
    {
      tableName: z.string().describe('DynamoDB table name'),
      key: z.record(z.string(), z.unknown()).describe('Primary key of item to delete'),
      conditionExpression: z.string().optional().describe('Condition expression'),
      expressionAttributeValues: z.record(z.string(), z.unknown()).optional().describe('Attribute values'),
      expressionAttributeNames: z.record(z.string(), z.string()).optional().describe('Attribute name substitutions'),
    },
    async ({ tableName, key, conditionExpression, expressionAttributeValues, expressionAttributeNames }) => {
      try {
        await client.dynamodbDeleteItem({
          tableName,
          key,
          conditionExpression,
          expressionAttributeValues,
          expressionAttributeNames,
        });
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Item deleted from ${tableName}`,
                  tableName,
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
  // Update Item
  // ===========================================================================
  server.tool(
    'aws_dynamodb_update_item',
    `Update an item in a DynamoDB table.

Args:
  - tableName: The table name (required)
  - key: The primary key of the item to update
  - updateExpression: Update expression (e.g., 'SET #n = :val, #s = :s')
  - expressionAttributeValues: Values for placeholders
  - expressionAttributeNames: Name substitutions
  - conditionExpression: Condition for the update

Returns confirmation of the update operation.`,
    {
      tableName: z.string().describe('DynamoDB table name'),
      key: z.record(z.string(), z.unknown()).describe('Primary key of item to update'),
      updateExpression: z.string().describe("Update expression (e.g., 'SET #n = :val')"),
      expressionAttributeValues: z.record(z.string(), z.unknown()).optional().describe('Attribute values'),
      expressionAttributeNames: z.record(z.string(), z.string()).optional().describe('Attribute name substitutions'),
      conditionExpression: z.string().optional().describe('Condition expression'),
    },
    async ({
      tableName,
      key,
      updateExpression,
      expressionAttributeValues,
      expressionAttributeNames,
      conditionExpression,
    }) => {
      try {
        await client.dynamodbUpdateItem({
          tableName,
          key,
          updateExpression,
          expressionAttributeValues,
          expressionAttributeNames,
          conditionExpression,
        });
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Item updated in ${tableName}`,
                  tableName,
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
  // Batch Get Item
  // ===========================================================================
  server.tool(
    'aws_dynamodb_batch_get_item',
    `Get multiple items from one or more DynamoDB tables in a single request.

Args:
  - requestItems: Object mapping table names to keys and options

Example requestItems:
{
  "TableName": {
    "keys": [{"PK": {"S": "user#1"}}, {"PK": {"S": "user#2"}}],
    "projectionExpression": "attribute1, attribute2"
  }
}

Returns items grouped by table name.`,
    {
      requestItems: z
        .record(
          z.string(),
          z.object({
            keys: z.array(z.record(z.string(), z.unknown())),
            projectionExpression: z.string().optional(),
            expressionAttributeNames: z.record(z.string(), z.string()).optional(),
            consistentRead: z.boolean().optional(),
          })
        )
        .describe('Map of table names to keys and options'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ requestItems, format }) => {
      try {
        const result = await client.dynamodbBatchGetItem({ requestItems });
        return formatResponse(
          {
            items: Object.entries(result.responses).flatMap(([table, items]) =>
              items.map((item) => ({ _table: table, ...item }))
            ),
            count: Object.values(result.responses).reduce((sum, items) => sum + items.length, 0),
            hasMore: !!result.unprocessedKeys && Object.keys(result.unprocessedKeys).length > 0,
            unprocessedKeys: result.unprocessedKeys,
          },
          format,
          'dynamodb_items'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Batch Write Item
  // ===========================================================================
  server.tool(
    'aws_dynamodb_batch_write_item',
    `Write (put or delete) multiple items to one or more DynamoDB tables.

Args:
  - requestItems: Object mapping table names to write requests

Example requestItems:
{
  "TableName": [
    {"putRequest": {"item": {"PK": {"S": "user#1"}, "data": {"S": "value"}}}},
    {"deleteRequest": {"key": {"PK": {"S": "user#2"}}}}
  ]
}

Returns unprocessed items if any.`,
    {
      requestItems: z
        .record(
          z.string(),
          z.array(
            z.union([
              z.object({ putRequest: z.object({ item: z.record(z.string(), z.unknown()) }) }),
              z.object({ deleteRequest: z.object({ key: z.record(z.string(), z.unknown()) }) }),
            ])
          )
        )
        .describe('Map of table names to write requests'),
    },
    async ({ requestItems }) => {
      try {
        const result = await client.dynamodbBatchWriteItem({ requestItems });
        const totalRequests = Object.values(requestItems).reduce((sum, reqs) => sum + reqs.length, 0);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Batch write completed`,
                  totalRequests,
                  unprocessedItems: result.unprocessedItems,
                  hasUnprocessed: !!result.unprocessedItems && Object.keys(result.unprocessedItems).length > 0,
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
  // Create Table
  // ===========================================================================
  server.tool(
    'aws_dynamodb_create_table',
    `Create a new DynamoDB table.

Args:
  - tableName: Name for the new table (required)
  - keySchema: Array of key schema elements (required)
    - attributeName: Attribute name
    - keyType: 'HASH' (partition key) or 'RANGE' (sort key)
  - attributeDefinitions: Array of attribute definitions (required)
    - attributeName: Attribute name
    - attributeType: 'S' (string), 'N' (number), or 'B' (binary)
  - billingMode: 'PROVISIONED' or 'PAY_PER_REQUEST' (default: PAY_PER_REQUEST)
  - provisionedThroughput: Required if billingMode is PROVISIONED
    - readCapacityUnits: Read capacity units
    - writeCapacityUnits: Write capacity units

Returns the created table details.`,
    {
      tableName: z.string().describe('Table name'),
      keySchema: z.array(z.object({
        attributeName: z.string().describe('Attribute name'),
        keyType: z.enum(['HASH', 'RANGE']).describe('Key type'),
      })).min(1).max(2).describe('Key schema'),
      attributeDefinitions: z.array(z.object({
        attributeName: z.string().describe('Attribute name'),
        attributeType: z.enum(['S', 'N', 'B']).describe('Attribute type'),
      })).min(1).describe('Attribute definitions'),
      billingMode: z.enum(['PROVISIONED', 'PAY_PER_REQUEST']).default('PAY_PER_REQUEST').describe('Billing mode'),
      provisionedThroughput: z.object({
        readCapacityUnits: z.number().int().min(1).describe('Read capacity units'),
        writeCapacityUnits: z.number().int().min(1).describe('Write capacity units'),
      }).optional().describe('Provisioned throughput (required for PROVISIONED billing)'),
    },
    async ({ tableName, keySchema, attributeDefinitions, billingMode, provisionedThroughput }) => {
      try {
        const table = await client.dynamodbCreateTable({
          tableName,
          keySchema,
          attributeDefinitions,
          billingMode,
          provisionedThroughput,
        });
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Table '${tableName}' created`,
                  tableName: table.tableName,
                  tableArn: table.tableArn,
                  tableStatus: table.tableStatus,
                  billingMode: table.billingModeSummary?.billingMode,
                  keySchema: table.keySchema,
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
  // Delete Table
  // ===========================================================================
  server.tool(
    'aws_dynamodb_delete_table',
    `Delete a DynamoDB table.

Args:
  - tableName: Name of the table to delete (required)

WARNING: This action is irreversible. All data in the table will be permanently deleted.

Returns confirmation of deletion.`,
    {
      tableName: z.string().describe('Table name to delete'),
    },
    async ({ tableName }) => {
      try {
        await client.dynamodbDeleteTable(tableName);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Table '${tableName}' deletion initiated`,
                  tableName,
                  warning: 'Table deletion is in progress. All data will be permanently deleted.',
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
  // Update Time To Live
  // ===========================================================================
  server.tool(
    'aws_dynamodb_update_time_to_live',
    `Enable or disable Time To Live (TTL) on a DynamoDB table.

Args:
  - tableName: Name of the table (required)
  - attributeName: Name of the TTL attribute (required)
  - enabled: Enable (true) or disable (false) TTL (required)

When enabled, items with the TTL attribute set to a past timestamp will be automatically deleted.

Returns confirmation of TTL update.`,
    {
      tableName: z.string().describe('Table name'),
      attributeName: z.string().describe('TTL attribute name'),
      enabled: z.boolean().describe('Enable or disable TTL'),
    },
    async ({ tableName, attributeName, enabled }) => {
      try {
        await client.dynamodbUpdateTimeToLive(tableName, attributeName, enabled);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `TTL ${enabled ? 'enabled' : 'disabled'} on table '${tableName}'`,
                  tableName,
                  attributeName,
                  enabled,
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
  // Describe Time To Live
  // ===========================================================================
  server.tool(
    'aws_dynamodb_describe_time_to_live',
    `Get the TTL settings for a DynamoDB table.

Args:
  - tableName: Name of the table (required)

Returns the TTL attribute name and status.`,
    {
      tableName: z.string().describe('Table name'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ tableName, format }) => {
      try {
        const ttl = await client.dynamodbDescribeTimeToLive(tableName);
        return formatResponse(
          { tableName, ...ttl },
          format,
          'dynamodb_ttl'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Create Backup
  // ===========================================================================
  server.tool(
    'aws_dynamodb_create_backup',
    `Create an on-demand backup of a DynamoDB table.

Args:
  - tableName: Name of the table to backup (required)
  - backupName: Name for the backup (required)

Returns the backup details.`,
    {
      tableName: z.string().describe('Table name'),
      backupName: z.string().describe('Backup name'),
    },
    async ({ tableName, backupName }) => {
      try {
        const backup = await client.dynamodbCreateBackup(tableName, backupName);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Backup '${backupName}' created for table '${tableName}'`,
                  ...backup,
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
  // List Backups
  // ===========================================================================
  server.tool(
    'aws_dynamodb_list_backups',
    `List backups for DynamoDB tables.

Args:
  - tableName: Filter by table name (optional)

Returns list of backup summaries.`,
    {
      tableName: z.string().optional().describe('Filter by table name'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ tableName, format }) => {
      try {
        const backups = await client.dynamodbListBackups(tableName);
        return formatResponse(
          { items: backups, count: backups.length, hasMore: false },
          format,
          'dynamodb_backups'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Describe Backup
  // ===========================================================================
  server.tool(
    'aws_dynamodb_describe_backup',
    `Get details of a DynamoDB backup.

Args:
  - backupArn: The backup ARN (required)

Returns backup details including size and status.`,
    {
      backupArn: z.string().describe('Backup ARN'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ backupArn, format }) => {
      try {
        const backup = await client.dynamodbDescribeBackup(backupArn);
        return formatResponse(backup, format, 'dynamodb_backup');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Delete Backup
  // ===========================================================================
  server.tool(
    'aws_dynamodb_delete_backup',
    `Delete a DynamoDB backup.

Args:
  - backupArn: The backup ARN (required)

Returns confirmation of deletion.`,
    {
      backupArn: z.string().describe('Backup ARN'),
    },
    async ({ backupArn }) => {
      try {
        await client.dynamodbDeleteBackup(backupArn);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Backup deleted',
                  backupArn,
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
  // Restore Table From Backup
  // ===========================================================================
  server.tool(
    'aws_dynamodb_restore_table_from_backup',
    `Restore a DynamoDB table from a backup.

Args:
  - targetTableName: Name for the restored table (required)
  - backupArn: The backup ARN to restore from (required)

Returns the restored table details.`,
    {
      targetTableName: z.string().describe('Target table name'),
      backupArn: z.string().describe('Backup ARN'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ targetTableName, backupArn, format }) => {
      try {
        const table = await client.dynamodbRestoreTableFromBackup(targetTableName, backupArn);
        return formatResponse(
          {
            success: true,
            message: `Table '${targetTableName}' restore initiated from backup`,
            table,
          },
          format,
          'dynamodb_table'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Enable Continuous Backups (Point-in-Time Recovery)
  // ===========================================================================
  server.tool(
    'aws_dynamodb_enable_continuous_backups',
    `Enable point-in-time recovery (PITR) for a DynamoDB table.

Args:
  - tableName: Name of the table (required)

Enables continuous backups which allow restore to any point in the last 35 days.

Returns confirmation.`,
    {
      tableName: z.string().describe('Table name'),
    },
    async ({ tableName }) => {
      try {
        await client.dynamodbEnableContinuousBackups(tableName);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Point-in-time recovery enabled for table '${tableName}'`,
                  tableName,
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
  // Describe Continuous Backups
  // ===========================================================================
  server.tool(
    'aws_dynamodb_describe_continuous_backups',
    `Get continuous backup (PITR) settings for a DynamoDB table.

Args:
  - tableName: Name of the table (required)

Returns PITR status and restore window.`,
    {
      tableName: z.string().describe('Table name'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ tableName, format }) => {
      try {
        const backups = await client.dynamodbDescribeContinuousBackups(tableName);
        return formatResponse(
          { tableName, ...backups },
          format,
          'dynamodb_continuous_backups'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Restore Table To Point In Time
  // ===========================================================================
  server.tool(
    'aws_dynamodb_restore_table_to_point_in_time',
    `Restore a DynamoDB table to a specific point in time.

Args:
  - sourceTableName: Name of the source table (required)
  - targetTableName: Name for the restored table (required)
  - restoreDateTime: ISO timestamp to restore to (optional, uses latest if not specified)

Requires point-in-time recovery to be enabled on the source table.

Returns the restored table details.`,
    {
      sourceTableName: z.string().describe('Source table name'),
      targetTableName: z.string().describe('Target table name'),
      restoreDateTime: z.string().optional().describe('ISO timestamp to restore to'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ sourceTableName, targetTableName, restoreDateTime, format }) => {
      try {
        const date = restoreDateTime ? new Date(restoreDateTime) : undefined;
        const table = await client.dynamodbRestoreTableToPointInTime(sourceTableName, targetTableName, date);
        return formatResponse(
          {
            success: true,
            message: `Table '${targetTableName}' restore initiated from '${sourceTableName}'`,
            restoreDateTime: restoreDateTime || 'latest',
            table,
          },
          format,
          'dynamodb_table'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Update Table
  // ===========================================================================
  server.tool(
    'aws_dynamodb_update_table',
    `Update a DynamoDB table's settings.

Args:
  - tableName: Name of the table (required)
  - billingMode: 'PROVISIONED' or 'PAY_PER_REQUEST' (optional)
  - readCapacityUnits: Read capacity (required if switching to PROVISIONED)
  - writeCapacityUnits: Write capacity (required if switching to PROVISIONED)

Returns the updated table details.`,
    {
      tableName: z.string().describe('Table name'),
      billingMode: z.enum(['PROVISIONED', 'PAY_PER_REQUEST']).optional().describe('Billing mode'),
      readCapacityUnits: z.number().int().min(1).optional().describe('Read capacity units'),
      writeCapacityUnits: z.number().int().min(1).optional().describe('Write capacity units'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ tableName, billingMode, readCapacityUnits, writeCapacityUnits, format }) => {
      try {
        const params: { provisionedThroughput?: { readCapacityUnits: number; writeCapacityUnits: number }; billingMode?: 'PROVISIONED' | 'PAY_PER_REQUEST' } = {};
        if (billingMode) params.billingMode = billingMode;
        if (readCapacityUnits !== undefined && writeCapacityUnits !== undefined) {
          params.provisionedThroughput = { readCapacityUnits, writeCapacityUnits };
        }
        const table = await client.dynamodbUpdateTable(tableName, params);
        return formatResponse(
          {
            success: true,
            message: `Table '${tableName}' updated`,
            table,
          },
          format,
          'dynamodb_table'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // List Global Tables
  // ===========================================================================
  server.tool(
    'aws_dynamodb_list_global_tables',
    `List DynamoDB global tables.

Returns global tables with their replication regions.`,
    {
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ format }) => {
      try {
        const tables = await client.dynamodbListGlobalTables();
        return formatResponse(
          { items: tables, count: tables.length, hasMore: false },
          format,
          'dynamodb_global_tables'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Describe Global Table
  // ===========================================================================
  server.tool(
    'aws_dynamodb_describe_global_table',
    `Get details of a DynamoDB global table.

Args:
  - globalTableName: The global table name (required)

Returns global table configuration and replication info.`,
    {
      globalTableName: z.string().describe('Global table name'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ globalTableName, format }) => {
      try {
        const table = await client.dynamodbDescribeGlobalTable(globalTableName);
        return formatResponse(table, format, 'dynamodb_global_table');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Tag Resource
  // ===========================================================================
  server.tool(
    'aws_dynamodb_tag_resource',
    `Add tags to a DynamoDB resource.

Args:
  - resourceArn: The DynamoDB resource ARN (required)
  - tags: Array of tags to add (required)

Returns confirmation.`,
    {
      resourceArn: z.string().describe('DynamoDB resource ARN'),
      tags: z.array(z.object({
        key: z.string().describe('Tag key'),
        value: z.string().describe('Tag value'),
      })).min(1).describe('Tags to add'),
    },
    async ({ resourceArn, tags }) => {
      try {
        await client.dynamodbTagResource(resourceArn, tags);
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
    'aws_dynamodb_untag_resource',
    `Remove tags from a DynamoDB resource.

Args:
  - resourceArn: The DynamoDB resource ARN (required)
  - tagKeys: Array of tag keys to remove (required)

Returns confirmation.`,
    {
      resourceArn: z.string().describe('DynamoDB resource ARN'),
      tagKeys: z.array(z.string()).min(1).describe('Tag keys to remove'),
    },
    async ({ resourceArn, tagKeys }) => {
      try {
        await client.dynamodbUntagResource(resourceArn, tagKeys);
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
  // List Tags Of Resource
  // ===========================================================================
  server.tool(
    'aws_dynamodb_list_tags_of_resource',
    `List tags on a DynamoDB resource.

Args:
  - resourceArn: The DynamoDB resource ARN (required)

Returns the resource tags.`,
    {
      resourceArn: z.string().describe('DynamoDB resource ARN'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ resourceArn, format }) => {
      try {
        const tags = await client.dynamodbListTagsOfResource(resourceArn);
        return formatResponse(
          { items: tags, count: tags.length, hasMore: false },
          format,
          'dynamodb_tags'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Describe Table Replica Auto Scaling
  // ===========================================================================
  server.tool(
    'aws_dynamodb_describe_table_replica_auto_scaling',
    `Describe auto scaling settings for a DynamoDB table replicas.

Args:
  - tableName: The table name (required)

Returns replica auto scaling configuration.`,
    {
      tableName: z.string().describe('Table name'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ tableName, format }) => {
      try {
        const scaling = await client.dynamodbDescribeTableReplicaAutoScaling(tableName);
        return formatResponse(scaling, format, 'dynamodb_replica_auto_scaling');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Describe Limits
  // ===========================================================================
  server.tool(
    'aws_dynamodb_describe_limits',
    `Describe DynamoDB account limits for capacity units.

Returns account and table capacity limits.`,
    {
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ format }) => {
      try {
        const limits = await client.dynamodbDescribeLimits();
        return formatResponse(limits, format, 'dynamodb_limits');
      } catch (error) {
        return formatError(error);
      }
    }
  );
}
