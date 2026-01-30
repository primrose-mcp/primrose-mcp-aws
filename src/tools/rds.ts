/**
 * RDS Tools
 *
 * MCP tools for Amazon RDS database operations.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { AwsClient } from '../client.js';
import { formatError, formatResponse } from '../utils/formatters.js';

export function registerRDSTools(server: McpServer, client: AwsClient): void {
  // ===========================================================================
  // Describe DB Instances
  // ===========================================================================
  server.tool(
    'aws_rds_describe_db_instances',
    `List RDS database instances.

Args:
  - dbInstanceIdentifier: Filter by instance ID (optional)

Returns instances with engine, class, status, and endpoint.`,
    {
      dbInstanceIdentifier: z.string().optional().describe('Filter by DB instance ID'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ dbInstanceIdentifier, format }) => {
      try {
        const instances = await client.rdsDescribeDBInstances(dbInstanceIdentifier);
        return formatResponse(
          { items: instances, count: instances.length, hasMore: false },
          format,
          'rds_instances'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Describe DB Clusters
  // ===========================================================================
  server.tool(
    'aws_rds_describe_db_clusters',
    `List RDS Aurora database clusters.

Args:
  - dbClusterIdentifier: Filter by cluster ID (optional)

Returns clusters with engine, status, and endpoints.`,
    {
      dbClusterIdentifier: z.string().optional().describe('Filter by DB cluster ID'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ dbClusterIdentifier, format }) => {
      try {
        const clusters = await client.rdsDescribeDBClusters(dbClusterIdentifier);
        return formatResponse(
          { items: clusters, count: clusters.length, hasMore: false },
          format,
          'rds_clusters'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Describe DB Snapshots
  // ===========================================================================
  server.tool(
    'aws_rds_describe_db_snapshots',
    `List RDS database snapshots.

Args:
  - dbInstanceIdentifier: Filter by source DB instance (optional)

Returns snapshots with type, status, and creation time.`,
    {
      dbInstanceIdentifier: z.string().optional().describe('Filter by source DB instance'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ dbInstanceIdentifier, format }) => {
      try {
        const snapshots = await client.rdsDescribeDBSnapshots(dbInstanceIdentifier);
        return formatResponse(
          { items: snapshots, count: snapshots.length, hasMore: false },
          format,
          'rds_snapshots'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Describe DB Parameter Groups
  // ===========================================================================
  server.tool(
    'aws_rds_describe_db_parameter_groups',
    `List RDS DB parameter groups.

Args:
  - dbParameterGroupName: Filter by parameter group name (optional)

Returns parameter groups with families and descriptions.`,
    {
      dbParameterGroupName: z.string().optional().describe('Filter by parameter group name'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ dbParameterGroupName, format }) => {
      try {
        const groups = await client.rdsDescribeDBParameterGroups(dbParameterGroupName);
        return formatResponse(
          { items: groups, count: groups.length, hasMore: false },
          format,
          'rds_parameter_groups'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Describe DB Subnet Groups
  // ===========================================================================
  server.tool(
    'aws_rds_describe_db_subnet_groups',
    `List RDS DB subnet groups.

Args:
  - dbSubnetGroupName: Filter by subnet group name (optional)

Returns subnet groups with VPCs and subnets.`,
    {
      dbSubnetGroupName: z.string().optional().describe('Filter by subnet group name'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ dbSubnetGroupName, format }) => {
      try {
        const groups = await client.rdsDescribeDBSubnetGroups(dbSubnetGroupName);
        return formatResponse(
          { items: groups, count: groups.length, hasMore: false },
          format,
          'rds_subnet_groups'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Create DB Snapshot
  // ===========================================================================
  server.tool(
    'aws_rds_create_db_snapshot',
    `Create a manual snapshot of an RDS database instance.

Args:
  - dbInstanceIdentifier: The DB instance identifier (required)
  - dbSnapshotIdentifier: The name for the snapshot (required)

Returns the snapshot details.`,
    {
      dbInstanceIdentifier: z.string().describe('DB instance identifier'),
      dbSnapshotIdentifier: z.string().describe('Name for the snapshot'),
    },
    async ({ dbInstanceIdentifier, dbSnapshotIdentifier }) => {
      try {
        const snapshot = await client.rdsCreateDBSnapshot(dbInstanceIdentifier, dbSnapshotIdentifier);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Snapshot creation initiated',
                  dbSnapshotIdentifier: snapshot.dbSnapshotIdentifier,
                  dbInstanceIdentifier: snapshot.dbInstanceIdentifier,
                  status: snapshot.status,
                  engine: snapshot.engine,
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
  // Delete DB Snapshot
  // ===========================================================================
  server.tool(
    'aws_rds_delete_db_snapshot',
    `Delete an RDS database snapshot.

Args:
  - dbSnapshotIdentifier: The snapshot identifier (required)

WARNING: This action is irreversible.

Returns confirmation of deletion.`,
    {
      dbSnapshotIdentifier: z.string().describe('Snapshot identifier'),
    },
    async ({ dbSnapshotIdentifier }) => {
      try {
        await client.rdsDeleteDBSnapshot(dbSnapshotIdentifier);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Snapshot deleted',
                  dbSnapshotIdentifier,
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
  // Start DB Instance
  // ===========================================================================
  server.tool(
    'aws_rds_start_db_instance',
    `Start a stopped RDS database instance.

Args:
  - dbInstanceIdentifier: The DB instance identifier (required)

Returns the instance details.`,
    {
      dbInstanceIdentifier: z.string().describe('DB instance identifier'),
    },
    async ({ dbInstanceIdentifier }) => {
      try {
        const instance = await client.rdsStartDBInstance(dbInstanceIdentifier);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Instance starting',
                  dbInstanceIdentifier: instance.dbInstanceIdentifier,
                  dbInstanceStatus: instance.dbInstanceStatus,
                  engine: instance.engine,
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
  // Stop DB Instance
  // ===========================================================================
  server.tool(
    'aws_rds_stop_db_instance',
    `Stop a running RDS database instance.

Args:
  - dbInstanceIdentifier: The DB instance identifier (required)
  - dbSnapshotIdentifier: Name for a final snapshot before stopping (optional)

Returns the instance details.`,
    {
      dbInstanceIdentifier: z.string().describe('DB instance identifier'),
      dbSnapshotIdentifier: z.string().optional().describe('Name for final snapshot'),
    },
    async ({ dbInstanceIdentifier, dbSnapshotIdentifier }) => {
      try {
        const instance = await client.rdsStopDBInstance(dbInstanceIdentifier, dbSnapshotIdentifier);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Instance stopping',
                  dbInstanceIdentifier: instance.dbInstanceIdentifier,
                  dbInstanceStatus: instance.dbInstanceStatus,
                  engine: instance.engine,
                  snapshotCreated: !!dbSnapshotIdentifier,
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
  // Reboot DB Instance
  // ===========================================================================
  server.tool(
    'aws_rds_reboot_db_instance',
    `Reboot an RDS database instance.

Args:
  - dbInstanceIdentifier: The DB instance identifier (required)
  - forceFailover: Force failover to a standby in Multi-AZ deployment (optional)

Returns the instance details.`,
    {
      dbInstanceIdentifier: z.string().describe('DB instance identifier'),
      forceFailover: z.boolean().optional().describe('Force failover to standby'),
    },
    async ({ dbInstanceIdentifier, forceFailover }) => {
      try {
        const instance = await client.rdsRebootDBInstance(dbInstanceIdentifier, forceFailover);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Instance rebooting',
                  dbInstanceIdentifier: instance.dbInstanceIdentifier,
                  dbInstanceStatus: instance.dbInstanceStatus,
                  engine: instance.engine,
                  forceFailover: !!forceFailover,
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
  // Delete DB Instance
  // ===========================================================================
  server.tool(
    'aws_rds_delete_db_instance',
    `Delete an RDS database instance.

Args:
  - dbInstanceIdentifier: The DB instance identifier (required)
  - skipFinalSnapshot: Skip creating a final snapshot (default: false)
  - finalSnapshotIdentifier: Name for the final snapshot (required if skipFinalSnapshot is false)

WARNING: This action is irreversible if skipFinalSnapshot is true.

Returns the instance details.`,
    {
      dbInstanceIdentifier: z.string().describe('DB instance identifier'),
      skipFinalSnapshot: z.boolean().optional().describe('Skip final snapshot'),
      finalSnapshotIdentifier: z.string().optional().describe('Name for final snapshot'),
    },
    async ({ dbInstanceIdentifier, skipFinalSnapshot, finalSnapshotIdentifier }) => {
      try {
        const instance = await client.rdsDeleteDBInstance(dbInstanceIdentifier, skipFinalSnapshot, finalSnapshotIdentifier);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Instance deletion initiated',
                  dbInstanceIdentifier: instance.dbInstanceIdentifier,
                  dbInstanceStatus: instance.dbInstanceStatus,
                  finalSnapshotCreated: !skipFinalSnapshot && !!finalSnapshotIdentifier,
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
  // Modify DB Instance
  // ===========================================================================
  server.tool(
    'aws_rds_modify_db_instance',
    `Modify an RDS database instance.

Args:
  - dbInstanceIdentifier: The DB instance identifier (required)
  - dbInstanceClass: New instance class (e.g., 'db.t3.medium')
  - allocatedStorage: New storage size in GB
  - masterUserPassword: New master password
  - backupRetentionPeriod: Days to retain backups (0-35)
  - multiAZ: Enable/disable Multi-AZ deployment
  - applyImmediately: Apply changes immediately (default: next maintenance window)

Returns the instance details.`,
    {
      dbInstanceIdentifier: z.string().describe('DB instance identifier'),
      dbInstanceClass: z.string().optional().describe('Instance class (e.g., db.t3.medium)'),
      allocatedStorage: z.number().int().optional().describe('Storage size in GB'),
      masterUserPassword: z.string().optional().describe('New master password'),
      backupRetentionPeriod: z.number().int().min(0).max(35).optional().describe('Backup retention days'),
      multiAZ: z.boolean().optional().describe('Enable Multi-AZ'),
      applyImmediately: z.boolean().optional().describe('Apply immediately'),
    },
    async ({ dbInstanceIdentifier, dbInstanceClass, allocatedStorage, masterUserPassword, backupRetentionPeriod, multiAZ, applyImmediately }) => {
      try {
        const instance = await client.rdsModifyDBInstance(dbInstanceIdentifier, {
          dbInstanceClass,
          allocatedStorage,
          masterUserPassword,
          backupRetentionPeriod,
          multiAZ,
          applyImmediately,
        });
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: applyImmediately ? 'Instance modification initiated' : 'Modification scheduled for next maintenance window',
                  dbInstanceIdentifier: instance.dbInstanceIdentifier,
                  dbInstanceStatus: instance.dbInstanceStatus,
                  dbInstanceClass: instance.dbInstanceClass,
                  allocatedStorage: instance.allocatedStorage,
                  multiAZ: instance.multiAZ,
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
  // Describe DB Cluster Snapshots
  // ===========================================================================
  server.tool(
    'aws_rds_describe_db_cluster_snapshots',
    `List RDS Aurora cluster snapshots.

Args:
  - dbClusterIdentifier: Filter by source DB cluster (optional)

Returns cluster snapshots with type, status, and creation time.`,
    {
      dbClusterIdentifier: z.string().optional().describe('Filter by source DB cluster'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ dbClusterIdentifier, format }) => {
      try {
        const snapshots = await client.rdsDescribeDBClusterSnapshots(dbClusterIdentifier);
        return formatResponse(
          { items: snapshots, count: snapshots.length, hasMore: false },
          format,
          'rds_cluster_snapshots'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Create DB Cluster Snapshot
  // ===========================================================================
  server.tool(
    'aws_rds_create_db_cluster_snapshot',
    `Create a manual snapshot of an RDS Aurora cluster.

Args:
  - dbClusterIdentifier: The DB cluster identifier (required)
  - dbClusterSnapshotIdentifier: The name for the snapshot (required)

Returns the snapshot details.`,
    {
      dbClusterIdentifier: z.string().describe('DB cluster identifier'),
      dbClusterSnapshotIdentifier: z.string().describe('Name for the snapshot'),
    },
    async ({ dbClusterIdentifier, dbClusterSnapshotIdentifier }) => {
      try {
        const snapshot = await client.rdsCreateDBClusterSnapshot(dbClusterIdentifier, dbClusterSnapshotIdentifier);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Cluster snapshot creation initiated',
                  dbClusterSnapshotIdentifier: snapshot.dbClusterSnapshotIdentifier,
                  dbClusterIdentifier: snapshot.dbClusterIdentifier,
                  status: snapshot.status,
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
  // Delete DB Cluster Snapshot
  // ===========================================================================
  server.tool(
    'aws_rds_delete_db_cluster_snapshot',
    `Delete an RDS Aurora cluster snapshot.

Args:
  - dbClusterSnapshotIdentifier: The cluster snapshot identifier (required)

WARNING: This action is irreversible.

Returns confirmation of deletion.`,
    {
      dbClusterSnapshotIdentifier: z.string().describe('Cluster snapshot identifier'),
    },
    async ({ dbClusterSnapshotIdentifier }) => {
      try {
        await client.rdsDeleteDBClusterSnapshot(dbClusterSnapshotIdentifier);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Cluster snapshot deleted',
                  dbClusterSnapshotIdentifier,
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
  // Describe DB Security Groups
  // ===========================================================================
  server.tool(
    'aws_rds_describe_db_security_groups',
    `List RDS DB security groups (for EC2-Classic).

Args:
  - dbSecurityGroupName: Filter by security group name (optional)

Returns DB security groups with descriptions.`,
    {
      dbSecurityGroupName: z.string().optional().describe('Filter by security group name'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ dbSecurityGroupName, format }) => {
      try {
        const groups = await client.rdsDescribeDBSecurityGroups(dbSecurityGroupName);
        return formatResponse(
          { items: groups, count: groups.length, hasMore: false },
          format,
          'rds_security_groups'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Describe Option Groups
  // ===========================================================================
  server.tool(
    'aws_rds_describe_option_groups',
    `List RDS option groups.

Args:
  - optionGroupName: Filter by option group name (optional)

Returns option groups with engines and versions.`,
    {
      optionGroupName: z.string().optional().describe('Filter by option group name'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ optionGroupName, format }) => {
      try {
        const groups = await client.rdsDescribeOptionGroups(optionGroupName);
        return formatResponse(
          { items: groups, count: groups.length, hasMore: false },
          format,
          'rds_option_groups'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Describe DB Engine Versions
  // ===========================================================================
  server.tool(
    'aws_rds_describe_db_engine_versions',
    `List available RDS database engine versions.

Args:
  - engine: Filter by engine name (e.g., 'mysql', 'postgres') (optional)

Returns engine versions with upgrade targets.`,
    {
      engine: z.string().optional().describe('Filter by engine name'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ engine, format }) => {
      try {
        const versions = await client.rdsDescribeDBEngineVersions(engine);
        return formatResponse(
          { items: versions, count: versions.length, hasMore: false },
          format,
          'rds_engine_versions'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Describe Orderable DB Instance Options
  // ===========================================================================
  server.tool(
    'aws_rds_describe_orderable_db_instance_options',
    `List available DB instance options for an engine.

Args:
  - engine: The DB engine name (required, e.g., 'mysql', 'postgres')

Returns available instance classes and configurations.`,
    {
      engine: z.string().describe('DB engine name (e.g., mysql, postgres)'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ engine, format }) => {
      try {
        const options = await client.rdsDescribeOrderableDBInstanceOptions(engine);
        return formatResponse(
          { items: options, count: options.length, hasMore: false },
          format,
          'rds_orderable_options'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Describe Events
  // ===========================================================================
  server.tool(
    'aws_rds_describe_events',
    `List RDS events.

Args:
  - sourceType: Filter by source type (e.g., 'db-instance', 'db-cluster') (optional)
  - sourceIdentifier: Filter by source identifier (optional)
  - duration: Events from the last N minutes (optional, default: 60)

Returns recent RDS events.`,
    {
      sourceType: z.string().optional().describe('Source type filter'),
      sourceIdentifier: z.string().optional().describe('Source identifier filter'),
      duration: z.number().int().optional().describe('Duration in minutes'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ sourceType, sourceIdentifier, duration, format }) => {
      try {
        const events = await client.rdsDescribeEvents({ sourceType, sourceIdentifier, duration });
        return formatResponse(
          { items: events, count: events.length, hasMore: false },
          format,
          'rds_events'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Describe Pending Maintenance Actions
  // ===========================================================================
  server.tool(
    'aws_rds_describe_pending_maintenance_actions',
    `List pending maintenance actions for RDS resources.

Args:
  - resourceIdentifier: Filter by resource ARN (optional)

Returns pending maintenance actions with details.`,
    {
      resourceIdentifier: z.string().optional().describe('Resource ARN filter'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ resourceIdentifier, format }) => {
      try {
        const actions = await client.rdsDescribePendingMaintenanceActions(resourceIdentifier);
        return formatResponse(
          { items: actions, count: actions.length, hasMore: false },
          format,
          'rds_pending_maintenance'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Add Tags To Resource
  // ===========================================================================
  server.tool(
    'aws_rds_add_tags_to_resource',
    `Add tags to an RDS resource.

Args:
  - resourceArn: The ARN of the RDS resource (required)
  - tags: Array of tags to add (required)

Returns confirmation.`,
    {
      resourceArn: z.string().describe('RDS resource ARN'),
      tags: z.array(z.object({
        key: z.string().describe('Tag key'),
        value: z.string().describe('Tag value'),
      })).min(1).describe('Tags to add'),
    },
    async ({ resourceArn, tags }) => {
      try {
        await client.rdsAddTagsToResource(resourceArn, tags);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Tags added to resource',
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
  // Remove Tags From Resource
  // ===========================================================================
  server.tool(
    'aws_rds_remove_tags_from_resource',
    `Remove tags from an RDS resource.

Args:
  - resourceArn: The ARN of the RDS resource (required)
  - tagKeys: Array of tag keys to remove (required)

Returns confirmation.`,
    {
      resourceArn: z.string().describe('RDS resource ARN'),
      tagKeys: z.array(z.string()).min(1).describe('Tag keys to remove'),
    },
    async ({ resourceArn, tagKeys }) => {
      try {
        await client.rdsRemoveTagsFromResource(resourceArn, tagKeys);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Tags removed from resource',
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
  // List Tags For Resource
  // ===========================================================================
  server.tool(
    'aws_rds_list_tags_for_resource',
    `List tags on an RDS resource.

Args:
  - resourceArn: The ARN of the RDS resource (required)

Returns the resource tags.`,
    {
      resourceArn: z.string().describe('RDS resource ARN'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ resourceArn, format }) => {
      try {
        const tags = await client.rdsListTagsForResource(resourceArn);
        return formatResponse(
          { items: tags, count: tags.length, hasMore: false },
          format,
          'rds_tags'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Restore DB Instance From Snapshot
  // ===========================================================================
  server.tool(
    'aws_rds_restore_db_instance_from_db_snapshot',
    `Restore an RDS instance from a snapshot.

Args:
  - dbInstanceIdentifier: The new DB instance identifier (required)
  - dbSnapshotIdentifier: The source snapshot identifier (required)
  - dbInstanceClass: The instance class (optional, uses snapshot setting if not specified)

Returns the new instance details.`,
    {
      dbInstanceIdentifier: z.string().describe('New DB instance identifier'),
      dbSnapshotIdentifier: z.string().describe('Source snapshot identifier'),
      dbInstanceClass: z.string().optional().describe('Instance class'),
    },
    async ({ dbInstanceIdentifier, dbSnapshotIdentifier, dbInstanceClass }) => {
      try {
        const instance = await client.rdsRestoreDBInstanceFromDBSnapshot(dbInstanceIdentifier, dbSnapshotIdentifier, dbInstanceClass);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Instance restore initiated',
                  dbInstanceIdentifier: instance.dbInstanceIdentifier,
                  dbInstanceStatus: instance.dbInstanceStatus,
                  engine: instance.engine,
                  dbInstanceClass: instance.dbInstanceClass,
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
  // Copy DB Snapshot
  // ===========================================================================
  server.tool(
    'aws_rds_copy_db_snapshot',
    `Copy an RDS database snapshot.

Args:
  - sourceSnapshotIdentifier: The source snapshot identifier (required)
  - targetSnapshotIdentifier: The target snapshot name (required)

Returns the new snapshot details.`,
    {
      sourceSnapshotIdentifier: z.string().describe('Source snapshot identifier'),
      targetSnapshotIdentifier: z.string().describe('Target snapshot name'),
    },
    async ({ sourceSnapshotIdentifier, targetSnapshotIdentifier }) => {
      try {
        const snapshot = await client.rdsCopyDBSnapshot(sourceSnapshotIdentifier, targetSnapshotIdentifier);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Snapshot copy initiated',
                  dbSnapshotIdentifier: snapshot.dbSnapshotIdentifier,
                  status: snapshot.status,
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
