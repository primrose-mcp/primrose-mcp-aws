/**
 * ECS Tools
 *
 * MCP tools for Amazon ECS container operations.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { AwsClient } from '../client.js';
import { formatError, formatResponse } from '../utils/formatters.js';

export function registerECSTools(server: McpServer, client: AwsClient): void {
  // ===========================================================================
  // List Clusters
  // ===========================================================================
  server.tool(
    'aws_ecs_list_clusters',
    `List all ECS clusters in the region.

Returns cluster ARNs. Use describe_clusters for details.`,
    {
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ format }) => {
      try {
        const clusters = await client.ecsListClusters();
        return formatResponse(
          { items: clusters.map((c) => ({ clusterArn: c })), count: clusters.length, hasMore: false },
          format,
          'ecs_clusters'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Describe Clusters
  // ===========================================================================
  server.tool(
    'aws_ecs_describe_clusters',
    `Get details of ECS clusters.

Args:
  - clusterArns: Array of cluster ARNs (required)

Returns cluster details including running tasks and services.`,
    {
      clusterArns: z.array(z.string()).min(1).describe('Cluster ARNs'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ clusterArns, format }) => {
      try {
        const clusters = await client.ecsDescribeClusters(clusterArns);
        return formatResponse(
          { items: clusters, count: clusters.length, hasMore: false },
          format,
          'ecs_clusters'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // List Services
  // ===========================================================================
  server.tool(
    'aws_ecs_list_services',
    `List services in an ECS cluster.

Args:
  - clusterArn: The cluster ARN (required)

Returns service ARNs.`,
    {
      clusterArn: z.string().describe('Cluster ARN'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ clusterArn, format }) => {
      try {
        const services = await client.ecsListServices(clusterArn);
        return formatResponse(
          { items: services.map((s) => ({ serviceArn: s })), count: services.length, hasMore: false },
          format,
          'ecs_services'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Describe Services
  // ===========================================================================
  server.tool(
    'aws_ecs_describe_services',
    `Get details of ECS services.

Args:
  - clusterArn: The cluster ARN (required)
  - serviceArns: Array of service ARNs (required)

Returns service configuration including desired and running counts.`,
    {
      clusterArn: z.string().describe('Cluster ARN'),
      serviceArns: z.array(z.string()).min(1).describe('Service ARNs'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ clusterArn, serviceArns, format }) => {
      try {
        const services = await client.ecsDescribeServices(clusterArn, serviceArns);
        return formatResponse(
          { items: services, count: services.length, hasMore: false },
          format,
          'ecs_services'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // List Tasks
  // ===========================================================================
  server.tool(
    'aws_ecs_list_tasks',
    `List tasks in an ECS cluster.

Args:
  - clusterArn: The cluster ARN (required)
  - serviceName: Filter by service name (optional)

Returns task ARNs.`,
    {
      clusterArn: z.string().describe('Cluster ARN'),
      serviceName: z.string().optional().describe('Filter by service name'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ clusterArn, serviceName, format }) => {
      try {
        const tasks = await client.ecsListTasks(clusterArn, serviceName);
        return formatResponse(
          { items: tasks.map((t) => ({ taskArn: t })), count: tasks.length, hasMore: false },
          format,
          'ecs_tasks'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Describe Tasks
  // ===========================================================================
  server.tool(
    'aws_ecs_describe_tasks',
    `Get details of ECS tasks.

Args:
  - clusterArn: The cluster ARN (required)
  - taskArns: Array of task ARNs (required)

Returns task details including status and containers.`,
    {
      clusterArn: z.string().describe('Cluster ARN'),
      taskArns: z.array(z.string()).min(1).describe('Task ARNs'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ clusterArn, taskArns, format }) => {
      try {
        const tasks = await client.ecsDescribeTasks(clusterArn, taskArns);
        return formatResponse(
          { items: tasks, count: tasks.length, hasMore: false },
          format,
          'ecs_tasks'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Describe Task Definition
  // ===========================================================================
  server.tool(
    'aws_ecs_describe_task_definition',
    `Get details of an ECS task definition.

Args:
  - taskDefinition: Task definition family:revision or ARN (required)

Returns task definition including container definitions.`,
    {
      taskDefinition: z.string().describe('Task definition family:revision or ARN'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ taskDefinition, format }) => {
      try {
        const td = await client.ecsDescribeTaskDefinition(taskDefinition);
        return formatResponse(td, format, 'ecs_task_definition');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // List Task Definitions
  // ===========================================================================
  server.tool(
    'aws_ecs_list_task_definitions',
    `List ECS task definition ARNs.

Args:
  - familyPrefix: Filter by task definition family prefix (optional)

Returns task definition ARNs.`,
    {
      familyPrefix: z.string().optional().describe('Family prefix filter'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ familyPrefix, format }) => {
      try {
        const taskDefinitions = await client.ecsListTaskDefinitions(familyPrefix);
        return formatResponse(
          { items: taskDefinitions.map((arn) => ({ taskDefinitionArn: arn })), count: taskDefinitions.length, hasMore: false },
          format,
          'ecs_task_definitions'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Update Service
  // ===========================================================================
  server.tool(
    'aws_ecs_update_service',
    `Update an ECS service.

Args:
  - clusterArn: The cluster ARN (required)
  - serviceName: The service name (required)
  - desiredCount: New desired count (optional)
  - taskDefinition: New task definition (optional)
  - forceNewDeployment: Force a new deployment (optional)

Returns the updated service details.`,
    {
      clusterArn: z.string().describe('Cluster ARN'),
      serviceName: z.string().describe('Service name'),
      desiredCount: z.number().int().min(0).optional().describe('Desired task count'),
      taskDefinition: z.string().optional().describe('New task definition'),
      forceNewDeployment: z.boolean().default(false).describe('Force new deployment'),
    },
    async ({ clusterArn, serviceName, desiredCount, taskDefinition, forceNewDeployment }) => {
      try {
        const service = await client.ecsUpdateService(clusterArn, serviceName, {
          desiredCount,
          taskDefinition,
          forceNewDeployment,
        });
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Service updated',
                  serviceArn: service.serviceArn,
                  serviceName: service.serviceName,
                  desiredCount: service.desiredCount,
                  runningCount: service.runningCount,
                  taskDefinition: service.taskDefinition,
                  status: service.status,
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
  // Run Task
  // ===========================================================================
  server.tool(
    'aws_ecs_run_task',
    `Run a new task in an ECS cluster.

Args:
  - clusterArn: The cluster ARN (required)
  - taskDefinition: The task definition family:revision or ARN (required)
  - count: Number of tasks to run (optional, default: 1)
  - launchType: Launch type - 'EC2' or 'FARGATE' (optional)
  - networkConfiguration: Network configuration for FARGATE (optional)

Returns the started task details.`,
    {
      clusterArn: z.string().describe('Cluster ARN'),
      taskDefinition: z.string().describe('Task definition family:revision or ARN'),
      count: z.number().int().min(1).max(10).optional().describe('Number of tasks to run'),
      launchType: z.enum(['EC2', 'FARGATE']).optional().describe('Launch type'),
      networkConfiguration: z.object({
        awsvpcConfiguration: z.object({
          subnets: z.array(z.string()).describe('Subnet IDs'),
          securityGroups: z.array(z.string()).optional().describe('Security group IDs'),
          assignPublicIp: z.enum(['ENABLED', 'DISABLED']).optional().describe('Assign public IP'),
        }).optional(),
      }).optional().describe('Network configuration (required for FARGATE)'),
    },
    async ({ clusterArn, taskDefinition, count, launchType, networkConfiguration }) => {
      try {
        const tasks = await client.ecsRunTask(clusterArn, taskDefinition, {
          count,
          launchType,
          networkConfiguration,
        });
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Started ${tasks.length} task(s)`,
                  tasks: tasks.map((t) => ({
                    taskArn: t.taskArn,
                    lastStatus: t.lastStatus,
                    desiredStatus: t.desiredStatus,
                    launchType: t.launchType,
                  })),
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
  // Stop Task
  // ===========================================================================
  server.tool(
    'aws_ecs_stop_task',
    `Stop a running ECS task.

Args:
  - clusterArn: The cluster ARN (required)
  - taskArn: The task ARN (required)
  - reason: Reason for stopping (optional)

Returns the stopped task details.`,
    {
      clusterArn: z.string().describe('Cluster ARN'),
      taskArn: z.string().describe('Task ARN'),
      reason: z.string().optional().describe('Reason for stopping'),
    },
    async ({ clusterArn, taskArn, reason }) => {
      try {
        const task = await client.ecsStopTask(clusterArn, taskArn, reason);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Task stopped',
                  taskArn: task.taskArn,
                  lastStatus: task.lastStatus,
                  desiredStatus: task.desiredStatus,
                  stoppedReason: task.stoppedReason,
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
  // Delete Service
  // ===========================================================================
  server.tool(
    'aws_ecs_delete_service',
    `Delete an ECS service.

Args:
  - clusterArn: The cluster ARN (required)
  - serviceName: The service name (required)
  - force: Force delete even if service has running tasks (optional)

Note: Before deleting, you should typically scale the service to 0 first,
or use force=true to delete a service with running tasks.

Returns the deleted service details.`,
    {
      clusterArn: z.string().describe('Cluster ARN'),
      serviceName: z.string().describe('Service name'),
      force: z.boolean().optional().describe('Force delete with running tasks'),
    },
    async ({ clusterArn, serviceName, force }) => {
      try {
        const service = await client.ecsDeleteService(clusterArn, serviceName, force);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Service deletion initiated',
                  serviceName: service.serviceName,
                  serviceArn: service.serviceArn,
                  status: service.status,
                  desiredCount: service.desiredCount,
                  runningCount: service.runningCount,
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
  // Deregister Task Definition
  // ===========================================================================
  server.tool(
    'aws_ecs_deregister_task_definition',
    `Deregister an ECS task definition.

Args:
  - taskDefinition: The task definition ARN or family:revision (required)

Deregistered task definitions can no longer be used to run new tasks,
but existing tasks using this definition will continue to run.

Returns the deregistered task definition details.`,
    {
      taskDefinition: z.string().describe('Task definition ARN or family:revision'),
    },
    async ({ taskDefinition }) => {
      try {
        const td = await client.ecsDeregisterTaskDefinition(taskDefinition);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Task definition deregistered',
                  taskDefinitionArn: td.taskDefinitionArn,
                  family: td.family,
                  revision: td.revision,
                  status: td.status,
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
  // List Container Instances
  // ===========================================================================
  server.tool(
    'aws_ecs_list_container_instances',
    `List container instances in an ECS cluster.

Args:
  - clusterArn: The cluster ARN (required)

Returns container instance ARNs.`,
    {
      clusterArn: z.string().describe('Cluster ARN'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ clusterArn, format }) => {
      try {
        const instances = await client.ecsListContainerInstances(clusterArn);
        return formatResponse(
          { items: instances.map((arn) => ({ containerInstanceArn: arn })), count: instances.length, hasMore: false },
          format,
          'ecs_container_instances'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Describe Container Instances
  // ===========================================================================
  server.tool(
    'aws_ecs_describe_container_instances',
    `Get details of ECS container instances.

Args:
  - clusterArn: The cluster ARN (required)
  - containerInstanceArns: Array of container instance ARNs (required)

Returns container instance details including EC2 instance ID and task counts.`,
    {
      clusterArn: z.string().describe('Cluster ARN'),
      containerInstanceArns: z.array(z.string()).min(1).describe('Container instance ARNs'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ clusterArn, containerInstanceArns, format }) => {
      try {
        const instances = await client.ecsDescribeContainerInstances(clusterArn, containerInstanceArns);
        return formatResponse(
          { items: instances, count: instances.length, hasMore: false },
          format,
          'ecs_container_instances'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Create Cluster
  // ===========================================================================
  server.tool(
    'aws_ecs_create_cluster',
    `Create a new ECS cluster.

Args:
  - clusterName: The name for the new cluster (required)

Returns the created cluster details.`,
    {
      clusterName: z.string().describe('Cluster name'),
    },
    async ({ clusterName }) => {
      try {
        const cluster = await client.ecsCreateCluster(clusterName);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Cluster created',
                  clusterArn: cluster.clusterArn,
                  clusterName: cluster.clusterName,
                  status: cluster.status,
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
  // Delete Cluster
  // ===========================================================================
  server.tool(
    'aws_ecs_delete_cluster',
    `Delete an ECS cluster.

Args:
  - clusterArn: The cluster ARN (required)

Note: The cluster must not have any services or tasks running.

Returns the deleted cluster details.`,
    {
      clusterArn: z.string().describe('Cluster ARN'),
    },
    async ({ clusterArn }) => {
      try {
        const cluster = await client.ecsDeleteCluster(clusterArn);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Cluster deleted',
                  clusterArn: cluster.clusterArn,
                  clusterName: cluster.clusterName,
                  status: cluster.status,
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
  // Create Service
  // ===========================================================================
  server.tool(
    'aws_ecs_create_service',
    `Create a new ECS service.

Args:
  - clusterArn: The cluster ARN (required)
  - serviceName: The service name (required)
  - taskDefinition: The task definition (required)
  - desiredCount: Number of tasks to run (required)
  - launchType: Launch type - 'EC2' or 'FARGATE' (optional)
  - networkConfiguration: Network configuration for FARGATE (optional)

Returns the created service details.`,
    {
      clusterArn: z.string().describe('Cluster ARN'),
      serviceName: z.string().describe('Service name'),
      taskDefinition: z.string().describe('Task definition family:revision or ARN'),
      desiredCount: z.number().int().min(0).describe('Desired task count'),
      launchType: z.enum(['EC2', 'FARGATE']).optional().describe('Launch type'),
      networkConfiguration: z.object({
        awsvpcConfiguration: z.object({
          subnets: z.array(z.string()).describe('Subnet IDs'),
          securityGroups: z.array(z.string()).optional().describe('Security group IDs'),
          assignPublicIp: z.enum(['ENABLED', 'DISABLED']).optional().describe('Assign public IP'),
        }).optional(),
      }).optional().describe('Network configuration (required for FARGATE)'),
    },
    async ({ clusterArn, serviceName, taskDefinition, desiredCount, launchType, networkConfiguration }) => {
      try {
        const service = await client.ecsCreateService(clusterArn, serviceName, taskDefinition, desiredCount, launchType, networkConfiguration);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Service created',
                  serviceArn: service.serviceArn,
                  serviceName: service.serviceName,
                  desiredCount: service.desiredCount,
                  status: service.status,
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
    'aws_ecs_tag_resource',
    `Add tags to an ECS resource.

Args:
  - resourceArn: The ARN of the ECS resource (required)
  - tags: Array of tags to add (required)

Returns confirmation.`,
    {
      resourceArn: z.string().describe('ECS resource ARN'),
      tags: z.array(z.object({
        key: z.string().describe('Tag key'),
        value: z.string().describe('Tag value'),
      })).min(1).describe('Tags to add'),
    },
    async ({ resourceArn, tags }) => {
      try {
        await client.ecsTagResource(resourceArn, tags);
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
    'aws_ecs_untag_resource',
    `Remove tags from an ECS resource.

Args:
  - resourceArn: The ARN of the ECS resource (required)
  - tagKeys: Array of tag keys to remove (required)

Returns confirmation.`,
    {
      resourceArn: z.string().describe('ECS resource ARN'),
      tagKeys: z.array(z.string()).min(1).describe('Tag keys to remove'),
    },
    async ({ resourceArn, tagKeys }) => {
      try {
        await client.ecsUntagResource(resourceArn, tagKeys);
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
  // List Tags For Resource
  // ===========================================================================
  server.tool(
    'aws_ecs_list_tags_for_resource',
    `List tags on an ECS resource.

Args:
  - resourceArn: The ARN of the ECS resource (required)

Returns the resource tags.`,
    {
      resourceArn: z.string().describe('ECS resource ARN'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ resourceArn, format }) => {
      try {
        const tags = await client.ecsListTagsForResource(resourceArn);
        return formatResponse(
          { items: tags, count: tags.length, hasMore: false },
          format,
          'ecs_tags'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // List Task Definition Families
  // ===========================================================================
  server.tool(
    'aws_ecs_list_task_definition_families',
    `List ECS task definition families.

Args:
  - familyPrefix: Filter by family prefix (optional)

Returns task definition family names.`,
    {
      familyPrefix: z.string().optional().describe('Family prefix filter'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ familyPrefix, format }) => {
      try {
        const families = await client.ecsListTaskDefinitionFamilies(familyPrefix);
        return formatResponse(
          { items: families.map((f) => ({ family: f })), count: families.length, hasMore: false },
          format,
          'ecs_task_definition_families'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Update Container Instances State
  // ===========================================================================
  server.tool(
    'aws_ecs_update_container_instances_state',
    `Update the state of ECS container instances.

Args:
  - clusterArn: The cluster ARN (required)
  - containerInstanceArns: Array of container instance ARNs (required)
  - status: New status - 'ACTIVE' or 'DRAINING' (required)

Use DRAINING to stop new tasks from being placed on the instances.

Returns the updated container instance details.`,
    {
      clusterArn: z.string().describe('Cluster ARN'),
      containerInstanceArns: z.array(z.string()).min(1).describe('Container instance ARNs'),
      status: z.enum(['ACTIVE', 'DRAINING']).describe('New status'),
    },
    async ({ clusterArn, containerInstanceArns, status }) => {
      try {
        const instances = await client.ecsUpdateContainerInstancesState(clusterArn, containerInstanceArns, status);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Container instances updated to ${status}`,
                  instances: instances,
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
