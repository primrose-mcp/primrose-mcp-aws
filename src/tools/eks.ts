/**
 * EKS Tools
 *
 * MCP tools for Amazon EKS (Elastic Kubernetes Service) operations.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { AwsClient } from '../client.js';
import { formatError, formatResponse } from '../utils/formatters.js';

export function registerEKSTools(server: McpServer, client: AwsClient): void {
  // ===========================================================================
  // List Clusters
  // ===========================================================================
  server.tool(
    'aws_eks_list_clusters',
    `List all EKS clusters in the region.

Returns cluster names. Use describe_cluster for details.`,
    {
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ format }) => {
      try {
        const clusters = await client.eksListClusters();
        return formatResponse(
          { items: clusters.map((c) => ({ clusterName: c })), count: clusters.length, hasMore: false },
          format,
          'eks_clusters'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Describe Cluster
  // ===========================================================================
  server.tool(
    'aws_eks_describe_cluster',
    `Get detailed information about an EKS cluster.

Args:
  - name: The cluster name (required)

Returns cluster configuration including endpoint, version, and VPC settings.`,
    {
      name: z.string().describe('EKS cluster name'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ name, format }) => {
      try {
        const cluster = await client.eksDescribeCluster(name);
        return formatResponse(cluster, format, 'eks_cluster');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // List Nodegroups
  // ===========================================================================
  server.tool(
    'aws_eks_list_nodegroups',
    `List all node groups in an EKS cluster.

Args:
  - clusterName: The cluster name (required)

Returns node group names.`,
    {
      clusterName: z.string().describe('EKS cluster name'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ clusterName, format }) => {
      try {
        const nodegroups = await client.eksListNodegroups(clusterName);
        return formatResponse(
          { items: nodegroups.map((n) => ({ nodegroupName: n })), count: nodegroups.length, hasMore: false },
          format,
          'eks_nodegroups'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Describe Nodegroup
  // ===========================================================================
  server.tool(
    'aws_eks_describe_nodegroup',
    `Get detailed information about an EKS node group.

Args:
  - clusterName: The cluster name (required)
  - nodegroupName: The node group name (required)

Returns node group configuration including scaling settings and instance types.`,
    {
      clusterName: z.string().describe('EKS cluster name'),
      nodegroupName: z.string().describe('Node group name'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ clusterName, nodegroupName, format }) => {
      try {
        const nodegroup = await client.eksDescribeNodegroup(clusterName, nodegroupName);
        return formatResponse(nodegroup, format, 'eks_nodegroup');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // List Fargate Profiles
  // ===========================================================================
  server.tool(
    'aws_eks_list_fargate_profiles',
    `List all Fargate profiles in an EKS cluster.

Args:
  - clusterName: The cluster name (required)

Returns Fargate profile names.`,
    {
      clusterName: z.string().describe('EKS cluster name'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ clusterName, format }) => {
      try {
        const profiles = await client.eksListFargateProfiles(clusterName);
        return formatResponse(
          { items: profiles.map((p) => ({ fargateProfileName: p })), count: profiles.length, hasMore: false },
          format,
          'eks_fargate_profiles'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Describe Fargate Profile
  // ===========================================================================
  server.tool(
    'aws_eks_describe_fargate_profile',
    `Get detailed information about an EKS Fargate profile.

Args:
  - clusterName: The cluster name (required)
  - fargateProfileName: The Fargate profile name (required)

Returns Fargate profile configuration including selectors and subnets.`,
    {
      clusterName: z.string().describe('EKS cluster name'),
      fargateProfileName: z.string().describe('Fargate profile name'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ clusterName, fargateProfileName, format }) => {
      try {
        const profile = await client.eksDescribeFargateProfile(clusterName, fargateProfileName);
        return formatResponse(profile, format, 'eks_fargate_profile');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // List Addons
  // ===========================================================================
  server.tool(
    'aws_eks_list_addons',
    `List all addons in an EKS cluster.

Args:
  - clusterName: The cluster name (required)

Returns addon names. Use describe_addon for details.`,
    {
      clusterName: z.string().describe('EKS cluster name'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ clusterName, format }) => {
      try {
        const addons = await client.eksListAddons(clusterName);
        return formatResponse(
          { items: addons.map((a) => ({ addonName: a })), count: addons.length, hasMore: false },
          format,
          'eks_addons'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Describe Addon
  // ===========================================================================
  server.tool(
    'aws_eks_describe_addon',
    `Get detailed information about an EKS addon.

Args:
  - clusterName: The cluster name (required)
  - addonName: The addon name (required)

Returns addon configuration including version, status, and health.`,
    {
      clusterName: z.string().describe('EKS cluster name'),
      addonName: z.string().describe('Addon name (e.g., vpc-cni, coredns, kube-proxy)'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ clusterName, addonName, format }) => {
      try {
        const addon = await client.eksDescribeAddon(clusterName, addonName);
        return formatResponse(addon, format, 'eks_addon');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // List Identity Provider Configs
  // ===========================================================================
  server.tool(
    'aws_eks_list_identity_provider_configs',
    `List all identity provider configurations in an EKS cluster.

Args:
  - clusterName: The cluster name (required)

Returns identity provider config names and types.`,
    {
      clusterName: z.string().describe('EKS cluster name'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ clusterName, format }) => {
      try {
        const configs = await client.eksListIdentityProviderConfigs(clusterName);
        return formatResponse(
          { items: configs, count: configs.length, hasMore: false },
          format,
          'eks_identity_provider_configs'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Describe Identity Provider Config
  // ===========================================================================
  server.tool(
    'aws_eks_describe_identity_provider_config',
    `Get detailed information about an EKS identity provider configuration.

Args:
  - clusterName: The cluster name (required)
  - type: The identity provider type (e.g., 'oidc') (required)
  - name: The identity provider config name (required)

Returns identity provider config details including OIDC settings.`,
    {
      clusterName: z.string().describe('EKS cluster name'),
      type: z.string().describe('Identity provider type (e.g., oidc)'),
      name: z.string().describe('Identity provider config name'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ clusterName, type, name, format }) => {
      try {
        const config = await client.eksDescribeIdentityProviderConfig(clusterName, type, name);
        return formatResponse(config, format, 'eks_identity_provider_config');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Update Nodegroup Config
  // ===========================================================================
  server.tool(
    'aws_eks_update_nodegroup_config',
    `Update the configuration of an EKS node group.

Args:
  - clusterName: The cluster name (required)
  - nodegroupName: The node group name (required)
  - scalingConfig: Scaling configuration (optional)
    - minSize: Minimum number of nodes
    - maxSize: Maximum number of nodes
    - desiredSize: Desired number of nodes

Returns the update ID and status.`,
    {
      clusterName: z.string().describe('EKS cluster name'),
      nodegroupName: z.string().describe('Node group name'),
      scalingConfig: z.object({
        minSize: z.number().int().min(0).optional().describe('Minimum node count'),
        maxSize: z.number().int().min(1).optional().describe('Maximum node count'),
        desiredSize: z.number().int().min(0).optional().describe('Desired node count'),
      }).optional().describe('Scaling configuration'),
    },
    async ({ clusterName, nodegroupName, scalingConfig }) => {
      try {
        const result = await client.eksUpdateNodegroupConfig(clusterName, nodegroupName, scalingConfig);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Nodegroup update initiated',
                  clusterName,
                  nodegroupName,
                  updateId: result.updateId,
                  status: result.status,
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
    'aws_eks_tag_resource',
    `Add tags to an EKS resource.

Args:
  - resourceArn: The ARN of the EKS resource (required)
  - tags: Tags to add as key-value pairs (required)

Returns confirmation.`,
    {
      resourceArn: z.string().describe('EKS resource ARN'),
      tags: z.record(z.string(), z.string()).describe('Tags to add'),
    },
    async ({ resourceArn, tags }) => {
      try {
        await client.eksTagResource(resourceArn, tags as Record<string, string>);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Resource tagged',
                  resourceArn,
                  tagsCount: Object.keys(tags).length,
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
    'aws_eks_untag_resource',
    `Remove tags from an EKS resource.

Args:
  - resourceArn: The ARN of the EKS resource (required)
  - tagKeys: Array of tag keys to remove (required)

Returns confirmation.`,
    {
      resourceArn: z.string().describe('EKS resource ARN'),
      tagKeys: z.array(z.string()).min(1).describe('Tag keys to remove'),
    },
    async ({ resourceArn, tagKeys }) => {
      try {
        await client.eksUntagResource(resourceArn, tagKeys);
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
  // List Updates
  // ===========================================================================
  server.tool(
    'aws_eks_list_updates',
    `List updates for an EKS cluster, nodegroup, or addon.

Args:
  - clusterName: The cluster name (required)
  - nodegroupName: Filter updates for a specific nodegroup (optional)
  - addonName: Filter updates for a specific addon (optional)

Returns update IDs.`,
    {
      clusterName: z.string().describe('EKS cluster name'),
      nodegroupName: z.string().optional().describe('Node group name filter'),
      addonName: z.string().optional().describe('Addon name filter'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ clusterName, nodegroupName, addonName, format }) => {
      try {
        const updates = await client.eksListUpdates(clusterName, nodegroupName, addonName);
        return formatResponse(
          { items: updates.map((id) => ({ updateId: id })), count: updates.length, hasMore: false },
          format,
          'eks_updates'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Describe Update
  // ===========================================================================
  server.tool(
    'aws_eks_describe_update',
    `Get details of an EKS update.

Args:
  - clusterName: The cluster name (required)
  - updateId: The update ID (required)
  - nodegroupName: If this was a nodegroup update (optional)
  - addonName: If this was an addon update (optional)

Returns update details including status and errors.`,
    {
      clusterName: z.string().describe('EKS cluster name'),
      updateId: z.string().describe('Update ID'),
      nodegroupName: z.string().optional().describe('Node group name'),
      addonName: z.string().optional().describe('Addon name'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ clusterName, updateId, nodegroupName, addonName, format }) => {
      try {
        const update = await client.eksDescribeUpdate(clusterName, updateId, nodegroupName, addonName);
        return formatResponse(update, format, 'eks_update');
      } catch (error) {
        return formatError(error);
      }
    }
  );
}
