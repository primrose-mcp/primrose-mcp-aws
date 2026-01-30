/**
 * EC2 Tools
 *
 * MCP tools for Amazon EC2 operations.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { AwsClient } from '../client.js';
import { formatError, formatResponse } from '../utils/formatters.js';

export function registerEC2Tools(server: McpServer, client: AwsClient): void {
  // ===========================================================================
  // Describe Instances
  // ===========================================================================
  server.tool(
    'aws_ec2_describe_instances',
    `List EC2 instances with optional filtering.

Args:
  - instanceIds: Array of instance IDs to filter by
  - filters: Array of filters with name and values

Returns list of instances with ID, type, state, IPs, and tags.`,
    {
      instanceIds: z.array(z.string()).optional().describe('Filter by instance IDs'),
      filters: z
        .array(
          z.object({
            name: z.string(),
            values: z.array(z.string()),
          })
        )
        .optional()
        .describe('Filters (e.g., [{name: "instance-state-name", values: ["running"]}])'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ instanceIds, filters, format }) => {
      try {
        const instances = await client.ec2DescribeInstances({ instanceIds, filters });
        return formatResponse(
          { items: instances, count: instances.length, hasMore: false },
          format,
          'ec2_instances'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Describe Security Groups
  // ===========================================================================
  server.tool(
    'aws_ec2_describe_security_groups',
    `List EC2 security groups.

Args:
  - groupIds: Array of security group IDs to filter by

Returns security groups with their inbound/outbound rules.`,
    {
      groupIds: z.array(z.string()).optional().describe('Filter by security group IDs'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ groupIds, format }) => {
      try {
        const groups = await client.ec2DescribeSecurityGroups(groupIds);
        return formatResponse(
          { items: groups, count: groups.length, hasMore: false },
          format,
          'ec2_security_groups'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Describe Volumes
  // ===========================================================================
  server.tool(
    'aws_ec2_describe_volumes',
    `List EBS volumes.

Args:
  - volumeIds: Array of volume IDs to filter by

Returns volumes with size, type, state, and attachments.`,
    {
      volumeIds: z.array(z.string()).optional().describe('Filter by volume IDs'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ volumeIds, format }) => {
      try {
        const volumes = await client.ec2DescribeVolumes(volumeIds);
        return formatResponse(
          { items: volumes, count: volumes.length, hasMore: false },
          format,
          'ec2_volumes'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Describe VPCs
  // ===========================================================================
  server.tool(
    'aws_ec2_describe_vpcs',
    `List VPCs in the region.

Args:
  - vpcIds: Array of VPC IDs to filter by

Returns VPCs with CIDR blocks and configuration.`,
    {
      vpcIds: z.array(z.string()).optional().describe('Filter by VPC IDs'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ vpcIds, format }) => {
      try {
        const vpcs = await client.ec2DescribeVpcs(vpcIds);
        return formatResponse(
          { items: vpcs, count: vpcs.length, hasMore: false },
          format,
          'vpcs'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Describe Subnets
  // ===========================================================================
  server.tool(
    'aws_ec2_describe_subnets',
    `List subnets in the region.

Args:
  - subnetIds: Array of subnet IDs to filter by

Returns subnets with CIDR blocks, AZ, and available IPs.`,
    {
      subnetIds: z.array(z.string()).optional().describe('Filter by subnet IDs'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ subnetIds, format }) => {
      try {
        const subnets = await client.ec2DescribeSubnets(subnetIds);
        return formatResponse(
          { items: subnets, count: subnets.length, hasMore: false },
          format,
          'subnets'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Describe Images (AMIs)
  // ===========================================================================
  server.tool(
    'aws_ec2_describe_images',
    `List AMI images.

Args:
  - imageIds: Array of AMI IDs to filter by
  - owners: Array of owner IDs (e.g., ['self', 'amazon', '123456789012'])

Returns AMIs with name, architecture, and platform info.`,
    {
      imageIds: z.array(z.string()).optional().describe('Filter by AMI IDs'),
      owners: z.array(z.string()).optional().describe("Owner IDs (e.g., 'self', 'amazon')"),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ imageIds, owners, format }) => {
      try {
        const images = await client.ec2DescribeImages({ imageIds, owners });
        return formatResponse(
          { items: images, count: images.length, hasMore: false },
          format,
          'amis'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Describe Key Pairs
  // ===========================================================================
  server.tool(
    'aws_ec2_describe_key_pairs',
    `List EC2 key pairs for SSH access.

Returns all key pairs with names and fingerprints.`,
    {
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ format }) => {
      try {
        const keyPairs = await client.ec2DescribeKeyPairs();
        return formatResponse(
          { items: keyPairs, count: keyPairs.length, hasMore: false },
          format,
          'key_pairs'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Start Instances
  // ===========================================================================
  server.tool(
    'aws_ec2_start_instances',
    `Start one or more stopped EC2 instances.

Args:
  - instanceIds: Array of instance IDs to start (required)

Returns confirmation of the start operation.`,
    {
      instanceIds: z.array(z.string()).min(1).describe('Instance IDs to start'),
    },
    async ({ instanceIds }) => {
      try {
        await client.ec2StartInstances(instanceIds);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Starting instances: ${instanceIds.join(', ')}`,
                  instanceIds,
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
  // Stop Instances
  // ===========================================================================
  server.tool(
    'aws_ec2_stop_instances',
    `Stop one or more running EC2 instances.

Args:
  - instanceIds: Array of instance IDs to stop (required)

Returns confirmation of the stop operation.`,
    {
      instanceIds: z.array(z.string()).min(1).describe('Instance IDs to stop'),
    },
    async ({ instanceIds }) => {
      try {
        await client.ec2StopInstances(instanceIds);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Stopping instances: ${instanceIds.join(', ')}`,
                  instanceIds,
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
  // Reboot Instances
  // ===========================================================================
  server.tool(
    'aws_ec2_reboot_instances',
    `Reboot one or more EC2 instances.

Args:
  - instanceIds: Array of instance IDs to reboot (required)

Returns confirmation of the reboot operation.`,
    {
      instanceIds: z.array(z.string()).min(1).describe('Instance IDs to reboot'),
    },
    async ({ instanceIds }) => {
      try {
        await client.ec2RebootInstances(instanceIds);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Rebooting instances: ${instanceIds.join(', ')}`,
                  instanceIds,
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
  // Terminate Instances
  // ===========================================================================
  server.tool(
    'aws_ec2_terminate_instances',
    `Terminate (permanently delete) one or more EC2 instances.

WARNING: This action is irreversible. The instances and their data will be permanently deleted.

Args:
  - instanceIds: Array of instance IDs to terminate (required)

Returns confirmation of the termination.`,
    {
      instanceIds: z.array(z.string()).min(1).describe('Instance IDs to terminate'),
    },
    async ({ instanceIds }) => {
      try {
        await client.ec2TerminateInstances(instanceIds);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Terminating instances: ${instanceIds.join(', ')}`,
                  warning: 'This action is irreversible',
                  instanceIds,
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
  // Describe Snapshots
  // ===========================================================================
  server.tool(
    'aws_ec2_describe_snapshots',
    `List EBS snapshots.

Args:
  - snapshotIds: Array of snapshot IDs to filter by
  - ownerIds: Array of owner IDs (default: 'self')

Returns list of snapshots with ID, volume, state, and size.`,
    {
      snapshotIds: z.array(z.string()).optional().describe('Filter by snapshot IDs'),
      ownerIds: z.array(z.string()).optional().describe('Filter by owner IDs'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ snapshotIds, ownerIds, format }) => {
      try {
        const snapshots = await client.ec2DescribeSnapshots({ snapshotIds, ownerIds });
        return formatResponse(
          { items: snapshots, count: snapshots.length, hasMore: false },
          format,
          'ec2_snapshots'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Describe NAT Gateways
  // ===========================================================================
  server.tool(
    'aws_ec2_describe_nat_gateways',
    `List NAT gateways.

Args:
  - natGatewayIds: Array of NAT gateway IDs to filter by

Returns list of NAT gateways with state, VPC, subnet, and addresses.`,
    {
      natGatewayIds: z.array(z.string()).optional().describe('Filter by NAT gateway IDs'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ natGatewayIds, format }) => {
      try {
        const gateways = await client.ec2DescribeNatGateways(natGatewayIds);
        return formatResponse(
          { items: gateways, count: gateways.length, hasMore: false },
          format,
          'ec2_nat_gateways'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Describe Launch Templates
  // ===========================================================================
  server.tool(
    'aws_ec2_describe_launch_templates',
    `List EC2 launch templates.

Args:
  - launchTemplateIds: Array of launch template IDs to filter by

Returns list of launch templates with ID, name, and version info.`,
    {
      launchTemplateIds: z.array(z.string()).optional().describe('Filter by launch template IDs'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ launchTemplateIds, format }) => {
      try {
        const templates = await client.ec2DescribeLaunchTemplates(launchTemplateIds);
        return formatResponse(
          { items: templates, count: templates.length, hasMore: false },
          format,
          'ec2_launch_templates'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Describe Addresses (Elastic IPs)
  // ===========================================================================
  server.tool(
    'aws_ec2_describe_addresses',
    `List Elastic IP addresses.

Args:
  - allocationIds: Array of allocation IDs to filter by

Returns list of Elastic IPs with associations and instance info.`,
    {
      allocationIds: z.array(z.string()).optional().describe('Filter by allocation IDs'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ allocationIds, format }) => {
      try {
        const addresses = await client.ec2DescribeAddresses(allocationIds);
        return formatResponse(
          { items: addresses, count: addresses.length, hasMore: false },
          format,
          'ec2_addresses'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Describe Availability Zones
  // ===========================================================================
  server.tool(
    'aws_ec2_describe_availability_zones',
    `List availability zones in the current region.

Returns list of availability zones with state and zone type.`,
    {
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ format }) => {
      try {
        const zones = await client.ec2DescribeAvailabilityZones();
        return formatResponse(
          { items: zones, count: zones.length, hasMore: false },
          format,
          'ec2_availability_zones'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Create Security Group
  // ===========================================================================
  server.tool(
    'aws_ec2_create_security_group',
    `Create a new EC2 security group.

Args:
  - groupName: Name of the security group (required)
  - description: Description of the security group (required)
  - vpcId: VPC ID to create the group in (optional, uses default VPC if not specified)

Returns the security group ID.`,
    {
      groupName: z.string().describe('Security group name'),
      description: z.string().describe('Security group description'),
      vpcId: z.string().optional().describe('VPC ID'),
    },
    async ({ groupName, description, vpcId }) => {
      try {
        const result = await client.ec2CreateSecurityGroup(groupName, description, vpcId);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Security group '${groupName}' created`,
                  groupId: result.groupId,
                  groupName,
                  vpcId,
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
  // Delete Security Group
  // ===========================================================================
  server.tool(
    'aws_ec2_delete_security_group',
    `Delete an EC2 security group.

Args:
  - groupId: ID of the security group to delete (required)

Returns confirmation of deletion.`,
    {
      groupId: z.string().describe('Security group ID'),
    },
    async ({ groupId }) => {
      try {
        await client.ec2DeleteSecurityGroup(groupId);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Security group '${groupId}' deleted`,
                  groupId,
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
  // Authorize Security Group Ingress
  // ===========================================================================
  server.tool(
    'aws_ec2_authorize_security_group_ingress',
    `Add inbound rules to a security group.

Args:
  - groupId: Security group ID (required)
  - rules: Array of rules to add (required)

Each rule can include:
  - protocol: Protocol (tcp, udp, icmp, or -1 for all)
  - fromPort: Start of port range
  - toPort: End of port range
  - cidrIpv4: IPv4 CIDR range (e.g., '0.0.0.0/0')
  - cidrIpv6: IPv6 CIDR range
  - sourceSecurityGroupId: Source security group ID

Returns confirmation of rule addition.`,
    {
      groupId: z.string().describe('Security group ID'),
      rules: z.array(z.object({
        protocol: z.string().describe('Protocol (tcp, udp, icmp, -1)'),
        fromPort: z.number().int().optional().describe('Start port'),
        toPort: z.number().int().optional().describe('End port'),
        cidrIpv4: z.string().optional().describe('IPv4 CIDR'),
        cidrIpv6: z.string().optional().describe('IPv6 CIDR'),
        sourceSecurityGroupId: z.string().optional().describe('Source security group'),
      })).min(1).describe('Ingress rules'),
    },
    async ({ groupId, rules }) => {
      try {
        await client.ec2AuthorizeSecurityGroupIngress(groupId, rules);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Ingress rules added to security group '${groupId}'`,
                  groupId,
                  rulesCount: rules.length,
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
  // Revoke Security Group Ingress
  // ===========================================================================
  server.tool(
    'aws_ec2_revoke_security_group_ingress',
    `Remove inbound rules from a security group.

Args:
  - groupId: Security group ID (required)
  - rules: Array of rules to remove (required)

Each rule must match an existing rule exactly.

Returns confirmation of rule removal.`,
    {
      groupId: z.string().describe('Security group ID'),
      rules: z.array(z.object({
        protocol: z.string().describe('Protocol (tcp, udp, icmp, -1)'),
        fromPort: z.number().int().optional().describe('Start port'),
        toPort: z.number().int().optional().describe('End port'),
        cidrIpv4: z.string().optional().describe('IPv4 CIDR'),
        cidrIpv6: z.string().optional().describe('IPv6 CIDR'),
        sourceSecurityGroupId: z.string().optional().describe('Source security group'),
      })).min(1).describe('Ingress rules to remove'),
    },
    async ({ groupId, rules }) => {
      try {
        await client.ec2RevokeSecurityGroupIngress(groupId, rules);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Ingress rules removed from security group '${groupId}'`,
                  groupId,
                  rulesCount: rules.length,
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
  // Authorize Security Group Egress
  // ===========================================================================
  server.tool(
    'aws_ec2_authorize_security_group_egress',
    `Add outbound rules to a security group.

Args:
  - groupId: Security group ID (required)
  - rules: Array of rules to add (required)

Each rule can include:
  - protocol: Protocol (tcp, udp, icmp, or -1 for all)
  - fromPort: Start of port range
  - toPort: End of port range
  - cidrIpv4: IPv4 CIDR range
  - cidrIpv6: IPv6 CIDR range
  - sourceSecurityGroupId: Destination security group ID

Returns confirmation of rule addition.`,
    {
      groupId: z.string().describe('Security group ID'),
      rules: z.array(z.object({
        protocol: z.string().describe('Protocol (tcp, udp, icmp, -1)'),
        fromPort: z.number().int().optional().describe('Start port'),
        toPort: z.number().int().optional().describe('End port'),
        cidrIpv4: z.string().optional().describe('IPv4 CIDR'),
        cidrIpv6: z.string().optional().describe('IPv6 CIDR'),
        sourceSecurityGroupId: z.string().optional().describe('Destination security group'),
      })).min(1).describe('Egress rules'),
    },
    async ({ groupId, rules }) => {
      try {
        await client.ec2AuthorizeSecurityGroupEgress(groupId, rules);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Egress rules added to security group '${groupId}'`,
                  groupId,
                  rulesCount: rules.length,
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
  // Revoke Security Group Egress
  // ===========================================================================
  server.tool(
    'aws_ec2_revoke_security_group_egress',
    `Remove outbound rules from a security group.

Args:
  - groupId: Security group ID (required)
  - rules: Array of rules to remove (required)

Each rule must match an existing rule exactly.

Returns confirmation of rule removal.`,
    {
      groupId: z.string().describe('Security group ID'),
      rules: z.array(z.object({
        protocol: z.string().describe('Protocol (tcp, udp, icmp, -1)'),
        fromPort: z.number().int().optional().describe('Start port'),
        toPort: z.number().int().optional().describe('End port'),
        cidrIpv4: z.string().optional().describe('IPv4 CIDR'),
        cidrIpv6: z.string().optional().describe('IPv6 CIDR'),
        sourceSecurityGroupId: z.string().optional().describe('Destination security group'),
      })).min(1).describe('Egress rules to remove'),
    },
    async ({ groupId, rules }) => {
      try {
        await client.ec2RevokeSecurityGroupEgress(groupId, rules);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Egress rules removed from security group '${groupId}'`,
                  groupId,
                  rulesCount: rules.length,
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
  // Allocate Address (Elastic IP)
  // ===========================================================================
  server.tool(
    'aws_ec2_allocate_address',
    `Allocate a new Elastic IP address.

Returns the allocation ID and public IP address.`,
    {},
    async () => {
      try {
        const result = await client.ec2AllocateAddress();
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Elastic IP allocated',
                  allocationId: result.allocationId,
                  publicIp: result.publicIp,
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
  // Release Address (Elastic IP)
  // ===========================================================================
  server.tool(
    'aws_ec2_release_address',
    `Release an Elastic IP address.

Args:
  - allocationId: Allocation ID of the Elastic IP (required)

Returns confirmation of release.`,
    {
      allocationId: z.string().describe('Allocation ID'),
    },
    async ({ allocationId }) => {
      try {
        await client.ec2ReleaseAddress(allocationId);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Elastic IP released',
                  allocationId,
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
  // Associate Address (Elastic IP)
  // ===========================================================================
  server.tool(
    'aws_ec2_associate_address',
    `Associate an Elastic IP with an instance or network interface.

Args:
  - allocationId: Allocation ID of the Elastic IP (required)
  - instanceId: Instance ID to associate with (optional)
  - networkInterfaceId: Network interface ID to associate with (optional)

Either instanceId or networkInterfaceId must be provided.

Returns the association ID.`,
    {
      allocationId: z.string().describe('Allocation ID'),
      instanceId: z.string().optional().describe('Instance ID'),
      networkInterfaceId: z.string().optional().describe('Network interface ID'),
    },
    async ({ allocationId, instanceId, networkInterfaceId }) => {
      try {
        const result = await client.ec2AssociateAddress(allocationId, instanceId, networkInterfaceId);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Elastic IP associated',
                  allocationId,
                  associationId: result.associationId,
                  instanceId,
                  networkInterfaceId,
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
  // Disassociate Address (Elastic IP)
  // ===========================================================================
  server.tool(
    'aws_ec2_disassociate_address',
    `Disassociate an Elastic IP from an instance or network interface.

Args:
  - associationId: Association ID (required)

Returns confirmation of disassociation.`,
    {
      associationId: z.string().describe('Association ID'),
    },
    async ({ associationId }) => {
      try {
        await client.ec2DisassociateAddress(associationId);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Elastic IP disassociated',
                  associationId,
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
  // Create Tags
  // ===========================================================================
  server.tool(
    'aws_ec2_create_tags',
    `Add or overwrite tags on EC2 resources.

Args:
  - resourceIds: Array of resource IDs to tag (required)
  - tags: Array of tags with key and value (required)

Returns confirmation of tag creation.`,
    {
      resourceIds: z.array(z.string()).min(1).describe('Resource IDs'),
      tags: z.array(z.object({
        key: z.string().describe('Tag key'),
        value: z.string().describe('Tag value'),
      })).min(1).describe('Tags to create'),
    },
    async ({ resourceIds, tags }) => {
      try {
        await client.ec2CreateTags(resourceIds, tags);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Tags created',
                  resourceIds,
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
  // Delete Tags
  // ===========================================================================
  server.tool(
    'aws_ec2_delete_tags',
    `Delete tags from EC2 resources.

Args:
  - resourceIds: Array of resource IDs to untag (required)
  - tags: Array of tag keys to delete (required)

Returns confirmation of tag deletion.`,
    {
      resourceIds: z.array(z.string()).min(1).describe('Resource IDs'),
      tags: z.array(z.object({
        key: z.string().describe('Tag key to delete'),
      })).min(1).describe('Tags to delete'),
    },
    async ({ resourceIds, tags }) => {
      try {
        await client.ec2DeleteTags(resourceIds, tags);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Tags deleted',
                  resourceIds,
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
  // Create Volume
  // ===========================================================================
  server.tool(
    'aws_ec2_create_volume',
    `Create a new EBS volume.

Args:
  - availabilityZone: The AZ to create the volume in (required)
  - size: Size in GiB (required if not creating from snapshot)
  - snapshotId: Snapshot ID to create from (optional)
  - volumeType: gp2, gp3, io1, io2, st1, sc1, standard (default: gp2)
  - iops: IOPS for io1/io2/gp3 volumes
  - encrypted: Enable encryption (optional)
  - kmsKeyId: KMS key for encryption (optional)

Returns the created volume details.`,
    {
      availabilityZone: z.string().describe('Availability zone'),
      size: z.number().int().optional().describe('Size in GiB'),
      snapshotId: z.string().optional().describe('Snapshot ID to create from'),
      volumeType: z.enum(['gp2', 'gp3', 'io1', 'io2', 'st1', 'sc1', 'standard']).optional().describe('Volume type'),
      iops: z.number().int().optional().describe('IOPS (for io1/io2/gp3)'),
      encrypted: z.boolean().optional().describe('Enable encryption'),
      kmsKeyId: z.string().optional().describe('KMS key ID'),
    },
    async ({ availabilityZone, size, snapshotId, volumeType, iops, encrypted, kmsKeyId }) => {
      try {
        const volume = await client.ec2CreateVolume({
          availabilityZone,
          size,
          snapshotId,
          volumeType,
          iops,
          encrypted,
          kmsKeyId,
        });
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Volume created',
                  volumeId: volume.volumeId,
                  availabilityZone: volume.availabilityZone,
                  size: volume.size,
                  volumeType: volume.volumeType,
                  state: volume.state,
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
  // Delete Volume
  // ===========================================================================
  server.tool(
    'aws_ec2_delete_volume',
    `Delete an EBS volume.

WARNING: This action cannot be undone.

Args:
  - volumeId: Volume ID to delete (required)

Returns confirmation of deletion.`,
    {
      volumeId: z.string().describe('Volume ID'),
    },
    async ({ volumeId }) => {
      try {
        await client.ec2DeleteVolume(volumeId);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Volume deleted',
                  volumeId,
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
  // Attach Volume
  // ===========================================================================
  server.tool(
    'aws_ec2_attach_volume',
    `Attach an EBS volume to an EC2 instance.

Args:
  - volumeId: Volume ID to attach (required)
  - instanceId: Instance ID to attach to (required)
  - device: Device name (e.g., /dev/sdf, /dev/xvdf) (required)

Returns attachment details.`,
    {
      volumeId: z.string().describe('Volume ID'),
      instanceId: z.string().describe('Instance ID'),
      device: z.string().describe('Device name (e.g., /dev/sdf)'),
    },
    async ({ volumeId, instanceId, device }) => {
      try {
        const result = await client.ec2AttachVolume(volumeId, instanceId, device);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Volume attached',
                  volumeId: result.volumeId,
                  instanceId: result.instanceId,
                  device: result.device,
                  state: result.state,
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
  // Detach Volume
  // ===========================================================================
  server.tool(
    'aws_ec2_detach_volume',
    `Detach an EBS volume from an EC2 instance.

Args:
  - volumeId: Volume ID to detach (required)
  - force: Force detach (may cause data loss) (optional)

Returns detachment details.`,
    {
      volumeId: z.string().describe('Volume ID'),
      force: z.boolean().optional().describe('Force detach'),
    },
    async ({ volumeId, force }) => {
      try {
        const result = await client.ec2DetachVolume(volumeId, force);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Volume detaching',
                  volumeId: result.volumeId,
                  instanceId: result.instanceId,
                  device: result.device,
                  state: result.state,
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
  // Create Snapshot
  // ===========================================================================
  server.tool(
    'aws_ec2_create_snapshot',
    `Create a snapshot of an EBS volume.

Args:
  - volumeId: Volume ID to snapshot (required)
  - description: Description for the snapshot (optional)

Returns the created snapshot details.`,
    {
      volumeId: z.string().describe('Volume ID'),
      description: z.string().optional().describe('Snapshot description'),
    },
    async ({ volumeId, description }) => {
      try {
        const snapshot = await client.ec2CreateSnapshot(volumeId, description);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Snapshot created',
                  snapshotId: snapshot.snapshotId,
                  volumeId: snapshot.volumeId,
                  state: snapshot.state,
                  volumeSize: snapshot.volumeSize,
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
  // Delete Snapshot
  // ===========================================================================
  server.tool(
    'aws_ec2_delete_snapshot',
    `Delete an EBS snapshot.

WARNING: This action cannot be undone.

Args:
  - snapshotId: Snapshot ID to delete (required)

Returns confirmation of deletion.`,
    {
      snapshotId: z.string().describe('Snapshot ID'),
    },
    async ({ snapshotId }) => {
      try {
        await client.ec2DeleteSnapshot(snapshotId);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Snapshot deleted',
                  snapshotId,
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
  // Copy Snapshot
  // ===========================================================================
  server.tool(
    'aws_ec2_copy_snapshot',
    `Copy an EBS snapshot, optionally to a different region.

Args:
  - sourceSnapshotId: Source snapshot ID (required)
  - sourceRegion: Source region (required)
  - description: Description for the new snapshot (optional)

Returns the new snapshot ID.`,
    {
      sourceSnapshotId: z.string().describe('Source snapshot ID'),
      sourceRegion: z.string().describe('Source region'),
      description: z.string().optional().describe('Description'),
    },
    async ({ sourceSnapshotId, sourceRegion, description }) => {
      try {
        const result = await client.ec2CopySnapshot(sourceSnapshotId, sourceRegion, description);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Snapshot copy initiated',
                  snapshotId: result.snapshotId,
                  sourceSnapshotId,
                  sourceRegion,
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
  // Create VPC
  // ===========================================================================
  server.tool(
    'aws_ec2_create_vpc',
    `Create a new VPC.

Args:
  - cidrBlock: The IPv4 CIDR block for the VPC (required, e.g., '10.0.0.0/16')
  - instanceTenancy: Instance tenancy option (optional: 'default' or 'dedicated')

Returns the created VPC details.`,
    {
      cidrBlock: z.string().describe('IPv4 CIDR block (e.g., 10.0.0.0/16)'),
      instanceTenancy: z.enum(['default', 'dedicated']).optional().describe('Instance tenancy'),
    },
    async ({ cidrBlock, instanceTenancy }) => {
      try {
        const vpc = await client.ec2CreateVpc(cidrBlock, instanceTenancy);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'VPC created',
                  vpcId: vpc.vpcId,
                  cidrBlock: vpc.cidrBlock,
                  state: vpc.state,
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
  // Delete VPC
  // ===========================================================================
  server.tool(
    'aws_ec2_delete_vpc',
    `Delete a VPC.

Args:
  - vpcId: The VPC ID (required)

Note: The VPC must have no dependencies (subnets, IGWs, etc.).`,
    {
      vpcId: z.string().describe('VPC ID to delete'),
    },
    async ({ vpcId }) => {
      try {
        await client.ec2DeleteVpc(vpcId);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `VPC ${vpcId} deleted`,
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
  // Create Subnet
  // ===========================================================================
  server.tool(
    'aws_ec2_create_subnet',
    `Create a subnet in a VPC.

Args:
  - vpcId: The VPC ID (required)
  - cidrBlock: The IPv4 CIDR block for the subnet (required)
  - availabilityZone: The availability zone (optional)

Returns the created subnet details.`,
    {
      vpcId: z.string().describe('VPC ID'),
      cidrBlock: z.string().describe('IPv4 CIDR block'),
      availabilityZone: z.string().optional().describe('Availability zone'),
    },
    async ({ vpcId, cidrBlock, availabilityZone }) => {
      try {
        const subnet = await client.ec2CreateSubnet(vpcId, cidrBlock, availabilityZone);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Subnet created',
                  subnetId: subnet.subnetId,
                  vpcId: subnet.vpcId,
                  cidrBlock: subnet.cidrBlock,
                  availabilityZone: subnet.availabilityZone,
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
  // Delete Subnet
  // ===========================================================================
  server.tool(
    'aws_ec2_delete_subnet',
    `Delete a subnet.

Args:
  - subnetId: The subnet ID (required)`,
    {
      subnetId: z.string().describe('Subnet ID to delete'),
    },
    async ({ subnetId }) => {
      try {
        await client.ec2DeleteSubnet(subnetId);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Subnet ${subnetId} deleted`,
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
  // Describe Internet Gateways
  // ===========================================================================
  server.tool(
    'aws_ec2_describe_internet_gateways',
    `List internet gateways.

Args:
  - internetGatewayIds: Filter by gateway IDs (optional)

Returns internet gateways with their VPC attachments.`,
    {
      internetGatewayIds: z.array(z.string()).optional().describe('Filter by gateway IDs'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ internetGatewayIds, format }) => {
      try {
        const gateways = await client.ec2DescribeInternetGateways(internetGatewayIds);
        return formatResponse(
          { items: gateways, count: gateways.length, hasMore: false },
          format,
          'ec2_internet_gateways'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Create Internet Gateway
  // ===========================================================================
  server.tool(
    'aws_ec2_create_internet_gateway',
    `Create an internet gateway.

Returns the created internet gateway ID.`,
    {},
    async () => {
      try {
        const result = await client.ec2CreateInternetGateway();
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Internet gateway created',
                  internetGatewayId: result.internetGatewayId,
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
  // Delete Internet Gateway
  // ===========================================================================
  server.tool(
    'aws_ec2_delete_internet_gateway',
    `Delete an internet gateway.

Args:
  - internetGatewayId: The internet gateway ID (required)

Note: The gateway must be detached from all VPCs first.`,
    {
      internetGatewayId: z.string().describe('Internet gateway ID'),
    },
    async ({ internetGatewayId }) => {
      try {
        await client.ec2DeleteInternetGateway(internetGatewayId);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Internet gateway ${internetGatewayId} deleted`,
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
  // Attach Internet Gateway
  // ===========================================================================
  server.tool(
    'aws_ec2_attach_internet_gateway',
    `Attach an internet gateway to a VPC.

Args:
  - internetGatewayId: The internet gateway ID (required)
  - vpcId: The VPC ID (required)`,
    {
      internetGatewayId: z.string().describe('Internet gateway ID'),
      vpcId: z.string().describe('VPC ID'),
    },
    async ({ internetGatewayId, vpcId }) => {
      try {
        await client.ec2AttachInternetGateway(internetGatewayId, vpcId);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Internet gateway ${internetGatewayId} attached to VPC ${vpcId}`,
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
  // Detach Internet Gateway
  // ===========================================================================
  server.tool(
    'aws_ec2_detach_internet_gateway',
    `Detach an internet gateway from a VPC.

Args:
  - internetGatewayId: The internet gateway ID (required)
  - vpcId: The VPC ID (required)`,
    {
      internetGatewayId: z.string().describe('Internet gateway ID'),
      vpcId: z.string().describe('VPC ID'),
    },
    async ({ internetGatewayId, vpcId }) => {
      try {
        await client.ec2DetachInternetGateway(internetGatewayId, vpcId);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Internet gateway ${internetGatewayId} detached from VPC ${vpcId}`,
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
  // Describe Route Tables
  // ===========================================================================
  server.tool(
    'aws_ec2_describe_route_tables',
    `List route tables.

Args:
  - routeTableIds: Filter by route table IDs (optional)

Returns route tables with their routes.`,
    {
      routeTableIds: z.array(z.string()).optional().describe('Filter by route table IDs'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ routeTableIds, format }) => {
      try {
        const routeTables = await client.ec2DescribeRouteTables(routeTableIds);
        return formatResponse(
          { items: routeTables, count: routeTables.length, hasMore: false },
          format,
          'ec2_route_tables'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Create Route Table
  // ===========================================================================
  server.tool(
    'aws_ec2_create_route_table',
    `Create a route table in a VPC.

Args:
  - vpcId: The VPC ID (required)

Returns the created route table ID.`,
    {
      vpcId: z.string().describe('VPC ID'),
    },
    async ({ vpcId }) => {
      try {
        const result = await client.ec2CreateRouteTable(vpcId);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Route table created',
                  routeTableId: result.routeTableId,
                  vpcId,
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
  // Delete Route Table
  // ===========================================================================
  server.tool(
    'aws_ec2_delete_route_table',
    `Delete a route table.

Args:
  - routeTableId: The route table ID (required)

Note: Cannot delete the main route table.`,
    {
      routeTableId: z.string().describe('Route table ID'),
    },
    async ({ routeTableId }) => {
      try {
        await client.ec2DeleteRouteTable(routeTableId);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Route table ${routeTableId} deleted`,
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
  // Create Route
  // ===========================================================================
  server.tool(
    'aws_ec2_create_route',
    `Create a route in a route table.

Args:
  - routeTableId: The route table ID (required)
  - destinationCidrBlock: Destination CIDR (required, e.g., '0.0.0.0/0')
  - gatewayId: Internet gateway ID (optional)
  - natGatewayId: NAT gateway ID (optional)

One of gatewayId or natGatewayId is required.`,
    {
      routeTableId: z.string().describe('Route table ID'),
      destinationCidrBlock: z.string().describe('Destination CIDR'),
      gatewayId: z.string().optional().describe('Internet gateway ID'),
      natGatewayId: z.string().optional().describe('NAT gateway ID'),
    },
    async ({ routeTableId, destinationCidrBlock, gatewayId, natGatewayId }) => {
      try {
        await client.ec2CreateRoute(routeTableId, destinationCidrBlock, gatewayId, natGatewayId);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Route created',
                  routeTableId,
                  destinationCidrBlock,
                  gatewayId,
                  natGatewayId,
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
  // Delete Route
  // ===========================================================================
  server.tool(
    'aws_ec2_delete_route',
    `Delete a route from a route table.

Args:
  - routeTableId: The route table ID (required)
  - destinationCidrBlock: Destination CIDR of the route to delete (required)`,
    {
      routeTableId: z.string().describe('Route table ID'),
      destinationCidrBlock: z.string().describe('Destination CIDR'),
    },
    async ({ routeTableId, destinationCidrBlock }) => {
      try {
        await client.ec2DeleteRoute(routeTableId, destinationCidrBlock);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Route ${destinationCidrBlock} deleted from ${routeTableId}`,
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
  // Associate Route Table
  // ===========================================================================
  server.tool(
    'aws_ec2_associate_route_table',
    `Associate a route table with a subnet.

Args:
  - routeTableId: The route table ID (required)
  - subnetId: The subnet ID (required)

Returns the association ID.`,
    {
      routeTableId: z.string().describe('Route table ID'),
      subnetId: z.string().describe('Subnet ID'),
    },
    async ({ routeTableId, subnetId }) => {
      try {
        const result = await client.ec2AssociateRouteTable(routeTableId, subnetId);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Route table associated with subnet',
                  associationId: result.associationId,
                  routeTableId,
                  subnetId,
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
  // Disassociate Route Table
  // ===========================================================================
  server.tool(
    'aws_ec2_disassociate_route_table',
    `Disassociate a route table from a subnet.

Args:
  - associationId: The association ID (required)`,
    {
      associationId: z.string().describe('Association ID'),
    },
    async ({ associationId }) => {
      try {
        await client.ec2DisassociateRouteTable(associationId);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Route table association ${associationId} removed`,
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
  // Allocate Address (Elastic IP)
  // ===========================================================================
  server.tool(
    'aws_ec2_allocate_address',
    `Allocate an Elastic IP address.

Returns the allocated Elastic IP details including allocation ID and public IP.`,
    {
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ format }) => {
      try {
        const eip = await client.ec2AllocateAddress();
        return formatResponse(
          {
            success: true,
            message: 'Elastic IP allocated',
            allocationId: eip.allocationId,
            publicIp: eip.publicIp,
          },
          format,
          'ec2_elastic_ip'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Release Address (Elastic IP)
  // ===========================================================================
  server.tool(
    'aws_ec2_release_address',
    `Release an Elastic IP address.

Args:
  - allocationId: The allocation ID (required)

Note: The address must be disassociated first.`,
    {
      allocationId: z.string().describe('Allocation ID'),
    },
    async ({ allocationId }) => {
      try {
        await client.ec2ReleaseAddress(allocationId);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Elastic IP ${allocationId} released`,
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
  // Associate Address (Elastic IP)
  // ===========================================================================
  server.tool(
    'aws_ec2_associate_address',
    `Associate an Elastic IP with an instance or network interface.

Args:
  - allocationId: The Elastic IP allocation ID (required)
  - instanceId: Instance ID to associate with (optional)
  - networkInterfaceId: Network interface ID to associate with (optional)

One of instanceId or networkInterfaceId is required.

Returns the association ID.`,
    {
      allocationId: z.string().describe('Allocation ID'),
      instanceId: z.string().optional().describe('Instance ID'),
      networkInterfaceId: z.string().optional().describe('Network interface ID'),
    },
    async ({ allocationId, instanceId, networkInterfaceId }) => {
      try {
        const result = await client.ec2AssociateAddress(allocationId, instanceId, networkInterfaceId);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Elastic IP associated',
                  associationId: result.associationId,
                  allocationId,
                  instanceId,
                  networkInterfaceId,
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
  // Disassociate Address (Elastic IP)
  // ===========================================================================
  server.tool(
    'aws_ec2_disassociate_address',
    `Disassociate an Elastic IP from an instance.

Args:
  - associationId: The association ID (required)`,
    {
      associationId: z.string().describe('Association ID'),
    },
    async ({ associationId }) => {
      try {
        await client.ec2DisassociateAddress(associationId);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Elastic IP association ${associationId} removed`,
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
  // Describe Network Interfaces
  // ===========================================================================
  server.tool(
    'aws_ec2_describe_network_interfaces',
    `List EC2 network interfaces.

Args:
  - networkInterfaceIds: Array of network interface IDs (optional)

Returns network interfaces with subnet, VPC, IP, and attachment info.`,
    {
      networkInterfaceIds: z.array(z.string()).optional().describe('Network interface IDs'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ networkInterfaceIds, format }) => {
      try {
        const interfaces = await client.ec2DescribeNetworkInterfaces(networkInterfaceIds);
        return formatResponse(
          { items: interfaces, count: interfaces.length, hasMore: false },
          format,
          'ec2_network_interfaces'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Create Network Interface
  // ===========================================================================
  server.tool(
    'aws_ec2_create_network_interface',
    `Create a network interface in a subnet.

Args:
  - subnetId: The subnet ID (required)
  - description: Description for the interface (optional)
  - securityGroupIds: Security group IDs to attach (optional)

Returns the created network interface details.`,
    {
      subnetId: z.string().describe('Subnet ID'),
      description: z.string().optional().describe('Description'),
      securityGroupIds: z.array(z.string()).optional().describe('Security group IDs'),
    },
    async ({ subnetId, description, securityGroupIds }) => {
      try {
        const eni = await client.ec2CreateNetworkInterface(subnetId, description, securityGroupIds);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Network interface created',
                  networkInterfaceId: eni.networkInterfaceId,
                  subnetId: eni.subnetId,
                  vpcId: eni.vpcId,
                  privateIpAddress: eni.privateIpAddress,
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
  // Delete Network Interface
  // ===========================================================================
  server.tool(
    'aws_ec2_delete_network_interface',
    `Delete a network interface.

Args:
  - networkInterfaceId: The network interface ID (required)

Note: The interface must be detached first.`,
    {
      networkInterfaceId: z.string().describe('Network interface ID'),
    },
    async ({ networkInterfaceId }) => {
      try {
        await client.ec2DeleteNetworkInterface(networkInterfaceId);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Network interface ${networkInterfaceId} deleted`,
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
  // Attach Network Interface
  // ===========================================================================
  server.tool(
    'aws_ec2_attach_network_interface',
    `Attach a network interface to an instance.

Args:
  - networkInterfaceId: The network interface ID (required)
  - instanceId: The instance ID (required)
  - deviceIndex: The device index (required)

Returns the attachment ID.`,
    {
      networkInterfaceId: z.string().describe('Network interface ID'),
      instanceId: z.string().describe('Instance ID'),
      deviceIndex: z.number().int().min(0).describe('Device index'),
    },
    async ({ networkInterfaceId, instanceId, deviceIndex }) => {
      try {
        const result = await client.ec2AttachNetworkInterface(networkInterfaceId, instanceId, deviceIndex);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Network interface attached',
                  attachmentId: result.attachmentId,
                  networkInterfaceId,
                  instanceId,
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
  // Detach Network Interface
  // ===========================================================================
  server.tool(
    'aws_ec2_detach_network_interface',
    `Detach a network interface from an instance.

Args:
  - attachmentId: The attachment ID (required)
  - force: Force detachment (optional)`,
    {
      attachmentId: z.string().describe('Attachment ID'),
      force: z.boolean().optional().describe('Force detachment'),
    },
    async ({ attachmentId, force }) => {
      try {
        await client.ec2DetachNetworkInterface(attachmentId, force);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Network interface detached`,
                  attachmentId,
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
  // Describe Placement Groups
  // ===========================================================================
  server.tool(
    'aws_ec2_describe_placement_groups',
    `List EC2 placement groups.

Args:
  - groupNames: Array of placement group names (optional)

Returns placement groups with strategy and state.`,
    {
      groupNames: z.array(z.string()).optional().describe('Placement group names'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ groupNames, format }) => {
      try {
        const groups = await client.ec2DescribePlacementGroups(groupNames);
        return formatResponse(
          { items: groups, count: groups.length, hasMore: false },
          format,
          'ec2_placement_groups'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Create Placement Group
  // ===========================================================================
  server.tool(
    'aws_ec2_create_placement_group',
    `Create an EC2 placement group.

Args:
  - groupName: The placement group name (required)
  - strategy: The placement strategy: 'cluster', 'spread', or 'partition' (required)

Returns the created placement group name.`,
    {
      groupName: z.string().describe('Placement group name'),
      strategy: z.enum(['cluster', 'spread', 'partition']).describe('Placement strategy'),
    },
    async ({ groupName, strategy }) => {
      try {
        await client.ec2CreatePlacementGroup(groupName, strategy);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Placement group created',
                  groupName,
                  strategy,
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
  // Delete Placement Group
  // ===========================================================================
  server.tool(
    'aws_ec2_delete_placement_group',
    `Delete an EC2 placement group.

Args:
  - groupName: The placement group name (required)

Note: The group must not have any instances.`,
    {
      groupName: z.string().describe('Placement group name'),
    },
    async ({ groupName }) => {
      try {
        await client.ec2DeletePlacementGroup(groupName);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Placement group ${groupName} deleted`,
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
  // Modify Instance Attribute
  // ===========================================================================
  server.tool(
    'aws_ec2_modify_instance_attribute',
    `Modify an EC2 instance attribute.

Args:
  - instanceId: The instance ID (required)
  - attribute: The attribute name (required, e.g., 'instanceType', 'userData', 'disableApiTermination')
  - value: The new value (required)

Note: Instance must be stopped for some attributes.`,
    {
      instanceId: z.string().describe('Instance ID'),
      attribute: z.string().describe('Attribute name'),
      value: z.string().describe('New value'),
    },
    async ({ instanceId, attribute, value }) => {
      try {
        await client.ec2ModifyInstanceAttribute(instanceId, attribute, value);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Instance attribute modified`,
                  instanceId,
                  attribute,
                  value,
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
  // Get Console Output
  // ===========================================================================
  server.tool(
    'aws_ec2_get_console_output',
    `Get the console output from an EC2 instance.

Args:
  - instanceId: The instance ID (required)

Returns the console output text (useful for debugging boot issues).`,
    {
      instanceId: z.string().describe('Instance ID'),
    },
    async ({ instanceId }) => {
      try {
        const result = await client.ec2GetConsoleOutput(instanceId);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  instanceId: result.instanceId,
                  timestamp: result.timestamp,
                  output: result.output || '(no output available)',
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
