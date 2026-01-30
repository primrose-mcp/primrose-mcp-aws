/**
 * Route53 Tools
 *
 * MCP tools for Amazon Route53 DNS operations.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { AwsClient } from '../client.js';
import { formatError, formatResponse } from '../utils/formatters.js';

export function registerRoute53Tools(server: McpServer, client: AwsClient): void {
  // ===========================================================================
  // List Hosted Zones
  // ===========================================================================
  server.tool(
    'aws_route53_list_hosted_zones',
    `List all Route53 hosted zones.

Returns zones with names, IDs, and record counts.`,
    {
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ format }) => {
      try {
        const zones = await client.route53ListHostedZones();
        return formatResponse(
          { items: zones, count: zones.length, hasMore: false },
          format,
          'route53_hosted_zones'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // List Resource Record Sets
  // ===========================================================================
  server.tool(
    'aws_route53_list_record_sets',
    `List DNS record sets in a hosted zone.

Args:
  - hostedZoneId: The hosted zone ID (required)

Returns DNS records with names, types, and values.`,
    {
      hostedZoneId: z.string().describe('Hosted zone ID'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ hostedZoneId, format }) => {
      try {
        const records = await client.route53ListResourceRecordSets(hostedZoneId);
        return formatResponse(
          { items: records, count: records.length, hasMore: false },
          format,
          'route53_record_sets'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Change Resource Record Sets
  // ===========================================================================
  server.tool(
    'aws_route53_change_record_sets',
    `Create, update, or delete DNS record sets in a hosted zone.

Args:
  - hostedZoneId: The hosted zone ID (required)
  - changes: Array of changes to apply

Each change requires:
  - action: 'CREATE', 'DELETE', or 'UPSERT'
  - resourceRecordSet: The record set to create/update/delete
    - name: Record name (e.g., 'example.com.')
    - type: Record type (e.g., 'A', 'CNAME', 'TXT')
    - ttl: Time to live in seconds
    - resourceRecords: Array of {value} for record values

Returns change status and ID.`,
    {
      hostedZoneId: z.string().describe('Hosted zone ID'),
      changes: z.array(z.object({
        action: z.enum(['CREATE', 'DELETE', 'UPSERT']).describe('Action to perform'),
        resourceRecordSet: z.object({
          name: z.string().describe('Record name (end with .)'),
          type: z.string().describe('Record type (A, CNAME, TXT, etc.)'),
          ttl: z.number().int().optional().describe('TTL in seconds'),
          resourceRecords: z.array(z.object({ value: z.string() })).optional().describe('Record values'),
        }),
      })).min(1).describe('Changes to apply'),
    },
    async ({ hostedZoneId, changes }) => {
      try {
        const result = await client.route53ChangeResourceRecordSets(hostedZoneId, changes);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Record set changes submitted',
                  changeId: result.id,
                  status: result.status,
                  submittedAt: result.submittedAt,
                  note: 'Changes may take time to propagate',
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
  // List Health Checks
  // ===========================================================================
  server.tool(
    'aws_route53_list_health_checks',
    `List Route53 health checks.

Returns health checks with their configurations and endpoints.`,
    {
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ format }) => {
      try {
        const healthChecks = await client.route53ListHealthChecks();
        return formatResponse(
          { items: healthChecks, count: healthChecks.length, hasMore: false },
          format,
          'route53_health_checks'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Get Hosted Zone
  // ===========================================================================
  server.tool(
    'aws_route53_get_hosted_zone',
    `Get detailed information about a Route53 hosted zone.

Args:
  - hostedZoneId: The hosted zone ID (required)

Returns zone details including name, configuration, and record count.`,
    {
      hostedZoneId: z.string().describe('Hosted zone ID'),
    },
    async ({ hostedZoneId }) => {
      try {
        const zone = await client.route53GetHostedZone(hostedZoneId);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(zone, null, 2),
            },
          ],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Create Hosted Zone
  // ===========================================================================
  server.tool(
    'aws_route53_create_hosted_zone',
    `Create a new Route53 hosted zone.

Args:
  - name: The domain name (e.g., 'example.com.') (required)
  - callerReference: A unique string to identify the request (required)
  - comment: Optional comment about the zone
  - privateZone: Set to true for a private hosted zone (requires VPC)
  - vpcId: VPC ID for private zones
  - vpcRegion: VPC region for private zones

Returns the created zone and change info.`,
    {
      name: z.string().describe('Domain name (end with .)'),
      callerReference: z.string().describe('Unique request identifier'),
      comment: z.string().optional().describe('Zone comment'),
      privateZone: z.boolean().optional().describe('Create as private zone'),
      vpcId: z.string().optional().describe('VPC ID for private zone'),
      vpcRegion: z.string().optional().describe('VPC region for private zone'),
    },
    async ({ name, callerReference, comment, privateZone, vpcId, vpcRegion }) => {
      try {
        const result = await client.route53CreateHostedZone(name, callerReference, comment, privateZone, vpcId, vpcRegion);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Hosted zone created for '${name}'`,
                  hostedZone: result.hostedZone,
                  changeInfo: result.changeInfo,
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
  // Delete Hosted Zone
  // ===========================================================================
  server.tool(
    'aws_route53_delete_hosted_zone',
    `Delete a Route53 hosted zone.

Args:
  - hostedZoneId: The hosted zone ID (required)

Note: The zone must not have any non-NS/SOA records.
Returns change status.`,
    {
      hostedZoneId: z.string().describe('Hosted zone ID to delete'),
    },
    async ({ hostedZoneId }) => {
      try {
        const changeInfo = await client.route53DeleteHostedZone(hostedZoneId);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Hosted zone deletion initiated`,
                  changeInfo,
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
  // Get Health Check
  // ===========================================================================
  server.tool(
    'aws_route53_get_health_check',
    `Get detailed information about a Route53 health check.

Args:
  - healthCheckId: The health check ID (required)

Returns health check configuration and status.`,
    {
      healthCheckId: z.string().describe('Health check ID'),
    },
    async ({ healthCheckId }) => {
      try {
        const healthCheck = await client.route53GetHealthCheck(healthCheckId);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(healthCheck, null, 2),
            },
          ],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Create Health Check
  // ===========================================================================
  server.tool(
    'aws_route53_create_health_check',
    `Create a Route53 health check.

Args:
  - callerReference: A unique string to identify the request (required)
  - type: Health check type: HTTP, HTTPS, HTTP_STR_MATCH, HTTPS_STR_MATCH, TCP (required)
  - ipAddress: IP address to check (optional, provide either this or FQDN)
  - port: Port number (optional, defaults based on type)
  - resourcePath: Path for HTTP/HTTPS checks (optional)
  - fullyQualifiedDomainName: Domain name to check (optional)
  - requestInterval: Seconds between checks: 10 or 30 (optional)
  - failureThreshold: Number of failures before unhealthy: 1-10 (optional)

Returns the created health check.`,
    {
      callerReference: z.string().describe('Unique request identifier'),
      type: z.string().describe('Health check type (HTTP, HTTPS, TCP, etc.)'),
      ipAddress: z.string().optional().describe('IP address to check'),
      port: z.number().int().optional().describe('Port number'),
      resourcePath: z.string().optional().describe('Path for HTTP/HTTPS checks'),
      fullyQualifiedDomainName: z.string().optional().describe('Domain name to check'),
      requestInterval: z.number().int().optional().describe('Seconds between checks (10 or 30)'),
      failureThreshold: z.number().int().min(1).max(10).optional().describe('Failures before unhealthy'),
    },
    async ({ callerReference, type, ipAddress, port, resourcePath, fullyQualifiedDomainName, requestInterval, failureThreshold }) => {
      try {
        const healthCheck = await client.route53CreateHealthCheck(callerReference, {
          type,
          ipAddress,
          port,
          resourcePath,
          fullyQualifiedDomainName,
          requestInterval,
          failureThreshold,
        });
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Health check created',
                  healthCheck,
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
  // Delete Health Check
  // ===========================================================================
  server.tool(
    'aws_route53_delete_health_check',
    `Delete a Route53 health check.

Args:
  - healthCheckId: The health check ID (required)

Returns confirmation of deletion.`,
    {
      healthCheckId: z.string().describe('Health check ID to delete'),
    },
    async ({ healthCheckId }) => {
      try {
        await client.route53DeleteHealthCheck(healthCheckId);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Health check '${healthCheckId}' deleted`,
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
  // Get Change Status
  // ===========================================================================
  server.tool(
    'aws_route53_get_change',
    `Get the status of a Route53 change request.

Args:
  - changeId: The change ID (required)

Returns change status (PENDING or INSYNC).`,
    {
      changeId: z.string().describe('Change ID to check'),
    },
    async ({ changeId }) => {
      try {
        const changeInfo = await client.route53GetChange(changeId);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(changeInfo, null, 2),
            },
          ],
        };
      } catch (error) {
        return formatError(error);
      }
    }
  );
}
