/**
 * IAM Tools
 *
 * MCP tools for AWS IAM operations.
 */

import type { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { z } from 'zod';
import type { AwsClient } from '../client.js';
import { formatError, formatResponse } from '../utils/formatters.js';

export function registerIAMTools(server: McpServer, client: AwsClient): void {
  // ===========================================================================
  // List Users
  // ===========================================================================
  server.tool(
    'aws_iam_list_users',
    `List all IAM users in the account.

Returns users with their names, IDs, creation dates, and last login times.`,
    {
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ format }) => {
      try {
        const users = await client.iamListUsers();
        return formatResponse(
          { items: users, count: users.length, hasMore: false },
          format,
          'iam_users'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Get User
  // ===========================================================================
  server.tool(
    'aws_iam_get_user',
    `Get detailed information about an IAM user.

Args:
  - userName: The IAM user name (required)

Returns user details including ARN, creation date, and password last used.`,
    {
      userName: z.string().describe('IAM user name'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ userName, format }) => {
      try {
        const user = await client.iamGetUser(userName);
        return formatResponse(user, format, 'iam_user');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // List Roles
  // ===========================================================================
  server.tool(
    'aws_iam_list_roles',
    `List all IAM roles in the account.

Returns roles with their names, IDs, ARNs, and descriptions.`,
    {
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ format }) => {
      try {
        const roles = await client.iamListRoles();
        return formatResponse(
          { items: roles, count: roles.length, hasMore: false },
          format,
          'iam_roles'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Get Role
  // ===========================================================================
  server.tool(
    'aws_iam_get_role',
    `Get detailed information about an IAM role.

Args:
  - roleName: The IAM role name (required)

Returns role details including trust policy and description.`,
    {
      roleName: z.string().describe('IAM role name'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ roleName, format }) => {
      try {
        const role = await client.iamGetRole(roleName);
        return formatResponse(role, format, 'iam_role');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // List Policies
  // ===========================================================================
  server.tool(
    'aws_iam_list_policies',
    `List IAM policies in the account.

Args:
  - onlyAttached: If true, only return policies attached to users/groups/roles

Returns policies with names, ARNs, and attachment counts.`,
    {
      onlyAttached: z.boolean().default(false).describe('Only show attached policies'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ onlyAttached, format }) => {
      try {
        const policies = await client.iamListPolicies(onlyAttached);
        return formatResponse(
          { items: policies, count: policies.length, hasMore: false },
          format,
          'iam_policies'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Get Policy
  // ===========================================================================
  server.tool(
    'aws_iam_get_policy',
    `Get detailed information about an IAM policy.

Args:
  - policyArn: The policy ARN (required)

Returns policy details including attachment count and description.`,
    {
      policyArn: z.string().describe('IAM policy ARN'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ policyArn, format }) => {
      try {
        const policy = await client.iamGetPolicy(policyArn);
        return formatResponse(policy, format, 'iam_policy');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // List Groups
  // ===========================================================================
  server.tool(
    'aws_iam_list_groups',
    `List all IAM groups in the account.

Returns groups with their names, IDs, and ARNs.`,
    {
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ format }) => {
      try {
        const groups = await client.iamListGroups();
        return formatResponse(
          { items: groups, count: groups.length, hasMore: false },
          format,
          'iam_groups'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // List Access Keys
  // ===========================================================================
  server.tool(
    'aws_iam_list_access_keys',
    `List access keys for an IAM user.

Args:
  - userName: The IAM user name (required)

Returns access keys with their IDs, status, and creation dates.`,
    {
      userName: z.string().describe('IAM user name'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ userName, format }) => {
      try {
        const keys = await client.iamListAccessKeys(userName);
        return formatResponse(
          { items: keys, count: keys.length, hasMore: false },
          format,
          'iam_access_keys'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // List Attached User Policies
  // ===========================================================================
  server.tool(
    'aws_iam_list_attached_user_policies',
    `List managed policies attached to an IAM user.

Args:
  - userName: The IAM user name (required)

Returns attached policies with names and ARNs.`,
    {
      userName: z.string().describe('IAM user name'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ userName, format }) => {
      try {
        const policies = await client.iamListAttachedUserPolicies(userName);
        return formatResponse(
          { items: policies, count: policies.length, hasMore: false },
          format,
          'iam_attached_policies'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // List Attached Role Policies
  // ===========================================================================
  server.tool(
    'aws_iam_list_attached_role_policies',
    `List managed policies attached to an IAM role.

Args:
  - roleName: The IAM role name (required)

Returns attached policies with names and ARNs.`,
    {
      roleName: z.string().describe('IAM role name'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ roleName, format }) => {
      try {
        const policies = await client.iamListAttachedRolePolicies(roleName);
        return formatResponse(
          { items: policies, count: policies.length, hasMore: false },
          format,
          'iam_attached_policies'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // List Groups For User
  // ===========================================================================
  server.tool(
    'aws_iam_list_groups_for_user',
    `List IAM groups that a user belongs to.

Args:
  - userName: The IAM user name (required)

Returns groups with names, IDs, and ARNs.`,
    {
      userName: z.string().describe('IAM user name'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ userName, format }) => {
      try {
        const groups = await client.iamListGroupsForUser(userName);
        return formatResponse(
          { items: groups, count: groups.length, hasMore: false },
          format,
          'iam_groups'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // List MFA Devices
  // ===========================================================================
  server.tool(
    'aws_iam_list_mfa_devices',
    `List MFA devices for an IAM user.

Args:
  - userName: The IAM user name (optional, defaults to current user)

Returns MFA devices with serial numbers and enable dates.`,
    {
      userName: z.string().optional().describe('IAM user name'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ userName, format }) => {
      try {
        const devices = await client.iamListMfaDevices(userName);
        return formatResponse(
          { items: devices, count: devices.length, hasMore: false },
          format,
          'iam_mfa_devices'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // List Instance Profiles
  // ===========================================================================
  server.tool(
    'aws_iam_list_instance_profiles',
    `List IAM instance profiles.

Returns instance profiles with names, IDs, and attached roles.`,
    {
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ format }) => {
      try {
        const profiles = await client.iamListInstanceProfiles();
        return formatResponse(
          { items: profiles, count: profiles.length, hasMore: false },
          format,
          'iam_instance_profiles'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Get Instance Profile
  // ===========================================================================
  server.tool(
    'aws_iam_get_instance_profile',
    `Get details of an IAM instance profile.

Args:
  - instanceProfileName: The instance profile name (required)

Returns instance profile details including attached roles.`,
    {
      instanceProfileName: z.string().describe('Instance profile name'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ instanceProfileName, format }) => {
      try {
        const profile = await client.iamGetInstanceProfile(instanceProfileName);
        return formatResponse(profile, format, 'iam_instance_profile');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Create User
  // ===========================================================================
  server.tool(
    'aws_iam_create_user',
    `Create a new IAM user.

Args:
  - userName: The name for the new user (required)

Returns the created user details.`,
    {
      userName: z.string().describe('New user name'),
    },
    async ({ userName }) => {
      try {
        const user = await client.iamCreateUser(userName);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `IAM user '${userName}' created`,
                  userName: user.userName,
                  userId: user.userId,
                  arn: user.arn,
                  createDate: user.createDate,
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
  // Delete User
  // ===========================================================================
  server.tool(
    'aws_iam_delete_user',
    `Delete an IAM user.

Args:
  - userName: The name of the user to delete (required)

Note: The user must have no attached policies, access keys, or other resources before deletion.

Returns confirmation of deletion.`,
    {
      userName: z.string().describe('User name to delete'),
    },
    async ({ userName }) => {
      try {
        await client.iamDeleteUser(userName);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `IAM user '${userName}' deleted`,
                  userName,
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
  // Create Role
  // ===========================================================================
  server.tool(
    'aws_iam_create_role',
    `Create a new IAM role.

Args:
  - roleName: The name for the new role (required)
  - assumeRolePolicyDocument: Trust policy as JSON string (required)
  - description: Role description (optional)

Returns the created role details.`,
    {
      roleName: z.string().describe('New role name'),
      assumeRolePolicyDocument: z.string().describe('Trust policy JSON'),
      description: z.string().optional().describe('Role description'),
    },
    async ({ roleName, assumeRolePolicyDocument, description }) => {
      try {
        const role = await client.iamCreateRole(roleName, assumeRolePolicyDocument, description);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `IAM role '${roleName}' created`,
                  roleName: role.roleName,
                  roleId: role.roleId,
                  arn: role.arn,
                  createDate: role.createDate,
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
  // Delete Role
  // ===========================================================================
  server.tool(
    'aws_iam_delete_role',
    `Delete an IAM role.

Args:
  - roleName: The name of the role to delete (required)

Note: The role must have no attached policies or instance profiles before deletion.

Returns confirmation of deletion.`,
    {
      roleName: z.string().describe('Role name to delete'),
    },
    async ({ roleName }) => {
      try {
        await client.iamDeleteRole(roleName);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `IAM role '${roleName}' deleted`,
                  roleName,
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
  // Attach User Policy
  // ===========================================================================
  server.tool(
    'aws_iam_attach_user_policy',
    `Attach a managed policy to an IAM user.

Args:
  - userName: The user name (required)
  - policyArn: The ARN of the policy to attach (required)

Returns confirmation of attachment.`,
    {
      userName: z.string().describe('User name'),
      policyArn: z.string().describe('Policy ARN'),
    },
    async ({ userName, policyArn }) => {
      try {
        await client.iamAttachUserPolicy(userName, policyArn);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Policy attached to user '${userName}'`,
                  userName,
                  policyArn,
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
  // Detach User Policy
  // ===========================================================================
  server.tool(
    'aws_iam_detach_user_policy',
    `Detach a managed policy from an IAM user.

Args:
  - userName: The user name (required)
  - policyArn: The ARN of the policy to detach (required)

Returns confirmation of detachment.`,
    {
      userName: z.string().describe('User name'),
      policyArn: z.string().describe('Policy ARN'),
    },
    async ({ userName, policyArn }) => {
      try {
        await client.iamDetachUserPolicy(userName, policyArn);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Policy detached from user '${userName}'`,
                  userName,
                  policyArn,
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
  // Attach Role Policy
  // ===========================================================================
  server.tool(
    'aws_iam_attach_role_policy',
    `Attach a managed policy to an IAM role.

Args:
  - roleName: The role name (required)
  - policyArn: The ARN of the policy to attach (required)

Returns confirmation of attachment.`,
    {
      roleName: z.string().describe('Role name'),
      policyArn: z.string().describe('Policy ARN'),
    },
    async ({ roleName, policyArn }) => {
      try {
        await client.iamAttachRolePolicy(roleName, policyArn);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Policy attached to role '${roleName}'`,
                  roleName,
                  policyArn,
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
  // Detach Role Policy
  // ===========================================================================
  server.tool(
    'aws_iam_detach_role_policy',
    `Detach a managed policy from an IAM role.

Args:
  - roleName: The role name (required)
  - policyArn: The ARN of the policy to detach (required)

Returns confirmation of detachment.`,
    {
      roleName: z.string().describe('Role name'),
      policyArn: z.string().describe('Policy ARN'),
    },
    async ({ roleName, policyArn }) => {
      try {
        await client.iamDetachRolePolicy(roleName, policyArn);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Policy detached from role '${roleName}'`,
                  roleName,
                  policyArn,
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
  // Create Access Key
  // ===========================================================================
  server.tool(
    'aws_iam_create_access_key',
    `Create a new access key for an IAM user.

Args:
  - userName: The user name (required)

WARNING: The secret access key is only available at creation time. Make sure to save it securely.

Returns the new access key ID and secret access key.`,
    {
      userName: z.string().describe('User name'),
    },
    async ({ userName }) => {
      try {
        const key = await client.iamCreateAccessKey(userName);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Access key created for user '${userName}'`,
                  userName,
                  accessKeyId: key.accessKeyId,
                  secretAccessKey: key.secretAccessKey,
                  warning: 'Save the secret access key now. It will not be shown again.',
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
  // Delete Access Key
  // ===========================================================================
  server.tool(
    'aws_iam_delete_access_key',
    `Delete an access key for an IAM user.

Args:
  - userName: The user name (required)
  - accessKeyId: The access key ID to delete (required)

Returns confirmation of deletion.`,
    {
      userName: z.string().describe('User name'),
      accessKeyId: z.string().describe('Access key ID'),
    },
    async ({ userName, accessKeyId }) => {
      try {
        await client.iamDeleteAccessKey(userName, accessKeyId);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Access key '${accessKeyId}' deleted for user '${userName}'`,
                  userName,
                  accessKeyId,
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
  // Update Access Key
  // ===========================================================================
  server.tool(
    'aws_iam_update_access_key',
    `Activate or deactivate an access key.

Args:
  - userName: The user name (required)
  - accessKeyId: The access key ID (required)
  - status: 'Active' or 'Inactive' (required)

Returns confirmation.`,
    {
      userName: z.string().describe('User name'),
      accessKeyId: z.string().describe('Access key ID'),
      status: z.enum(['Active', 'Inactive']).describe('Key status'),
    },
    async ({ userName, accessKeyId, status }) => {
      try {
        await client.iamUpdateAccessKey(userName, accessKeyId, status);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Access key '${accessKeyId}' set to ${status}`,
                  userName,
                  accessKeyId,
                  status,
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
  // Create Policy
  // ===========================================================================
  server.tool(
    'aws_iam_create_policy',
    `Create a new IAM policy.

Args:
  - policyName: Name for the policy (required)
  - policyDocument: JSON policy document (required)
  - description: Description of the policy (optional)

Returns the created policy details.`,
    {
      policyName: z.string().describe('Policy name'),
      policyDocument: z.string().describe('Policy document JSON'),
      description: z.string().optional().describe('Policy description'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ policyName, policyDocument, description, format }) => {
      try {
        const policy = await client.iamCreatePolicy(policyName, policyDocument, description);
        return formatResponse(
          {
            success: true,
            message: `Policy '${policyName}' created`,
            policy,
          },
          format,
          'iam_policy'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Delete Policy
  // ===========================================================================
  server.tool(
    'aws_iam_delete_policy',
    `Delete an IAM policy.

Args:
  - policyArn: The policy ARN (required)

Note: Policy must be detached from all users, groups, and roles first.
All policy versions except the default must be deleted first.

Returns confirmation.`,
    {
      policyArn: z.string().describe('Policy ARN'),
    },
    async ({ policyArn }) => {
      try {
        await client.iamDeletePolicy(policyArn);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Policy deleted',
                  policyArn,
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
  // Get Policy Version
  // ===========================================================================
  server.tool(
    'aws_iam_get_policy_version',
    `Get a specific version of an IAM policy.

Args:
  - policyArn: The policy ARN (required)
  - versionId: The version ID (required, e.g., 'v1', 'v2')

Returns the policy document for that version.`,
    {
      policyArn: z.string().describe('Policy ARN'),
      versionId: z.string().describe('Version ID'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ policyArn, versionId, format }) => {
      try {
        const version = await client.iamGetPolicyVersion(policyArn, versionId);
        return formatResponse(version, format, 'iam_policy_version');
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // List Policy Versions
  // ===========================================================================
  server.tool(
    'aws_iam_list_policy_versions',
    `List all versions of an IAM policy.

Args:
  - policyArn: The policy ARN (required)

Returns version IDs and which is the default.`,
    {
      policyArn: z.string().describe('Policy ARN'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ policyArn, format }) => {
      try {
        const versions = await client.iamListPolicyVersions(policyArn);
        return formatResponse(
          { items: versions, count: versions.length, hasMore: false },
          format,
          'iam_policy_versions'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Create Policy Version
  // ===========================================================================
  server.tool(
    'aws_iam_create_policy_version',
    `Create a new version of an IAM policy.

Args:
  - policyArn: The policy ARN (required)
  - policyDocument: New policy document JSON (required)
  - setAsDefault: Set as the default version (optional)

A policy can have up to 5 versions. Delete old versions if at the limit.

Returns the new version ID.`,
    {
      policyArn: z.string().describe('Policy ARN'),
      policyDocument: z.string().describe('Policy document JSON'),
      setAsDefault: z.boolean().optional().describe('Set as default version'),
    },
    async ({ policyArn, policyDocument, setAsDefault }) => {
      try {
        const result = await client.iamCreatePolicyVersion(policyArn, policyDocument, setAsDefault);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Policy version created',
                  versionId: result.versionId,
                  isDefault: setAsDefault || false,
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
  // Delete Policy Version
  // ===========================================================================
  server.tool(
    'aws_iam_delete_policy_version',
    `Delete a specific version of an IAM policy.

Args:
  - policyArn: The policy ARN (required)
  - versionId: The version ID to delete (required)

Note: Cannot delete the default version.

Returns confirmation.`,
    {
      policyArn: z.string().describe('Policy ARN'),
      versionId: z.string().describe('Version ID'),
    },
    async ({ policyArn, versionId }) => {
      try {
        await client.iamDeletePolicyVersion(policyArn, versionId);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Policy version deleted',
                  policyArn,
                  versionId,
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
  // Add User To Group
  // ===========================================================================
  server.tool(
    'aws_iam_add_user_to_group',
    `Add an IAM user to a group.

Args:
  - groupName: The group name (required)
  - userName: The user name (required)

Returns confirmation.`,
    {
      groupName: z.string().describe('Group name'),
      userName: z.string().describe('User name'),
    },
    async ({ groupName, userName }) => {
      try {
        await client.iamAddUserToGroup(groupName, userName);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `User '${userName}' added to group '${groupName}'`,
                  groupName,
                  userName,
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
  // Remove User From Group
  // ===========================================================================
  server.tool(
    'aws_iam_remove_user_from_group',
    `Remove an IAM user from a group.

Args:
  - groupName: The group name (required)
  - userName: The user name (required)

Returns confirmation.`,
    {
      groupName: z.string().describe('Group name'),
      userName: z.string().describe('User name'),
    },
    async ({ groupName, userName }) => {
      try {
        await client.iamRemoveUserFromGroup(groupName, userName);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `User '${userName}' removed from group '${groupName}'`,
                  groupName,
                  userName,
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
  // Create Group
  // ===========================================================================
  server.tool(
    'aws_iam_create_group',
    `Create a new IAM group.

Args:
  - groupName: Name for the group (required)

Returns the created group details.`,
    {
      groupName: z.string().describe('Group name'),
      format: z.enum(['json', 'markdown']).default('json'),
    },
    async ({ groupName, format }) => {
      try {
        const group = await client.iamCreateGroup(groupName);
        return formatResponse(
          {
            success: true,
            message: `Group '${groupName}' created`,
            group,
          },
          format,
          'iam_group'
        );
      } catch (error) {
        return formatError(error);
      }
    }
  );

  // ===========================================================================
  // Delete Group
  // ===========================================================================
  server.tool(
    'aws_iam_delete_group',
    `Delete an IAM group.

Args:
  - groupName: The group name (required)

Note: Group must be empty (no users) and have no policies attached.

Returns confirmation.`,
    {
      groupName: z.string().describe('Group name'),
    },
    async ({ groupName }) => {
      try {
        await client.iamDeleteGroup(groupName);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: `Group '${groupName}' deleted`,
                  groupName,
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
  // Tag User
  // ===========================================================================
  server.tool(
    'aws_iam_tag_user',
    `Add or update tags on an IAM user.

Args:
  - userName: The user name (required)
  - tags: Array of tags to add (required)

Returns confirmation.`,
    {
      userName: z.string().describe('User name'),
      tags: z.array(z.object({
        key: z.string().describe('Tag key'),
        value: z.string().describe('Tag value'),
      })).min(1).describe('Tags to add'),
    },
    async ({ userName, tags }) => {
      try {
        await client.iamTagUser(userName, tags);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'User tagged',
                  userName,
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
  // Untag User
  // ===========================================================================
  server.tool(
    'aws_iam_untag_user',
    `Remove tags from an IAM user.

Args:
  - userName: The user name (required)
  - tagKeys: Array of tag keys to remove (required)

Returns confirmation.`,
    {
      userName: z.string().describe('User name'),
      tagKeys: z.array(z.string()).min(1).describe('Tag keys to remove'),
    },
    async ({ userName, tagKeys }) => {
      try {
        await client.iamUntagUser(userName, tagKeys);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Tags removed',
                  userName,
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
  // Tag Role
  // ===========================================================================
  server.tool(
    'aws_iam_tag_role',
    `Add or update tags on an IAM role.

Args:
  - roleName: The role name (required)
  - tags: Array of tags to add (required)

Returns confirmation.`,
    {
      roleName: z.string().describe('Role name'),
      tags: z.array(z.object({
        key: z.string().describe('Tag key'),
        value: z.string().describe('Tag value'),
      })).min(1).describe('Tags to add'),
    },
    async ({ roleName, tags }) => {
      try {
        await client.iamTagRole(roleName, tags);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Role tagged',
                  roleName,
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
  // Untag Role
  // ===========================================================================
  server.tool(
    'aws_iam_untag_role',
    `Remove tags from an IAM role.

Args:
  - roleName: The role name (required)
  - tagKeys: Array of tag keys to remove (required)

Returns confirmation.`,
    {
      roleName: z.string().describe('Role name'),
      tagKeys: z.array(z.string()).min(1).describe('Tag keys to remove'),
    },
    async ({ roleName, tagKeys }) => {
      try {
        await client.iamUntagRole(roleName, tagKeys);
        return {
          content: [
            {
              type: 'text',
              text: JSON.stringify(
                {
                  success: true,
                  message: 'Tags removed',
                  roleName,
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
}
