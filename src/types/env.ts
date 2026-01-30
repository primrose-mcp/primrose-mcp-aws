/**
 * Environment Bindings for AWS MCP Server
 *
 * MULTI-TENANT ARCHITECTURE:
 * AWS credentials are passed via request headers, NOT stored in wrangler secrets.
 * This allows a single deployment to serve multiple AWS accounts.
 *
 * Required Headers:
 * - X-AWS-Access-Key-ID: AWS access key ID
 * - X-AWS-Secret-Access-Key: AWS secret access key
 *
 * Optional Headers:
 * - X-AWS-Region: AWS region (default: us-east-1)
 * - X-AWS-Session-Token: Session token for temporary credentials
 */

// =============================================================================
// Tenant Credentials (parsed from request headers)
// =============================================================================

export interface AwsCredentials {
  /** AWS Access Key ID (from X-AWS-Access-Key-ID header) */
  accessKeyId: string;

  /** AWS Secret Access Key (from X-AWS-Secret-Access-Key header) */
  secretAccessKey: string;

  /** AWS Region (from X-AWS-Region header, defaults to us-east-1) */
  region: string;

  /** AWS Session Token for temporary credentials (from X-AWS-Session-Token header) */
  sessionToken?: string;
}

/**
 * Parse AWS credentials from request headers
 */
export function parseAwsCredentials(request: Request, defaultRegion: string): AwsCredentials {
  const headers = request.headers;

  return {
    accessKeyId: headers.get('X-AWS-Access-Key-ID') || '',
    secretAccessKey: headers.get('X-AWS-Secret-Access-Key') || '',
    region: headers.get('X-AWS-Region') || defaultRegion,
    sessionToken: headers.get('X-AWS-Session-Token') || undefined,
  };
}

/**
 * Validate that required credentials are present
 */
export function validateAwsCredentials(credentials: AwsCredentials): void {
  if (!credentials.accessKeyId) {
    throw new Error('Missing X-AWS-Access-Key-ID header');
  }
  if (!credentials.secretAccessKey) {
    throw new Error('Missing X-AWS-Secret-Access-Key header');
  }
}

// =============================================================================
// Environment Configuration
// =============================================================================

export interface Env {
  /** Maximum character limit for responses */
  CHARACTER_LIMIT: string;

  /** Default page size for list operations */
  DEFAULT_PAGE_SIZE: string;

  /** Maximum page size allowed */
  MAX_PAGE_SIZE: string;

  /** Default AWS region */
  DEFAULT_REGION: string;

  /** KV namespace for caching (optional) */
  CACHE_KV?: KVNamespace;

  /** Durable Object namespace for MCP sessions */
  MCP_SESSIONS?: DurableObjectNamespace;

  /** Cloudflare AI binding (optional) */
  AI?: Ai;
}

// =============================================================================
// Helper Functions
// =============================================================================

/**
 * Get a numeric environment value with a default
 */
export function getEnvNumber(env: Env, key: keyof Env, defaultValue: number): number {
  const value = env[key];
  if (typeof value === 'string') {
    const parsed = Number.parseInt(value, 10);
    return Number.isNaN(parsed) ? defaultValue : parsed;
  }
  return defaultValue;
}

/**
 * Get the character limit from environment
 */
export function getCharacterLimit(env: Env): number {
  return getEnvNumber(env, 'CHARACTER_LIMIT', 50000);
}

/**
 * Get the default page size from environment
 */
export function getDefaultPageSize(env: Env): number {
  return getEnvNumber(env, 'DEFAULT_PAGE_SIZE', 20);
}

/**
 * Get the maximum page size from environment
 */
export function getMaxPageSize(env: Env): number {
  return getEnvNumber(env, 'MAX_PAGE_SIZE', 100);
}
