/**
 * Error Handling Utilities for AWS MCP Server
 */

/**
 * Base AWS API error
 */
export class AwsApiError extends Error {
  public statusCode?: number;
  public code: string;
  public retryable: boolean;
  public requestId?: string;

  constructor(
    message: string,
    statusCode?: number,
    code?: string,
    retryable = false,
    requestId?: string
  ) {
    super(message);
    this.name = 'AwsApiError';
    this.statusCode = statusCode;
    this.code = code || 'AWS_ERROR';
    this.retryable = retryable;
    this.requestId = requestId;
  }
}

/**
 * Rate limit exceeded error (throttling)
 */
export class ThrottlingError extends AwsApiError {
  public retryAfterSeconds: number;

  constructor(message: string, retryAfterSeconds = 1) {
    super(message, 429, 'THROTTLING', true);
    this.name = 'ThrottlingError';
    this.retryAfterSeconds = retryAfterSeconds;
  }
}

/**
 * Authentication error
 */
export class AuthenticationError extends AwsApiError {
  constructor(message: string) {
    super(message, 401, 'AUTHENTICATION_FAILED', false);
    this.name = 'AuthenticationError';
  }
}

/**
 * Access denied error
 */
export class AccessDeniedError extends AwsApiError {
  constructor(message: string) {
    super(message, 403, 'ACCESS_DENIED', false);
    this.name = 'AccessDeniedError';
  }
}

/**
 * Resource not found error
 */
export class ResourceNotFoundError extends AwsApiError {
  constructor(resourceType: string, id: string) {
    super(`${resourceType} '${id}' not found`, 404, 'RESOURCE_NOT_FOUND', false);
    this.name = 'ResourceNotFoundError';
  }
}

/**
 * Validation error
 */
export class ValidationError extends AwsApiError {
  public details: Record<string, string[]>;

  constructor(message: string, details: Record<string, string[]> = {}) {
    super(message, 400, 'VALIDATION_ERROR', false);
    this.name = 'ValidationError';
    this.details = details;
  }
}

/**
 * Service unavailable error
 */
export class ServiceUnavailableError extends AwsApiError {
  constructor(message: string) {
    super(message, 503, 'SERVICE_UNAVAILABLE', true);
    this.name = 'ServiceUnavailableError';
  }
}

/**
 * Check if an error is retryable
 */
export function isRetryableError(error: unknown): boolean {
  if (error instanceof AwsApiError) {
    return error.retryable;
  }
  if (error instanceof Error) {
    const message = error.message.toLowerCase();
    return (
      message.includes('network') ||
      message.includes('timeout') ||
      message.includes('econnreset') ||
      message.includes('socket') ||
      message.includes('throttl')
    );
  }
  return false;
}

/**
 * Parse AWS error response
 */
export function parseAwsError(
  statusCode: number,
  responseBody: string,
  requestId?: string
): AwsApiError {
  let errorCode = 'UnknownError';
  let errorMessage = responseBody;

  // Try to parse XML error response
  const codeMatch = responseBody.match(/<Code>([^<]+)<\/Code>/);
  const messageMatch = responseBody.match(/<Message>([^<]+)<\/Message>/);

  if (codeMatch) {
    errorCode = codeMatch[1];
  }
  if (messageMatch) {
    errorMessage = messageMatch[1];
  }

  // Try to parse JSON error response
  try {
    const jsonError = JSON.parse(responseBody);
    if (jsonError.__type) {
      errorCode = jsonError.__type.split('#').pop() || errorCode;
    }
    if (jsonError.message || jsonError.Message) {
      errorMessage = jsonError.message || jsonError.Message;
    }
    if (jsonError.code || jsonError.Code) {
      errorCode = jsonError.code || jsonError.Code;
    }
  } catch {
    // Not JSON, use what we have
  }

  // Map common AWS error codes
  switch (errorCode) {
    case 'AccessDenied':
    case 'AccessDeniedException':
      return new AccessDeniedError(errorMessage);

    case 'InvalidAccessKeyId':
    case 'SignatureDoesNotMatch':
    case 'IncompleteSignature':
    case 'UnauthorizedException':
    case 'InvalidSignatureException':
      return new AuthenticationError(errorMessage);

    case 'Throttling':
    case 'ThrottlingException':
    case 'RequestLimitExceeded':
    case 'ProvisionedThroughputExceededException':
      return new ThrottlingError(errorMessage);

    case 'NoSuchBucket':
    case 'NoSuchKey':
    case 'ResourceNotFoundException':
    case 'NotFoundException':
      return new ResourceNotFoundError('Resource', errorMessage);

    case 'ServiceUnavailable':
    case 'ServiceUnavailableException':
      return new ServiceUnavailableError(errorMessage);

    case 'ValidationError':
    case 'ValidationException':
    case 'InvalidParameterValue':
    case 'MissingParameter':
      return new ValidationError(errorMessage);

    default:
      const retryable =
        statusCode >= 500 ||
        errorCode.includes('Throttl') ||
        errorCode.includes('ServiceUnavailable');
      return new AwsApiError(errorMessage, statusCode, errorCode, retryable, requestId);
  }
}

/**
 * Format an error for logging
 */
export function formatErrorForLogging(error: unknown): Record<string, unknown> {
  if (error instanceof AwsApiError) {
    return {
      name: error.name,
      message: error.message,
      code: error.code,
      statusCode: error.statusCode,
      retryable: error.retryable,
      requestId: error.requestId,
      ...(error instanceof ThrottlingError && { retryAfterSeconds: error.retryAfterSeconds }),
      ...(error instanceof ValidationError && { details: error.details }),
    };
  }
  if (error instanceof Error) {
    return {
      name: error.name,
      message: error.message,
      stack: error.stack,
    };
  }
  return { error: String(error) };
}
