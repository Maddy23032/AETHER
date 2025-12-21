/**
 * Base API configuration and utilities
 */

const DEFAULT_API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

// Custom API URL storage
let customApiUrl: string | null = null;

/**
 * Set a custom API base URL (persists to localStorage)
 */
export function setApiBaseUrl(url: string): void {
  customApiUrl = url;
  if (typeof window !== 'undefined') {
    localStorage.setItem('aether_api_url', url);
  }
}

/**
 * Get the current API base URL
 */
export function getApiBaseUrl(): string {
  if (customApiUrl) return customApiUrl;
  
  if (typeof window !== 'undefined') {
    const stored = localStorage.getItem('aether_api_url');
    if (stored) {
      customApiUrl = stored;
      return stored;
    }
  }
  
  return DEFAULT_API_URL;
}

/**
 * Reset to default API URL
 */
export function resetApiBaseUrl(): void {
  customApiUrl = null;
  if (typeof window !== 'undefined') {
    localStorage.removeItem('aether_api_url');
  }
}

export interface ApiError {
  status: number;
  message: string;
  detail?: string;
}

export class ApiException extends Error {
  status: number;
  detail?: string;

  constructor(status: number, message: string, detail?: string) {
    super(message);
    this.name = 'ApiException';
    this.status = status;
    this.detail = detail;
  }
}

/**
 * Generic API request function with error handling
 */
export async function apiRequest<T>(
  endpoint: string,
  options: RequestInit = {}
): Promise<T> {
  const url = `${getApiBaseUrl()}${endpoint}`;
  
  try {
    const response = await fetch(url, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
    });

    if (!response.ok) {
      const errorData = await response.json().catch(() => ({}));
      throw new ApiException(
        response.status,
        errorData.detail || `API Error: ${response.status} ${response.statusText}`,
        errorData.detail
      );
    }

    return response.json();
  } catch (error) {
    if (error instanceof ApiException) {
      throw error;
    }
    
    // Network or other errors
    if (error instanceof TypeError && error.message === 'Failed to fetch') {
      throw new ApiException(
        0,
        'Unable to connect to the reconnaissance API. Please ensure the server is running.',
        'Network Error'
      );
    }
    
    throw new ApiException(
      500,
      error instanceof Error ? error.message : 'An unknown error occurred',
      'Unknown Error'
    );
  }
}

/**
 * Check if API is available
 */
export async function checkApiHealth(): Promise<boolean> {
  try {
    const response = await fetch(`${getApiBaseUrl()}/`);
    return response.ok;
  } catch {
    return false;
  }
}
