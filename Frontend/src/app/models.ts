export type Algorithm = "xor" | "aes" | "3des" | "perm" | "rc4" | "blowfish";

export interface User {
  id: number;
  email: string;
  full_name: string | null;
  is_2fa_enabled: boolean;
  created_at: string | null;
}

export interface ApiImage {
  id: number;
  url: string;
  filename: string;
  original_name: string | null;
  file_size: number | null;
  mime_type: string | null;
  uploaded_at: string | null;
  result_count: number;
}

export interface Metrics {
  mse?: number;
  psnr?: number;
  ssim?: number;
  npcr?: number;
  uaci?: number;
  entropy?: number;
  [key: string]: number | undefined;
}

export interface ApiResult {
  id: number;
  image_id: number;
  algorithm: Algorithm;
  metrics: Metrics;
  encrypted_image_url: string | null;
  processing_time_ms: number | null;
  created_at: string | null;
  original_image_url?: string | null;
}

export interface HealthResponse {
  success: boolean;
  status: string;
  version: string;
  framework: string;
  algorithms: Algorithm[];
}

export interface RegisterResponse {
  success: boolean;
  message: string;
  user: User;
  totp_uri: string;
  qr_code: string;
}

export interface LoginResponse {
  success: boolean;
  requires_2fa: boolean;
  pre_auth_token: string;
  message: string;
}

export interface VerifyResponse {
  success: boolean;
  message: string;
  access_token: string;
  refresh_token: string;
  token_type: string;
  user: User;
}
