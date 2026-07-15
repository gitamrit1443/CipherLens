import { Injectable, signal } from "@angular/core";
import { HttpClient, HttpHeaders } from "@angular/common/http";
import { Observable, tap } from "rxjs";
import {
  Algorithm,
  ApiImage,
  ApiResult,
  HealthResponse,
  LoginResponse,
  RegisterResponse,
  User,
  VerifyResponse
} from "./models";

interface ListImagesResponse {
  success: boolean;
  images: ApiImage[];
  total: number;
}

interface ListResultsResponse {
  success: boolean;
  results: ApiResult[];
  total: number;
}

interface UploadResponse {
  success: boolean;
  image: ApiImage;
}

interface ProcessResponse {
  success: boolean;
  result: ApiResult;
  original_image_url: string;
  encrypted_image_url: string;
  processing_time_ms: number;
}

interface BenchmarkResponse {
  success: boolean;
  image_id: number;
  original_url: string;
  results: Array<ApiResult & { success: boolean; error?: string }>;
}

@Injectable({ providedIn: "root" })
export class ApiService {
  private readonly baseUrl = "http://127.0.0.1:8001";
  readonly accessToken = signal(localStorage.getItem("cipherlens_access") ?? "");
  readonly refreshToken = signal(localStorage.getItem("cipherlens_refresh") ?? "");
  readonly user = signal<User | null>(this.readUser());

  constructor(private readonly http: HttpClient) {}

  health(): Observable<HealthResponse> {
    return this.http.get<HealthResponse>(`${this.baseUrl}/api/health`);
  }

  register(payload: { email: string; password: string; full_name?: string }): Observable<RegisterResponse> {
    return this.http.post<RegisterResponse>(`${this.baseUrl}/api/auth/register`, payload);
  }

  login(payload: { email: string; password: string }): Observable<LoginResponse> {
    return this.http.post<LoginResponse>(`${this.baseUrl}/api/auth/login`, payload);
  }

  verify2fa(preAuthToken: string, code: string): Observable<VerifyResponse> {
    return this.http
      .post<VerifyResponse>(
        `${this.baseUrl}/api/auth/verify-2fa`,
        { code },
        { headers: this.bearer(preAuthToken) }
      )
      .pipe(tap((response) => this.saveSession(response)));
  }

  me(): Observable<{ success: boolean; user: User }> {
    return this.http.get<{ success: boolean; user: User }>(`${this.baseUrl}/api/auth/me`, {
      headers: this.authHeaders()
    });
  }

  logout(): Observable<{ success: boolean; message: string }> {
    return this.http
      .post<{ success: boolean; message: string }>(
        `${this.baseUrl}/api/auth/logout`,
        {},
        { headers: this.authHeaders() }
      )
      .pipe(tap(() => this.clearSession()));
  }

  upload(file: File): Observable<UploadResponse> {
    const form = new FormData();
    form.append("image", file);
    return this.http.post<UploadResponse>(`${this.baseUrl}/api/images/upload`, form, {
      headers: this.authHeaders()
    });
  }

  images(): Observable<ListImagesResponse> {
    return this.http.get<ListImagesResponse>(`${this.baseUrl}/api/images/`, {
      headers: this.authHeaders()
    });
  }

  deleteImage(imageId: number): Observable<{ success: boolean; message: string }> {
    return this.http.delete<{ success: boolean; message: string }>(`${this.baseUrl}/api/images/${imageId}`, {
      headers: this.authHeaders()
    });
  }

  process(imageId: number, algorithm: Algorithm, key: string): Observable<ProcessResponse> {
    return this.http.post<ProcessResponse>(
      `${this.baseUrl}/api/process`,
      { image_id: imageId, algorithm, key },
      { headers: this.authHeaders() }
    );
  }

  benchmark(imageId: number, key: string, algorithms: Algorithm[]): Observable<BenchmarkResponse> {
    return this.http.post<BenchmarkResponse>(
      `${this.baseUrl}/api/process/benchmark`,
      { image_id: imageId, key, algorithms },
      { headers: this.authHeaders() }
    );
  }

  results(imageId?: number): Observable<ListResultsResponse> {
    const query = imageId ? `?image_id=${imageId}` : "";
    return this.http.get<ListResultsResponse>(`${this.baseUrl}/api/process/results${query}`, {
      headers: this.authHeaders()
    });
  }

  deleteResult(resultId: number): Observable<{ success: boolean; message: string }> {
    return this.http.delete<{ success: boolean; message: string }>(`${this.baseUrl}/api/process/results/${resultId}`, {
      headers: this.authHeaders()
    });
  }

  clearSession(): void {
    localStorage.removeItem("cipherlens_access");
    localStorage.removeItem("cipherlens_refresh");
    localStorage.removeItem("cipherlens_user");
    this.accessToken.set("");
    this.refreshToken.set("");
    this.user.set(null);
  }

  private saveSession(response: VerifyResponse): void {
    localStorage.setItem("cipherlens_access", response.access_token);
    localStorage.setItem("cipherlens_refresh", response.refresh_token);
    localStorage.setItem("cipherlens_user", JSON.stringify(response.user));
    this.accessToken.set(response.access_token);
    this.refreshToken.set(response.refresh_token);
    this.user.set(response.user);
  }

  private authHeaders(): HttpHeaders {
    return this.bearer(this.accessToken());
  }

  private bearer(token: string): HttpHeaders {
    return new HttpHeaders({ Authorization: `Bearer ${token}` });
  }

  private readUser(): User | null {
    const raw = localStorage.getItem("cipherlens_user");
    if (!raw) {
      return null;
    }
    try {
      return JSON.parse(raw) as User;
    } catch {
      localStorage.removeItem("cipherlens_user");
      return null;
    }
  }
}
