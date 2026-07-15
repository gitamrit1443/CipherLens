import { CommonModule } from "@angular/common";
import { Component, OnInit, computed, signal } from "@angular/core";
import { FormsModule } from "@angular/forms";
import { ApiService } from "./api.service";
import { Algorithm, ApiImage, ApiResult, HealthResponse, RegisterResponse } from "./models";

@Component({
  selector: "app-root",
  standalone: true,
  imports: [CommonModule, FormsModule],
  templateUrl: "./app.component.html"
})
export class AppComponent implements OnInit {
  readonly algorithms: Algorithm[] = ["xor", "aes", "3des", "perm", "rc4", "blowfish"];
  readonly apiOnline = signal(false);
  readonly health = signal<HealthResponse | null>(null);
  readonly loading = signal(false);
  readonly notice = signal("");
  readonly error = signal("");
  readonly authMode = signal<"login" | "register" | "verify">("login");
  readonly selectedImageId = signal<number | null>(null);
  readonly selectedAlgorithm = signal<Algorithm>("aes");
  readonly selectedBenchmark = signal<Record<Algorithm, boolean>>({
    xor: true,
    aes: true,
    "3des": false,
    perm: false,
    rc4: false,
    blowfish: false
  });
  readonly images = signal<ApiImage[]>([]);
  readonly results = signal<ApiResult[]>([]);
  readonly latestResult = signal<ApiResult | null>(null);
  readonly registerQr = signal<RegisterResponse | null>(null);
  readonly activeUser = computed(() => this.api.user());
  readonly signedIn = computed(() => Boolean(this.api.accessToken()));

  loginForm = { email: "", password: "" };
  registerForm = { full_name: "", email: "", password: "" };
  verifyForm = { code: "" };
  preAuthToken = "";
  processKey = "";
  uploadFile: File | null = null;

  constructor(readonly api: ApiService) {}

  ngOnInit(): void {
    this.checkHealth();
    if (this.signedIn()) {
      this.refreshWorkspace();
    }
  }

  checkHealth(): void {
    this.api.health().subscribe({
      next: (health) => {
        this.health.set(health);
        this.apiOnline.set(health.success);
      },
      error: () => {
        this.apiOnline.set(false);
      }
    });
  }

  register(): void {
    this.run(() =>
      this.api
        .register({
          full_name: this.registerForm.full_name || undefined,
          email: this.registerForm.email,
          password: this.registerForm.password
        })
        .subscribe({
          next: (response) => {
            this.registerQr.set(response);
            this.notice.set(response.message);
            this.loginForm.email = this.registerForm.email;
            this.loginForm.password = this.registerForm.password;
            this.authMode.set("login");
          },
          error: (error) => this.showError(error)
        })
    );
  }

  login(): void {
    this.run(() =>
      this.api.login(this.loginForm).subscribe({
        next: (response) => {
          this.preAuthToken = response.pre_auth_token;
          this.notice.set(response.message);
          this.authMode.set("verify");
        },
        error: (error) => this.showError(error)
      })
    );
  }

  verify(): void {
    this.run(() =>
      this.api.verify2fa(this.preAuthToken, this.verifyForm.code).subscribe({
        next: () => {
          this.notice.set("Signed in.");
          this.registerQr.set(null);
          this.verifyForm.code = "";
          this.refreshWorkspace();
        },
        error: (error) => this.showError(error)
      })
    );
  }

  logout(): void {
    this.api.logout().subscribe({
      next: () => {
        this.images.set([]);
        this.results.set([]);
        this.latestResult.set(null);
        this.notice.set("Signed out.");
      },
      error: () => this.api.clearSession()
    });
  }

  onFileChange(event: Event): void {
    const input = event.target as HTMLInputElement;
    this.uploadFile = input.files?.[0] ?? null;
  }

  upload(): void {
    if (!this.uploadFile) {
      this.error.set("Choose an image first.");
      return;
    }

    this.run(() =>
      this.api.upload(this.uploadFile as File).subscribe({
        next: (response) => {
          this.notice.set("Image uploaded.");
          this.selectedImageId.set(response.image.id);
          this.uploadFile = null;
          this.refreshWorkspace();
        },
        error: (error) => this.showError(error)
      })
    );
  }

  process(): void {
    const imageId = this.selectedImageId();
    if (!imageId || !this.processKey) {
      this.error.set("Select an image and enter an encryption key.");
      return;
    }

    this.run(() =>
      this.api.process(imageId, this.selectedAlgorithm(), this.processKey).subscribe({
        next: (response) => {
          this.latestResult.set(response.result);
          this.notice.set(`${response.result.algorithm.toUpperCase()} completed in ${response.processing_time_ms} ms.`);
          this.refreshResults(imageId);
        },
        error: (error) => this.showError(error)
      })
    );
  }

  benchmark(): void {
    const imageId = this.selectedImageId();
    const selected = this.algorithms.filter((algo) => this.selectedBenchmark()[algo]);
    if (!imageId || !this.processKey || selected.length === 0) {
      this.error.set("Select an image, key, and at least one algorithm.");
      return;
    }

    this.run(() =>
      this.api.benchmark(imageId, this.processKey, selected).subscribe({
        next: (response) => {
          const firstSuccess = response.results.find((result) => result.success && result.encrypted_image_url);
          this.latestResult.set(firstSuccess ?? null);
          this.notice.set(`Benchmark finished for ${response.results.length} algorithms.`);
          this.refreshResults(imageId);
        },
        error: (error) => this.showError(error)
      })
    );
  }

  selectImage(image: ApiImage): void {
    this.selectedImageId.set(image.id);
    this.latestResult.set(null);
    this.refreshResults(image.id);
  }

  deleteImage(image: ApiImage): void {
    this.run(() =>
      this.api.deleteImage(image.id).subscribe({
        next: () => {
          this.notice.set("Image deleted.");
          if (this.selectedImageId() === image.id) {
            this.selectedImageId.set(null);
            this.results.set([]);
          }
          this.refreshWorkspace();
        },
        error: (error) => this.showError(error)
      })
    );
  }

  deleteResult(result: ApiResult): void {
    this.run(() =>
      this.api.deleteResult(result.id).subscribe({
        next: () => {
          this.notice.set("Result deleted.");
          this.refreshResults(this.selectedImageId() ?? undefined);
        },
        error: (error) => this.showError(error)
      })
    );
  }

  setBenchmark(algo: Algorithm, checked: boolean): void {
    this.selectedBenchmark.update((current) => ({ ...current, [algo]: checked }));
  }

  selectedImage(): ApiImage | null {
    return this.images().find((image) => image.id === this.selectedImageId()) ?? null;
  }

  imageFor(result: ApiResult): ApiImage | null {
    return this.images().find((image) => image.id === result.image_id) ?? null;
  }

  formatBytes(value: number | null): string {
    if (!value) {
      return "0 B";
    }
    if (value < 1024) {
      return `${value} B`;
    }
    if (value < 1024 * 1024) {
      return `${(value / 1024).toFixed(1)} KB`;
    }
    return `${(value / 1024 / 1024).toFixed(1)} MB`;
  }

  metricValue(result: ApiResult, key: string): string {
    const value = result.metrics?.[key];
    return typeof value === "number" ? value.toFixed(key === "psnr" ? 2 : 4) : "-";
  }

  private refreshWorkspace(): void {
    this.api.images().subscribe({
      next: (response) => {
        this.images.set(response.images);
        if (!this.selectedImageId() && response.images.length > 0) {
          this.selectedImageId.set(response.images[0].id);
        }
        this.refreshResults(this.selectedImageId() ?? undefined);
      },
      error: (error) => this.showError(error)
    });
  }

  private refreshResults(imageId?: number): void {
    this.api.results(imageId).subscribe({
      next: (response) => this.results.set(response.results),
      error: (error) => this.showError(error)
    });
  }

  private run(start: () => void): void {
    this.loading.set(true);
    this.error.set("");
    this.notice.set("");
    start();
    setTimeout(() => this.loading.set(false), 250);
  }

  private showError(error: unknown): void {
    this.loading.set(false);
    this.error.set(this.formatError(error));
  }

  private formatError(error: unknown): string {
    const maybeHttp = error as {
      error?: { detail?: unknown; message?: unknown };
      message?: unknown;
    };

    const detail = maybeHttp.error?.detail;
    if (Array.isArray(detail)) {
      return detail
        .map((item) => {
          const validation = item as { loc?: unknown[]; msg?: string };
          const field = validation.loc?.filter((part) => part !== "body").join(".");
          return field ? `${field}: ${validation.msg}` : validation.msg;
        })
        .filter(Boolean)
        .join(" ");
    }

    if (typeof detail === "string") {
      return detail;
    }

    if (detail && typeof detail === "object") {
      const validation = detail as { msg?: string; message?: string };
      return validation.msg ?? validation.message ?? JSON.stringify(detail);
    }

    if (typeof maybeHttp.error?.message === "string") {
      return maybeHttp.error.message;
    }

    if (typeof maybeHttp.message === "string") {
      return maybeHttp.message;
    }

    return "Request failed.";
  }
}
