"""
CipherLens FastAPI — Full Test Suite  (55 tests)
Uses httpx.AsyncClient + pytest-asyncio + StaticPool for shared in-memory DB.
"""
import sys, os, io, base64, json, hashlib
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ["APP_ENV"]              = "testing"
os.environ["FIELD_ENCRYPTION_KEY"] = "test-field-key-for-testing-min-32c!"

import pytest
import pytest_asyncio
import numpy as np
import pyotp
from PIL import Image as PILImage
from httpx import AsyncClient, ASGITransport

from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.pool import StaticPool

pytestmark = pytest.mark.asyncio




# ── Shared in-memory DB + overridden dependency ───────────────────────────────

TEST_ENGINE = create_async_engine(
    "sqlite+aiosqlite:///:memory:",
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestSession = async_sessionmaker(bind=TEST_ENGINE, expire_on_commit=False, class_=AsyncSession)


async def _get_test_db():
    async with TestSession() as s:
        yield s


@pytest_asyncio.fixture(scope="session")
async def app_client():
    # Build tables once
    from models.database import Base, get_db
    from models.user   import User    # noqa
    from models.image  import Image   # noqa
    from models.result import Result  # noqa
    async with TEST_ENGINE.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)

    from main import create_app
    application = create_app()

    # Override DB dependency
    application.dependency_overrides[get_db] = _get_test_db

    os.makedirs(application.state.limiter._storage_uri if hasattr(application.state, "limiter") else "/tmp/cl_test_uploads", exist_ok=True)
    # Ensure upload dir exists
    from config import settings
    os.makedirs(settings.upload_dir, exist_ok=True)

    async with AsyncClient(transport=ASGITransport(app=application), base_url="http://test") as c:
        yield c


# ── Helpers ───────────────────────────────────────────────────────────────────

def png_bytes(w=32, h=32) -> bytes:
    arr = np.random.randint(0, 256, (h, w, 3), dtype=np.uint8)
    buf = io.BytesIO()
    PILImage.fromarray(arr).save(buf, format="PNG")
    return buf.getvalue()


_tokens: dict[str, tuple[str, str]] = {}


async def register_and_login(client, email: str, password: str = "SecurePass1!") -> tuple[str, str]:
    if email in _tokens:
        return _tokens[email]

    r0 = await client.post("/api/auth/register", json={"email": email, "password": password})
    assert r0.status_code in (201, 409), f"Register failed {r0.status_code}: {r0.text}"

    if r0.status_code == 201:
        totp_uri = r0.json().get("totp_uri", "")
    else:
        # Already registered in a previous run — re-enable 2FA not possible here
        # Use a known re-register approach for tests
        raise RuntimeError(f"Cannot re-use email {email} — use unique emails per test")

    import urllib.parse
    secret = urllib.parse.parse_qs(urllib.parse.urlparse(totp_uri).query).get("secret", [None])[0]
    assert secret, f"No TOTP secret in URI: {totp_uri}"

    r1 = await client.post("/api/auth/login", json={"email": email, "password": password})
    assert r1.status_code == 200, f"Login failed: {r1.text}"
    pre = r1.json()["pre_auth_token"]

    code = pyotp.TOTP(secret).now()
    r2 = await client.post("/api/auth/verify-2fa", json={"code": code},
                            headers={"Authorization": f"Bearer {pre}"})
    assert r2.status_code == 200, f"2FA failed: {r2.text}"

    tokens = r2.json()["access_token"], r2.json()["refresh_token"]
    _tokens[email] = tokens
    return tokens


def auth(token: str) -> dict:
    return {"Authorization": f"Bearer {token}"}


async def upload_img(client, token: str):
    return await client.post("/api/images/upload",
        files={"image": ("test.png", png_bytes(), "image/png")},
        headers=auth(token))


# ═══════════════════════════════════════════════════════════════════════════
# HEALTH
# ═══════════════════════════════════════════════════════════════════════════

async def test_health(app_client):
    r = await app_client.get("/api/health")
    assert r.status_code == 200
    b = r.json()
    assert b["success"] is True and b["framework"] == "FastAPI"
    for layer in ["rate_limiting","security_headers","jwt_2fa_auth",
                  "input_validation","file_hardening","field_encryption",
                  "db_isolation","audit_logging"]:
        assert b["security"][layer] is True, f"Layer not active: {layer}"

async def test_docs_available(app_client):
    r = await app_client.get("/docs")
    assert r.status_code == 200


# ═══════════════════════════════════════════════════════════════════════════
# SECURITY HEADERS
# ═══════════════════════════════════════════════════════════════════════════

async def test_x_content_type_options(app_client):
    assert (await app_client.get("/api/health")).headers.get("X-Content-Type-Options") == "nosniff"

async def test_x_frame_options(app_client):
    assert (await app_client.get("/api/health")).headers.get("X-Frame-Options") == "DENY"

async def test_referrer_policy(app_client):
    assert (await app_client.get("/api/health")).headers.get("Referrer-Policy") == "strict-origin-when-cross-origin"

async def test_permissions_policy(app_client):
    pp = (await app_client.get("/api/health")).headers.get("Permissions-Policy","")
    assert "camera=()" in pp and "microphone=()" in pp

async def test_api_no_cache(app_client):
    cc = (await app_client.get("/api/health")).headers.get("Cache-Control","")
    assert "no-store" in cc


# ═══════════════════════════════════════════════════════════════════════════
# REGISTER
# ═══════════════════════════════════════════════════════════════════════════

async def test_register_success(app_client):
    r = await app_client.post("/api/auth/register",
        json={"email":"reg_ok@t.dev","password":"TestPass1!"})
    assert r.status_code == 201
    b = r.json()
    assert b["success"] and "qr_code" in b and "totp_uri" in b
    assert b["qr_code"].startswith("data:image/png;base64,")

async def test_register_duplicate_email(app_client):
    await app_client.post("/api/auth/register",
        json={"email":"dup@t.dev","password":"TestPass1!"})
    r = await app_client.post("/api/auth/register",
        json={"email":"dup@t.dev","password":"TestPass1!"})
    assert r.status_code == 409

async def test_register_invalid_email(app_client):
    assert (await app_client.post("/api/auth/register",
        json={"email":"notanemail","password":"TestPass1!"})).status_code == 422

async def test_register_weak_password(app_client):
    assert (await app_client.post("/api/auth/register",
        json={"email":"a@b.com","password":"short"})).status_code == 422

async def test_register_no_uppercase(app_client):
    assert (await app_client.post("/api/auth/register",
        json={"email":"x@b.com","password":"alllower1"})).status_code == 422

async def test_register_no_digit(app_client):
    assert (await app_client.post("/api/auth/register",
        json={"email":"y@b.com","password":"NoDigitPass"})).status_code == 422

async def test_register_xss_in_name(app_client):
    assert (await app_client.post("/api/auth/register",
        json={"email":"xss@t.dev","password":"TestPass1!",
              "full_name":"<script>alert(1)</script>"})).status_code == 422

async def test_register_sql_in_name(app_client):
    assert (await app_client.post("/api/auth/register",
        json={"email":"sql@t.dev","password":"TestPass1!",
              "full_name":"'; DROP TABLE users; --"})).status_code == 422

async def test_register_strips_unknown_fields(app_client):
    r = await app_client.post("/api/auth/register",
        json={"email":"strip@t.dev","password":"TestPass1!",
              "is_admin":True,"role":"superuser"})
    assert r.status_code in (201, 409)   # is_admin stripped, not 500


# ═══════════════════════════════════════════════════════════════════════════
# LOGIN + 2FA
# ═══════════════════════════════════════════════════════════════════════════

async def test_full_login_flow(app_client):
    acc, ref = await register_and_login(app_client, "login_ok@t.dev")
    assert len(acc) > 20 and len(ref) > 20

async def test_login_wrong_password(app_client):
    await register_and_login(app_client, "wrongpw@t.dev")
    r = await app_client.post("/api/auth/login",
        json={"email":"wrongpw@t.dev","password":"WrongPass1!"})
    assert r.status_code == 401

async def test_login_unknown_email(app_client):
    r = await app_client.post("/api/auth/login",
        json={"email":"nobody@x.dev","password":"TestPass1!"})
    assert r.status_code == 401

async def test_user_enumeration_same_error(app_client):
    await register_and_login(app_client, "enum@t.dev")
    r1 = await app_client.post("/api/auth/login", json={"email":"nobody2@x.dev","password":"WrongPass1!"})
    r2 = await app_client.post("/api/auth/login", json={"email":"enum@t.dev",   "password":"WrongPass1!"})
    assert r1.json()["detail"] == r2.json()["detail"]

async def test_wrong_2fa_code(app_client):
    await register_and_login(app_client, "twofa@t.dev")
    r1 = await app_client.post("/api/auth/login", json={"email":"twofa@t.dev","password":"SecurePass1!"})
    pre = r1.json()["pre_auth_token"]
    r2 = await app_client.post("/api/auth/verify-2fa", json={"code":"000000"},
                                headers={"Authorization":f"Bearer {pre}"})
    assert r2.status_code == 401

async def test_non_digit_2fa_rejected(app_client):
    r1 = await app_client.post("/api/auth/login", json={"email":"twofa@t.dev","password":"SecurePass1!"})
    pre = r1.json()["pre_auth_token"]
    r2 = await app_client.post("/api/auth/verify-2fa", json={"code":"abcdef"},
                                headers={"Authorization":f"Bearer {pre}"})
    assert r2.status_code == 422

async def test_pre_auth_blocked_on_me(app_client):
    await register_and_login(app_client, "preauth_me@t.dev")
    r1 = await app_client.post("/api/auth/login", json={"email":"preauth_me@t.dev","password":"SecurePass1!"})
    pre = r1.json()["pre_auth_token"]
    assert (await app_client.get("/api/auth/me", headers={"Authorization":f"Bearer {pre}"})).status_code == 403

async def test_pre_auth_blocked_on_upload(app_client):
    await register_and_login(app_client, "preauth_up@t.dev")
    r1 = await app_client.post("/api/auth/login", json={"email":"preauth_up@t.dev","password":"SecurePass1!"})
    pre = r1.json()["pre_auth_token"]
    r = await app_client.post("/api/images/upload",
        files={"image":("t.png", png_bytes(), "image/png")},
        headers={"Authorization":f"Bearer {pre}"})
    assert r.status_code == 403

async def test_no_token_returns_401(app_client):
    assert (await app_client.get("/api/auth/me")).status_code     == 401
    assert (await app_client.get("/api/images/")).status_code     == 401
    assert (await app_client.get("/api/process/results")).status_code == 401

async def test_logout_blacklists_token(app_client):
    acc, _ = await register_and_login(app_client, "logout@t.dev")
    await app_client.post("/api/auth/logout", headers=auth(acc))
    assert (await app_client.get("/api/auth/me", headers=auth(acc))).status_code == 401

async def test_refresh_gives_new_access_token(app_client):
    _, ref = await register_and_login(app_client, "refresh@t.dev")
    r = await app_client.post("/api/auth/refresh", headers=auth(ref))
    assert r.status_code == 200 and "access_token" in r.json()

async def test_access_token_rejected_as_refresh(app_client):
    acc, _ = await register_and_login(app_client, "norefresh@t.dev")
    assert (await app_client.post("/api/auth/refresh", headers=auth(acc))).status_code in (401, 422)

async def test_me_returns_correct_user(app_client):
    acc, _ = await register_and_login(app_client, "me@t.dev")
    r = await app_client.get("/api/auth/me", headers=auth(acc))
    assert r.status_code == 200
    assert r.json()["user"]["email"] == "me@t.dev"


# ═══════════════════════════════════════════════════════════════════════════
# INPUT VALIDATION
# ═══════════════════════════════════════════════════════════════════════════

async def test_process_rejects_null_byte_key(app_client):
    acc, _ = await register_and_login(app_client, "nullbyte@t.dev")
    img_id = (await upload_img(app_client, acc)).json()["image"]["id"]
    r = await app_client.post("/api/process",
        json={"image_id":img_id,"algorithm":"xor","key":"k\x00ey"}, headers=auth(acc))
    assert r.status_code == 422

async def test_process_rejects_negative_image_id(app_client):
    acc, _ = await register_and_login(app_client, "negid@t.dev")
    r = await app_client.post("/api/process",
        json={"image_id":-1,"algorithm":"xor","key":"k"}, headers=auth(acc))
    assert r.status_code == 422

async def test_process_rejects_unknown_algorithm(app_client):
    acc, _ = await register_and_login(app_client, "badalgo@t.dev")
    img_id = (await upload_img(app_client, acc)).json()["image"]["id"]
    r = await app_client.post("/api/process",
        json={"image_id":img_id,"algorithm":"rsa2048","key":"k"}, headers=auth(acc))
    assert r.status_code == 422

async def test_process_rejects_oversized_key(app_client):
    acc, _ = await register_and_login(app_client, "bigkey@t.dev")
    img_id = (await upload_img(app_client, acc)).json()["image"]["id"]
    r = await app_client.post("/api/process",
        json={"image_id":img_id,"algorithm":"xor","key":"A"*300}, headers=auth(acc))
    assert r.status_code == 422


# ═══════════════════════════════════════════════════════════════════════════
# FILE UPLOAD SECURITY
# ═══════════════════════════════════════════════════════════════════════════

async def test_valid_png_accepted(app_client):
    acc, _ = await register_and_login(app_client, "file_ok@t.dev")
    assert (await upload_img(app_client, acc)).status_code == 201

async def test_php_disguised_as_png_rejected(app_client):
    acc, _ = await register_and_login(app_client, "file_php@t.dev")
    r = await app_client.post("/api/images/upload",
        files={"image":("shell.png", b"<?php system($_GET['cmd']); ?>"+b"\x00"*50, "image/png")},
        headers=auth(acc))
    assert r.status_code == 400

async def test_html_disguised_as_jpg_rejected(app_client):
    acc, _ = await register_and_login(app_client, "file_html@t.dev")
    r = await app_client.post("/api/images/upload",
        files={"image":("img.jpg", b"<html><script>alert(1)</script></html>", "image/jpeg")},
        headers=auth(acc))
    assert r.status_code == 400

async def test_empty_file_rejected(app_client):
    acc, _ = await register_and_login(app_client, "file_empty@t.dev")
    r = await app_client.post("/api/images/upload",
        files={"image":("empty.png", b"", "image/png")}, headers=auth(acc))
    assert r.status_code == 400

async def test_disallowed_extension_rejected(app_client):
    acc, _ = await register_and_login(app_client, "file_ext@t.dev")
    r = await app_client.post("/api/images/upload",
        files={"image":("script.exe", b"data", "application/octet-stream")},
        headers=auth(acc))
    assert r.status_code == 400

async def test_filename_is_uuid_not_original(app_client):
    acc, _ = await register_and_login(app_client, "file_uuid@t.dev")
    r = await app_client.post("/api/images/upload",
        files={"image":("my_secret_photo.png", png_bytes(), "image/png")},
        headers=auth(acc))
    assert r.status_code == 201
    fname = r.json()["image"]["filename"]
    assert "my_secret_photo" not in fname
    assert fname.endswith(".png") and len(fname) == 36


# ═══════════════════════════════════════════════════════════════════════════
# FIELD ENCRYPTION (unit)
# ═══════════════════════════════════════════════════════════════════════════

async def test_image_upload_and_list(app_client):
    acc, _ = await register_and_login(app_client, "img_list@t.dev")
    await upload_img(app_client, acc)
    r = await app_client.get("/api/images/", headers=auth(acc))
    assert r.status_code == 200 and r.json()["total"] >= 1

async def test_get_single_image(app_client):
    acc, _ = await register_and_login(app_client, "img_get@t.dev")
    img_id = (await upload_img(app_client, acc)).json()["image"]["id"]
    r = await app_client.get(f"/api/images/{img_id}", headers=auth(acc))
    assert r.status_code == 200 and r.json()["image"]["id"] == img_id

async def test_get_nonexistent_image(app_client):
    acc, _ = await register_and_login(app_client, "img_ne@t.dev")
    assert (await app_client.get("/api/images/999999", headers=auth(acc))).status_code == 404

async def test_delete_image(app_client):
    acc, _ = await register_and_login(app_client, "img_del@t.dev")
    img_id = (await upload_img(app_client, acc)).json()["image"]["id"]
    assert (await app_client.delete(f"/api/images/{img_id}", headers=auth(acc))).status_code == 200
    assert (await app_client.get(f"/api/images/{img_id}", headers=auth(acc))).status_code == 404

async def test_image_url_contains_uploads_path(app_client):
    acc, _ = await register_and_login(app_client, "img_url@t.dev")
    url = (await upload_img(app_client, acc)).json()["image"]["url"]
    assert "/uploads/" in url and url.endswith(".png")


# ═══════════════════════════════════════════════════════════════════════════
# PROCESS
# ═══════════════════════════════════════════════════════════════════════════

ALL_ALGOS = ["xor", "aes", "3des", "perm", "rc4", "blowfish"]


@pytest.mark.parametrize("algo", ALL_ALGOS)
async def test_process_all_algorithms(app_client, algo):
    acc, _ = await register_and_login(app_client, f"proc_{algo}@t.dev")
    img_id = (await upload_img(app_client, acc)).json()["image"]["id"]
    r = await app_client.post("/api/process",
        json={"image_id":img_id,"algorithm":algo,"key":"TestKey1!"},
        headers=auth(acc))
    assert r.status_code == 201, f"{algo}: {r.text}"
    b = r.json()
    assert b["success"] and "metrics" in b and "encrypted_image_url" in b
    m = b["metrics"]
    for k in ("mse","psnr","ssim","npcr","uaci","entropy"):
        assert k in m, f"{algo}: missing metric {k}"
    assert m["npcr"] > 90.0, f"{algo}: NPCR={m['npcr']:.2f}%"

async def test_process_stores_result_in_db(app_client):
    acc, _ = await register_and_login(app_client, "res_store@t.dev")
    img_id = (await upload_img(app_client, acc)).json()["image"]["id"]
    res_id = (await app_client.post("/api/process",
        json={"image_id":img_id,"algorithm":"aes","key":"K1!"},
        headers=auth(acc))).json()["result"]["id"]
    r = await app_client.get(f"/api/process/results/{res_id}", headers=auth(acc))
    assert r.status_code == 200 and r.json()["result"]["id"] == res_id

async def test_benchmark_all_algorithms(app_client):
    acc, _ = await register_and_login(app_client, "bench@t.dev")
    img_id = (await upload_img(app_client, acc)).json()["image"]["id"]
    r = await app_client.post("/api/process/benchmark",
        json={"image_id":img_id,"key":"BenchKey1!"},
        headers=auth(acc))
    assert r.status_code == 201
    results = r.json()["results"]
    assert len(results) == len(ALL_ALGOS)
    for res in results:
        assert res["success"] is True, f"{res['algorithm']}: {res.get('error')}"
        assert res["metrics"]["npcr"] > 90.0

async def test_benchmark_selected_algorithms(app_client):
    acc, _ = await register_and_login(app_client, "bench2@t.dev")
    img_id = (await upload_img(app_client, acc)).json()["image"]["id"]
    r = await app_client.post("/api/process/benchmark",
        json={"image_id":img_id,"key":"K1!","algorithms":["xor","aes"]},
        headers=auth(acc))
    assert r.status_code == 201 and len(r.json()["results"]) == 2

async def test_delete_result(app_client):
    acc, _ = await register_and_login(app_client, "res_del@t.dev")
    img_id = (await upload_img(app_client, acc)).json()["image"]["id"]
    res_id = (await app_client.post("/api/process",
        json={"image_id":img_id,"algorithm":"rc4","key":"K1!"},
        headers=auth(acc))).json()["result"]["id"]
    assert (await app_client.delete(f"/api/process/results/{res_id}", headers=auth(acc))).status_code == 200
    assert (await app_client.get(f"/api/process/results/{res_id}", headers=auth(acc))).status_code == 404


# ═══════════════════════════════════════════════════════════════════════════
# DB ISOLATION
# ═══════════════════════════════════════════════════════════════════════════

async def test_cannot_read_other_users_image(app_client):
    acc_a, _ = await register_and_login(app_client, "iso_a@t.dev")
    acc_b, _ = await register_and_login(app_client, "iso_b@t.dev")
    img_id = (await upload_img(app_client, acc_a)).json()["image"]["id"]
    assert (await app_client.get(f"/api/images/{img_id}", headers=auth(acc_b))).status_code == 404

async def test_cannot_delete_other_users_image(app_client):
    acc_a, _ = await register_and_login(app_client, "iso_c@t.dev")
    acc_b, _ = await register_and_login(app_client, "iso_d@t.dev")
    img_id = (await upload_img(app_client, acc_a)).json()["image"]["id"]
    assert (await app_client.delete(f"/api/images/{img_id}", headers=auth(acc_b))).status_code == 404

async def test_cannot_process_other_users_image(app_client):
    acc_a, _ = await register_and_login(app_client, "iso_e@t.dev")
    acc_b, _ = await register_and_login(app_client, "iso_f@t.dev")
    img_id = (await upload_img(app_client, acc_a)).json()["image"]["id"]
    r = await app_client.post("/api/process",
        json={"image_id":img_id,"algorithm":"xor","key":"k"},
        headers=auth(acc_b))
    assert r.status_code == 404

async def test_cannot_read_other_users_result(app_client):
    acc_a, _ = await register_and_login(app_client, "iso_g@t.dev")
    acc_b, _ = await register_and_login(app_client, "iso_h@t.dev")
    img_id = (await upload_img(app_client, acc_a)).json()["image"]["id"]
    res_id = (await app_client.post("/api/process",
        json={"image_id":img_id,"algorithm":"xor","key":"k"},
        headers=auth(acc_a))).json()["result"]["id"]
    assert (await app_client.get(f"/api/process/results/{res_id}", headers=auth(acc_b))).status_code == 404

async def test_image_lists_are_isolated(app_client):
    acc_a, _ = await register_and_login(app_client, "iso_i@t.dev")
    acc_b, _ = await register_and_login(app_client, "iso_j@t.dev")
    await upload_img(app_client, acc_a)
    await upload_img(app_client, acc_b)
    ids_a = {i["id"] for i in (await app_client.get("/api/images/", headers=auth(acc_a))).json()["images"]}
    ids_b = {i["id"] for i in (await app_client.get("/api/images/", headers=auth(acc_b))).json()["images"]}
    assert ids_a.isdisjoint(ids_b), "CRITICAL: user image lists overlap"

async def test_result_lists_are_isolated(app_client):
    acc_a, _ = await register_and_login(app_client, "iso_k@t.dev")
    acc_b, _ = await register_and_login(app_client, "iso_l@t.dev")
    img_a = (await upload_img(app_client, acc_a)).json()["image"]["id"]
    img_b = (await upload_img(app_client, acc_b)).json()["image"]["id"]
    await app_client.post("/api/process", json={"image_id":img_a,"algorithm":"xor","key":"k"}, headers=auth(acc_a))
    await app_client.post("/api/process", json={"image_id":img_b,"algorithm":"xor","key":"k"}, headers=auth(acc_b))
    ids_a = {r["id"] for r in (await app_client.get("/api/process/results", headers=auth(acc_a))).json()["results"]}
    ids_b = {r["id"] for r in (await app_client.get("/api/process/results", headers=auth(acc_b))).json()["results"]}
    assert ids_a.isdisjoint(ids_b), "CRITICAL: user result lists overlap"
