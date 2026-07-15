# CipherLens

CipherLens is a full-stack image cryptography benchmarking application. It lets users register with 2FA, upload images, encrypt them with multiple algorithms, and compare encryption quality metrics from a web dashboard.

## Tech Stack

**Frontend**

- Angular 19
- Tailwind CSS
- DaisyUI

**Backend**

- FastAPI
- SQLAlchemy async
- SQLite with `aiosqlite`
- JWT authentication
- TOTP based 2FA
- Pillow, NumPy, PyCryptodome

## Features

- User registration and login
- Two-factor authentication with authenticator QR code
- Secure image upload
- Image encryption using XOR, AES, 3DES, permutation, RC4, and Blowfish
- Multi-algorithm benchmark mode
- Metrics table for MSE, PSNR, NPCR, UACI, entropy, and more
- Original and encrypted image preview
- Result history and deletion
- Responsive Angular dashboard

## Project Structure

```text
CipherLens/
|-- Backend/
|   |-- main.py
|   |-- config.py
|   |-- requirements.txt
|   |-- algorithms/
|   |-- models/
|   |-- routes/
|   |-- security/
|   |-- static/
|   |-- tests/
|   `-- utils/
|
|-- Frontend/
|   |-- angular.json
|   |-- package.json
|   |-- tailwind.config.js
|   |-- src/
|   |   |-- app/
|   |   |-- index.html
|   |   `-- styles.css
|   `-- README.md
|
`-- README.md
```

## Prerequisites

Install these before running the project:

- Python 3.11 or newer
- Node.js 20 or newer
- npm

Check versions:

```powershell
python --version
node --version
npm --version
```

## Backend Setup

Open a terminal:

```powershell
cd D:\CipherLens\Backend
python -m pip install -r requirements.txt
```

Run the backend on port `8001`:

```powershell
$env:BASE_URL = "http://127.0.0.1:8001"
python -m uvicorn main:app --host 127.0.0.1 --port 8001
```

Backend URLs:

```text
Health check: http://127.0.0.1:8001/api/health
Swagger docs: http://127.0.0.1:8001/docs
ReDoc:        http://127.0.0.1:8001/redoc
```

Note: this project uses port `8001` because port `8000` may already be used by another local API.

## Frontend Setup

Open a second terminal:

```powershell
cd D:\CipherLens\Frontend
npm install
npm start
```

Open the website:

```text
http://127.0.0.1:4200
```

The frontend is configured to call:

```text
http://127.0.0.1:8001
```

## How To Use

1. Start the backend.
2. Start the frontend.
3. Open `http://127.0.0.1:4200`.
4. Register a new account.
5. Use a strong password, for example `Test1234`.
6. Scan the 2FA QR code with Google Authenticator or another TOTP app.
7. Login and enter the 6-digit 2FA code.
8. Upload an image.
9. Select an encryption algorithm and enter a key.
10. Run encryption or benchmark multiple algorithms.
11. View metrics and encrypted image output.

## API Endpoints

### Auth

| Method | Endpoint | Description |
| --- | --- | --- |
| POST | `/api/auth/register` | Create account and get 2FA QR code |
| POST | `/api/auth/login` | Login with email and password |
| POST | `/api/auth/verify-2fa` | Verify TOTP code and get JWT tokens |
| POST | `/api/auth/refresh` | Refresh access token |
| POST | `/api/auth/logout` | Logout and revoke token |
| GET | `/api/auth/me` | Get current user |

### Images

| Method | Endpoint | Description |
| --- | --- | --- |
| POST | `/api/images/upload` | Upload image with multipart field `image` |
| GET | `/api/images/` | List uploaded images |
| GET | `/api/images/{image_id}` | Get image details |
| DELETE | `/api/images/{image_id}` | Delete image and related results |

### Processing

| Method | Endpoint | Description |
| --- | --- | --- |
| POST | `/api/process` | Encrypt one image with one algorithm |
| POST | `/api/process/benchmark` | Run multiple algorithms |
| GET | `/api/process/results` | List results |
| GET | `/api/process/results/{result_id}` | Get one result |
| DELETE | `/api/process/results/{result_id}` | Delete result |

## Supported Algorithms

- XOR
- AES
- 3DES
- Pixel permutation
- RC4
- Blowfish

## Common Issues

### Opening `http://127.0.0.1:8001/` shows 404

That is expected. The backend is an API, not the website.

Use:

```text
Frontend: http://127.0.0.1:4200
API docs: http://127.0.0.1:8001/docs
```

### `[object Object]` during registration

This was caused by raw validation error display. The frontend now formats FastAPI validation errors. Also make sure your password has:

- At least 8 characters
- One uppercase letter
- One lowercase letter
- One number

Example:

```text
Test1234
```

### `node` or `npm` is not recognized

Install Node.js from:

```text
https://nodejs.org/
```

Then close and reopen the terminal.

### Port `8000` is already in use

Run CipherLens backend on `8001`:

```powershell
python -m uvicorn main:app --host 127.0.0.1 --port 8001
```

### CORS or image URLs are wrong

Make sure the backend was started with:

```powershell
$env:BASE_URL = "http://127.0.0.1:8001"
```

## Testing Backend

```powershell
cd D:\CipherLens\Backend
python -m pytest
```

## Build Frontend

```powershell
cd D:\CipherLens\Frontend
npm run build
```

The production build will be generated inside:

```text
Frontend/dist/
```

## Environment Notes

The backend reads configuration from `Backend\.env` and environment variables. For production use, update secrets such as:

- `SECRET_KEY`
- `FIELD_ENCRYPTION_KEY`
- database settings
- allowed frontend origins

Do not use development secrets in production.
