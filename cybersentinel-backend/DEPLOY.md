# CyberSentinel Backend — AWS Deployment

## What is included in this repo

| Artifact | Purpose |
|----------|---------|
| `Dockerfile` | Production image (FastAPI + ML models + Supabase client) |
| `docker-compose.yml` | Local prod-like test before AWS |
| `.github/workflows/backend-tests.yml` | CI: pytest + Docker build on PR/push |
| `.github/workflows/aws-ecr-deploy.yml` | Push image to Amazon ECR on `backend` branch |

## Recommended AWS architecture (FYP / production)

```
Internet → ALB → ECS Fargate (Docker) → Supabase Postgres (managed DB)
                      ↓
                 Secrets Manager (.env values)
```

- **Compute:** ECS Fargate (no server management) or EC2 + Docker
- **Database:** Keep **Supabase** (already configured) — no need to run Postgres on AWS
- **Image registry:** Amazon ECR
- **Secrets:** AWS Secrets Manager or ECS task environment from GitHub Actions secrets
- **HTTPS:** Application Load Balancer + ACM certificate

Packet capture / Windows firewall monitor **do not work** inside a typical Linux container — core API, ML inference, and auth work fine.

## 1. One-time AWS setup

### ECR repository

```bash
aws ecr create-repository --repository-name cybersentinel-backend --region ap-south-1
```

### ECS (Fargate) — high level

1. Create ECS cluster
2. Create task definition (1 vCPU, 2 GB RAM minimum for ML models)
3. Container image: `<account>.dkr.ecr.ap-south-1.amazonaws.com/cybersentinel-backend:latest`
4. Port mapping: `8000`
5. Health check path: `/health`
6. Create ALB target group → ECS service (desired count: 1+)

### GitHub repository secrets

| Secret | Description |
|--------|-------------|
| `AWS_ACCESS_KEY_ID` | IAM user/role for ECR push (+ optional ECS deploy) |
| `AWS_SECRET_ACCESS_KEY` | Matching secret key |

### GitHub repository variables (optional)

| Variable | Example | Purpose |
|----------|---------|---------|
| `AWS_REGION` | `ap-south-1` | ECR region |
| `ECR_REPOSITORY` | `cybersentinel-backend` | Repository name |
| `ECS_CLUSTER` | `cybersentinel` | Auto redeploy after push |
| `ECS_SERVICE` | `cybersentinel-api` | Auto redeploy after push |

## 2. Required environment variables (ECS task / `.env`)

Copy from `.env.example`. **Never commit real `.env`.**

| Variable | Required | Notes |
|----------|----------|-------|
| `DATABASE_URL` | Yes | Supabase pooler URL (`postgresql+asyncpg://...`) |
| `JWT_SECRET_KEY` | Yes | `python -c "import secrets; print(secrets.token_hex(32))"` |
| `CORS_ORIGINS` | Yes | Your Flutter/web frontend URL(s) |
| `RESEND_API_KEY` or `SMTP_*` | For password reset | |
| `FRONTEND_RESET_PASSWORD_URL` | For password reset | Production frontend URL |
| `VIRUSTOTAL_API_KEY` | Optional | Threat intel |
| `ABUSEIPDB_API_KEY` | Optional | IP reputation |
| `DEBUG` | No | Must be `false` in production |

Model paths default to `../supervised_learning/models` and `../unsupervised_learning/models` — correct inside the Docker image.

## 3. Build and run locally with Docker

```powershell
cd cybersentinel
docker compose up --build
```

Open http://127.0.0.1:8000/docs

## 4. Manual push to ECR

```powershell
aws ecr get-login-password --region ap-south-1 | docker login --username AWS --password-stdin <account>.dkr.ecr.ap-south-1.amazonaws.com
docker build -t cybersentinel-backend .
docker tag cybersentinel-backend:latest <account>.dkr.ecr.ap-south-1.amazonaws.com/cybersentinel-backend:latest
docker push <account>.dkr.ecr.ap-south-1.amazonaws.com/cybersentinel-backend:latest
```

## 5. CI/CD flow

1. Push to `backend` → **backend-tests** runs pytest + Docker build
2. Push to `backend` → **aws-ecr-deploy** pushes image to ECR (if AWS secrets set)
3. If `ECS_CLUSTER` + `ECS_SERVICE` variables are set → ECS rolling deploy

## 6. Post-deploy checks

```bash
curl https://your-alb-domain/health
curl -X POST https://your-alb-domain/api/v1/auth/token -d "username=admin@cybersentinel.local&password=..."
```

Expect `database: ok` and `database_provider: supabase` in `/health`.
