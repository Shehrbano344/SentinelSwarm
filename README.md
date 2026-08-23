# SentinelSwarm AI SOC

SentinelSwarm is a multi-agent security triage system. It ingests security alerts, enriches them with live threat intelligence from abuse.ch, assesses severity using an LLM (Claude-based), and presents the reasoning trace and triage decisions on a React dashboard.

## Tech Stack
- **Database**: PostgreSQL
- **Backend**: FastAPI (Python), Uvicorn
- **Frontend**: React (Vite/Next), NPM

## Quickstart (Local Native Setup)

### 1. Database Setup
1. Install PostgreSQL on your machine (e.g. via `winget install PostgreSQL.PostgreSQL` or official installer).
2. Start the PostgreSQL service.
3. Create a database named `sentinelswarm` (and note your superuser password).

### 2. Environment Configuration
1. Copy `.env.example` to `.env`.
2. Update the `DATABASE_URL` in `.env` with your actual Postgres password:
   `DATABASE_URL=postgresql://postgres:<password>@localhost:5432/sentinelswarm`
3. Add your Anthropic API Key to `.env`.

### 3. Backend Setup
Navigate to the `backend` directory and start the API:
```bash
cd backend
pip install -r ../requirements.txt
uvicorn main:app --reload
```

### 4. Dashboard Setup
Navigate to the `dashboard` directory, install dependencies, and run the development server:
```bash
cd dashboard
npm install
npm run dev
```

The React dashboard will be accessible via your localhost (typically port 5173 or 3000), and the backend API will run on `http://127.0.0.1:8000`.
