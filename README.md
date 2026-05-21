# Flutter Backend API (Node.js + Express + MongoDB)

Production-ready REST API for a Flutter app with email/password auth, JWT-based access control, and MongoDB.

## Features

- Email/password auth with JWT
- MongoDB + Mongoose models
- Role-based access control (student, doctor, admin)
- File uploads for model answers and student submissions
- Rate limiting, security headers, CORS, logging
- Request validation with Joi
- Single Postman collection test flow: `postman_test_collection.json`
- CI workflow on GitHub Actions (`lint` + Postman smoke run)

## Setup

1. Install dependencies:

```bash
npm install
```

2. Create `.env` from the example and fill in values:

```bash
# in project root
copy .env.example .env
```

Set a strong `JWT_SECRET` value before starting the server.

AI Detection service:

- `AI_DETECTION_URL` should point to the Flask service (default: `http://127.0.0.1:5000/predict`).
- See "AI Detection Service" section below.

3. Run the server:

```bash
npm run dev
```

The server will start on `PORT` (default `4000`).

### Environment Variables

Core:
- `PORT` (default `4000`)
- `MONGO_URI`
- `JWT_SECRET`

Recommended for production:
- `CORS_ORIGIN` (comma-separated allowed origins)
- `TRUST_PROXY` (default `1` for hosted environments)

## API Overview

Auth routes:

- `POST /api/auth/register`
- `POST /api/auth/login`

All routes (except `/health` and `/api/auth/*`) require:

```
Authorization: Bearer <jwt_token>
```

### Health

- `GET /health` -> `{ ok: true }`

## Testing

Postman collection:
- File: `postman_test_collection.json`
- Run in Postman Collection Runner, or by CLI:

```bash
npx newman run postman_test_collection.json --reporters cli
```

Local smoke script:

```bash
npm run smoke
```

Production checklist:
- See [`PRODUCTION_CHECKLIST.md`](./PRODUCTION_CHECKLIST.md)

### Assignments (doctor only for create + my)

- `POST /assignments`
- `GET /assignments`
- `GET /assignments/my`
- `GET /assignments/:id`
- `PUT /assignments/:id`
- `DELETE /assignments/:id`
- `POST /assignments/:id/model-answer` (upload file)
- `GET /assignments/:id/submissions` (doctor only)

`POST /assignments` supports both:
- `application/json` (text fields only)
- `multipart/form-data` (text fields + optional file in `file` / `image` / `images`)

### Submissions (student only for create + my)

- `POST /submissions`
- `GET /submissions/my`
- `GET /submissions/:id`
- `PUT /submissions/:id/grade` (doctor only)

### Results

- `GET /results/my` (student)
- `GET /results/assignment/:assignmentId` (doctor/admin)

### Analytics

- `GET /analytics/doctor` (doctor/admin)

### Doctor Exam APIs

- `GET /doctor/exams`
- `GET /doctor/exams/:examId/submissions`
- `GET /doctor/exams/:examId/results`
- `GET /doctor/results/ranking`
- `GET /doctor/results/:assignmentId/details`

### Users (admin only)

- `PUT /users/:id/role`

### AI Detection

- `POST /ai-detection` (any authenticated user)

## AI Detection Service

The AI detector runs as a separate Flask service under `services/AI_detection`.

From `services/AI_detection/AI_detection`:

```bash
python -m venv .venv
.venv\\Scripts\\activate
pip install -r requirements.txt
python app.py
```

Then set:

```
AI_DETECTION_URL=http://127.0.0.1:5000/predict
```

## Example curl Requests

```bash
# Register
curl -X POST http://localhost:4000/api/auth/register \
  -H "Content-Type: application/json" \
  -d '{"name":"Amina","email":"amina@example.com","password":"Passw0rd!"}'
```

```bash
# Login
curl -X POST http://localhost:4000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"amina@example.com","password":"Passw0rd!"}'
```

Replace `<TOKEN>` with the JWT returned from login/register.

```bash
# Create assignment (doctor) - JSON
curl -X POST http://localhost:4000/assignments \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"title":"Quiz 1","description":"Intro quiz","assignmentText":"Solve all questions","totalMark":10,"dueDate":"2026-03-01T12:00:00.000Z"}'
```

```bash
# Create assignment (doctor) - multipart (with file)
curl -X POST http://localhost:4000/assignments \
  -H "Authorization: Bearer <TOKEN>" \
  -F "title=Quiz 1" \
  -F "description=Intro quiz" \
  -F "assignmentText=Solve all questions in the attached paper" \
  -F "totalMark=10" \
  -F "dueDate=2026-03-01T12:00:00.000Z" \
  -F "file=@C:\\path\\to\\assignment-paper.pdf"
```

```bash
# Upload model answer (doctor)
curl -X POST http://localhost:4000/assignments/<ASSIGNMENT_ID>/model-answer \
  -H "Authorization: Bearer <TOKEN>" \
  -F "file=@C:\\path\\to\\model-answer.pdf"
```

```bash
# Submit assignment (student)
curl -X POST http://localhost:4000/submissions \
  -H "Authorization: Bearer <TOKEN>" \
  -F "assignmentId=<ASSIGNMENT_ID>" \
  -F "answerText=My answer" \
  -F "file=@C:\\path\\to\\answer.pdf"
```

```bash
# AI detection (manual)
curl -X POST http://localhost:4000/ai-detection \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"text":"This is my answer"}'
```

```bash
# Grade submission (doctor)
curl -X PUT http://localhost:4000/submissions/<SUBMISSION_ID>/grade \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"score":8}'
```

```bash
# Update user role (admin)
curl -X PUT http://localhost:4000/users/<USER_ID>/role \
  -H "Authorization: Bearer <TOKEN>" \
  -H "Content-Type: application/json" \
  -d '{"role":"doctor"}'
```
