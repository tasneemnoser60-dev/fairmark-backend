# Production Readiness Checklist

## Security
- [ ] `JWT_SECRET` is long and private in production variables.
- [ ] `MONGO_URI` points to production MongoDB and is not hardcoded.
- [ ] `CORS_ORIGIN` is set to trusted frontend domains only (comma-separated).
- [ ] Rate limiting is active for public and auth routes.

## API Behavior
- [ ] `POST /api/auth/register` works for `student`, `doctor`, and `admin`.
- [ ] Doctor endpoints return only doctor-owned data.
- [ ] Student endpoints return only student-owned data.
- [ ] Admin update flow works: `PUT /admin/users/:id/profile`.

## Database
- [ ] Required indexes exist (`users.email`, `assignments.doctorId`, `submissions.assignmentId`, `submissions.studentId`).
- [ ] Duplicate email is rejected with clear `409` response.

## Deployment
- [ ] Railway deployment is on latest commit from `main`.
- [ ] Logs show `MongoDB connected` and `MongoDB indexes ensured`.
- [ ] Health endpoint returns `200`: `GET /health`.

## Testing
- [ ] `postman_test_collection.json` passes with Collection Runner.
- [ ] CI passes (`lint` + `postman-smoke`) on push/PR.
- [ ] Manual spot-check done for file upload endpoint.

## Documentation
- [ ] `README.md` reflects current endpoints and role behavior.
- [ ] Team uses one Postman collection file only.
