# SecureCheck API

Web-Based REST API Security Checker with JWT Authentication and Role-Based Access Control (User / single Admin).
 
## Stack
Node.js + Express, MySQL 8, Docker, vanilla JS frontend

## Run
```bash
docker compose up --build
```
- Web: http://localhost:3000
- MySQL: localhost:3307

## Default Admin
- Email: `admin@securecheck.local`
- Password: `Admin@1234`

## Main Endpoints
| Method | Path | Access |
|---|---|---|
| POST | /api/auth/register | public |
| POST | /api/auth/login | public |
| POST | /api/auth/logout | public |
| POST | /api/auth/forgot-password | public |
| POST | /api/auth/reset-password | public |
| GET/PUT | /api/users/me | user |
| PUT | /api/users/me/password | user |
| GET | /api/users/me/scans | user |
| POST | /api/scans | user |
| GET | /api/admin/dashboard, /users, /scans, /history, /logs | admin |
| DELETE | /api/admin/users/:id | admin |
