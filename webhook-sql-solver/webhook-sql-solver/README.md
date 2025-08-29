# Webhook SQL Solver (Spring Boot)

## Overview
This Spring Boot app:
1. On startup, generates a webhook by calling the Hiring API.
2. Receives a webhook URL and accessToken.
3. Selects the SQL problem based on registration number (last 2 digits).
4. Submits the final SQL query to the returned webhook URL with the provided JWT token.

No controllers/endpoints — everything runs automatically at startup.

## Your details (pre-filled)
- Name: Mariya Gracious
- RegNo: 22BCE11427
- Email: graciousmariya@gmail.com

## Build & Run
1. Build:
```bash
mvn -DskipTests package
```
2. Run:
```bash
java -jar target/webhook-sql-solver-1.0.0.jar
```

## Notes
- Authorization header is sent exactly as returned (no Bearer prefix). If you get 401, try adding 'Bearer '.
- The project contains the PostgreSQL final query for Question 1 (odd regNo).
