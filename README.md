# AI-Assisted Software Engineering System — Audit Log Service

A tamper-evident, append-only audit log service backend prototype built with **Java 21**, **Spring Boot 3.x**, and **MySQL 8**.

## Project Purpose

The primary objective of this service is to provide an immutable, cryptographically verifiable, append-only audit logging mechanism for sensitive operations within enterprise systems. The service ensures data integrity through cryptographic hash chaining, supports structured redaction without breaking chain integrity, enforces retention policies, and provides rich filtering, pagination, and export capabilities.

## Technology Stack

- **Runtime & Language**: Java 21 LTS
- **Framework**: Spring Boot 3.3.3
- **Data Persistence**: Spring Data JPA / Hibernate
- **Database**: MySQL 8 (local installation; no Docker)
- **Validation**: Jakarta Bean Validation API
- **API Documentation**: Springdoc OpenAPI 2.x (Swagger UI)
- **Utilities**: Project Lombok
- **Testing**: JUnit 5, Mockito, Spring Boot Test Starter
- **Build Tool**: Apache Maven

## Project Structure

```text
com.example.auditlog
├── controller    # REST API endpoints & request routing
├── service       # Core business logic & interfaces
├── repository    # Spring Data JPA repositories & database access
├── entity        # JPA domain models / database entities
├── dto           # Data Transfer Objects for API requests/responses
├── exception     # Custom exception classes & global exception handlers
├── config        # Spring configurations (OpenAPI, security, etc.)
└── util          # Helper utilities (hashing, canonicalization, etc.)
```

## Local Setup & Configuration

### Prerequisites
- **Java Development Kit (JDK)** 21 installed and configured on your `PATH`.
- **Apache Maven** 3.9+ installed.
- **MySQL 8 Server** installed and running locally on `localhost:3306`.

### Database Preparation

Ensure the target database exists in your local MySQL instance:

```sql
CREATE DATABASE IF NOT EXISTS auditdb CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

### Environment Variables

Database credentials and host parameters are supplied securely via environment variables. Never commit actual passwords to version control.

| Environment Variable | Description | Default / Example Value | Required |
| :--- | :--- | :--- | :--- |
| `DB_USERNAME` | Local MySQL username | `your_mysql_username` (e.g., `root`) | **Yes** |
| `DB_PASSWORD` | Local MySQL password | `your_mysql_password` | **Yes** |
| `DB_HOST` | MySQL server host | `localhost` | No |
| `DB_PORT` | MySQL server port | `3306` | No |
| `DB_NAME` | MySQL database name | `auditdb` | No |
| `DB_URL` | Override full JDBC URL | *(Derived from host/port/name)* | No |
| `PORT` | Application HTTP server port | `8080` | No |
| `JPA_DDL_AUTO` | Hibernate DDL mode | `update` | No |
| `SHOW_SQL` | Log SQL queries | `false` | No |

### Setting Environment Variables Locally

#### Windows (PowerShell)
```powershell
$env:DB_USERNAME="<your_username>"
$env:DB_PASSWORD="<your_password>"
```

#### Windows (Command Prompt)
```cmd
set DB_USERNAME=<your_username>
set DB_PASSWORD=<your_password>
```

#### macOS / Linux (Bash / Zsh)
```bash
export DB_USERNAME="<your_username>"
export DB_PASSWORD="<your_password>"
```

---

## Build & Run

1. **Compile and Run Tests** (verifies local MySQL connectivity):
   ```bash
   mvn clean test
   ```

2. **Run Application**:
   ```bash
   mvn spring-boot:run
   ```

3. **Access API Documentation (Swagger UI)**:
   Once the application is running, open:
   [http://localhost:8080/swagger-ui.html](http://localhost:8080/swagger-ui.html)
