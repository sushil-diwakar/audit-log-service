# AI-Assisted Software Engineering System — Audit Log Service

A tamper-evident, append-only audit log service backend prototype built with **Java 21** and **Spring Boot 3.x**.

## Project Purpose

The primary objective of this service is to provide an immutable, cryptographically verifiable, append-only audit logging mechanism for sensitive operations within enterprise systems. The service ensures data integrity through cryptographic hash chaining, supports structured redaction without breaking chain integrity, enforces retention policies, and provides rich filtering, pagination, and export capabilities.

## Technology Stack

- **Runtime & Language**: Java 21 LTS
- **Framework**: Spring Boot 3.3.3
- **Data Persistence**: Spring Data JPA / Hibernate
- **Database**: MySQL 8
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

## Local Setup & Getting Started

### Prerequisites
- **Java Development Kit (JDK)** 21 installed and configured on your `PATH`.
- **Apache Maven** 3.9+ installed (or use standard Maven CLI).
- **MySQL Server** 8.x running locally or reachable via network.

### Environment Configuration

The application reads configuration dynamically from environment variables. No credentials are hardcoded.

| Environment Variable | Description | Default Value |
| :--- | :--- | :--- |
| `DB_URL` | Full JDBC database connection URL | `jdbc:mysql://localhost:3306/audit_log_db?...` |
| `DB_HOST` | MySQL hostname (if `DB_URL` not set) | `localhost` |
| `DB_PORT` | MySQL port (if `DB_URL` not set) | `3306` |
| `DB_NAME` | MySQL database name | `audit_log_db` |
| `DB_USERNAME` | MySQL database username | `root` |
| `DB_PASSWORD` | MySQL database password | *(empty)* |
| `PORT` | Application HTTP server port | `8080` |
| `JPA_DDL_AUTO` | Hibernate DDL auto-generation mode | `update` |
| `SHOW_SQL` | Log SQL queries to stdout | `false` |

### Database Initialization

Create a database in your local MySQL instance:

```sql
CREATE DATABASE IF NOT EXISTS audit_log_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
```

### Build & Run

1. **Compile & Package**:
   ```bash
   mvn clean package
   ```

2. **Run Tests**:
   ```bash
   mvn test
   ```

3. **Run Application**:
   ```bash
   # Using Maven
   mvn spring-boot:run

   # Or execute the packaged JAR
   java -jar target/audit-log-service-0.0.1-SNAPSHOT.jar
   ```

4. **Access API Documentation (Swagger UI)**:
   Once the application is running, open:
   [http://localhost:8080/swagger-ui.html](http://localhost:8080/swagger-ui.html)
