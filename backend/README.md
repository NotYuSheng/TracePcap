# TracePcap Backend

Spring Boot backend for TracePcap - PCAP file analysis and visualization tool.

## Tech Stack

- **Java 21**
- **Spring Boot 3.2.1**
- **PostgreSQL** - Metadata and analysis results
- **MinIO** - Object storage for PCAP files
- **Pcap4J** - PCAP file parsing
- **MapStruct** - Object mapping
- **Flyway** - Database migration
- **Swagger/OpenAPI** - API documentation

## Prerequisites

1. **Java 21** or higher
2. **Maven 3.8+**
3. **PostgreSQL 15+**
4. **MinIO** (or S3-compatible storage)

## Quick Start

### 1. Set up PostgreSQL

```bash
# Create database and user
psql -U postgres
CREATE DATABASE tracepcap;
CREATE USER tracepcap_user WITH PASSWORD 'tracepcap_pass';
GRANT ALL PRIVILEGES ON DATABASE tracepcap TO tracepcap_user;
```

### 2. Set up MinIO

```bash
# Using Docker
docker run -d \
  -p 9000:9000 \
  -p 9001:9001 \
  --name minio \
  -e "MINIO_ROOT_USER=minioadmin" \
  -e "MINIO_ROOT_PASSWORD=minioadmin" \
  -v /data/minio:/data \
  minio/minio server /data --console-address ":9001"

# Access MinIO Console: http://localhost:9001
# Create bucket: tracepcap-files
```

### 3. Configure Application

Copy and modify environment-specific configs:

```bash
cd backend
cp src/main/resources/application.yml src/main/resources/application-local.yml
# Edit application-local.yml with your settings
```

### 4. Build and Run

```bash
# Build
mvn clean package

# Run
mvn spring-boot:run

# Or run with specific profile
mvn spring-boot:run -Dspring-boot.run.profiles=dev
```

The application will start at http://localhost:8080

## API Documentation

Once running, access API docs at:
- **Swagger UI**: http://localhost:8080/swagger-ui.html
- **OpenAPI JSON**: http://localhost:8080/api-docs

## Project Structure

```
backend/
├── src/
│   ├── main/
│   │   ├── java/com/tracepcap/
│   │   │   ├── config/              # Configuration classes
│   │   │   ├── common/              # Shared utilities
│   │   │   ├── file/                # File management
│   │   │   ├── analysis/            # PCAP analysis
│   │   │   ├── conversation/        # Network conversations
│   │   │   ├── timeline/            # Traffic timeline
│   │   │   ├── story/               # Narrative generation
│   │   │   └── admin/               # Admin endpoints
│   │   └── resources/
│   │       ├── application.yml       # Main config
│   │       ├── application-dev.yml   # Dev config
│   │       ├── application-prod.yml  # Prod config
│   │       └── db/migration/        # Flyway SQL scripts
│   └── test/                        # Test files
├── pom.xml                          # Maven dependencies
└── README.md
```

## Architecture

**Layered Architecture:**
```
Controller → Service → Repository → Database
          ↓           ↓
      MinIO     PCAP Analysis
```

**Key Design Patterns:**
- Repository Pattern (Data Access)
- DTO Pattern (API Contracts)
- Service Layer (Business Logic)
- Strategy Pattern (Protocol Analysis)

## Configuration

### Environment Variables

**Database:**
- `DATABASE_URL` - PostgreSQL connection URL
- `DATABASE_USERNAME` - Database username
- `DATABASE_PASSWORD` - Database password

**MinIO:**
- `MINIO_ENDPOINT` - MinIO server endpoint
- `MINIO_ACCESS_KEY` - Access key
- `MINIO_SECRET_KEY` - Secret key
- `MINIO_BUCKET` - Bucket name

**Server:**
- `SERVER_PORT` - Server port (default: 8080)
- `SPRING_PROFILES_ACTIVE` - Active profile (dev/prod)

### application.yml

Key configurations:
- File upload size limit: 100MB
- Analysis timeout: 300 seconds
- Max concurrent analyses: 3
- Cleanup cron: Daily at 2 AM

## Database Schema

Schema is managed by Flyway migrations in `src/main/resources/db/migration/`

**Tables:**
- `files` - Uploaded PCAP file metadata
- `analysis_results` - Analysis summary and statistics
- `conversations` - Network conversations
- `packets` - Individual packet data
- `timeline_data` - Timeline aggregated data
- `stories` - Generated narratives

## Testing

```bash
# Run all tests
mvn test

# Run specific test class
mvn test -Dtest=FileServiceTest

# Run integration tests
mvn verify -P integration-tests

# Generate coverage report
mvn jacoco:report
```

## Building for Production

```bash
# Build JAR
mvn clean package -DskipTests

# JAR will be at: target/tracepcap-backend-1.0.0-SNAPSHOT.jar

# Run JAR
java -jar target/tracepcap-backend-1.0.0-SNAPSHOT.jar --spring.profiles.active=prod
```

## Docker Build

```dockerfile
# Dockerfile (to be created)
FROM eclipse-temurin:21-jre-alpine
WORKDIR /app
COPY target/*.jar app.jar
EXPOSE 8080
ENTRYPOINT ["java", "-jar", "app.jar"]
```

```bash
# Build image
docker build -t tracepcap-backend:1.0.0 .

# Run container
docker run -d \
  -p 8080:8080 \
  -e SPRING_PROFILES_ACTIVE=prod \
  -e DATABASE_URL=jdbc:postgresql://host:5432/tracepcap \
  -e MINIO_ENDPOINT=http://minio:9000 \
  tracepcap-backend:1.0.0
```

## Development

### Code Style
- Follow Java Code Conventions
- Use Lombok to reduce boilerplate
- Write meaningful variable/method names
- Add Javadoc for public APIs

### Git Workflow
```bash
# Create feature branch
git checkout -b feature/your-feature

# Make changes and commit
git add .
git commit -m "feat: add feature description"

# Push and create PR
git push origin feature/your-feature
```

### Useful Maven Commands

```bash
# Clean build
mvn clean install

# Skip tests
mvn clean install -DskipTests

# Run specific profile
mvn spring-boot:run -Dspring-boot.run.profiles=dev

# Update dependencies
mvn versions:display-dependency-updates

# Format code
mvn fmt:format
```

## Troubleshooting

### Database Connection Issues
```bash
# Check PostgreSQL is running
psql -U postgres -c "SELECT version();"

# Test connection
psql -U tracepcap_user -d tracepcap
```

### MinIO Connection Issues
```bash
# Check MinIO is accessible
curl http://localhost:9000/minio/health/live

# Create bucket via mc CLI
mc alias set local http://localhost:9000 minioadmin minioadmin
mc mb local/tracepcap-files
```

### Port Already in Use
```bash
# Find process using port 8080
lsof -i :8080

# Kill process
kill -9 <PID>
```

## Performance Tuning

### Database
- Increase connection pool size for high load
- Add indexes on frequently queried columns
- Use database query optimization

### File Upload
- Increase max file size if needed
- Use chunked upload for large files
- Configure multipart threshold

### Analysis
- Adjust batch size for PCAP processing
- Increase max concurrent analyses
- Use async processing for long operations

## Security

### API Security (To be implemented)
- JWT-based authentication
- Role-based access control
- Rate limiting
- Input validation

### File Security
- Validate PCAP file format
- Scan for malicious content
- Implement file size limits
- Secure MinIO access with pre-signed URLs

## Monitoring

### Health Check
```bash
curl http://localhost:8080/actuator/health
```

### Metrics
```bash
curl http://localhost:8080/actuator/metrics
```

### Logs
```bash
# View logs
tail -f logs/tracepcap-dev.log

# Search logs
grep "ERROR" logs/tracepcap-dev.log
```

## License

MIT License - see LICENSE file

## Support

For issues and questions:
- GitHub Issues: https://github.com/tracepcap/tracepcap/issues
- Email: support@tracepcap.com

## Roadmap

- [x] File upload and storage
- [ ] PCAP parsing engine
- [ ] Protocol analysis
- [ ] Conversation extraction
- [ ] Timeline aggregation
- [ ] AI narrative generation
- [ ] WebSocket progress updates
- [ ] Authentication and authorization
- [ ] Multi-tenant support
- [ ] Cloud deployment
