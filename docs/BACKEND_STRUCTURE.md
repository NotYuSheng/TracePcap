# TracePcap Backend - Project Structure

## Architecture

**Layered Architecture:**
```
Controller Layer → Service Layer → Repository Layer → Database
                ↓                  ↓
            MinIO Storage     PCAP Analysis
```

**Design Patterns:**
- **MVC Pattern**: Controllers handle HTTP, Services handle business logic
- **Repository Pattern**: Data access abstraction
- **DTO Pattern**: Separate API contracts from domain models
- **Mapper Pattern**: Convert between DTOs and Entities
- **Strategy Pattern**: Different analysis strategies for protocols
- **Observer Pattern**: Async progress updates

## Project Structure

```
TracePcap/
└── backend/
    ├── src/
    │   ├── main/
    │   │   ├── java/
    │   │   │   └── com/
    │   │   │       └── tracepcap/
    │   │   │           ├── TracepcapApplication.java         # Main application class
    │   │   │           │
    │   │   │           ├── config/                           # Configuration classes
    │   │   │           │   ├── MinioConfig.java             # MinIO client configuration
    │   │   │           │   ├── AsyncConfig.java             # Async processing config
    │   │   │           │   ├── OpenApiConfig.java           # Swagger/OpenAPI config
    │   │   │           │   ├── WebConfig.java               # CORS and web config
    │   │   │           │   └── DatabaseConfig.java          # Database configuration
    │   │   │           │
    │   │   │           ├── common/                          # Shared components
    │   │   │           │   ├── exception/                   # Exception handling
    │   │   │           │   │   ├── GlobalExceptionHandler.java
    │   │   │           │   │   ├── ResourceNotFoundException.java
    │   │   │           │   │   ├── InvalidFileException.java
    │   │   │           │   │   ├── StorageException.java
    │   │   │           │   │   └── AnalysisException.java
    │   │   │           │   │
    │   │   │           │   ├── validation/                  # Custom validators
    │   │   │           │   │   ├── FileValidator.java
    │   │   │           │   │   └── PcapValidator.java
    │   │   │           │   │
    │   │   │           │   ├── dto/                         # Common DTOs
    │   │   │           │   │   ├── ErrorResponse.java
    │   │   │           │   │   ├── PageResponse.java
    │   │   │           │   │   └── ApiResponse.java
    │   │   │           │   │
    │   │   │           │   └── util/                        # Utility classes
    │   │   │           │       ├── DateUtils.java
    │   │   │           │       └── FileUtils.java
    │   │   │           │
    │   │   │           ├── file/                            # File management feature
    │   │   │           │   ├── controller/
    │   │   │           │   │   └── FileController.java      # REST endpoints for files
    │   │   │           │   │
    │   │   │           │   ├── service/
    │   │   │           │   │   ├── FileService.java         # Business logic
    │   │   │           │   │   ├── FileServiceImpl.java
    │   │   │           │   │   ├── StorageService.java      # MinIO operations
    │   │   │           │   │   └── StorageServiceImpl.java
    │   │   │           │   │
    │   │   │           │   ├── repository/
    │   │   │           │   │   └── FileRepository.java      # JPA repository
    │   │   │           │   │
    │   │   │           │   ├── entity/
    │   │   │           │   │   └── FileEntity.java          # Database entity
    │   │   │           │   │
    │   │   │           │   ├── dto/
    │   │   │           │   │   ├── FileUploadResponse.java
    │   │   │           │   │   ├── FileMetadataDto.java
    │   │   │           │   │   └── FileListDto.java
    │   │   │           │   │
    │   │   │           │   └── mapper/
    │   │   │           │       └── FileMapper.java          # Entity ↔ DTO mapping
    │   │   │           │
    │   │   │           ├── analysis/                        # Analysis feature
    │   │   │           │   ├── controller/
    │   │   │           │   │   └── AnalysisController.java
    │   │   │           │   │
    │   │   │           │   ├── service/
    │   │   │           │   │   ├── AnalysisService.java
    │   │   │           │   │   ├── AnalysisServiceImpl.java
    │   │   │           │   │   ├── PcapParserService.java   # PCAP file parsing
    │   │   │           │   │   └── ProtocolAnalyzer.java    # Protocol analysis
    │   │   │           │   │
    │   │   │           │   ├── repository/
    │   │   │           │   │   └── AnalysisRepository.java
    │   │   │           │   │
    │   │   │           │   ├── entity/
    │   │   │           │   │   └── AnalysisEntity.java
    │   │   │           │   │
    │   │   │           │   ├── dto/
    │   │   │           │   │   ├── AnalysisSummaryDto.java
    │   │   │           │   │   ├── ProtocolStatsDto.java
    │   │   │           │   │   └── FiveWsDto.java
    │   │   │           │   │
    │   │   │           │   ├── mapper/
    │   │   │           │   │   └── AnalysisMapper.java
    │   │   │           │   │
    │   │   │           │   └── worker/
    │   │   │           │       ├── AnalysisWorker.java      # Async analysis
    │   │   │           │       └── AnalysisTaskExecutor.java
    │   │   │           │
    │   │   │           ├── conversation/                    # Conversation feature
    │   │   │           │   ├── controller/
    │   │   │           │   │   └── ConversationController.java
    │   │   │           │   ├── service/
    │   │   │           │   │   ├── ConversationService.java
    │   │   │           │   │   └── ConversationServiceImpl.java
    │   │   │           │   ├── repository/
    │   │   │           │   │   ├── ConversationRepository.java
    │   │   │           │   │   └── PacketRepository.java
    │   │   │           │   ├── entity/
    │   │   │           │   │   ├── ConversationEntity.java
    │   │   │           │   │   └── PacketEntity.java
    │   │   │           │   ├── dto/
    │   │   │           │   │   ├── ConversationDto.java
    │   │   │           │   │   ├── PacketDto.java
    │   │   │           │   │   └── SessionDto.java
    │   │   │           │   └── mapper/
    │   │   │           │       └── ConversationMapper.java
    │   │   │           │
    │   │   │           ├── timeline/                        # Timeline feature
    │   │   │           │   ├── controller/
    │   │   │           │   │   └── TimelineController.java
    │   │   │           │   ├── service/
    │   │   │           │   │   ├── TimelineService.java
    │   │   │           │   │   └── TimelineServiceImpl.java
    │   │   │           │   ├── repository/
    │   │   │           │   │   └── TimelineRepository.java
    │   │   │           │   ├── entity/
    │   │   │           │   │   └── TimelineDataEntity.java
    │   │   │           │   ├── dto/
    │   │   │           │   │   └── TimelineDataDto.java
    │   │   │           │   └── mapper/
    │   │   │           │       └── TimelineMapper.java
    │   │   │           │
    │   │   │           ├── story/                           # Story/Narrative feature
    │   │   │           │   ├── controller/
    │   │   │           │   │   └── StoryController.java
    │   │   │           │   ├── service/
    │   │   │           │   │   ├── StoryService.java
    │   │   │           │   │   ├── StoryServiceImpl.java
    │   │   │           │   │   └── NarrativeGenerator.java  # AI narrative
    │   │   │           │   ├── repository/
    │   │   │           │   │   └── StoryRepository.java
    │   │   │           │   ├── entity/
    │   │   │           │   │   └── StoryEntity.java
    │   │   │           │   ├── dto/
    │   │   │           │   │   ├── StoryDto.java
    │   │   │           │   │   ├── NarrativeSectionDto.java
    │   │   │           │   │   └── HighlightDto.java
    │   │   │           │   └── mapper/
    │   │   │           │       └── StoryMapper.java
    │   │   │           │
    │   │   │           └── admin/                           # Admin features
    │   │   │               ├── controller/
    │   │   │               │   └── StorageAdminController.java
    │   │   │               └── service/
    │   │   │                   ├── StorageAdminService.java
    │   │   │                   └── CleanupService.java
    │   │   │
    │   │   └── resources/
    │   │       ├── application.yml                          # Main config
    │   │       ├── application-dev.yml                      # Dev environment
    │   │       ├── application-prod.yml                     # Prod environment
    │   │       ├── logback-spring.xml                       # Logging config
    │   │       └── db/
    │   │           └── migration/                           # Flyway migrations
    │   │               ├── V1__create_files_table.sql
    │   │               ├── V2__create_analysis_table.sql
    │   │               ├── V3__create_conversation_table.sql
    │   │               ├── V4__create_timeline_table.sql
    │   │               └── V5__create_story_table.sql
    │   │
    │   └── test/
    │       └── java/
    │           └── com/
    │               └── tracepcap/
    │                   ├── file/
    │                   │   ├── FileServiceTest.java
    │                   │   ├── FileControllerTest.java
    │                   │   └── StorageServiceTest.java
    │                   ├── analysis/
    │                   │   ├── AnalysisServiceTest.java
    │                   │   └── PcapParserServiceTest.java
    │                   └── integration/
    │                       ├── FileUploadIntegrationTest.java
    │                       └── AnalysisIntegrationTest.java
    │
    ├── pom.xml                                              # Maven dependencies
    ├── .gitignore
    └── README.md

```

## Layer Responsibilities

### 1. Controller Layer
- Handle HTTP requests/responses
- Validate request parameters
- Map DTOs to/from JSON
- Return appropriate HTTP status codes
- **No business logic**

### 2. Service Layer
- Implement business logic
- Transaction management
- Call repositories for data access
- Call external services (MinIO, AI)
- Async processing coordination

### 3. Repository Layer
- Data access using Spring Data JPA
- Custom queries with @Query
- Pagination and sorting

### 4. Entity Layer
- JPA entities mapping to database tables
- Relationships (@OneToMany, @ManyToOne, etc.)
- Audit fields (createdAt, updatedAt)

### 5. DTO Layer
- API request/response contracts
- Validation annotations (@NotNull, @Size, etc.)
- Separate from entities for flexibility

### 6. Mapper Layer
- Convert between Entity ↔ DTO
- Use MapStruct for automated mapping
- Custom mapping logic when needed

## Key Dependencies (pom.xml)

```xml
<dependencies>
    <!-- Spring Boot Starters -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-data-jpa</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-validation</artifactId>
    </dependency>

    <!-- Database -->
    <dependency>
        <groupId>org.postgresql</groupId>
        <artifactId>postgresql</artifactId>
    </dependency>
    <dependency>
        <groupId>org.flywaydb</groupId>
        <artifactId>flyway-core</artifactId>
    </dependency>

    <!-- MinIO -->
    <dependency>
        <groupId>io.minio</groupId>
        <artifactId>minio</artifactId>
        <version>8.5.7</version>
    </dependency>

    <!-- PCAP Parsing -->
    <dependency>
        <groupId>org.pcap4j</groupId>
        <artifactId>pcap4j-core</artifactId>
        <version>1.8.2</version>
    </dependency>

    <!-- Mapping -->
    <dependency>
        <groupId>org.mapstruct</groupId>
        <artifactId>mapstruct</artifactId>
        <version>1.5.5.Final</version>
    </dependency>

    <!-- OpenAPI/Swagger -->
    <dependency>
        <groupId>org.springdoc</groupId>
        <artifactId>springdoc-openapi-starter-webmvc-ui</artifactId>
        <version>2.3.0</version>
    </dependency>

    <!-- Lombok -->
    <dependency>
        <groupId>org.projectlombok</groupId>
        <artifactId>lombok</artifactId>
    </dependency>

    <!-- Testing -->
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-test</artifactId>
        <scope>test</scope>
    </dependency>
</dependencies>
```

## Configuration Files

### application.yml
```yaml
spring:
  application:
    name: tracepcap
  profiles:
    active: dev
  datasource:
    url: jdbc:postgresql://localhost:5432/tracepcap
    username: tracepcap_user
    password: tracepcap_pass
  jpa:
    hibernate:
      ddl-auto: validate
    show-sql: false
  servlet:
    multipart:
      max-file-size: 100MB
      max-request-size: 100MB

minio:
  endpoint: http://localhost:9000
  access-key: minioadmin
  secret-key: minioadmin
  bucket: tracepcap-files
  max-file-size: 104857600

server:
  port: 8080

logging:
  level:
    com.tracepcap: DEBUG
```

## Best Practices Applied

1. **Package by Feature**: Related classes grouped together
2. **Separation of Concerns**: Each layer has single responsibility
3. **Interface Segregation**: Services have interfaces
4. **Dependency Injection**: Constructor injection preferred
5. **Immutability**: Use `final` fields and Lombok `@Value` for DTOs
6. **Validation**: Bean Validation at controller layer
7. **Exception Handling**: Global exception handler
8. **Logging**: SLF4J with Logback
9. **Testing**: Unit tests + Integration tests
10. **Documentation**: OpenAPI/Swagger auto-generated docs
11. **Database Migrations**: Flyway for versioned schema
12. **Async Processing**: @Async for long-running tasks
13. **Transaction Management**: @Transactional where needed
14. **Clean Code**: Meaningful names, small methods
15. **SOLID Principles**: Applied throughout

## Next Steps

1. Initialize Spring Boot project with Spring Initializr
2. Set up database schema with Flyway
3. Implement file upload feature first
4. Add MinIO integration
5. Implement PCAP parsing
6. Build analysis engine
7. Create REST endpoints
8. Add tests
9. Deploy and test

Ready to start implementing?
