# Database ER Diagram

```mermaid
erDiagram
    USER ||--o{ SCAN : owns
    USER ||--o{ REPOSITORY_AUTHORIZATION : grants
    REPOSITORY_AUTHORIZATION ||--o{ SCAN : authorizes
    SCAN ||--o{ FINDING : contains
    SCAN ||--o{ RECOMMENDATION : generates
    USER ||--o{ AUDIT_EVENT : generates

    USER {
        bigint id PK
        string username UK
        string email UK
        boolean ai_consent
        datetime ai_consent_at
        datetime created_at
    }

    REPOSITORY_AUTHORIZATION {
        bigint id PK
        bigint user_id FK
        string repository
        string token_fingerprint
        string scopes
        datetime authorized_at
        datetime expires_at
        datetime last_scanned_at
        boolean is_active
    }

    SCAN {
        uuid id PK
        bigint user_id FK
        bigint authorization_id FK
        string scan_type
        string status
        string source_name
        string source_hash
        string mime_type
        bigint size_bytes
        json metadata
        json summary
        int risk_score
        string risk_level
        text ai_summary
        boolean ai_used
        text error_message
        datetime created_at
        datetime started_at
        datetime completed_at
    }

    FINDING {
        bigint id PK
        uuid scan_id FK
        string category
        string severity
        string title
        string redacted_evidence
        string redacted_context
        string fingerprint
        string location
        text explanation
        text remediation
        float confidence
        string source_tool
        boolean false_positive
        datetime created_at
    }

    RECOMMENDATION {
        bigint id PK
        uuid scan_id FK
        string title
        text description
        int priority
        string category
        string action_key
    }

    AUDIT_EVENT {
        bigint id PK
        bigint user_id FK
        string action
        string target
        json metadata
        datetime created_at
    }
```

## Constraints and privacy notes

- `USER.email` and `USER.username` are unique; authentication uses `email`.
- `REPOSITORY_AUTHORIZATION(user_id, repository)` is unique. The token itself is never stored; `token_fingerprint` is SHA-256 of the supplied token.
- `FINDING(scan_id, fingerprint)` is unique, preventing duplicate detections per scan.
- `FINDING.redacted_evidence`/`redacted_context` contain placeholders only. The raw matched value is never persisted.
- `SCAN.source_name` is sanitized before persistence (emails and phone-like sequences are replaced with placeholders).
- `SCAN.metadata` stores counts, field names and engine status rather than raw document metadata values.
- `AUDIT_EVENT.metadata` stores counts, booleans and status values only; raw text, detected secrets and tokens are never written to the audit log.
- PostgreSQL is used in production; a SQLite fallback exists for local development only.
