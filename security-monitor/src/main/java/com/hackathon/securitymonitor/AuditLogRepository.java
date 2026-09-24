package com.hackathon.securitymonitor;

import org.springframework.data.mongodb.repository.MongoRepository;

public interface AuditLogRepository extends MongoRepository<AuditLogEntry, String> {
}
