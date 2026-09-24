package com.hackathon.securitymonitor;

import org.springframework.stereotype.Service;

@Service
public class SeverityService {

    public void applySeverity(Incident incident) {
        if (incident == null) {
            return;
        }

        int eventCount = incident.getEventCount();
        int affectedFiles = incident.getAffectedFiles() == null ? 0 : incident.getAffectedFiles().size();
        String severity = determineSeverity(eventCount, affectedFiles);

        incident.setSeverity(severity);
        incident.setSeverityReason(determineReason(severity, eventCount, affectedFiles));
    }

    public String determineSeverity(int eventCount, int affectedFiles) {
        if (eventCount > 10 || affectedFiles > 10) {
            return "CRITICAL";
        }
        if ((eventCount >= 6 && eventCount <= 10) || (affectedFiles >= 6 && affectedFiles <= 10)) {
            return "HIGH";
        }
        if ((eventCount >= 3 && eventCount <= 5) || (affectedFiles >= 3 && affectedFiles <= 5)) {
            return "MEDIUM";
        }
        return "LOW";
    }

    public String determineReason(String severity, int eventCount, int affectedFiles) {
        switch (severity) {
            case "CRITICAL":
                return "Extreme event volume or file impact indicates a severe incident.";
            case "HIGH":
                return "Multiple file changes detected within a short time window.";
            case "MEDIUM":
                return "Moderate event volume or file impact suggests a developing issue.";
            default:
                return "Only a small number of events affected a limited number of files.";
        }
    }
}
