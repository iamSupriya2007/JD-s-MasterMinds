package com.hackathon.securitymonitor;

import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.Map;

@Service
public class HashService {

    private final Map<String, String> baselineStore = new HashMap<>();

    public String sha256(Path filePath) {
        try {
            byte[] fileBytes = Files.readAllBytes(filePath);
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hashBytes = digest.digest(fileBytes);

            StringBuilder hex = new StringBuilder();
            for (byte current : hashBytes) {
                String value = Integer.toHexString(0xff & current);
                if (value.length() == 1) {
                    hex.append('0');
                }
                hex.append(value);
            }

            return hex.toString();
        } catch (IOException | NoSuchAlgorithmException e) {
            throw new IllegalStateException("Unable to calculate SHA-256 for file: " + filePath, e);
        }
    }

    public String updateBaseline(Path filePath) {
        return updateBaseline(filePath, sha256(filePath));
    }

    public String updateBaseline(Path filePath, String currentHash) {
        String normalizedPath = filePath.toAbsolutePath().normalize().toString();

        if (!baselineStore.containsKey(normalizedPath)) {
            baselineStore.put(normalizedPath, currentHash);
            return "BASELINE_CREATED";
        }

        String storedHash = baselineStore.get(normalizedPath);
        if (storedHash.equals(currentHash)) {
            return "FILE_UNCHANGED";
        }

        baselineStore.put(normalizedPath, currentHash);
        return "FILE_CHANGED";
    }
}
