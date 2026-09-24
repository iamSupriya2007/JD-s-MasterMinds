package com.hackathon.securitymonitor;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;

class HashServiceTest {

    @Test
    void shouldTrackBaselineStatusForCreatedModifiedFiles() throws IOException {
        HashService hashService = new HashService();
        Path tempFile = Files.createTempFile("baseline-test", ".txt");

        Files.writeString(tempFile, "hello world");
        assertEquals("BASELINE_CREATED", hashService.updateBaseline(tempFile));

        assertEquals("FILE_UNCHANGED", hashService.updateBaseline(tempFile));

        Files.writeString(tempFile, "hello world!");
        assertEquals("FILE_CHANGED", hashService.updateBaseline(tempFile));
    }
}
