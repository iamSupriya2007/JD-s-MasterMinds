package com.hackathon.securitymonitor;

import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardWatchEventKinds;
import java.nio.file.WatchEvent;
import java.nio.file.WatchKey;
import java.nio.file.WatchService;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

@Component
public class FileSystemWatcher {

    private static final Logger log = LoggerFactory.getLogger(FileSystemWatcher.class);
    private static final DateTimeFormatter TIMESTAMP_FORMATTER = DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss");

    private final HashService hashService;
    private final IncidentService incidentService;

    public FileSystemWatcher(HashService hashService, IncidentService incidentService) {
        this.hashService = hashService;
        this.incidentService = incidentService;
    }

    @PostConstruct
    public void startWatching() {
        Thread watcherThread = new Thread(this::watchLoop, "file-system-watcher");
        watcherThread.setDaemon(true);
        watcherThread.start();
        log.info("WatchService thread started.");
    }

    private Path resolveMonitoredFolder() {
        Path userDir = Paths.get(System.getProperty("user.dir")).toAbsolutePath().normalize();

        Path projectFolder = userDir.resolve("security-monitor");
        Path directFolder = userDir.resolve("monitored-folder");

        if (Files.exists(directFolder)) {
            return directFolder.toAbsolutePath().normalize();
        }

        if (Files.exists(projectFolder)) {
            return projectFolder.resolve("monitored-folder").toAbsolutePath().normalize();
        }

        return userDir.resolve("security-monitor").resolve("monitored-folder").toAbsolutePath().normalize();
    }

    private void watchLoop() {
        Path monitoredFolder = resolveMonitoredFolder();

        try {
            Files.createDirectories(monitoredFolder);
            log.info("Starting file system watcher for folder: {}", monitoredFolder);
        } catch (IOException e) {
            log.error("Could not create monitored folder: {}", monitoredFolder, e);
            return;
        }

        try (WatchService watchService = FileSystems.getDefault().newWatchService()) {
            monitoredFolder.register(
                    watchService,
                    StandardWatchEventKinds.ENTRY_CREATE,
                    StandardWatchEventKinds.ENTRY_MODIFY,
                    StandardWatchEventKinds.ENTRY_DELETE
            );

            log.info("Registered events: CREATE, MODIFY, DELETE");
            log.info("Watcher is active. Monitoring: {}", monitoredFolder);

            while (true) {
                WatchKey watchKey;

                try {
                    watchKey = watchService.take();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    log.warn("Watcher thread interrupted.");
                    return;
                }

                for (WatchEvent<?> event : watchKey.pollEvents()) {
                    WatchEvent.Kind<?> kind = event.kind();

                    if (kind == StandardWatchEventKinds.OVERFLOW) {
                        continue;
                    }

                    Path fileName = (Path) event.context();
                    if (fileName == null) {
                        continue;
                    }

                    Path fullPath = monitoredFolder.resolve(fileName);
                    LocalDateTime eventTime = LocalDateTime.now();
                    String timestamp = eventTime.format(TIMESTAMP_FORMATTER);

                    String hashText = "";
                    String baselineStatus = "";
                    if (kind == StandardWatchEventKinds.ENTRY_CREATE || kind == StandardWatchEventKinds.ENTRY_MODIFY) {
                        if (Files.exists(fullPath)) {
                            String fileHash = hashService.sha256(fullPath);
                            baselineStatus = " | baselineStatus=" + hashService.updateBaseline(fullPath, fileHash);
                            hashText = " | sha256=" + fileHash;
                            incidentService.recordEvent(fullPath, eventTime);
                        }
                    }

                    System.out.printf(
                            "[%s] eventType=%s | fileName=%s | fullPath=%s%s%s%n",
                            timestamp,
                            kind.name(),
                            fileName,
                            fullPath,
                            hashText,
                            baselineStatus
                    );
                }

                boolean isValid = watchKey.reset();
                if (!isValid) {
                    log.warn("Watch key is no longer valid. Stopping watcher.");
                    return;
                }
            }
        } catch (IOException e) {
            log.error("File watcher failed.", e);
        }
    }
}
