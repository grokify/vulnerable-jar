package com.example.vulnerabilities;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;

/**
 * OWASP A01:2021 - Broken Access Control
 *
 * Demonstrates vulnerabilities where users can access resources or perform actions
 * beyond their intended permissions.
 */
public class A01_BrokenAccessControl {

    /**
     * VULNERABILITY: Path Traversal
     * Allows users to access files outside intended directory using ../
     */
    public String readUserFile(String filename) throws IOException {
        // INSECURE: No validation of filename - allows path traversal
        File file = new File("/var/app/users/" + filename);
        return new String(Files.readAllBytes(file.toPath()));
    }

    /**
     * VULNERABILITY: Insecure Direct Object Reference (IDOR)
     * User ID taken directly from request without authorization check
     */
    public String getUserData(String userId) {
        // INSECURE: No check if current user is authorized to view this userId
        return "SELECT * FROM users WHERE id = " + userId;
    }

    /**
     * VULNERABILITY: Missing Access Control Check
     * Admin function with no authorization validation
     */
    public void deleteUser(String userId) {
        // INSECURE: No check if caller has admin privileges
        System.out.println("Deleting user: " + userId);
    }

    /**
     * VULNERABILITY: File path manipulation
     * Allows arbitrary file access through user-controlled path
     */
    public byte[] downloadFile(String filepath) throws IOException {
        // INSECURE: User controls entire filepath
        return Files.readAllBytes(Paths.get(filepath));
    }

    /**
     * VULNERABILITY: URL-based access control bypass
     * Checks permissions based on URL pattern instead of proper authorization
     */
    public boolean isAdminPage(String url) {
        // INSECURE: Easily bypassed by URL manipulation
        return url.contains("/admin/");
    }
}
