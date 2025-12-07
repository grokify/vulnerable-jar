package com.example.vulnerabilities;

/**
 * OWASP A09:2021 - Security Logging and Monitoring Failures
 *
 * Demonstrates insufficient logging, monitoring, and incident response.
 */
public class A09_SecurityLoggingFailures {

    /**
     * VULNERABILITY: No Logging of Security Events
     * Failed login attempts are not logged
     */
    public boolean login(String username, String password) {
        // INSECURE: Failed login not logged
        if (!"admin".equals(username) || !"password".equals(password)) {
            return false;
        }
        return true;
    }

    /**
     * VULNERABILITY: Logging Sensitive Data
     * Passwords and tokens logged in plaintext
     */
    public void loginWithLogging(String username, String password, String token) {
        // INSECURE: Logging sensitive data
        System.out.println("Login attempt - Username: " + username +
                         ", Password: " + password +
                         ", Token: " + token);
    }

    /**
     * VULNERABILITY: Insufficient Log Detail
     * Missing critical context like IP, timestamp, user agent
     */
    public void logActivity(String action) {
        // INSECURE: Missing IP address, timestamp, session ID, etc.
        System.out.println("Action: " + action);
    }

    /**
     * VULNERABILITY: No Audit Trail
     * Sensitive operations not logged
     */
    public void deleteAllUsers() {
        // INSECURE: Critical operation with no audit trail
        System.out.println("All users deleted");
    }

    /**
     * VULNERABILITY: Log Injection
     * User input not sanitized before logging
     */
    public void logUserInput(String userInput) {
        // INSECURE: User can inject fake log entries with \n
        System.out.println("User input: " + userInput);
    }

    /**
     * VULNERABILITY: Silent Failures
     * Exceptions caught and ignored without logging
     */
    public void processPayment(String creditCard) {
        try {
            // Payment processing logic
            throw new Exception("Payment failed");
        } catch (Exception e) {
            // INSECURE: Exception swallowed without logging
        }
    }

    /**
     * VULNERABILITY: No Monitoring of Suspicious Activity
     * Multiple failed attempts not tracked or alerted
     */
    public boolean authenticateWithoutMonitoring(String username, String password) {
        // INSECURE: No tracking of failed attempts or rate limiting
        return "admin".equals(username) && "password123".equals(password);
    }

    /**
     * VULNERABILITY: Logs Not Protected
     * Logs accessible to unauthorized users
     */
    public String getLogFile() {
        // INSECURE: Log files should have restricted access
        return "/var/log/app.log";
    }

    /**
     * VULNERABILITY: No Integrity Protection for Logs
     * Logs can be modified without detection
     */
    public void modifyLog(String logEntry) {
        // INSECURE: No signing or integrity check for log entries
        System.out.println("Modified log: " + logEntry);
    }

    /**
     * VULNERABILITY: Missing Security Event Logging
     * Privilege escalation not logged
     */
    public void grantAdminAccess(String username) {
        // INSECURE: Security-critical operation not logged
        System.out.println("Admin access granted to " + username);
    }

    /**
     * VULNERABILITY: No Alerting on Critical Events
     * No alerts for suspicious patterns
     */
    public void detectBruteForce(String username, int attemptCount) {
        // INSECURE: No alerting even after many failed attempts
        if (attemptCount > 100) {
            // Should trigger alert but doesn't
        }
    }

    /**
     * VULNERABILITY: Insufficient Log Retention
     * Logs deleted too quickly
     */
    public void rotateLogsDaily() {
        // INSECURE: 1-day retention is insufficient for security investigation
        System.out.println("Deleting logs older than 1 day");
    }
}
