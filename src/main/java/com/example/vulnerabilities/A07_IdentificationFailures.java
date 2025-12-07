package com.example.vulnerabilities;

import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

/**
 * OWASP A07:2021 - Identification and Authentication Failures
 *
 * Demonstrates authentication and session management vulnerabilities.
 */
public class A07_IdentificationFailures {

    private Map<String, String> sessions = new HashMap<>();
    private Map<String, String> users = new HashMap<>();

    /**
     * VULNERABILITY: Weak Password Requirements
     * Allows weak passwords without complexity requirements
     */
    public boolean registerUser(String username, String password) {
        // INSECURE: No password complexity requirements
        if (password.length() >= 1) {
            users.put(username, password);
            return true;
        }
        return false;
    }

    /**
     * VULNERABILITY: Credentials in URL
     * Passing credentials as URL parameters
     */
    public String buildLoginURL(String username, String password) {
        // INSECURE: Credentials in URL will be logged and cached
        return "https://example.com/login?username=" + username + "&password=" + password;
    }

    /**
     * VULNERABILITY: Predictable Session IDs
     * Using sequential or simple session identifiers
     */
    private int sessionCounter = 1000;

    public String createPredictableSession(String username) {
        // INSECURE: Predictable session ID
        String sessionId = "SESSION_" + sessionCounter++;
        sessions.put(sessionId, username);
        return sessionId;
    }

    /**
     * VULNERABILITY: Session Fixation
     * Reusing session ID after authentication
     */
    public String login(String username, String password, String existingSessionId) {
        if (authenticate(username, password)) {
            // INSECURE: Should create new session ID after login
            sessions.put(existingSessionId, username);
            return existingSessionId;
        }
        return null;
    }

    /**
     * VULNERABILITY: No Session Timeout
     * Sessions never expire
     */
    public boolean isSessionValid(String sessionId) {
        // INSECURE: No timeout check
        return sessions.containsKey(sessionId);
    }

    /**
     * VULNERABILITY: Weak Password Recovery
     * Security question with easily guessable answers
     */
    public boolean resetPassword(String username, String mothersMaidenName) {
        // INSECURE: Weak authentication method for password reset
        return "Smith".equals(mothersMaidenName);
    }

    /**
     * VULNERABILITY: Username Enumeration
     * Different responses reveal whether username exists
     */
    public String loginWithEnumeration(String username, String password) {
        if (!users.containsKey(username)) {
            // INSECURE: Reveals that username doesn't exist
            return "Username not found";
        }
        if (!users.get(username).equals(password)) {
            // INSECURE: Reveals that username exists but password is wrong
            return "Invalid password";
        }
        return "Login successful";
    }

    /**
     * VULNERABILITY: Session Stored in Client-Side Cookie
     * Trusting client-side session data
     */
    public String createClientSideSession(String username, String role) {
        // INSECURE: Session data in client-controlled cookie
        return "username=" + username + ";role=" + role + ";admin=false";
    }

    /**
     * VULNERABILITY: Insufficient Authentication for Sensitive Operations
     * No re-authentication required for critical actions
     */
    public void changePassword(String sessionId, String newPassword) {
        // INSECURE: Should require current password or re-authentication
        String username = sessions.get(sessionId);
        if (username != null) {
            users.put(username, newPassword);
        }
    }

    /**
     * VULNERABILITY: Brute Force - No CAPTCHA
     * No CAPTCHA or other protection against automated attacks
     */
    public boolean loginWithoutCaptcha(String username, String password) {
        // INSECURE: No CAPTCHA or rate limiting
        return authenticate(username, password);
    }

    private boolean authenticate(String username, String password) {
        return users.containsKey(username) && users.get(username).equals(password);
    }
}
