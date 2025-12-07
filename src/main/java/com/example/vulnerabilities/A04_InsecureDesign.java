package com.example.vulnerabilities;

import java.util.HashMap;
import java.util.Map;

/**
 * OWASP A04:2021 - Insecure Design
 *
 * Demonstrates design flaws and missing security controls.
 */
public class A04_InsecureDesign {

    private Map<String, Integer> loginAttempts = new HashMap<>();

    /**
     * VULNERABILITY: No Rate Limiting
     * Allows unlimited login attempts enabling brute force attacks
     */
    public boolean login(String username, String password) {
        // INSECURE: No rate limiting or account lockout
        if (checkPassword(username, password)) {
            return true;
        }
        return false;
    }

    /**
     * VULNERABILITY: No Account Lockout
     * Account never gets locked despite failed attempts
     */
    public boolean loginWithTracking(String username, String password) {
        if (checkPassword(username, password)) {
            loginAttempts.put(username, 0);
            return true;
        } else {
            // INSECURE: Tracking attempts but no lockout mechanism
            int attempts = loginAttempts.getOrDefault(username, 0) + 1;
            loginAttempts.put(username, attempts);
            return false;
        }
    }

    /**
     * VULNERABILITY: Unlimited Resource Allocation
     * No limits on resource consumption
     */
    public void processUserData(int recordCount) {
        // INSECURE: No upper bound check - can cause DoS
        int[] data = new int[recordCount];
        for (int i = 0; i < recordCount; i++) {
            data[i] = i;
        }
    }

    /**
     * VULNERABILITY: Missing Transaction Verification
     * No confirmation required for sensitive operations
     */
    public void transferMoney(String fromAccount, String toAccount, double amount) {
        // INSECURE: No verification, CAPTCHA, or confirmation required
        System.out.println("Transferring $" + amount + " from " + fromAccount + " to " + toAccount);
    }

    /**
     * VULNERABILITY: Predictable Password Reset Tokens
     * Using simple sequential or timestamp-based tokens
     */
    public String generatePasswordResetToken(String username) {
        // INSECURE: Predictable token based on timestamp
        return username + "_" + System.currentTimeMillis();
    }

    /**
     * VULNERABILITY: No Business Logic Validation
     * Allows negative quantities or prices
     */
    public double calculateOrderTotal(int quantity, double price) {
        // INSECURE: No validation - negative values can bypass payment
        return quantity * price;
    }

    /**
     * VULNERABILITY: Race Condition
     * No synchronization on shared resource
     */
    private int accountBalance = 1000;

    public void withdraw(int amount) {
        // INSECURE: Race condition - multiple threads can overdraw
        if (accountBalance >= amount) {
            accountBalance -= amount;
        }
    }

    /**
     * VULNERABILITY: Missing Input Validation
     * Accepts unrealistic values without validation
     */
    public void updateAge(int age) {
        // INSECURE: No validation of age range
        System.out.println("Age updated to: " + age);
    }

    private boolean checkPassword(String username, String password) {
        return "admin".equals(username) && "password123".equals(password);
    }
}
