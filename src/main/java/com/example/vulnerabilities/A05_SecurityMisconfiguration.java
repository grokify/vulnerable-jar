package com.example.vulnerabilities;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;
import java.io.FilePermission;
import java.net.URL;
import java.security.cert.X509Certificate;

/**
 * OWASP A05:2021 - Security Misconfiguration
 *
 * Demonstrates security misconfigurations and insecure default settings.
 */
public class A05_SecurityMisconfiguration {

    /**
     * VULNERABILITY: Disabled SSL/TLS Certificate Validation
     * Accepts all certificates including self-signed and expired ones
     */
    public void disableSSLValidation() throws Exception {
        // INSECURE: Disabling certificate validation
        TrustManager[] trustAllCerts = new TrustManager[]{
            new X509TrustManager() {
                public X509Certificate[] getAcceptedIssuers() {
                    return null;
                }
                public void checkClientTrusted(X509Certificate[] certs, String authType) {
                }
                public void checkServerTrusted(X509Certificate[] certs, String authType) {
                }
            }
        };

        SSLContext sc = SSLContext.getInstance("SSL");
        sc.init(null, trustAllCerts, new java.security.SecureRandom());
        HttpsURLConnection.setDefaultSSLSocketFactory(sc.getSocketFactory());
    }

    /**
     * VULNERABILITY: Disabled Hostname Verification
     * Disables hostname verification in SSL/TLS connections
     */
    public void disableHostnameVerification() throws Exception {
        // INSECURE: Accepting all hostnames
        HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);

        URL url = new URL("https://example.com");
        HttpsURLConnection conn = (HttpsURLConnection) url.openConnection();
        conn.connect();
    }

    /**
     * VULNERABILITY: Excessive Permissions
     * Granting overly broad file system permissions
     */
    public FilePermission getFilePermission() {
        // INSECURE: Too broad permissions
        return new FilePermission("<<ALL FILES>>", "read,write,execute,delete");
    }

    /**
     * VULNERABILITY: Debug Mode Enabled in Production
     * Debug features expose sensitive information
     */
    public static final boolean DEBUG_MODE = true;

    public void processRequest(String request) {
        if (DEBUG_MODE) {
            // INSECURE: Exposing sensitive debug information
            System.out.println("DEBUG: Processing request: " + request);
            System.out.println("DEBUG: Stack trace:");
            new Exception().printStackTrace();
        }
    }

    /**
     * VULNERABILITY: Exposed Error Messages
     * Detailed error messages reveal system information
     */
    public String handleError(Exception e) {
        // INSECURE: Exposing full stack trace to user
        return "Error: " + e.getMessage() + "\nStack: " + e.getStackTrace()[0];
    }

    /**
     * VULNERABILITY: Insecure Default Credentials
     * Using default/hardcoded credentials
     */
    public static final String DEFAULT_USERNAME = "admin";
    public static final String DEFAULT_PASSWORD = "admin";

    public boolean authenticateDefault(String username, String password) {
        // INSECURE: Default credentials should never be used
        return DEFAULT_USERNAME.equals(username) && DEFAULT_PASSWORD.equals(password);
    }

    /**
     * VULNERABILITY: Permissive CORS Configuration
     * Allows requests from any origin
     */
    public String getCORSHeader() {
        // INSECURE: Overly permissive CORS
        return "Access-Control-Allow-Origin: *";
    }

    /**
     * VULNERABILITY: Missing Security Headers
     * No security headers configured
     */
    public void setResponseHeaders() {
        // INSECURE: Missing security headers like:
        // X-Frame-Options, X-Content-Type-Options, CSP, HSTS, etc.
    }

    /**
     * VULNERABILITY: Unnecessary Services Enabled
     * Features that should be disabled in production
     */
    public boolean isFeatureEnabled(String feature) {
        // INSECURE: All features enabled by default
        return true;
    }
}
