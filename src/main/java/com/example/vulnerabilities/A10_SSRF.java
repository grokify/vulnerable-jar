package com.example.vulnerabilities;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLConnection;

/**
 * OWASP A10:2021 - Server-Side Request Forgery (SSRF)
 *
 * Demonstrates SSRF vulnerabilities where the application fetches remote resources
 * without validating user-supplied URLs.
 */
public class A10_SSRF {

    /**
     * VULNERABILITY: Basic SSRF
     * Fetching URL provided by user without validation
     */
    public String fetchURL(String urlString) throws Exception {
        // INSECURE: User controls URL - can access internal resources
        URL url = new URL(urlString);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        BufferedReader reader = new BufferedReader(new InputStreamReader(conn.getInputStream()));

        StringBuilder response = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            response.append(line);
        }
        reader.close();

        return response.toString();
    }

    /**
     * VULNERABILITY: SSRF via Redirect
     * Following redirects without validation
     */
    public String fetchWithRedirect(String urlString) throws Exception {
        // INSECURE: Automatically follows redirects to any URL
        URL url = new URL(urlString);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setInstanceFollowRedirects(true); // Default is true
        return conn.getResponseMessage();
    }

    /**
     * VULNERABILITY: SSRF to Internal Services
     * Allows access to localhost/internal IPs
     */
    public String checkInternalService(String host, int port) throws Exception {
        // INSECURE: Can access internal services like databases, admin panels
        URL url = new URL("http://" + host + ":" + port + "/status");
        URLConnection conn = url.openConnection();
        return conn.getContentType();
    }

    /**
     * VULNERABILITY: SSRF with File Protocol
     * Allows reading local files via file:// protocol
     */
    public String readResource(String resourceUrl) throws Exception {
        // INSECURE: User can use file:// to read local files
        URL url = new URL(resourceUrl);
        BufferedReader reader = new BufferedReader(new InputStreamReader(url.openStream()));

        StringBuilder content = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            content.append(line);
        }
        reader.close();

        return content.toString();
    }

    /**
     * VULNERABILITY: SSRF via Image/Avatar Upload
     * Fetching image from user-provided URL
     */
    public byte[] downloadAvatar(String imageUrl) throws Exception {
        // INSECURE: User can point to internal resources
        URL url = new URL(imageUrl);
        return url.openStream().readAllBytes();
    }

    /**
     * VULNERABILITY: SSRF via Webhook
     * Calling webhook URL without validation
     */
    public void triggerWebhook(String webhookUrl, String payload) throws Exception {
        // INSECURE: User-controlled webhook can target internal services
        URL url = new URL(webhookUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setRequestMethod("POST");
        conn.setDoOutput(true);
        conn.getOutputStream().write(payload.getBytes());
        conn.getResponseCode();
    }

    /**
     * VULNERABILITY: SSRF via PDF Generation
     * Generating PDF from user-provided URL
     */
    public void generatePDF(String htmlUrl) throws Exception {
        // INSECURE: HTML can contain references to internal resources
        URL url = new URL(htmlUrl);
        url.openStream();
        // PDF generation would process the HTML
    }

    /**
     * VULNERABILITY: Blind SSRF
     * Making request without returning response to user
     */
    public void pingCallback(String callbackUrl) throws Exception {
        // INSECURE: Blind SSRF - still allows port scanning and service detection
        URL url = new URL(callbackUrl);
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setConnectTimeout(5000);
        conn.connect();
        // Don't return response but attacker can detect success via timing
    }

    /**
     * VULNERABILITY: SSRF with DNS Rebinding
     * No validation of resolved IP address
     */
    public String fetchWithDNS(String hostname) throws Exception {
        // INSECURE: DNS can resolve to internal IP after validation
        URL url = new URL("http://" + hostname + "/api/data");
        return url.openStream().toString();
    }

    /**
     * VULNERABILITY: SSRF via XML External Entity in URL
     * Processing XML that references external URLs
     */
    public void processXMLFromURL(String xmlUrl) throws Exception {
        // INSECURE: XML can contain XXE pointing to internal resources
        URL url = new URL(xmlUrl);
        url.openStream();
        // XML parsing would follow external entity references
    }
}
