package com.example.vulnerabilities;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

/**
 * OWASP A03:2021 - Injection
 *
 * Demonstrates injection vulnerabilities including SQL, OS command, and XXE.
 */
public class A03_Injection {

    /**
     * VULNERABILITY: SQL Injection
     * User input concatenated directly into SQL query
     */
    public String getUserByUsername(String username) throws Exception {
        // INSECURE: SQL Injection - use PreparedStatement instead
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "pass");
        Statement stmt = conn.createStatement();
        String query = "SELECT * FROM users WHERE username = '" + username + "'";
        ResultSet rs = stmt.executeQuery(query);

        if (rs.next()) {
            return rs.getString("email");
        }
        return null;
    }

    /**
     * VULNERABILITY: SQL Injection with ORDER BY
     * User-controlled ORDER BY clause
     */
    public void searchUsers(String searchTerm, String sortColumn) throws Exception {
        // INSECURE: SQL Injection in ORDER BY clause
        Connection conn = DriverManager.getConnection("jdbc:mysql://localhost/db", "user", "pass");
        Statement stmt = conn.createStatement();
        String query = "SELECT * FROM users WHERE name LIKE '%" + searchTerm + "%' ORDER BY " + sortColumn;
        stmt.executeQuery(query);
    }

    /**
     * VULNERABILITY: OS Command Injection
     * User input passed to Runtime.exec without validation
     */
    public String pingHost(String hostname) throws IOException {
        // INSECURE: Command Injection - user controls part of command
        String command = "ping -c 4 " + hostname;
        Process process = Runtime.getRuntime().exec(command);
        return "Ping executed";
    }

    /**
     * VULNERABILITY: OS Command Injection with ProcessBuilder
     * User input in command array without validation
     */
    public void executeCommand(String userInput) throws IOException {
        // INSECURE: Command injection via user input
        ProcessBuilder pb = new ProcessBuilder("sh", "-c", userInput);
        pb.start();
    }

    /**
     * VULNERABILITY: XXE (XML External Entity) Injection
     * XML parser configured to process external entities
     */
    public void parseXML(String xmlContent) throws Exception {
        // INSECURE: XXE vulnerability - external entities enabled
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        // Missing: factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        DocumentBuilder builder = factory.newDocumentBuilder();
        builder.parse(new ByteArrayInputStream(xmlContent.getBytes()));
    }

    /**
     * VULNERABILITY: LDAP Injection
     * User input in LDAP filter without sanitization
     */
    public String ldapSearch(String username) {
        // INSECURE: LDAP Injection
        String filter = "(uid=" + username + ")";
        return "LDAP filter: " + filter;
    }

    /**
     * VULNERABILITY: Expression Language Injection
     * User input evaluated as EL expression
     */
    public String evaluateExpression(String userInput) {
        // INSECURE: EL Injection - user input evaluated as code
        return "${" + userInput + "}";
    }

    /**
     * VULNERABILITY: NoSQL Injection (MongoDB-style)
     * User input in NoSQL query without validation
     */
    public String buildMongoQuery(String username, String password) {
        // INSECURE: NoSQL Injection
        return "{ username: '" + username + "', password: '" + password + "' }";
    }

    /**
     * VULNERABILITY: Log Injection / CRLF Injection
     * User input written to logs without sanitization
     */
    public void logUserAction(String action) {
        // INSECURE: Log Injection - user can inject newlines
        System.out.println("User action: " + action);
    }
}
