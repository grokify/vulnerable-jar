package com.example.vulnerabilities;

import java.io.*;
import java.net.URL;
import java.net.URLClassLoader;

/**
 * OWASP A08:2021 - Software and Data Integrity Failures
 *
 * Demonstrates vulnerabilities related to insecure deserialization and code integrity.
 */
public class A08_SoftwareDataIntegrityFailures {

    /**
     * VULNERABILITY: Insecure Deserialization
     * Deserializing untrusted data can lead to remote code execution
     */
    public Object deserializeObject(byte[] data) throws Exception {
        // INSECURE: Deserializing untrusted data
        ByteArrayInputStream bis = new ByteArrayInputStream(data);
        ObjectInputStream ois = new ObjectInputStream(bis);
        return ois.readObject();
    }

    /**
     * VULNERABILITY: Insecure Deserialization from File
     * Reading and deserializing from user-controlled file
     */
    public Object loadObjectFromFile(String filename) throws Exception {
        // INSECURE: Deserializing from user-controlled file
        FileInputStream fis = new FileInputStream(filename);
        ObjectInputStream ois = new ObjectInputStream(fis);
        return ois.readObject();
    }

    /**
     * VULNERABILITY: Loading Untrusted JAR Files
     * Dynamically loading code from untrusted sources
     */
    public void loadUntrustedJar(String jarPath) throws Exception {
        // INSECURE: Loading JAR from user-controlled path
        URL[] urls = {new URL("file://" + jarPath)};
        URLClassLoader classLoader = new URLClassLoader(urls);
        Class<?> cls = classLoader.loadClass("UntrustedClass");
        cls.newInstance();
    }

    /**
     * VULNERABILITY: No Integrity Check on Downloaded Updates
     * Downloading and executing code without verification
     */
    public void downloadAndExecute(String updateUrl) throws Exception {
        // INSECURE: No signature or checksum verification
        URL url = new URL(updateUrl);
        InputStream in = url.openStream();
        // Execute downloaded code without verification
    }

    /**
     * VULNERABILITY: Unvalidated Redirect/Forward
     * Redirecting to user-controlled URL
     */
    public String redirect(String targetUrl) {
        // INSECURE: Open redirect vulnerability
        return "redirect:" + targetUrl;
    }

    /**
     * VULNERABILITY: Trusting Client-Side Data
     * Using client-provided data for security decisions
     */
    public boolean checkPermission(String clientRole) {
        // INSECURE: Trusting client-provided role
        return "admin".equals(clientRole);
    }

    /**
     * VULNERABILITY: No Code Signing Verification
     * Loading plugins without verifying signatures
     */
    public void loadPlugin(File pluginFile) throws Exception {
        // INSECURE: No verification of plugin integrity
        FileInputStream fis = new FileInputStream(pluginFile);
        ObjectInputStream ois = new ObjectInputStream(fis);
        Object plugin = ois.readObject();
    }

    /**
     * VULNERABILITY: Unsafe Reflection
     * Using reflection with user-controlled class names
     */
    public Object createInstance(String className) throws Exception {
        // INSECURE: User controls class name - can instantiate dangerous classes
        Class<?> clazz = Class.forName(className);
        return clazz.newInstance();
    }

    /**
     * VULNERABILITY: XML Deserialization
     * Deserializing XML without validation
     */
    public Object deserializeXML(String xml) throws Exception {
        // INSECURE: XML deserialization can be exploited
        // (Implementation would use XMLDecoder or similar)
        return xml;
    }

    /**
     * VULNERABILITY: Auto-binding of Request Parameters
     * Automatically binding HTTP parameters to object properties
     */
    public void updateUser(Object userData) {
        // INSECURE: Mass assignment - user can modify unintended fields
        // like isAdmin, accountBalance, etc.
        System.out.println("User updated: " + userData);
    }
}
