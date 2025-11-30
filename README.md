# Vulnerable JAR

This project contains a deliberately vulnerable JAR file for security testing and vulnerability scanning purposes.

## Vulnerability

This project uses **log4j-core version 2.14.1**, which is vulnerable to CVE-2021-44228 (Log4Shell).

⚠️ **WARNING**: This is for testing purposes only. Do not use in production environments.

## Purpose

This project is intended for:
- Testing vulnerability scanners
- Security research and education
- Validating dependency analysis tools
- Demonstrating security vulnerabilities

## Building

```bash
mvn package
```

The JAR will be created at `target/vulnerable-jar-1.0-SNAPSHOT.jar`

## Running

```bash
java -jar target/vulnerable-jar-1.0-SNAPSHOT.jar
```

## Disclaimer

This software is provided for educational and testing purposes only. Use responsibly and only in controlled environments.
