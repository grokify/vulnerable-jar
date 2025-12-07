# Vulnerable JAR

This project contains deliberately vulnerable Java code covering the **OWASP Top 10 (2021)** for security testing, scanning, and educational purposes.

⚠️ **WARNING**: This contains intentionally insecure code. For testing purposes only. Do not use in production environments.

## Coverage

### OWASP Top 10 (2021)

This project includes vulnerability examples for all OWASP Top 10 categories:

| Category | File | Vulnerabilities Demonstrated |
|----------|------|------------------------------|
| **A01** Broken Access Control | `A01_BrokenAccessControl.java` | Path traversal, IDOR, missing authorization checks |
| **A02** Cryptographic Failures | `A02_CryptographicFailures.java` | Weak algorithms (DES, MD5, SHA-1), hardcoded keys, insecure random |
| **A03** Injection | `A03_Injection.java` | SQL injection, command injection, XXE, LDAP injection |
| **A04** Insecure Design | `A04_InsecureDesign.java` | No rate limiting, race conditions, missing validation |
| **A05** Security Misconfiguration | `A05_SecurityMisconfiguration.java` | Disabled SSL validation, debug mode, default credentials |
| **A06** Vulnerable Components | `A06_VulnerableComponents.java` | Log4j 2.14.1 (CVE-2021-44228 - Log4Shell) |
| **A07** Identification Failures | `A07_IdentificationFailures.java` | Weak passwords, session fixation, username enumeration |
| **A08** Software Integrity Failures | `A08_SoftwareDataIntegrityFailures.java` | Insecure deserialization, unsafe reflection |
| **A09** Logging Failures | `A09_SecurityLoggingFailures.java` | Missing logs, logging sensitive data, log injection |
| **A10** SSRF | `A10_SSRF.java` | Server-side request forgery, internal resource access |

### Vulnerable Dependencies

- **log4j-core 2.14.1** - Vulnerable to CVE-2021-44228 (Log4Shell), CVE-2021-45046, CVE-2021-45105

## Security Scanning

This project includes automated security scanning in CI/CD:

### Tools Used

1. **SpotBugs + FindSecBugs** - Static analysis for Java security bugs
2. **Semgrep** - Pattern-based security scanning with:
   - `p/owasp-top-ten` ruleset
   - `p/security-audit` ruleset
   - `p/java` ruleset

### CI/CD Pipeline

The GitHub Actions workflow (`.github/workflows/ci.yaml`) includes:
- **Build job**: Compiles and packages the JAR across JDK versions 8, 11, 17, 21, 25
- **Security scan job**: Runs all security scanners and produces JSON reports

### Scan Results

Security scan results are uploaded as GitHub Actions artifacts with consistent naming:

**Pattern:** `{tool}_{format}.{ext}`

**Files:**
- `spotbugs-findsecbugs_raw.xml` - Original SpotBugs XML output
- `spotbugs-findsecbugs_converted.json` - Converted with file/line extraction
- `semgrep-owasp-top-ten.json` - Native Semgrep JSON output
- `semgrep-security-audit.json` - Native Semgrep JSON output
- `semgrep-java.json` - Native Semgrep JSON output

Artifacts are retained for 30 days and can be downloaded from the Actions tab.

**Why conversion?** SpotBugs XML is converted to JSON to extract and structure findings with file paths, line numbers, priority, category, and messages in an easily parseable format. Both raw and converted formats are provided.

## Building

```bash
mvn clean package
```

The JAR will be created at `target/vulnerable-jar-1.0-SNAPSHOT.jar`

## Running Security Scans Locally

### SpotBugs + FindSecBugs
```bash
mvn clean compile spotbugs:spotbugs
# Results in: target/spotbugs/spotbugsXml.xml
```

### Semgrep
```bash
# OWASP Top Ten
semgrep --config "p/owasp-top-ten" --json --output results.json .

# Security Audit
semgrep --config "p/security-audit" --json --output results.json .

# Java
semgrep --config "p/java" --json --output results.json .
```

## Purpose

This project is intended for:
- Testing and validating security scanners (SAST tools)
- Security research and education
- Demonstrating OWASP Top 10 vulnerabilities
- Training developers on secure coding practices
- Benchmarking vulnerability detection tools

## Disclaimer

This software is provided for educational and testing purposes only. All vulnerabilities are intentional. Use responsibly and only in controlled environments. Do not deploy this code in any production system.
