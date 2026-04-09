# Harvester Parameterization Summary

This document provides examples and best practices for configuring harvester parameters.

## Overview

Five harvesters now support parameterization to adapt to different environments:

1. **HTTP** - URL parameters, headers, and session cookies
2. **Telnet** - Login/password prompts
3. **LDAP** - DN attribute extraction
4. **SNMP** - Community string validation
5. Other harvesters use standard protocols and don't require parameters

## HTTP Harvester Parameters

### Sensitive URL Parameters

Configure which URL parameter names to capture:

```yaml
parameters:
  sensitive_params:
    - "key"
    - "token"
    - "api_key"
    - "apikey"
    - "api-key"
    - "secret"
    - "password"
    - "access_token"
    - "refresh_token"
    - "auth"
    - "jwt"
    - "bearer"
```

**Use Case**: Different web applications use different parameter names for API keys and tokens. Customize this list for your target applications.

### Sensitive Headers

Configure which HTTP headers to check:

```yaml
parameters:
  sensitive_headers:
    - "Authorization"
    - "X-API-Key"
    - "X-Auth-Token"
    - "X-Access-Token"
    - "X-Custom-Auth"  # Add custom headers
```

### Session Cookies

Configure session cookie detection:

```yaml
parameters:
  session_cookie_names:
    - "PHPSESSID"      # PHP
    - "JSESSIONID"     # Java
    - "sessionid"      # Django
    - "connect.sid"    # Express
    - "my_app_session" # Custom application
  min_cookie_length: 8
```

**Use Case**: Add your application's custom session cookie names to capture session identifiers.

## Telnet Harvester Parameters

### Localized or Custom Prompts

Configure to match different login prompt styles:

```yaml
parameters:
  # English variations
  login_patterns: ["login:", "username:", "Username:", "login as:"]
  password_patterns: ["Password:", "password:", "Pass:"]
```

```yaml
parameters:
  # French prompts
  login_patterns: ["identifiant:", "utilisateur:", "nom d'utilisateur:"]
  password_patterns: ["mot de passe:", "Mot de passe:"]
```

```yaml
parameters:
  # German prompts
  login_patterns: ["Benutzername:", "benutzername:", "Anmeldung:"]
  password_patterns: ["Passwort:", "passwort:", "Kennwort:"]
```

**Use Case**: Capture credentials from systems with non-English interfaces or custom prompts.

## LDAP Harvester Parameters

### DN Attribute Extraction

Configure which LDAP attributes to extract as usernames:

```yaml
parameters:
  # Active Directory environment
  username_attributes: ["sAMAccountName", "cn", "uid", "mail"]
  extract_simple_username: true
```

```yaml
parameters:
  # OpenLDAP environment
  username_attributes: ["uid", "cn", "mail"]
  extract_simple_username: true
```

```yaml
parameters:
  # Keep full DN for audit trails
  username_attributes: ["cn", "uid"]
  extract_simple_username: false  # Returns full DN like "cn=admin,dc=example,dc=com"
```

**Examples**:

- DN: `cn=john.doe,ou=users,dc=company,dc=com`
  - With `username_attributes: ["cn"]` → Extracts: `john.doe`
  
- DN: `uid=jdoe,ou=people,dc=example,dc=org`
  - With `username_attributes: ["uid", "cn"]` → Extracts: `jdoe`
  
- DN: `sAMAccountName=JDOE,CN=Users,DC=corp,DC=local`
  - With `username_attributes: ["sAMAccountName"]` → Extracts: `JDOE`

## SNMP Harvester Parameters

### Community String Validation

Configure length constraints for community strings:

```yaml
parameters:
  # Strict validation (security policy: min 6 chars)
  min_community_length: 6
  max_community_length: 32
```

```yaml
parameters:
  # Permissive validation (capture everything)
  min_community_length: 1
  max_community_length: 255
```

**Use Cases**:
- **Security Testing**: Set `min_community_length: 1` to capture all community strings including weak ones like "public"
- **Compliance**: Set `min_community_length: 6` to only capture community strings that meet your security policy
- **Noise Reduction**: Set `min_community_length: 4` to filter out very short garbage matches

## Real-World Configuration Examples

### Web Application Penetration Testing

```yaml
harvesters:
  - name: "HTTP"
    enabled: true
    ports: [80, 443, 8080, 8443, 3000, 4200, 5000, 8000]
    parameters:
      sensitive_params:
        - "key"
        - "api_key"
        - "apiKey"
        - "apikey"
        - "token"
        - "access_token"
        - "accessToken"
        - "refresh_token"
        - "refreshToken"
        - "jwt"
        - "bearer"
        - "auth"
        - "authorization"
        - "secret"
        - "apiSecret"
        - "api_secret"
      session_cookie_names:
        - "PHPSESSID"
        - "laravel_session"
        - "XSRF-TOKEN"
        - "JSESSIONID"
        - "sessionid"
        - "csrftoken"
        - "connect.sid"
        - "express:sess"
        - "_session"
      min_cookie_length: 6
```

### Enterprise Active Directory Assessment

```yaml
harvesters:
  - name: "LDAP"
    enabled: true
    ports: [389, 636, 3268, 3269]
    parameters:
      username_attributes: ["sAMAccountName", "userPrincipalName", "cn", "mail"]
      extract_simple_username: true
  
  - name: "Kerberos AS-REQ"
    enabled: true
    ports: [88]
    parameters: {}
  
  - name: "Kerberos AS-REP"
    enabled: true
    ports: [88]
    parameters: {}
  
  - name: "NTLMSSP"
    enabled: true
    ports: [445, 139]
    parameters: {}
```

### IoT/Embedded Device Assessment

```yaml
harvesters:
  - name: "Telnet"
    enabled: true
    ports: [23, 2323, 2332]  # Common telnet ports on IoT devices
    parameters:
      login_patterns: 
        - "login:"
        - "username:"
        - "User:"
        - "name:"
        - "Login Name:"
      password_patterns:
        - "Password:"
        - "password:"
        - "Pass:"
        - "passwd:"
        - "PWD:"
  
  - name: "SNMP"
    enabled: true
    ports: [161, 162]
    parameters:
      min_community_length: 1  # Capture default strings like "public"
      max_community_length: 255
  
  - name: "HTTP"
    enabled: true
    ports: [80, 8080, 8081, 8888, 9000]  # Common web UI ports
    parameters:
      sensitive_params: ["key", "token", "password", "pwd", "pass"]
```

### Multi-Language Environment

```yaml
harvesters:
  - name: "Telnet"
    enabled: true
    ports: [23]
    parameters:
      login_patterns:
        # English
        - "login:"
        - "username:"
        # French
        - "identifiant:"
        - "utilisateur:"
        # German  
        - "Benutzername:"
        - "Anmeldung:"
        # Spanish
        - "usuario:"
        - "nombre de usuario:"
        # Italian
        - "utente:"
        - "nome utente:"
      password_patterns:
        - "Password:"
        - "password:"
        - "mot de passe:"
        - "Passwort:"
        - "contraseña:"
        - "password:"
```

## Performance Considerations

### Minimize Pattern Lists

Longer pattern lists require more regex matches. For optimal performance:

1. **Start with defaults** - They cover 90% of use cases
2. **Add only needed patterns** - Don't add "just in case" patterns
3. **Order by frequency** - Put most common patterns first (they're tried in order)

Example:
```yaml
# ❌ BAD: Too many patterns, many rarely used
login_patterns: ["login:", "username:", "user:", "name:", "uname:", "uid:", "id:", "account:", ...]  # 20+ patterns

# ✅ GOOD: Focused list for your environment
login_patterns: ["login:", "username:", "Username:"]  # 3 patterns that cover your systems
```

### Harvester-Specific Impact

- **HTTP**: Session cookie list size has minimal impact (single pass through headers)
- **Telnet**: Each login pattern × password pattern = one regex check (be selective)
- **LDAP**: Username attributes checked in order until match (put most common first)
- **SNMP**: Length checks are fast (minimal impact)

## Best Practices

1. **Start with defaults** - Use the built-in configuration as a baseline
2. **Analyze your environment** - Check what parameter names/prompts your applications use
3. **Test incrementally** - Add one customization at a time and verify it works
4. **Document customizations** - Add comments to your config explaining why patterns were added
5. **Review periodically** - Update configurations as applications change

## Troubleshooting

### Harvester Not Capturing Expected Credentials

1. **Check the pattern** - Ensure your pattern exactly matches what's in the traffic
2. **Test with default** - Try removing parameters to use defaults
3. **Check case sensitivity** - Some patterns are case-sensitive
4. **Verify ports** - Ensure the port is in the harvester's port list
5. **Check banner size** - Increase `--hbsize` if credentials appear late in the stream

### False Positives

1. **Increase minimum lengths** - For HTTP cookies, increase `min_cookie_length`
2. **Remove broad patterns** - Remove patterns that match too much
3. **Add validation** - For SNMP, increase `min_community_length`

### Performance Issues

1. **Reduce pattern lists** - Remove rarely-used patterns
2. **Disable unused harvesters** - Set `enabled: false` for protocols you're not testing
3. **Optimize regex** - Use more specific patterns to fail fast

