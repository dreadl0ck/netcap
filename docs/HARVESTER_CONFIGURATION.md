# Credential Harvester Configuration

## Overview

The harvester configuration system allows you to control which credential harvesters are enabled, configure their behavior, and manage presets through both CLI and WebUI.

**Important: Configuration files are optional!** The system works out of the box with sensible defaults defined in code. Configuration files are only needed when you want to customize the default behavior.

## Default Behavior

When no configuration file is specified:
- All harvesters are enabled by default
- Standard port mappings are used (e.g., HTTP on 80, 8080, 3000, 9090, 8888)
- HTTP harvester uses a comprehensive list of sensitive parameters
- The system is ready to use immediately without any configuration

## When to Use Configuration Files

Use a configuration file when you want to:
- Disable specific harvesters you don't need
- Add custom ports for specific protocols
- Customize HTTP sensitive parameter names
- Create custom regex-based harvesters
- Optimize performance by running only needed harvesters

## Configuration File Format

Harvester configurations use YAML format with the following structure:

```yaml
harvesters:
  - name: "HTTP"
    enabled: true
    ports: [80, 8080, 3000]
    parameters:
      sensitive_params: ["key", "token", "api_key"]
      sensitive_headers: ["Authorization", "X-API-Key"]
  
  - name: "FTP"
    enabled: true
    ports: [21]
    parameters: {}

custom_harvesters:
  - name: "Custom Pattern"
    enabled: true
    ports: []
    regex: "your-regex-here"
    parameters: {}
```

## Configuration Fields

### Harvester Fields

- **name** (string, required): Name of the harvester. Must match an available harvester.
- **enabled** (boolean, required): Whether the harvester is active.
- **ports** (array of integers, required): List of ports where this harvester should be used.
- **parameters** (object, optional): Harvester-specific configuration parameters.
- **description** (string, optional): Human-readable description.

### Custom Harvester Fields

- **name** (string, required): Custom name for the harvester.
- **enabled** (boolean, required): Whether the harvester is active.
- **ports** (array of integers, required): List of ports where this harvester should be used.
- **regex** (string, required): Regular expression pattern for credential extraction.
- **parameters** (object, optional): Additional configuration.

## Available Harvesters

The following harvesters are built-in and can be configured:

### Authentication Protocols
- **HTTP**: HTTP Basic/Digest auth, URL parameters, session cookies
- **HTTP NTLM**: HTTP NTLM authentication with base64 encoding
- **FTP**: FTP plaintext authentication
- **SMTP**: SMTP AUTH plaintext
- **POP3**: POP3 email authentication
- **IMAP**: IMAP email authentication
- **Telnet**: Telnet plaintext login
- **LDAP**: LDAP Simple Bind authentication

### Hash-Based Protocols
- **NTLMSSP**: NTLM Security Support Provider
- **Kerberos AS-REQ**: Kerberos authentication requests
- **Kerberos AS-REP**: Kerberos authentication responses
- **Kerberos TGS-REP**: Kerberos ticket-granting service responses

### Database Protocols
- **PostgreSQL**: PostgreSQL plaintext authentication
- **PostgreSQL Hash**: PostgreSQL MD5 password hashes
- **MySQL**: MySQL challenge-response authentication
- **MongoDB**: MongoDB SCRAM-SHA authentication
- **MongoDB Challenge Response**: MongoDB wire protocol authentication
- **Redis**: Redis AUTH command

### Other Protocols
- **SNMP**: SNMP community strings
- **VNC**: VNC DES challenge-response

## Harvester-Specific Parameters

Several harvesters support customizable parameters to adapt to different environments and use cases.

### HTTP Harvester

The HTTP harvester supports the following parameters:

```yaml
parameters:
  sensitive_params:
    - "key"
    - "token"
    - "api_key"
    - "apikey"
    - "secret"
    - "password"
  sensitive_headers:
    - "Authorization"
    - "X-API-Key"
    - "X-Auth-Token"
  session_cookie_names:
    - "PHPSESSID"
    - "JSESSIONID"
    - "sessionid"
    - "connect.sid"
    # ... more cookie names
  min_cookie_length: 8
```

- **sensitive_params**: List of URL parameter names to extract as potential credentials
- **sensitive_headers**: List of HTTP headers to check for authentication data
- **session_cookie_names**: List of cookie names to recognize as session cookies
- **min_cookie_length**: Minimum length for a cookie value to be considered valid (default: 8)

### Telnet Harvester

The Telnet harvester can be configured to recognize different login prompts:

```yaml
parameters:
  login_patterns: ["login:", "username:", "Username:", "login as:", "Login:"]
  password_patterns: ["Password:", "password:", "Pass:", "passwd:"]
```

- **login_patterns**: List of strings that indicate a username prompt
- **password_patterns**: List of strings that indicate a password prompt

This is useful for systems with non-standard login prompts or localized prompts in different languages.

### LDAP Harvester

The LDAP harvester can extract usernames from Distinguished Names (DNs):

```yaml
parameters:
  username_attributes: ["cn", "uid", "mail", "sAMAccountName"]
  extract_simple_username: true
```

- **username_attributes**: Ordered list of DN attributes to try extracting as username
- **extract_simple_username**: If true, extracts simple username from DN (e.g., "admin" from "cn=admin,dc=example,dc=com"). If false, returns the full DN.

Example: For DN `cn=john.doe,ou=users,dc=company,dc=com` with `username_attributes: ["cn", "uid"]`, it will extract `john.doe`.

### SNMP Harvester

The SNMP harvester validates community string length:

```yaml
parameters:
  min_community_length: 1
  max_community_length: 255
```

- **min_community_length**: Minimum length for a valid community string (default: 1)
- **max_community_length**: Maximum length for a valid community string (default: 255)

Useful for filtering out noise or enforcing security policies that require minimum community string lengths.

### Other Harvesters

Other harvesters (FTP, SMTP, IMAP, POP3, Redis, etc.) use standard protocol patterns and currently have no configurable parameters. They work out of the box for standard implementations.

## Usage

### Default Usage (No Configuration)

Simply run capture without any harvester configuration:

```bash
# Uses default configuration - all harvesters enabled
net capture -r input.pcap
```

### Command Line with Custom Configuration

Specify a harvester configuration file when you want to override defaults:

```bash
net capture -r input.pcap --harvesters-config /path/to/harvesters.yml
```

If the config file cannot be loaded, the system will fall back to defaults and continue running.

### Web UI

1. Navigate to the "Harvesters" page in the Web UI
2. Use the "Configure" tab to:
   - Toggle harvesters on/off
   - Edit port lists
   - Configure parameters
3. Save the configuration
4. Restart the capture for changes to take effect

### Preset Management

#### Saving a Preset

1. Configure harvesters as desired
2. Click "Save as Preset"
3. Enter a name for the preset
4. Click "Save"

#### Loading a Preset

1. Go to the "Presets" tab
2. Select a preset from the dropdown
3. Click "Load"
4. Click "Save Configuration"
5. Restart capture

#### Uploading/Downloading Presets

- **Upload**: Click "Upload Preset" and select a YAML file
- **Download**: Click the download icon next to a preset in the list

## Example Configurations

### Note About Example Files

The example YAML files in `configs/` are provided as **reference and templates only**. They are not required to use the system. The default configuration is defined in the code and matches what you see in `harvesters-default.yml`.

### Default Configuration

The default configuration enables all harvesters with their standard port mappings. See `configs/harvesters-default.yml`.

### Minimal Configuration

A minimal configuration with only basic harvesters enabled. See `configs/harvesters-minimal.yml`.

### Web Application Security Testing

```yaml
harvesters:
  - name: "HTTP"
    enabled: true
    ports: [80, 443, 8080, 8443, 3000, 4200, 5000]
    parameters:
      sensitive_params:
        - "key"
        - "token"
        - "api_key"
        - "apikey"
        - "api-key"
        - "secret"
        - "apiSecret"
        - "access_token"
        - "accessToken"
        - "refresh_token"
        - "refreshToken"
        - "auth"
        - "authorization"
        - "jwt"
        - "bearer"
  
  - name: "HTTP NTLM"
    enabled: true
    ports: [80, 443, 8080, 8443]
    parameters: {}
```

### Database Assessment

```yaml
harvesters:
  - name: "PostgreSQL"
    enabled: true
    ports: [5432, 5433]
    parameters: {}
  
  - name: "PostgreSQL Hash"
    enabled: true
    ports: [5432, 5433]
    parameters: {}
  
  - name: "MySQL"
    enabled: true
    ports: [3306, 3307]
    parameters: {}
  
  - name: "MongoDB"
    enabled: true
    ports: [27017, 27018]
    parameters: {}
  
  - name: "MongoDB Challenge Response"
    enabled: true
    ports: [27017, 27018]
    parameters: {}
  
  - name: "Redis"
    enabled: true
    ports: [6379]
    parameters: {}
```

### Active Directory / Enterprise Networks

```yaml
harvesters:
  - name: "Kerberos AS-REQ"
    enabled: true
    ports: [88]
    parameters: {}
  
  - name: "Kerberos AS-REP"
    enabled: true
    ports: [88]
    parameters: {}
  
  - name: "Kerberos TGS-REP"
    enabled: true
    ports: [88]
    parameters: {}
  
  - name: "NTLMSSP"
    enabled: true
    ports: [445, 139]
    parameters: {}
  
  - name: "HTTP NTLM"
    enabled: true
    ports: [80, 443, 8080]
    parameters: {}
  
  - name: "LDAP"
    enabled: true
    ports: [389, 636, 3268, 3269]
    parameters: {}
```

## Best Practices

1. **Start Minimal**: Begin with a minimal configuration and enable harvesters as needed
2. **Port Selection**: Configure ports specific to your target environment
3. **Parameter Tuning**: Adjust HTTP parameter names based on the applications you're analyzing
4. **Preset Management**: Save different configurations as presets for different scenarios
5. **Performance**: Disable unused harvesters to improve processing performance
6. **Testing**: Test configurations on sample captures before production use

## Troubleshooting

### Harvester Not Finding Credentials

1. Check that the harvester is enabled
2. Verify port configuration includes the actual port in use
3. Ensure banner size (`--hbsize`) is large enough for the protocol
4. Review harvester-specific parameters

### Configuration Not Loading

1. Verify YAML syntax is correct
2. Check file permissions
3. Ensure harvester names match exactly (case-sensitive)
4. Look for error messages in the console output

### Changes Not Taking Effect

Remember that harvester configuration is loaded at capture startup. You must:
1. Save the configuration
2. Stop any running capture
3. Start a new capture

## Advanced Usage

### Custom Regex Harvesters

You can define custom harvesters using regular expressions:

```yaml
custom_harvesters:
  - name: "API Key Pattern"
    enabled: true
    ports: []
    regex: "api[_-]?key[=:\"']\\s*([a-zA-Z0-9]{32,})"
    parameters: {}
```

Note: Custom regex harvesters run against all traffic when ports list is empty, or only on specified ports.

### Programmatic Configuration

You can load and modify configurations programmatically:

```go
import "github.com/dreadl0ck/netcap/decoder/stream/credentials"

// Load configuration
config, err := credentials.LoadHarvestersConfig("my-config.yml")
if err != nil {
    log.Fatal(err)
}

// Modify configuration
for i, h := range config.Harvesters {
    if h.Name == "HTTP" {
        config.Harvesters[i].Enabled = false
    }
}

// Save configuration
err = credentials.SaveHarvestersConfig("modified-config.yml", config)
```

## API Reference

See the full API documentation for programmatic access to harvester configuration in the WebUI API endpoints:

- `GET /api/harvesters` - List all available harvesters
- `GET /api/harvesters/config` - Get current configuration
- `POST /api/harvesters/config` - Save configuration
- `GET /api/harvesters/presets` - List saved presets
- `POST /api/harvesters/presets/save` - Save new preset
- `POST /api/harvesters/presets/load` - Load preset
- `DELETE /api/harvesters/presets/delete` - Delete preset
- `POST /api/harvesters/presets/upload` - Upload preset file
- `GET /api/harvesters/presets/download` - Download preset file

