# Bug Fix: Rule Name with Forward Slash Causes Path Error

## Issue

Rule names containing forward slashes (`/`) were causing filesystem path errors when executing rules against captured traffic. For example, a rule named `RTP Audio/Video Stream Detected` would fail when the WebUI attempted to create a temporary rules file.

## Root Cause

In `cmd/capture/webui/rules_handlers.go` at line 1041, the `executeRuleOnCapture` function was using the rule name directly in a file path without sanitization:

```go
tempRulesPath := filepath.Join(outDir, fmt.Sprintf(".temp_rule_%s.yml", rule.Name))
```

When a rule name contains a `/` character, the operating system interprets it as a directory separator, causing the function to attempt to create a file in a non-existent subdirectory, resulting in a "no such file or directory" error.

## Impact

- Rules with names containing forward slashes would fail to execute
- The WebUI would be unable to test such rules against captured traffic
- Users would receive cryptic filesystem errors

## Solution

Applied the existing `sanitizeFilename()` function (defined at line 365) to the rule name before using it in the file path:

```go
tempRulesPath := filepath.Join(outDir, fmt.Sprintf(".temp_rule_%s.yml", sanitizeFilename(rule.Name)))
```

The `sanitizeFilename()` function replaces any character that is not alphanumeric, dash, or underscore with an underscore, making it safe for use in filenames.

## Changes Made

### 1. Fixed the Primary Bug (Rule Names)
- **File**: `cmd/capture/webui/rules_handlers.go`
- **Line**: 1041
- **Change**: Added `sanitizeFilename()` call around `rule.Name` when creating temporary rule files

### 2. Fixed Related Security Issues (Decoder Config Names)
While investigating this issue, we discovered similar vulnerabilities in decoder configuration handling:

- **File**: `cmd/capture/webui/decoders.go`
- **Lines Fixed**:
  - Line 808: `applyDecoderConfig` - now uses `sanitizeFilename(request.Name)`
  - Lines 878-879: `handleUploadDecoderConfig` - replaced partial sanitization with `sanitizeFilename()`
  - Line 944: `handleDeleteDecoderConfig` - now uses `sanitizeFilename(request.Name)`
  - Lines 985-986: `handleSaveDecoderConfigAs` - replaced partial sanitization with `sanitizeFilename()`

These fixes ensure that decoder configuration names (which are user-provided) cannot be used for path traversal attacks or cause filesystem errors.

### 3. Added Comprehensive Tests
- **File**: `cmd/capture/webui/rules_handlers_test.go` (new file)
- **Tests Added**:
  - `TestSanitizeFilename`: Tests various special characters including:
    - Forward slashes (`/`)
    - Backslashes (`\`)
    - Colons, parentheses, brackets
    - Unicode characters
    - Spaces and special characters
    - Empty strings
    - Path traversal attempts (`../../../etc/passwd`)
  - `TestSanitizeFilenameProperties`: Ensures sanitized names:
    - Are never empty
    - Don't contain path separators
    - Only contain safe characters (alphanumeric, dash, underscore)

## Testing

All tests pass successfully:

```bash
cd cmd/capture/webui
go test -v -run TestSanitizeFilename
```

Output:
```
=== RUN   TestSanitizeFilename
=== RUN   TestSanitizeFilename/forward_slash
...
--- PASS: TestSanitizeFilename (0.00s)
=== RUN   TestSanitizeFilenameProperties
...
--- PASS: TestSanitizeFilenameProperties (0.00s)
PASS
```

## Examples

### Before Fix
```
Rule name: "RTP Audio/Video Stream Detected"
File path: "/out/.temp_rule_RTP Audio/Video Stream Detected.yml"
Result: ERROR - no such file or directory (tries to write to subdirectory "RTP Audio/")
```

### After Fix
```
Rule name: "RTP Audio/Video Stream Detected"
Sanitized: "RTP_Audio_Video_Stream_Detected"
File path: "/out/.temp_rule_RTP_Audio_Video_Stream_Detected.yml"
Result: SUCCESS
```

## Related Code

The `sanitizeFilename()` function was already being used correctly in one location:
- Line 344 in `rules_handlers.go`: When saving orphaned rules created via the UI

However, it was NOT being used in several other locations where user-provided names were used in file paths. This investigation revealed and fixed all of these issues:
- Temporary rule file creation (fixed)
- Decoder config application (fixed)
- Decoder config upload (upgraded from partial to full sanitization)
- Decoder config deletion (fixed)
- Decoder config save-as (upgraded from partial to full sanitization)

This comprehensive fix ensures consistency by using the same sanitization approach across all user-provided filenames.

## Verification

To verify the fix works with the example rule:
1. Edit `rules/examples/streaming_protocols.yml`
2. Change line 137 from:
   ```yaml
   - name: RTP Audio Video Stream Detected
   ```
   to:
   ```yaml
   - name: RTP Audio/Video Stream Detected
   ```
3. Run the WebUI and attempt to execute the rule against captured traffic
4. The rule should now execute successfully without path errors

## Prevention

The comprehensive test suite added ensures:
- Future modifications won't reintroduce this bug
- All special characters are handled correctly
- Path traversal attempts are sanitized
- The function maintains its safety properties

## Security Note

This fix addresses multiple security concerns:

1. **Path Traversal Prevention**: Without proper sanitization, malicious rule or config names could be crafted to create or access files in unintended locations (e.g., `../../etc/passwd`).

2. **Directory Traversal**: Names containing path separators (`/` or `\`) could attempt to create files in non-existent subdirectories or escape the intended directory.

3. **Consistent Security**: By applying the same `sanitizeFilename()` function everywhere user input is used in file paths, we ensure consistent security across the entire application.

The `sanitizeFilename()` function prevents such attacks by:
- Removing all path separator characters (`/`, `\`)
- Removing all special characters except alphanumeric, dash, and underscore
- Ensuring the result is never empty (defaults to "rule" if all characters are removed)
- Preventing any filesystem-level exploits through malicious filenames

## Impact Summary

- **Files Changed**: 2 (`rules_handlers.go`, `decoders.go`)
- **Functions Fixed**: 5 locations
- **Security Issues Resolved**: Multiple path traversal vulnerabilities
- **Functionality Restored**: Rules with special characters in names now work correctly
- **Test Coverage Added**: Comprehensive test suite for filename sanitization

