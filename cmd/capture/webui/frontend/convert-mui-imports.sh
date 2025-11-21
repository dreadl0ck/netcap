#!/bin/bash

# Script to convert MUI barrel imports to direct imports
# This improves tree-shaking and reduces bundle size

set -e

echo "Converting MUI barrel imports to direct imports..."

# Find all TypeScript/TSX files with MUI imports
find src -name "*.tsx" -o -name "*.ts" | while read -r file; do
  # Skip if file doesn't have @mui/material imports
  if ! grep -q "from '@mui/material'" "$file"; then
    continue
  fi
  
  echo "Processing: $file"
  
  # Create a backup
  cp "$file" "$file.bak"
  
  # Extract the import statement
  python3 << 'PYTHON_SCRIPT' - "$file"
import sys
import re

file_path = sys.argv[1]

with open(file_path, 'r') as f:
    content = f.read()

# Find MUI material imports with proper multiline handling
pattern = r'import\s+\{([^}]+)\}\s+from\s+[\'"]@mui/material[\'"];'
match = re.search(pattern, content, re.MULTILINE | re.DOTALL)

if not match:
    sys.exit(0)

# Extract components
components_text = match.group(1)
components = []

for line in components_text.split(','):
    line = line.strip()
    if not line:
        continue
    # Handle aliased imports like "SelectChangeEvent"
    if ' as ' in line:
        parts = line.split(' as ')
        original = parts[0].strip()
        alias = parts[1].strip()
        components.append((original, alias))
    else:
        comp = line.strip()
        components.append((comp, None))

# Generate direct imports
direct_imports = []
for comp, alias in components:
    if alias:
        direct_imports.append(f"import {comp} from '@mui/material/{comp}';")
        direct_imports.append(f"import type {{ {comp} as {alias} }} from '@mui/material';")
    else:
        direct_imports.append(f"import {comp} from '@mui/material/{comp}';")

# Replace the barrel import with direct imports
new_imports = '\n'.join(direct_imports)
new_content = content.replace(match.group(0), new_imports)

with open(file_path, 'w') as f:
    f.write(new_content)

print(f"  Converted {len(components)} components")

PYTHON_SCRIPT

done

echo "Done! Backup files created with .bak extension"
echo "Test the build, then remove .bak files with: find src -name '*.bak' -delete"

