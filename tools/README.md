# tools/

Local tool discovery directory for REVcore.

This directory is intended to hold SDK-compliant external tools during local development and testing.

REVcore scans subdirectories inside `tools/` and looks for a manifest file named `rev_tool.json`.  
If a manifest is valid, REVcore can load the tool into its runtime registry.

This directory is not meant to store committed tool repos in the long term.  
Actual tools should live in their own repositories. During development, they may be copied, linked, or mounted here for testing.

## Expected layout

```text
tools/
  <tool-name>/
    rev_tool.json
    rev_adapter/
      ...
```
Example: 

```
tools/
  stringer/
    rev_tool.json
    rev_adapter/
      stringer_adapter.py
```

## rev_tool.json

The rev_tool.json file is the passive discovery manifest used by REVcore.

It declares:

- which REVSDK version the tool integration implements
- tool identity and display metadata
- adapter transport and entrypoint
- supported operations
- widget descriptors used by REVcore

## Example manifest

```
{
  "revsdk_version": "0.1",
  "manifest_version": "0.1",
  "tool": {
    "id": "stringer",
    "name": "Stringer",
    "version": "0.1.0",
    "description": "Extracts printable strings from binaries"
  },
  "adapter": {
    "transport": "stdio-json",
    "entrypoint": "./rev_adapter/stringer_adapter.py"
  },
  "operations": [
    {
      "id": "extract_strings",
      "name": "Extract Strings"
    }
  ],
  "widgets": [
    {
      "id": "string_table",
      "name": "String Table",
      "type": "table",
      "min_w": 40,
      "min_h": 10
    }
  ]
}
```

## Notes  

- entrypoint should be relative to the manifest location
- widgets are static descriptors, not runtime widget state
- manifests should stay small and focused on discovery metadata
- active validation such as adapter handshake happens after manifest loading