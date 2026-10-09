# Example agent packages

A package is an agent that comes with what it runs, and says what it needs. See
[docs/REFERENCE.md](../../docs/REFERENCE.md#agents), "Agent packages".

```bash
agent install examples/packages/echo-agent     # shows what it gets, asks
agent do --agent echo-agent "hello"            # runs it in a sandbox
agent diff                                     # it left a file in your folder, held for review
agent packages                                 # installed, and intact
agent uninstall echo-agent
```
