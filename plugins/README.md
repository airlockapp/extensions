# Airlock Plugins

This directory contains standalone plugins and integrations that act as Host Enforcers for various AI tools and companions.

Unlike the default IDE extensions (which are located in `src/extensions/src` and packaged as `.vsix` files for VS Code-compatible editors), these plugins are designed for different environments or CLI-based AI companions.

## Available Plugins

- **[`claude-code-enforcer`](claude-code-enforcer/README.md)**: A security plugin for Anthropic's [Claude Code](https://code.claude.com/). It gates tool use (Bash, Edit, Write, Read, etc.) through the Airlock security gateway for human-in-the-loop approval via the mobile app.

## Development

Each plugin in this directory is fully standalone and may have its own build, installation, and publication lifecycle. Please refer to each plugin's respective `README.md` and `INSTALL.md` for specific instructions.

General responsibilities for Airlock plugins:
1. Extract the intention (the action the AI wants to perform).
2. Package the action into a HARP Artifact.
3. Submit it to the Airlock Gateway and long-poll for a decision.
4. Verify the cryptographic signature on the decision locally.
5. Either allow or block the execution based on the verified decision.
