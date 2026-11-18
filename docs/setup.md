# Setup Guide

## Overview

This guide explains how to set up a local environment for developing and running B2C tools.

## Prerequisites

- Git
- PowerShell 7+
- Visual Studio Code
- Azure CLI (optional)

## Clone Repository

```bash
git clone <repository-url>
cd b2c-tools
```

## Recommended VS Code Extensions

- PowerShell
    #inititlize config
    `.\init-config.ps1 -Project claims-viewer -Environment prd`
- GitLens
- Markdown All In One
- Azure Tools

## Authentication

Login to Azure:

```bash
az login
```

Verify subscription:

```bash
az account show
```

## Repository Validation

Confirm documentation is available:

```bash
tree .
```

## Next Steps

Review:

- architecture.md
- runbook.md
