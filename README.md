<h3 align="center">secretscan</h3>
---

Find leaked secrets in files, staged changes and git history

## Architecture

The core design rule: Three independent stages that only communicate through small data types.

```mermaid
flowchart LR
    subgraph Sources
        W["worktree: files on disk"]
        S["staged: git diff --cached"]
        H["history: git log -p"]
    end
    subgraph Engine
        R["rules: regex + entropy filter"]
        E["entropy detector (opt-in)"]
        F["filters: placeholder, ignore marker"]
    end
    subgraph Post
        A["allowlist (.secretscan.toml)"]
        B["baseline (fingerprints)"]
    end
    subgraph Output
        T["text"]
        J["JSON"]
        SA["SARIF"]
    end
    W --> |Chunk| R
    S --> |Chunk| R
    H --> |Chunk| R
    R --> F
    E --> F
    F --> |Finding| A --> B
    B --> T
    B --> J
    B --> SA
```

## Engine

Turn chunks of text into findings.

```mermaid
flowchart TD
    C["Chunk"] --> L{"line too long or has ignore marker?"}
    L -- yes --> X["skip"]
    L -- no --> RL["for each rule: finditer"]
    RL --> P{"placeholder or already seen?"}
    P -- yes --> RL
    P -- no --> EN{"rule has min_entropy and H below it?"}
    EN -- yes --> RL
    EN -- no --> Y["yield Finding"]
    RL --> ED{"entropy threshold set?"}
    ED -- yes --> TK["for each 20+ char token: H >= threshold?"]
    TK --> Y
```