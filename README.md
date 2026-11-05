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

## Sources

sources turn the outside world into `Chunk`s. Three of them share one diff parser.

```mermaid
stateDiagram-v2
    [*] --> Idle
    Idle --> Header: "diff --git" line
    Header --> Header: "+++ b/path" sets current path
    Header --> Hunk: "@@ -a,b +c,d @@" sets line = c
    Hunk --> Hunk: "+" line, emit Chunk and line += 1
    Hunk --> Header: next "diff --git" line
    Hunk --> Idle: "commit:sha" marker
    Idle --> Idle: "commit:sha" marker
```