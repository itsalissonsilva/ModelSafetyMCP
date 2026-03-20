# Model Safety MCP

Malicious or unsafe ML artifacts are a real supply-chain problem, not a theoretical one. There have already been real cases of malicious or suspicious models being discovered in the wild, including models hosted on public platforms and larger batches of unsafe AI/ML artifacts. See [RL identifies malware ML model hosted on Hugging Face](https://www.reversinglabs.com/blog/rl-identifies-malware-ml-model-hosted-on-hugging-face) and [Over 100 Malicious AI/ML Models Found on Hugging Face](https://thehackernews.com/2024/03/over-100-malicious-aiml-models-found-on.html).

One of the biggest reasons this matters is deserialization risk. Many model formats, especially pickle-based and framework-specific formats, can execute code or invoke unsafe logic while being loaded or reconstructed. That means a model file can become an execution vector, not just a passive blob of weights.

`model-safety` is an MCP server for inspecting machine learning model artifacts before you load, ship, or trust them.

It is designed for practical triage:

- scan a local model file
- scan a downloadable model URL
- triage a whole directory of artifacts
- combine heuristic checks with dedicated scanners
- return normalized findings and concrete next actions

## What It Can Do

The server currently exposes these tools:

- `available_scanners`
  Shows which scanner backends are installed and ready.
- `artifact_safety_report`
  Runs the broadest scan available on one model artifact and returns per-scanner results, normalized findings, highest severity, and recommended actions.
- `modelscan_scan`
  Runs ModelScan directly against a local file or URL.
- `picklescan_scan`
  Runs PickleScan directly against a local file or URL.
- `deep_model_inspect`
  Runs lightweight structural checks for risky extensions, embedded pickle members, and suspicious packaging patterns.
- `scan_directory`
  Runs `artifact_safety_report` across every file in a directory and aggregates the risky files.

## Current Detection Strengths

This MCP is strongest when scanning:

- PyTorch checkpoints such as `.pt` and `.pth`
- pickle-like artifacts such as `.pkl`, `.pickle`, and `.joblib`
- Keras and TensorFlow HDF5 models such as `.h5`
- model bundles that are actually ZIP or TAR containers

It currently combines:

- `modelscan`
  Best general-purpose backend, especially for model-specific unsafe patterns like Keras `Lambda`.
- `picklescan`
  Best supporting backend for pickle-oriented artifacts.
- `deep_model_inspect`
  Fast heuristic fallback that catches risky packaging even when specialized scanners are quiet.

## Supported Inputs

You can scan either:

- a local filesystem path
- a direct `http` or `https` artifact URL

For Hugging Face specifically, use the direct file URL:

- Good: `https://huggingface.co/<repo>/resolve/main/model.h5`
- Not ideal: `https://huggingface.co/<repo>/blob/main/model.h5`

`blob` URLs usually return an HTML page, while `resolve` URLs return the real artifact bytes.

## Runtime

This repo includes a local Python 3.12 runtime in [`python312`](C:/Users/Lenovo/Documents/ModelSafetyMCP/python312). That is the supported runtime because it works with:

- `mcp`
- `modelscan`
- `picklescan`
- `h5py`

If you ever need to rebuild that runtime manually:

```bash
python312\python.exe -m pip install mcp picklescan modelscan h5py
```

## Start The Server

Run the MCP server with:

```bash
python312\python.exe run_server.py
```

The launcher is repo-local and uses the runtime already bundled in this project.

## Cursor Setup

Add the server in Cursor MCP settings with:

- Name: `model-safety`
- Type: `stdio`
- Command: `C:/Users/Lenovo/Documents/ModelSafetyMCP/python312/python.exe`
- Args: `C:/Users/Lenovo/Documents/ModelSafetyMCP/run_server.py`

Equivalent JSON:

```json
{
  "mcpServers": {
    "model-safety": {
      "type": "stdio",
      "command": "C:/Users/Lenovo/Documents/ModelSafetyMCP/python312/python.exe",
      "args": ["C:/Users/Lenovo/Documents/ModelSafetyMCP/run_server.py"]
    }
  }
}
```

A copy-paste example also lives in [`cursor.mcp.example.json`](C:/Users/Lenovo/Documents/ModelSafetyMCP/cursor.mcp.example.json).

## Claude Code Setup

Add the server with:

```bash
claude mcp add model-safety -- C:/Users/Lenovo/Documents/ModelSafetyMCP/python312/python.exe C:/Users/Lenovo/Documents/ModelSafetyMCP/run_server.py
```

## Workflow

### 1. Confirm the server is connected

In your MCP client, ask:

```text
Use available_scanners from the model-safety MCP server
```

You should see the installed backends, including `modelscan` and `picklescan`.

### 2. Start with the broad report

For a local file:

```text
Use artifact_safety_report with path="C:/path/to/model.pth"
```

For a direct URL:

```text
Use artifact_safety_report with url="https://example.com/model.h5"
```

This is the default entrypoint for single-artifact scans.

### 3. Read the normalized findings

`artifact_safety_report` returns:

- raw per-scanner outputs
- `normalized_findings`
- `highest_severity`
- `finding_count`
- `recommended_actions`

That means the tool is useful both for detailed investigation and for quick decision-making.

### 4. Drill down only when needed

Use:

- `modelscan_scan` when you want the dedicated ModelScan output
- `picklescan_scan` when you want pickle-specific detail
- `deep_model_inspect` when you want lightweight packaging and archive heuristics

### 5. Triage folders in bulk

If you have a whole drop of models:

```text
Use scan_directory with path="C:/path/to/model-folder"
```

This returns:

- aggregated normalized findings
- a directory-level highest severity
- `risky_files` for quick prioritization
- per-file nested reports

`scan_directory` works best on folders that mostly contain model artifacts rather than general source code.

## Examples

### Example: suspicious PyTorch checkpoint

```text
Use artifact_safety_report with path="C:/Users/Lenovo/Documents/ModelSafetyMCP/credit-risk-pytorch-v1.1.pth"
```

Typical result shape:

- risky extension `.pth`
- embedded pickle member inside the archive
- recommended action to avoid trusted loading until reviewed

### Example: suspicious Keras model from Hugging Face

```text
Use artifact_safety_report with url="https://huggingface.co/MrKrauzer/FacenetRetweeted/resolve/main/facenet-retrained.h5"
```

Typical result shape:

- risky extension `.h5`
- ModelScan `H5LambdaDetectScan` finding
- recommendation to inspect the Keras `Lambda` layer before deserializing

## Output Philosophy

The server treats the scanners as complementary:

- `modelscan` is the primary security backend
- `picklescan` is a specialized supporting backend
- `deep_model_inspect` is a fast structural fallback

Instead of forcing users to interpret each tool separately, the server also produces normalized findings with:

- `scanner`
- `severity`
- `category`
- `evidence`
- `source`
- `recommended_action`

## Limitations

This tool helps triage risk. It does not prove a model is safe.

Important limits:

- some formats are better covered than others
- a clean scan does not guarantee harmless behavior
- remote URL scanning depends on the URL pointing to the real artifact bytes
- directory scans are literal and can be noisy on non-model folders
- model behavior risks are different from serialization and packaging risks

## Development

Quick verification:

```bash
python312\python.exe -m compileall src run_server.py
```
