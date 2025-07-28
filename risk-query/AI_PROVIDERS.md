# AI Providers Support

Risk Query now supports multiple AI providers for natural language processing and query generation.

## Supported Providers

### 1. Ollama (Local)
- **Description**: Local LLM hosting platform
- **Requires API Key**: No
- **Models**: Any model available in your local Ollama instance
- **Pros**: 
  - Privacy (local processing)
  - No API costs
  - Fast for local models
- **Cons**:
  - Requires local setup
  - Model quality depends on local hardware

### 2. Anthropic Claude (Cloud)
- **Description**: Anthropic's Claude AI models via API
- **Requires API Key**: Yes
- **Models**: 
  - claude-3-5-sonnet-20241022 (recommended)
  - claude-3-5-haiku-20241022
  - claude-3-opus-20240229
  - claude-3-sonnet-20240229
  - claude-3-haiku-20240307
- **Pros**:
  - High-quality responses
  - No local setup required
  - Advanced reasoning capabilities
- **Cons**:
  - Requires API key and internet
  - Usage costs apply

### 3. Mistral AI (Cloud)
- **Description**: Mistral AI's language models via API
- **Requires API Key**: Yes
- **Models**: 
  - mistral-large-latest (recommended)
  - mistral-small-latest
  - codestral-latest
  - mistral-medium-latest
- **Pros**:
  - High performance
  - European-based (data privacy)
  - Competitive pricing
  - Coding-specific models available
- **Cons**:
  - Requires API key and internet
  - Usage costs apply

## Configuration

### Current Configuration
The active provider is configured in `config/config.yaml`:

```yaml
# AI Provider Configuration
ai_provider: "ollama"  # Options: "ollama", "anthropic", "mistral"

ollama:
  host: "http://localhost:11434"
  model: "mistral:7b"
  timeout: 600
  max_tokens: 2048

anthropic:
  api_key: "${ANTHROPIC_API_KEY}"  # Set via environment variable
  model: "claude-3-5-sonnet-20241022"
  timeout: 300
  max_tokens: 4096

mistral:
  api_key: "${MISTRAL_API_KEY}"  # Set via environment variable
  model: "mistral-large-latest"
  timeout: 300
  max_tokens: 4096
```

### Switching Providers

#### To use Ollama:
1. Ensure Ollama is running: `ollama serve`
2. Pull desired model: `ollama pull mistral:7b`
3. Set `ai_provider: "ollama"` in config.yaml
4. Restart the service

#### To use Anthropic:
1. Get API key from [Anthropic Console](https://console.anthropic.com/)
2. Set environment variable: `export ANTHROPIC_API_KEY=your_api_key`
3. Set `ai_provider: "anthropic"` in config.yaml
4. Restart the service

#### To use Mistral AI:
1. Get API key from [Mistral AI Console](https://console.mistral.ai/)
2. Set environment variable: `export MISTRAL_API_KEY=your_api_key`
3. Set `ai_provider: "mistral"` in config.yaml
4. Restart the service

## API Endpoints

### Get Current Provider Info
```bash
curl http://localhost:8003/api/providers
```

### Test AI Connection
```bash
curl http://localhost:8003/api/test/ai
```

### List Available Models
```bash
curl http://localhost:8003/api/models
```

## Testing

Run the test scripts to verify provider functionality:

```bash
# Test both providers
python test_providers.py

# Test configuration switching
python test_config_switch.py
```

## Environment Variables

### Required for Anthropic
- `ANTHROPIC_API_KEY`: Your Anthropic API key

### Required for Mistral AI
- `MISTRAL_API_KEY`: Your Mistral AI API key

### Optional
- `OLLAMA_HOST`: Override Ollama host (default: http://localhost:11434)

## Performance Considerations

### Ollama
- Response time depends on local hardware
- GPU acceleration recommended for larger models
- Consider model size vs quality tradeoff

### Anthropic
- Network latency affects response time
- Rate limits apply based on your plan
- Higher token costs for larger models

### Mistral AI
- Generally faster response times than Anthropic
- Competitive rate limits
- Good price/performance ratio for most use cases

## Troubleshooting

### Ollama Issues
- Ensure Ollama service is running: `ps aux | grep ollama`
- Check model availability: `ollama list`
- Verify host connectivity: `curl http://localhost:11434/api/tags`

### Anthropic Issues
- Verify API key is set: `echo $ANTHROPIC_API_KEY`
- Check API quota and billing
- Ensure internet connectivity

### Mistral AI Issues
- Verify API key is set: `echo $MISTRAL_API_KEY`
- Check API quota and billing
- Ensure internet connectivity
- Check Mistral AI status page for outages

### General Issues
- Check service logs for detailed error messages
- Verify configuration syntax in config.yaml
- Test individual providers with test scripts

## Architecture

The system uses a factory pattern to create the appropriate AI client:

```
config.yaml → ai_client_factory.py → OllamaClient/AnthropicClient → QueryProcessor
```

All providers implement the same `AIClientBase` interface, making switching transparent to the rest of the application.

# Command Line Interface (CLI)

Risk Query now includes a powerful CLI tool for executing queries from the command line.

## CLI Features

- **Natural Language Queries**: Same functionality as the web service
- **Multiple Output Formats**: Human-readable or raw JSON
- **Provider Information**: Show current and available AI providers
- **Example Queries**: Built-in examples to get started
- **Verbose Mode**: Detailed output with Cypher queries and sample data

## Installation

The CLI uses the same configuration and dependencies as the web service:

```bash
# Ensure dependencies are installed
pip install -r requirements.txt

# Make CLI executable
chmod +x risk_query_cli.py
```

## Usage

### Basic Query
```bash
python risk_query_cli.py "show me high risk domains"
```

### With Verbose Output
```bash
python risk_query_cli.py "which domains have incidents?" --verbose
```

### Raw JSON Output
```bash
python risk_query_cli.py "find critical vulnerabilities" --raw
```

### Show Available Providers
```bash
python risk_query_cli.py --providers
```

### Show Example Queries
```bash
python risk_query_cli.py --examples
```

### Custom Configuration
```bash
python risk_query_cli.py "your query" --config /path/to/config.yaml
```

## CLI Options

| Option | Short | Description |
|--------|-------|-------------|
| `--help` | `-h` | Show help message |
| `--config` | `-c` | Path to configuration file |
| `--verbose` | `-v` | Show detailed output |
| `--raw` | `-r` | Output raw JSON |
| `--providers` | `-p` | Show available providers |
| `--examples` | `-e` | Show example queries |

## Examples

### Basic Usage
```bash
# Simple query
python risk_query_cli.py "show domains with high risk scores"

# Complex query with details
python risk_query_cli.py "find domains that use third-party providers and have incidents" --verbose

# Get raw data for scripting
python risk_query_cli.py "list all assessments" --raw | jq '.raw_results.data'
```

### Provider Management
```bash
# Check current provider
python risk_query_cli.py --providers

# Test with different provider (change config.yaml first)
python risk_query_cli.py "test query" --verbose
```

### Automation Examples
```bash
# Use in scripts
RESULT=$(python risk_query_cli.py "count high risk domains" --raw)
echo "Found $(echo $RESULT | jq '.raw_results.count') domains"

# Batch processing
cat queries.txt | while read query; do
    python risk_query_cli.py "$query" --raw >> results.json
done
```

## Environment Variables

The CLI respects the same environment variables as the web service:

- `ANTHROPIC_API_KEY`: For Anthropic Claude
- `MISTRAL_API_KEY`: For Mistral AI
- `OLLAMA_HOST`: Override Ollama host

## Integration Examples

### Shell Alias
```bash
# Add to ~/.bashrc or ~/.zshrc
alias rq='python /path/to/risk_query_cli.py'

# Usage
rq "show me critical domains"
rq --examples
```

### Script Integration
```python
import subprocess
import json

def query_risk_db(query):
    cmd = ["python", "risk_query_cli.py", query, "--raw"]
    result = subprocess.run(cmd, capture_output=True, text=True)
    return json.loads(result.stdout)

# Usage
data = query_risk_db("find high risk domains")
print(f"Found {data['raw_results']['count']} domains")
```

## CLI vs Web Service

| Feature | CLI | Web Service |
|---------|-----|-------------|
| **Natural Language Queries** | ✅ | ✅ |
| **Multiple AI Providers** | ✅ | ✅ |
| **Configuration** | Same file | Same file |
| **Output Format** | Text/JSON | JSON API |
| **Interactive** | Command-based | REST API |
| **Automation** | Shell scripts | HTTP clients |
| **Performance** | Single query | Persistent service |