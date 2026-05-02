use anyhow::Result;
use rig::client::{CompletionClient, ProviderClient};
use rig::completion::Prompt;
use rig::providers::cohere;
use rig::tool::Tool;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::collections::HashSet;
use std::error::Error as StdError;
use std::fmt;

// Agent state holds context for multi-turn reasoning sessions.
#[allow(dead_code)]
struct AgentState {
    llm: cohere::Client,  // Cohere provider client for LLM calls.
    sandbox_path: String, // Path to ironclad-runtime binary.
    model: String,        // Model identifier (e.g., "command-r-plus").
    memory: Vec<String>,  // Conversation history for multi-turn context.
    max_steps: usize,     // Maximum reasoning steps to prevent infinite loops.
}

// Actions the agent can take in each reasoning step.
enum AgentAction {
    ExecuteCode { code: String }, // Run Python code in sandbox.
    Finish { answer: String },    // Finalize and return the answer.
}

// Represents one reasoning turn: agent's thought and corresponding action.
struct AgentTurn {
    thought: String,     // Agent's reasoning explanation.
    action: AgentAction, // Action to execute based on the thought.
}

// Custom error type for tool execution. Rig's Tool trait requires Error: StdError.
#[derive(Debug)]
struct ToolError(String);

impl fmt::Display for ToolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

// Implement std::error::Error to satisfy Rig's Tool trait bounds.
impl StdError for ToolError {}

// Build the ReAct system prompt that instructs the model on agent behavior.
// Format guides the LLM to output structured Thought/Action/FinalAnswer blocks.
fn build_system_prompt() -> String {
    r#"You are a ReAct agent solving problems step by step.

    You have one tool available: execute_code
    Use it ONLY for computation or verification.
    When you use execute_code, write a complete Python script, not a fragment.
    The script should be valid on its own and may assign intermediate variables.
    If the script needs third-party packages, add a comment line with the PyPI distribution names,
    not the import names. Examples:
    - import yaml -> REQUIRES: pyyaml
    - import dateutil -> REQUIRES: python-dateutil
    - import PIL -> REQUIRES: pillow
    - import bs4 -> REQUIRES: beautifulsoup4
    The runtime will resolve those packages before execution.
    Never call pip, uv, poetry, subprocess, or any installer inside the Python script.
    Never attempt to install packages at runtime. If a package is needed, declare it in # REQUIRES:
    using the PyPI distribution name and let the host resolver handle it.
    If a package is rejected, treat the observation as structured JSON and replan.
    After any error, your next response must still use the exact Thought / Action / ActionInput format.
    Do not respond with prose only.

    Output format:
    Thought: <your reasoning>
    Action: execute_code
    ActionInput: {"code": "<python code>"}

    When done:
    Thought: <reasoning>
    Action: finish
    FinalAnswer: <your answer>

    If code errors, analyze and retry ONCE.
    "#
    .to_string()
}

fn extract_package_hints(code: &str) -> Vec<String> {
    code.lines()
        .filter_map(|line| {
            let trimmed = line.trim_start();
            let requires = trimmed
                .strip_prefix("# REQUIRES:")
                .or_else(|| trimmed.strip_prefix("REQUIRES:"));
            requires.map(|value| value.trim().to_string())
        })
        .flat_map(|value| split_requires_packages(&value))
        .collect()
}

fn split_requires_packages(value: &str) -> Vec<String> {
    value
        .split(',')
        .map(|segment| segment.trim())
        .filter(|segment| !segment.is_empty())
        .map(|segment| segment.to_string())
        .collect()
}

fn normalize_requires_comment(code: &str) -> (String, Vec<String>) {
    let mut packages = Vec::new();
    let mut cleaned_lines = Vec::new();

    for line in code.lines() {
        if let Some(pos) = line.find("# REQUIRES:") {
            let rest = &line[pos + "# REQUIRES:".len()..];
            packages.extend(split_requires_packages(rest));

            // If the REQUIRES comment was inline, keep the first part of the line
            let before = &line[..pos];
            if !before.trim().is_empty() {
                cleaned_lines.push(before.trim_end());
            }
            continue;
        }

        if let Some(pos) = line.find("REQUIRES:") {
            let rest = &line[pos + "REQUIRES:".len()..];
            packages.extend(split_requires_packages(rest));

            let before = &line[..pos];
            if !before.trim().is_empty() {
                cleaned_lines.push(before.trim_end());
            }
            continue;
        }

        cleaned_lines.push(line);
    }

    if packages.is_empty() {
        return (code.to_string(), Vec::new());
    }

    let mut seen = HashSet::new();
    let mut deduped = Vec::new();
    for package in packages {
        if seen.insert(package.clone()) {
            deduped.push(package);
        }
    }

    let mut normalized = String::new();
    normalized.push_str("# REQUIRES: ");
    normalized.push_str(&deduped.join(", "));
    normalized.push('\n');
    normalized.push_str(&cleaned_lines.join("\n"));

    (normalized, deduped)
}

fn normalize_runtime_observation(stdout: &str, stderr: &str, success: bool) -> String {
    if success {
        return stdout.to_string();
    }

    let stderr_trim = stderr.trim();
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(stderr_trim) {
        if value
            .get("error")
            .and_then(|error| error.as_str())
            .is_some()
        {
            return stderr_trim.to_string();
        }

        if value.get("status").is_some() {
            return value.to_string();
        }
    }

    if stderr_trim.is_empty() {
        let stdout_trim = stdout.trim();
        if let Ok(value) = serde_json::from_str::<serde_json::Value>(stdout_trim) {
            if value
                .get("error")
                .and_then(|error| error.as_str())
                .is_some()
            {
                return stdout_trim.to_string();
            }

            if value.get("status").is_some() {
                return value.to_string();
            }
        }

        if !stdout_trim.is_empty() {
            return stdout_trim.to_string();
        }
    }

    stderr.to_string()
}

fn parse_observation_json(observation: &str) -> Option<serde_json::Value> {
    let trimmed = observation.trim();
    if let Ok(value) = serde_json::from_str::<serde_json::Value>(trimmed) {
        return Some(value);
    }

    let start = trimmed.find('{')?;
    let candidate = &trimmed[start..];
    serde_json::from_str::<serde_json::Value>(candidate).ok()
}

fn extract_execution_rejection(observation: &str) -> Option<serde_json::Value> {
    let outer = parse_observation_json(observation)?;
    if outer
        .get("status")
        .and_then(|value| value.as_str())
        .is_some_and(|status| status == "execution_rejected")
    {
        return Some(outer);
    }

    let error_json = outer.get("error").and_then(|value| value.as_str())?;
    let inner = serde_json::from_str::<serde_json::Value>(error_json).ok()?;
    if inner
        .get("status")
        .and_then(|value| value.as_str())
        .is_some_and(|status| status == "execution_rejected")
    {
        return Some(inner);
    }

    None
}

fn format_rejection_summary(rejection: &serde_json::Value) -> String {
    let mut lines = Vec::new();
    if let Some(rejected) = rejection
        .get("packages_rejected")
        .and_then(|value| value.as_array())
    {
        for entry in rejected {
            let package = entry
                .get("package")
                .and_then(|value| value.as_str())
                .unwrap_or("unknown");
            let details = entry
                .get("details")
                .and_then(|value| value.as_str())
                .unwrap_or("rejected");
            lines.push(format!("Package '{}' rejected: {}", package, details));

            if let Some(alternatives) = entry.get("alternatives").and_then(|value| value.as_array())
            {
                let choices: Vec<&str> = alternatives
                    .iter()
                    .filter_map(|value| value.as_str())
                    .collect();
                if !choices.is_empty() {
                    lines.push(format!("Alternatives: {}", choices.join(", ")));
                }
            }
        }
    }

    if lines.is_empty() {
        let reason = rejection
            .get("reason")
            .and_then(|value| value.as_str())
            .unwrap_or("execution_rejected");
        lines.push(format!("Execution rejected: {}", reason));
    }

    lines.join("\n")
}

// Perform one reasoning step with a single composed prompt.
// This avoids provider-specific multi-message payload incompatibilities.
async fn reason_once(
    agent: &rig::agent::Agent<cohere::CompletionModel>,
    user_task: &str,
    scratchpad: &[String],
) -> Result<AgentTurn> {
    let mut prompt = format!("Task: {}", user_task);
    if !scratchpad.is_empty() {
        prompt.push_str("\n\nPrevious steps:\n");
        prompt.push_str(&scratchpad.join("\n"));
    }

    let response = agent.prompt(prompt).await?;
    if std::env::var("NOS_DEBUG").is_ok() {
        println!("\n[DEBUG] Raw LLM response:\n{}\n---", response);
    }
    parse_agent_response(&response)
}

// Parse LLM response into structured AgentTurn (Thought + Action).
// Handles both "execute_code" and "finish" actions.
fn parse_agent_response(text: &str) -> Result<AgentTurn> {
    let thought = extract_section(text, "Thought").unwrap_or_else(|_| "(no thought)".to_string());
    let action_name = extract_section(text, "Action")?;

    // Check if agent is finishing.
    if action_name.to_lowercase().contains("finish") {
        let answer = extract_section(text, "FinalAnswer")
            .or_else(|_| extract_section(text, "Final Answer"))?;
        return Ok(AgentTurn {
            thought,
            action: AgentAction::Finish { answer },
        });
    }

    // Check if agent is executing code.
    if action_name.to_lowercase().contains("execute_code") {
        if let Ok(code) = extract_code_input(text) {
            return Ok(AgentTurn {
                thought,
                action: AgentAction::ExecuteCode { code },
            });
        }

        // If model chose execute_code but omitted ActionInput, fall back to finish if present.
        if let Ok(answer) =
            extract_section(text, "FinalAnswer").or_else(|_| extract_section(text, "Final Answer"))
        {
            return Ok(AgentTurn {
                thought,
                action: AgentAction::Finish { answer },
            });
        }

        return Err(anyhow::anyhow!(
            "Could not parse ActionInput/Code for execute_code action"
        ));
    }
    Err(anyhow::anyhow!("Could not parse action"))
}

// Extract executable code from several allowed model formats.
fn extract_code_input(text: &str) -> Result<String> {
    // 1) Preferred: ActionInput JSON object on the same line.
    if let Ok(action_input) = extract_section(text, "ActionInput") {
        if let Ok(args) = serde_json::from_str::<CodeArgs>(&action_input) {
            return Ok(args.code);
        }
    }

    // 2) ActionInput followed by multi-line JSON object.
    if let Some(idx) = text.find("ActionInput:") {
        let after = &text[idx + "ActionInput:".len()..];
        if let Some(start) = after.find('{') {
            let mut depth = 0usize;
            let mut end_pos = None;
            for (i, ch) in after[start..].char_indices() {
                if ch == '{' {
                    depth += 1;
                } else if ch == '}' {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        end_pos = Some(start + i + 1);
                        break;
                    }
                }
            }
            if let Some(end) = end_pos {
                let json_blob = &after[start..end];
                if let Ok(args) = serde_json::from_str::<CodeArgs>(json_blob) {
                    return Ok(args.code);
                }
            }
        }
    }

    // 3) Fallback: explicit Code: <python code>
    if let Some(idx) = text.find("Code:") {
        let after = &text[idx + "Code:".len()..].trim_start();
        // If there's an Observation or FinalAnswer block after, clip it.
        let end_idx = after.find("Observation:").unwrap_or(after.len());
        let end_idx = after[..end_idx].find("FinalAnswer:").unwrap_or(end_idx);
        let end_idx = after[..end_idx].find("Final Answer:").unwrap_or(end_idx);
        let code = after[..end_idx].trim().to_string();
        if !code.is_empty() {
            return Ok(code);
        }
    }

    // 4) Fallback: code inside markdown fenced block (```python ... ``` or ```bash ... ```)
    if let Some(fence_start) = text.find("```") {
        let after_fence = &text[fence_start + 3..];
        // Skip the language tag line (e.g., "python\n" or "bash\n")
        if let Some(newline) = after_fence.find('\n') {
            let code_start = &after_fence[newline + 1..];
            if let Some(fence_end) = code_start.find("```") {
                let code = code_start[..fence_end].trim().to_string();
                if !code.is_empty() {
                    return Ok(code);
                }
            }
        }
    }

    Err(anyhow::anyhow!("Could not extract code input"))
}

/// Extracts the manifest header fields from a diagnostic bash script.
/// Returns (fs_requires, purpose, timestamp).
fn parse_script_manifest(code: &str) -> (Vec<String>, String, String) {
    let mut requires = Vec::new();
    let mut purpose = String::new();
    let mut timestamp = String::new();

    for line in code.lines() {
        let t = line.trim();
        if let Some(v) = t.strip_prefix("# REQUIRES:") {
            // Only collect fs: entries (not Python PyPI packages)
            requires.extend(
                v.split(',')
                 .map(|s| s.trim().to_string())
                 .filter(|s| s.starts_with("fs:"))
            );
        } else if let Some(v) = t.strip_prefix("# PURPOSE:") {
            purpose = v.trim().to_string();
        } else if let Some(v) = t.strip_prefix("# TIMESTAMP:") {
            timestamp = v.trim().to_string();
        }
    }
    (requires, purpose, timestamp)
}

// Extract a labeled section from response text. Pattern: "Label: value"
fn extract_section(text: &str, label: &str) -> Result<String> {
    let pattern = format!("{}:", label);
    if let Some(start) = text.find(&pattern) {
        let after = &text[start + pattern.len()..];
        let section = after.lines().next().unwrap_or("").trim();
        if !section.is_empty() {
            return Ok(section.to_string());
        }
    }
    Err(anyhow::anyhow!("Could not find section: {}", label))
}

// Arguments for the execute_code tool: Python code string.
#[derive(Serialize, Deserialize)]
struct CodeArgs {
    code: String,
}

// Tool definition for Rig: executes Python code in ironclad-runtime sandbox.
#[derive(Serialize, Deserialize)]
struct ExecuteCodeTool;

impl Tool for ExecuteCodeTool {
    const NAME: &'static str = "execute_code";
    type Error = ToolError;
    type Args = CodeArgs;
    type Output = String;

    // Define tool schema for the execute_code tool.
    async fn definition(&self, _prompt: String) -> rig::completion::ToolDefinition {
        rig::completion::ToolDefinition {
            name: "execute_code".to_string(),
            description: "Execute Python code in a secure sandbox".to_string(),
            parameters: json!({
                "type": "object",
                "properties": {
                    "code": {
                        "type": "string",
                        "description": "Python code to execute"
                    }
                },
                "required": ["code"]
            }),
        }
    }

    // Step 10: Execute Python code via ironclad-runtime subprocess.
    // Writes code to temp file, calls sandbox, captures output.
    async fn call(&self, args: Self::Args) -> Result<Self::Output, Self::Error> {
        use std::fs;
        use std::io::Write;
        use std::process::Command;

        // Use a Windows-friendly temporary path under the system temp directory.
        let sandbox_dir = std::env::temp_dir().join("ironclad-sandbox");
        let temp_path = sandbox_dir.join("script.py");

        // Create sandbox directory if it doesn't exist.
        fs::create_dir_all(&sandbox_dir)
            .map_err(|e| ToolError(format!("Failed to create sandbox dir: {}", e)))?;

        // Write Python code to temp file.
        let mut file = fs::File::create(&temp_path)
            .map_err(|e| ToolError(format!("Failed to create temp file: {}", e)))?;
        let (normalized_code, normalized_requires) = normalize_requires_comment(&args.code);
        file.write_all(normalized_code.as_bytes())
            .map_err(|e| ToolError(format!("Failed to write code: {}", e)))?;

        let package_hints = if normalized_requires.is_empty() {
            extract_package_hints(&normalized_code)
        } else {
            normalized_requires
        };

        // Execute ironclad-runtime with the temp script.
        // Prefer the workspace binary target path, then fall back to a local executable name.
        let runtime_path = if cfg!(windows) {
            "target\\release\\ironclad-runtime.exe"
        } else {
            "target/release/ironclad-runtime"
        };

        let runtime_candidate = std::path::Path::new(runtime_path);
        let command = if runtime_candidate.exists() {
            runtime_candidate
        } else if cfg!(windows) {
            std::path::Path::new("ironclad-runtime.exe")
        } else {
            std::path::Path::new("ironclad-runtime")
        };

        let mut command_line = Command::new(command);
        if !package_hints.is_empty() {
            command_line.arg("--packages");
            command_line.arg(package_hints.join(","));
        }
        command_line.arg(&temp_path);

        let output = command_line
            .output()
            .map_err(|e| ToolError(format!("Failed to execute sandbox: {}", e)))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        // Return error if execution failed.
        if !output.status.success() {
            return Ok(normalize_runtime_observation(&stdout, &stderr, false));
        }

        Ok(normalize_runtime_observation(&stdout, &stderr, true))
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    // Load environment variables from the workspace .env file.
    dotenvy::dotenv().ok();

    // Initialize Cohere client from COHERE_API_KEY environment variable.
    let client = cohere::Client::from_env();

    // Build Rig agent: model + system prompt + token limit.
    // Note: We intentionally do NOT register tools at provider level for Cohere,
    // and instead execute tools manually from parsed ReAct actions.
    let agent = client
        .agent("command-r-08-2024")
        .preamble(&build_system_prompt())
        .max_tokens(2048)
        .build();

    // Task comes from first CLI argument; fallback to a default demo task.
    let user_task = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "Calculate: 5 + 3 * 2".to_string());

    // Scratchpad stores text-only turn summaries used to build the next prompt.
    let mut scratchpad: Vec<String> = Vec::new();
    let mut steps = 0;
    const MAX_STEPS: usize = 30;

    // ReAct loop: iterate until agent finishes or max steps reached.
    loop {
        steps += 1;
        println!("\n--- Step {} ---", steps);

        // Dot printer while LLM is thinking
        let dot_handle = tokio::spawn(async {
            loop {
                print!(".");
                let _ = std::io::Write::flush(&mut std::io::stdout());
                tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            }
        });
        let turn_result = reason_once(&agent, &user_task, &scratchpad).await;
        dot_handle.abort();
        println!(); // newline after dots

        // Get next reasoning turn from LLM.
        match turn_result {
            Ok(turn) => {
                println!("Thought: {}", turn.thought);

                match turn.action {
                    AgentAction::ExecuteCode { code } => {
                        // Execute code in sandbox.
                        println!("Action: execute_code");
                        println!("Code: {}", code);

                        // Call tool (runs ironclad-runtime subprocess).
                        // Clone code before moving into CodeArgs so it remains available
                        // for scratchpad recording after the call consumes args.
                        let tool = ExecuteCodeTool;
                        let code_snapshot = code.clone();
                        let args = CodeArgs { code };
                        let result = Tool::call(&tool, args)
                            .await
                            .map_err(|e| anyhow::anyhow!("Tool call failed: {}", e))?;
                        println!("Observation: {}", result);

                        // On a structured package rejection, push it to the scratchpad
                        // so the model can replan (not hard-exit). Hard-exit only when
                        // the model has already seen the rejection and still can't fix it
                        // (detected by checking if the same rejection is already in scratchpad).
                        if let Some(rejection) = extract_execution_rejection(&result) {
                            let rejection_summary = format_rejection_summary(&rejection);
                            let already_seen = scratchpad
                                .iter()
                                .any(|entry| entry.contains(&rejection_summary));
                            if already_seen {
                                // Model already tried and failed to replan; surface and exit.
                                println!("Final Answer: {}", rejection_summary);
                                return Ok(());
                            }
                            // First occurrence: let the model replan.
                            scratchpad.push(format!(
                                "Thought: {}\nAction: execute_code\nCode:\n{}",
                                turn.thought, code_snapshot
                            ));
                            scratchpad.push(format!(
                                "Observation: Package rejected — {}. Rewrite without these packages.",
                                rejection_summary
                            ));
                            continue;
                        }

                        // Add this turn to scratchpad for the next reasoning step.
                        // Include the code so the model can see which # REQUIRES: it used
                        // and carry them forward correctly on retry.
                        scratchpad.push(format!(
                            "Thought: {}\nAction: execute_code\nCode:\n{}",
                            turn.thought, code_snapshot
                        ));
                        scratchpad.push(format!("Observation: {}", result));
                    }
                    AgentAction::Finish { answer } => {
                        // Agent is done; return the final answer.
                        println!("Final Answer: {}", answer);
                        return Ok(());
                    }
                }
            }
            Err(e) => {
                // Parsing error; continue or fail if max steps reached.
                println!("Parse error: {}", e);
                if steps >= MAX_STEPS {
                    return Err(e);
                }
            }
        }

        // Stop after max iterations.
        if steps >= MAX_STEPS {
            println!("Max steps reached");
            return Ok(());
        }
    }
}
