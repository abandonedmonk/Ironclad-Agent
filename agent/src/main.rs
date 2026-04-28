use anyhow::Result;
use rig::client::{CompletionClient, ProviderClient};
use rig::completion::Prompt;
use rig::providers::cohere;
use rig::tool::Tool;
use serde::{Deserialize, Serialize};
use serde_json::json;
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
        if let Ok(answer) = extract_section(text, "FinalAnswer").or_else(|_| extract_section(text, "Final Answer")) {
            return Ok(AgentTurn {
                thought,
                action: AgentAction::Finish { answer },
            });
        }

        return Err(anyhow::anyhow!("Could not parse ActionInput/Code for execute_code action"));
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
    if let Ok(code_line) = extract_section(text, "Code") {
        return Ok(code_line);
    }

    Err(anyhow::anyhow!("Could not extract code input"))
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
        file.write_all(args.code.as_bytes())
            .map_err(|e| ToolError(format!("Failed to write code: {}", e)))?;

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

        let output = Command::new(command)
            .arg(&temp_path)
            .output()
            .map_err(|e| ToolError(format!("Failed to execute sandbox: {}", e)))?;

        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);

        // Return error if execution failed.
        if !output.status.success() {
            return Ok(format!("Error:\n{}", stderr));
        }

        Ok(stdout.to_string())
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
    const MAX_STEPS: usize = 5;

    // ReAct loop: iterate until agent finishes or max steps reached.
    loop {
        steps += 1;
        println!("\n--- Step {} ---", steps);

        // Get next reasoning turn from LLM.
        match reason_once(&agent, &user_task, &scratchpad).await {
            Ok(turn) => {
                println!("Thought: {}", turn.thought);

                match turn.action {
                    AgentAction::ExecuteCode { code } => {
                        // Execute code in sandbox.
                        println!("Action: execute_code");
                        println!("Code: {}", code);

                        // Call tool (runs ironclad-runtime subprocess).
                        let tool = ExecuteCodeTool;
                        let args = CodeArgs { code };
                        let result = Tool::call(&tool, args)
                            .await
                            .map_err(|e| anyhow::anyhow!("Tool call failed: {}", e))?;
                        println!("Observation: {}", result);

                        // Add this turn to scratchpad for the next reasoning step.
                        scratchpad.push(format!("Thought: {}\nAction: execute_code", turn.thought));
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
