"""
Triage Agent - Vulnerability Remediation

This agent orchestrates the process of fixing a security vulnerability.
It takes a finding, enriches it with threat intelligence, generates a
patch using an LLM, and applies the fix to the target codebase.
"""

import os
import logging
import shutil
from dataclasses import dataclass
from typing import List, Dict, Any, Optional
from git import Repo, GitCommandError, InvalidGitRepositoryError
import re 

from scout_agent import ScoutAgent
from shared_types import Finding
from llama_index.core import ChatPromptTemplate
from llama_index.core.llms import ChatMessage, MessageRole
from llama_index.llms.openai import OpenAI

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# System prompt for the patch generation LLM
PATCH_GENERATION_SYSTEM_PROMPT = """
You are an expert security engineer. Your task is to fix a security vulnerability in a given code snippet.
You will receive the vulnerable code, the finding details, and context from a threat intelligence database.
Your goal is to generate a secure, high-quality patch that remediates the vulnerability while preserving functionality.

Instructions:
1.  **Analyze the Vulnerability**: Carefully review the finding type, evidence, and file context.
2.  **Consult Intelligence**: Use the provided "Similar Vulnerabilities" and "Proven Patches" to understand common remediation patterns.
3.  **Generate the Patch**: Create a precise code replacement. ONLY output the new code block that should replace the vulnerable line(s). Do not include explanations, apologies, or any surrounding code that is not part of the direct replacement.
4.  **Preserve Formatting**: Maintain the original indentation and code style of the file.
5.  **Be Precise**: The patch will be applied programmatically. Any deviation from the required output format will cause the fix to fail.

Example:
If the vulnerable line is `password = "admin123"`, a correct output would be `password = os.environ.get("DB_PASSWORD")`.
An incorrect output would be: `Here's the fix:\npassword = os.environ.get("DB_PASSWORD")`.
"""

class TriageAgent:
    """
    Orchestrates the remediation of a security finding.
    """

    def __init__(self, scout_agent: ScoutAgent, target_directory: str):
        """
        Initialize the Triage Agent.

        :param scout_agent: An instance of the ScoutAgent for threat intelligence.
        :param target_directory: The absolute path to the target codebase (can be a Git repo or a plain folder).
        """
        self.scout_agent = scout_agent
        self.target_directory = os.path.abspath(target_directory)
        self.llm = OpenAI(model="gpt-4-turbo", temperature=0.0)
        self.repo = None
        
        # Initialize Git repo if available
        try:
            self.repo = Repo(self.target_directory)
            logger.info(f"Target directory '{self.target_directory}' is a Git repository. Git operations enabled.")
        except InvalidGitRepositoryError:
            logger.warning(f"Target directory '{self.target_directory}' is not a Git repository. Git operations will be disabled.")

    def process_finding(self, finding: Finding) -> bool:
        """
        Process a single finding: create branch, enrich, generate patch, and commit.
        PR creation is handled by the orchestrator.
        """
        logger.info(f"Processing finding: {finding.id} ({finding.type}) in {finding.file_path}")

        # 0. Create a new branch for the fix (if in a Git repo)
        branch_name = f"fix/{finding.type}/{finding.id}"
        if not self._create_branch(branch_name):
            return False

        try:
            # 1. Enrich the finding with context from the Scout Agent
            self._enrich_finding(finding)

            # 2. Generate a patch
            patch_content = self._generate_patch(finding)
            if not patch_content:
                logger.error(f"Failed to generate patch for finding {finding.id}")
                self._checkout_branch('main') # Revert to main on failure
                return False

            # 3. Apply the patch
            success = self._apply_patch(finding, patch_content)
            if not success:
                logger.error(f"Failed to apply patch for finding {finding.id}")
                self._checkout_branch('main') # Revert to main on failure
                return False

            # 4. Commit the changes (if in a Git repo)
            commit_message = f"fix: Remediate {finding.type} in {finding.file_path}\n\n"
            commit_message += f"This commit automatically remediates a {finding.severity.lower()} severity vulnerability.\n\n"
            if finding.issue_number:
                commit_message += f"Closes #{finding.issue_number}\n"
            commit_message += f"Finding ID: {finding.id}"
            
            if not self._commit_changes(finding.file_path, commit_message):
                self._checkout_branch('main')
                return False

            if self.repo:
                logger.info(f"Successfully committed patch for finding {finding.id} to branch '{branch_name}'")

        finally:
            # 5. Return to the main branch to be ready for the next finding (if in a Git repo)
            self._checkout_branch('main')
            
        return True

    def _create_branch(self, branch_name: str) -> bool:
        """Create and checkout a new git branch if in a repo."""
        if not self.repo:
            return True # Not a failure, just skipping
        try:
            # Ensure we are on the main branch before creating a new one
            self._checkout_branch('main')
            
            # Delete the branch if it already exists to start fresh
            if branch_name in self.repo.heads:
                logger.warning(f"Branch '{branch_name}' already exists. Deleting and recreating.")
                self.repo.delete_head(branch_name, force=True)

            new_branch = self.repo.create_head(branch_name)
            new_branch.checkout()
            logger.info(f"Created and checked out new branch: {branch_name}")
            return True
        except GitCommandError as e:
            logger.error(f"Failed to create branch '{branch_name}': {e}")
            return False

    def _checkout_branch(self, branch_name: str):
        """Checkout an existing git branch if in a repo."""
        if not self.repo:
            return # Skip if not a repo
        try:
            self.repo.heads[branch_name].checkout()
        except GitCommandError as e:
            logger.error(f"Failed to checkout branch '{branch_name}': {e}")
            
    def _commit_changes(self, file_path: str, message: str) -> bool:
        """Commit the patched file to the current branch if in a repo."""
        if not self.repo:
            return True # Not a failure, just skipping
        try:
            # The file_path is relative to the repo root, so we can use it directly
            self.repo.index.add([file_path])
            self.repo.index.commit(message)
            logger.info(f"Committed changes for {file_path}")
            return True
        except GitCommandError as e:
            logger.error(f"Failed to commit changes: {e}")
            return False

    def _enrich_finding(self, finding: Finding):
        """
        Enrich a finding with similar vulnerabilities and proven patches from the Scout Agent.
        """
        logger.info(f"Enriching finding {finding.id} with threat intelligence...")
        
        # Find similar vulnerabilities
        finding.vector_matches = self.scout_agent.find_similar_vulnerabilities(
            query=f"{finding.type} in {os.path.basename(finding.file_path)}",
            k=3
        )

        # Find proven patches
        finding.suggested_patches = self.scout_agent.find_proven_patches(
            vulnerability_type=finding.type,
            k=3
        )
        
        logger.info(f"Enrichment complete. Found {len(finding.vector_matches)} similar vulnerabilities and {len(finding.suggested_patches)} patches.")

    def _generate_patch(self, finding: Finding) -> str:
        """
        Generate a patch for the vulnerability.
        For this demo, we will use a more robust, rule-based approach for the specific finding.
        """
        logger.info(f"Generating patch for finding {finding.id}...")

        # Rule-based patch generation for this specific demo case
        if finding.type == "HARDCODED_SECRETS" and finding.file_path.endswith('.py'):
            logger.info("Applying rule-based fix for hardcoded secret in Python file.")
            
            # Extract the variable name from the evidence line
            # e.g., "const JWT_SECRET = '...'" -> "JWT_SECRET"
            match = re.search(r"(\w+)\s*=", finding.evidence)
            variable_name = "SECRET_KEY" # Default
            if match:
                raw_name = match.group(1)
                # Remove "const", "let", "var" etc.
                variable_name = raw_name.replace("const", "").replace("let", "").replace("var", "").strip().upper()

            patch = f"os.environ.get('{variable_name}')"
            logger.info(f"Generated patch: {patch}")
            return patch

        # Fallback to LLM for other cases (though not used in this specific demo)
        logger.info("Falling back to LLM-based patch generation.")
        try:
            # Determine language from file extension for better context
            language = "javascript" if finding.file_path.endswith('.js') else "python"

            # Get the content of the vulnerable file
            full_path = os.path.join(self.target_directory, finding.file_path.lstrip('./'))
            with open(full_path, 'r') as f:
                file_lines = f.readlines()
            
            # Provide some context around the vulnerable line
            start = max(0, finding.line_number - 6)
            end = min(len(file_lines), finding.line_number + 5)
            context_lines = "".join(file_lines[start:end])

            # Prepare the user prompt
            user_prompt = f"""
            **Vulnerability Details:**
            - **Type**: {finding.type}
            - **File**: {finding.file_path}
            - **Language**: {language}
            - **Line**: {finding.line_number}
            - **Severity**: {finding.severity}
            - **Vulnerable Code (Evidence)**:
            ```
            {finding.evidence}
            ```

            **Code Context (lines {start+1} to {end}):**
            ```
            {context_lines}
            ```

            **Threat Intelligence:**
            - **Similar Vulnerabilities**:
            {self._format_intelligence(finding.vector_matches)}

            - **Proven Patches**:
            {self._format_intelligence(finding.suggested_patches)}

            Based on all the information above, please generate the exact replacement for the secret value.
            For example, if the vulnerable code is `password = "123"` and the language is Python, a good response would be `os.environ.get("DB_PASS")`.
            If the language is JavaScript, a good response would be `process.env.DB_PASS`.
            Remember: Output ONLY the replacement value.
            """

            # Create chat messages
            messages = [
                ChatMessage(role=MessageRole.SYSTEM, content=PATCH_GENERATION_SYSTEM_PROMPT),
                ChatMessage(role=MessageRole.USER, content=user_prompt.strip())
            ]

            # Get response from LLM
            response = self.llm.chat(messages)
            patch = response.message.content.strip()

            if not patch:
                logger.warning("LLM generated an empty patch.")
                return None

            logger.info(f"Generated patch:\n---\n{patch}\n---")
            return patch

        except Exception as e:
            logger.error(f"Error during patch generation: {e}")
            return None

    def _format_intelligence(self, intelligence_items: List[Dict]) -> str:
        """Helper to format intelligence data for the prompt."""
        if not intelligence_items:
            return "None available."
        
        formatted = ""
        for i, item in enumerate(intelligence_items, 1):
            content = item.get('content', 'N/A').strip()
            score = item.get('score', 0.0)
            formatted += f"{i}. (Score: {score:.3f})\n```\n{content}\n```\n"
        return formatted

    def _apply_patch(self, finding: Finding, patch_content: str) -> bool:
        """
        Apply the generated patch to the target file.
        This version intelligently replaces the secret within the line, not the entire line.
        """
        full_path = os.path.join(self.target_directory, finding.file_path)
        backup_path = full_path + ".bak"
        
        try:
            # Create a backup of the original file
            shutil.copy2(full_path, backup_path)
            logger.info(f"Created backup of original file at: {backup_path}")
            
            with open(full_path, 'r') as f:
                file_lines = f.readlines()

            # The line number from the finding is 1-based, list index is 0-based
            line_index = finding.line_number - 1
            original_line = file_lines[line_index]

            # The "evidence" from the report contains the part to be replaced.
            # E.g., "SECRET = 'my-super-secret-key-12345'"
            # We need to find the actual secret value in that string.
            secret_match = re.search(r"['\"](.*?)['\"]", finding.evidence)
            if not secret_match:
                logger.error(f"Could not extract secret value from evidence: {finding.evidence}")
                raise ValueError("Secret extraction failed.")
            
            secret_to_replace = secret_match.group(0) # The secret including quotes

            # The patch content from the LLM is the replacement code.
            # E.g., "os.environ.get('MY_SUPER_SECRET_KEY')"
            # We replace just the secret part of the original line.
            new_line = original_line.replace(secret_to_replace, patch_content)
            
            file_lines[line_index] = new_line

            with open(full_path, 'w') as f:
                f.writelines(file_lines)

            logger.info(f"Applied patch to {full_path} at line {finding.line_number}")
            return True

        except (IOError, IndexError, ValueError) as e:
            logger.error(f"Failed to apply patch to {full_path}: {e}")
            # Restore from backup on failure
            if os.path.exists(backup_path):
                shutil.move(backup_path, full_path)
                logger.info(f"Restored original file from backup.")
            return False

# Example usage (requires scout_agent and pentest_agent to be available)
if __name__ == "__main__":
    # This is a placeholder for a full integration test.
    # To run this, you would need:
    # 1. A running Redis instance for the ScoutAgent.
    # 2. A populated knowledge base in Redis.
    # 3. A dummy project with a known vulnerability.
    
    print("Triage Agent example execution (run main.py for a full demo).")

    # This is a simplified example. The main orchestrator is in main.py.
    DUMMY_PROJECT_DIR = "repo_demo_triage_test"
    if not os.path.exists(DUMMY_PROJECT_DIR):
        os.makedirs(DUMMY_PROJECT_DIR)
    
    vulnerable_file_path = os.path.join(DUMMY_PROJECT_DIR, "config.py")
    with open(vulnerable_file_path, "w") as f:
        f.write("import os\n\n")
        f.write("class Settings:\n")
        f.write("    # Hardcoded secret below!\n")
        f.write("    API_SECRET_KEY = 'super-secret-key-12345'\n")

    try:
        from shared_types import Finding
        scout = ScoutAgent()
        # Test on a non-git directory
        triage = TriageAgent(scout_agent=scout, target_directory=DUMMY_PROJECT_DIR)
        
        dummy_finding = Finding(
            id="finding_dummy_01",
            type="hardcoded_password",
            file_path="config.py",
            line_number=5,
            confidence="High",
            severity="Critical",
            message="Potential Hardcoded Password found.",
            evidence="API_SECRET_KEY = 'super-secret-key-12345'"
        )

        success = triage.process_finding(dummy_finding)

        if success:
            print(f"Success! Review the fix in: {vulnerable_file_path}")
            with open(vulnerable_file_path, "r") as f:
                print("\nFile content after patch:\n" + f.read())
        else:
            print("Remediation failed.")

    except (ImportError, ModuleNotFoundError):
        print("Could not import dependencies. Make sure scout_agent.py and shared_types.py are available.")
    except Exception as e:
        print(f"An error occurred: {e}")
        print("Please ensure Redis is running and the OPENAI_API_KEY is set.")
        
    finally:
        # Clean up
        import shutil
        if os.path.exists(DUMMY_PROJECT_DIR):
            shutil.rmtree(DUMMY_PROJECT_DIR)
