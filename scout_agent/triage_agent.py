"""
Triage Agent - Code Remediation

This agent takes a vulnerability finding, enriches it with threat intelligence,
generates a patch, and applies it to the local codebase in a new branch.
"""
import os
import logging
import shutil
from typing import List, Dict, Any, Optional
from git import Repo, GitCommandError, InvalidGitRepositoryError
import re
from llama_index.llms.openai import OpenAI
from pathlib import Path

from .scout_agent import ScoutAgent
from .shared_types import Finding

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class TriageAgent:
    """Orchestrates the remediation of a security finding."""

    def __init__(self, scout_agent: ScoutAgent, target_directory: str):
        self.scout_agent = scout_agent
        self.target_directory = os.path.abspath(target_directory)
        self.llm = OpenAI(model="gpt-4-turbo", temperature=0.0)
        self.repo = None
        try:
            self.repo = Repo(self.target_directory)
            logger.info("Git repository detected. Git operations enabled.")
        except InvalidGitRepositoryError:
            logger.warning("Not a Git repository. Git operations will be disabled.")

    def remediate_and_commit(self, finding: Finding) -> bool:
        """
        Applies a patch for a single finding and commits it to the current branch.
        This method does NOT manage branches.
        """
        logger.info(f"Applying fix for finding: {finding.id} in {finding.file_path}")
        
        # 1. Generate the patch
        patch_content = self._generate_patch(finding)
        if not patch_content:
            logger.error(f"Failed to generate patch for {finding.id}")
            return False

        # 2. Apply the patch to the file
        if not self._apply_patch(finding, patch_content):
            logger.error(f"Failed to apply patch for {finding.id}")
            return False
        
        # 3. Commit the changes
        commit_message = f"fix: Remediate {finding.type} in {finding.file_path}\n\n"
        if finding.issue_number:
            commit_message += f"Closes #{finding.issue_number}\n"
        
        if not self._commit_changes(finding.file_path, commit_message):
            logger.error(f"Failed to commit changes for {finding.id}")
            return False
        
        logger.info(f"Successfully applied and committed fix for {finding.id}")
        return True

    def _commit_changes(self, file_path: str, message: str) -> bool:
        if not self.repo: return True
        try:
            # Normalize the file path to remove any leading './'
            normalized_file_path = os.path.normpath(file_path)
            
            # Use the relative path from the repo root
            self.repo.index.add([normalized_file_path])
            self.repo.index.commit(message)
            return True
        except GitCommandError as e:
            logger.error(f"Failed to commit changes: {e}")
            return False
            
    def _generate_patch(self, finding: Finding) -> Optional[str]:
        """
        Generates a patch for a given finding.
        Attempts a rule-based approach first for high-confidence fixes,
        then falls back to an AI-powered approach for more complex cases.
        """
        use_ai_fallback = False

        # --- Rule-Based Remediation Attempt for High-Confidence Fixes ---
        if finding.type == 'HARDCODED_SECRETS':
            logger.info(f"Attempting rule-based remediation for {finding.type}")
            
            # First, validate if the rule is even applicable to the evidence.
            # The rule expects a quoted string to replace.
            if not re.search(r"['\"].*?['\"]", finding.evidence):
                logger.warning(f"Rule-based remediation is not applicable for evidence: '{finding.evidence}'. Falling back to AI.")
                use_ai_fallback = True
            else:
                # If applicable, try to generate the patch
                language = Path(finding.file_path).suffix.lower()
                if language in ['.py', '.js', '.jsx', '.ts', '.tsx']:
                    match = re.search(r"(\w+)\s*[:=]", finding.evidence)
                    variable_name = "YOUR_SECRET_VARIABLE"
                    if match:
                        raw_name = match.group(1)
                        variable_name = re.sub(r'^(const|let|var)\s+', '', raw_name).strip().upper()
                    
                    if language == '.py':
                        return f"os.getenv('{variable_name}')"
                    else:
                        return f"process.env.{variable_name}"
                else:
                    # Language not supported by rule, fall back to AI
                    use_ai_fallback = True
        
        # --- AI-Powered Remediation for Other Vulnerabilities OR as a Fallback ---
        if use_ai_fallback or finding.type != 'HARDCODED_SECRETS':
            logger.info(f"Using AI-powered remediation for {finding.type}")
            try:
                # 1. Read the full source code of the vulnerable file
                full_file_path = os.path.join(self.target_directory, finding.file_path)
                with open(full_file_path, 'r', encoding='utf-8') as f:
                    source_code = f.read()

                # 2. Construct a detailed prompt for the LLM
                prompt = f"""
                You are an expert security engineer. A security vulnerability has been detected.
                Your task is to provide the precise code change needed to fix it.
                
                VULNERABILITY DETAILS:
                - Type: {finding.type}
                - File: {finding.file_path}
                - Line: {finding.line_number}
                - Description: {finding.message}
                - Vulnerable Code Snippet:
                ```
                {finding.evidence}
                ```

                FULL SOURCE CODE of `{finding.file_path}`:
                ```
                {source_code}
                ```

                INSTRUCTIONS:
                Based on the vulnerability details and the full source code, provide the corrected line of code ONLY.
                Do not provide explanations, apologies, or any text other than the code fix itself.
                For example, if the vulnerable line is `password = "12345"`, you should only return `password = os.getenv("DB_PASSWORD")`.
                """

                # 3. Query the LLM for a patch
                response = self.llm.complete(prompt)
                patch_content = response.text.strip()
                
                # 4. Clean the patch: Remove markdown formatting from the AI's response
                markdown_match = re.search(r"```(?:\w+\n)?([\s\S]+?)```", patch_content)
                if markdown_match:
                    patch_content = markdown_match.group(1).strip()

                # Basic validation: ensure the patch is not empty and is code-like
                if patch_content and ('=' in patch_content or '(' in patch_content or '=>' in patch_content):
                    logger.info(f"AI generated patch for {finding.type}: {patch_content}")
                    return patch_content
                else:
                    logger.warning(f"AI returned an invalid or empty patch: '{patch_content}'")
                    return None

            except Exception as e:
                logger.error(f"Error during AI-powered patch generation: {e}")
                return None

    def _apply_patch(self, finding: Finding, patch_content: str) -> bool:
        """
        Applies a patch to a file.
        For secrets, it replaces just the secret value.
        For AI-generated patches, it replaces the entire line.
        """
        full_file_path = os.path.join(self.target_directory, finding.file_path)
        try:
            # Create a backup of the original file
            backup_path = f"{full_file_path}.bak"
            shutil.copy(full_file_path, backup_path)

            with open(full_file_path, 'r', encoding='utf-8', errors='ignore') as f:
                lines = f.readlines()

            line_index = finding.line_number - 1
            if line_index >= len(lines):
                logger.error(f"Line number {finding.line_number} is out of bounds for file {finding.file_path}")
                return False
            
            original_line = lines[line_index]

            # Use specific logic for rule-based secret replacement
            if finding.type == 'HARDCODED_SECRETS':
                secret_match = re.search(r"['\"].*?['\"]", original_line)
                if not secret_match: 
                    logger.error(f"Rule-based fix failed: Could not find a secret string to replace in line: {original_line.strip()}")
                    return False
                
                # Preserve indentation
                indentation = len(original_line) - len(original_line.lstrip(' '))
                new_line = original_line.replace(secret_match.group(0), patch_content)
                lines[line_index] = ' ' * indentation + new_line.lstrip(' ') + '\n'
            else:
                # For AI-generated patches, replace the entire line but preserve indentation
                indentation = len(original_line) - len(original_line.lstrip(' '))
                lines[line_index] = ' ' * indentation + patch_content.strip() + '\n'

            with open(full_file_path, 'w', encoding='utf-8') as f:
                f.writelines(lines)
            
            # Clean up the backup file on success
            os.remove(backup_path)
            return True

        except FileNotFoundError:
            logger.error(f"Could not find file to patch: {full_file_path}")
            return False
        except Exception as e:
            logger.error(f"Failed to apply patch: {e}")
            # Restore from backup in case of error
            if os.path.exists(backup_path):
                shutil.move(backup_path, full_file_path)
            return False
