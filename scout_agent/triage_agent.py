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
        # Simplified rule-based patch for demo
        if finding.type == "HARDCODED_SECRETS":
            variable_name = "SECRET_KEY"
            match = re.search(r"(\w+)\s*=", finding.evidence)
            if match:
                # Strip language keywords to get a clean variable name
                raw_name = match.group(1)
                variable_name = re.sub(r'^(const|let|var)\s+', '', raw_name).strip().upper()
            return f"process.env.{variable_name}"
        return None # Fallback for other types

    def _apply_patch(self, finding: Finding, patch_content: str) -> bool:
        full_path = os.path.join(self.target_directory, finding.file_path)
        backup_path = full_path + ".bak"
        try:
            shutil.copy2(full_path, backup_path)
            with open(full_path, 'r') as f:
                lines = f.readlines()
            
            line_index = finding.line_number - 1
            original_line = lines[line_index]
            
            secret_match = re.search(r"['\"].*?['\"]", original_line)
            if not secret_match: 
                logger.error(f"Could not find a secret string to replace in line: {original_line.strip()}")
                return False
            
            new_line = original_line.replace(secret_match.group(0), patch_content)
            lines[line_index] = new_line
            
            with open(full_path, 'w') as f:
                f.writelines(lines)
            return True
        except Exception as e:
            logger.error(f"Failed to apply patch: {e}")
            shutil.move(backup_path, full_path)
            return False
