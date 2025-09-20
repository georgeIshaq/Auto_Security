"""
Flask Backend for GitHub Repository Management

This Flask application provides REST API endpoints to interact with GitHub repositories
using PyGithub library. It supports listing repositories with various filters and options.

Endpoints:
- GET /api/repositories - List GitHub repositories
- GET /api/repositories/<owner> - List repositories for a specific user/organization
- GET /api/repositories/<owner>/<repo> - Get details of a specific repository

Authentication:
- Uses GitHub Personal Access Token from environment variable GITHUB_TOKEN
- Or can be passed as a parameter in the request

Requirements:
- Flask
- Flask-CORS
- PyGithub
"""

import os
import logging
from typing import Optional, Dict, Any, List
from flask import Flask, request, jsonify
from flask_cors import CORS
from github import Github, GithubException
import subprocess
import threading
import uuid
import json

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# In-memory store for scan jobs (for demonstration purposes)
SCAN_JOBS = {}

# Initialize Flask app
app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

# Configuration
app.config['JSON_SORT_KEYS'] = False


class GitHubRepositoryService:
    """Service class for GitHub repository operations."""
    
    def __init__(self, token: Optional[str] = None):
        """
        Initialize GitHub service.
        
        Args:
            token: GitHub personal access token. If None, will try to get from GITHUB_TOKEN env var.
        """
        self.token = token or os.getenv('GITHUB_TOKEN')
        if not self.token:
            raise ValueError("GitHub token is required. Set GITHUB_TOKEN env var or pass token parameter.")
        
        self.github = Github(self.token)
        self.user = self.github.get_user()
        logger.info(f"GitHub service initialized for user: {self.user.login}")
    
    def get_user_repositories(
        self,
        username: Optional[str] = None,
        repo_type: str = "all",
        sort: str = "created",
        direction: str = "desc",
        per_page: int = 30,
        page: int = 1
    ) -> List[Dict[str, Any]]:
        """
        Get repositories for a user.
        
        Args:
            username: GitHub username. If None, returns current user's repos.
            repo_type: Type of repositories ('all', 'owner', 'public', 'private', 'member')
            sort: Sort field ('created', 'updated', 'pushed', 'full_name')
            direction: Sort direction ('asc', 'desc')
            per_page: Number of repositories per page (max 100)
            page: Page number
            
        Returns:
            List of repository dictionaries
        """
        try:
            if username:
                user = self.github.get_user(username)
                repos = user.get_repos(
                    type=repo_type,
                    sort=sort,
                    direction=direction
                )
            else:
                repos = self.user.get_repos(
                    type=repo_type,
                    sort=sort,
                    direction=direction
                )
            
            # Apply pagination
            repos = repos.get_page(page - 1)  # GitHub API is 0-indexed for pages
            
            # Convert to list of dictionaries
            repo_list = []
            for repo in repos:
                repo_dict = self._repository_to_dict(repo)
                repo_list.append(repo_dict)
            
            logger.info(f"Retrieved {len(repo_list)} repositories for user: {username or self.user.login}")
            return repo_list
            
        except GithubException as e:
            logger.error(f"Failed to get repositories for user {username}: {e}")
            raise
    
    def get_organization_repositories(
        self,
        org_name: str,
        repo_type: str = "all",
        sort: str = "created",
        direction: str = "desc",
        per_page: int = 30,
        page: int = 1
    ) -> List[Dict[str, Any]]:
        """
        Get repositories for an organization.
        
        Args:
            org_name: GitHub organization name
            repo_type: Type of repositories ('all', 'public', 'private', 'forks', 'sources', 'member')
            sort: Sort field ('created', 'updated', 'pushed', 'full_name')
            direction: Sort direction ('asc', 'desc')
            per_page: Number of repositories per page (max 100)
            page: Page number
            
        Returns:
            List of repository dictionaries
        """
        try:
            org = self.github.get_organization(org_name)
            repos = org.get_repos(
                type=repo_type,
                sort=sort,
                direction=direction
            )
            
            # Apply pagination
            repos = repos.get_page(page - 1)  # GitHub API is 0-indexed for pages
            
            # Convert to list of dictionaries
            repo_list = []
            for repo in repos:
                repo_dict = self._repository_to_dict(repo)
                repo_list.append(repo_dict)
            
            logger.info(f"Retrieved {len(repo_list)} repositories for organization: {org_name}")
            return repo_list
            
        except GithubException as e:
            logger.error(f"Failed to get repositories for organization {org_name}: {e}")
            raise
    
    def get_repository_details(self, owner: str, repo_name: str) -> Dict[str, Any]:
        """
        Get detailed information about a specific repository.
        
        Args:
            owner: Repository owner (username or organization)
            repo_name: Repository name
            
        Returns:
            Repository details dictionary
        """
        try:
            repo = self.github.get_repo(f"{owner}/{repo_name}")
            repo_dict = self._repository_to_dict(repo, detailed=True)
            
            logger.info(f"Retrieved details for repository: {owner}/{repo_name}")
            return repo_dict
            
        except GithubException as e:
            logger.error(f"Failed to get repository {owner}/{repo_name}: {e}")
            raise
    
    def search_repositories(
        self,
        query: str,
        sort: str = "best-match",
        order: str = "desc",
        per_page: int = 30,
        page: int = 1
    ) -> Dict[str, Any]:
        """
        Search for repositories using GitHub's search API.
        
        Args:
            query: Search query (e.g., "language:python", "user:octocat")
            sort: Sort field ('stars', 'forks', 'help-wanted-issues', 'updated')
            order: Sort direction ('asc', 'desc')
            per_page: Number of results per page (max 100)
            page: Page number
            
        Returns:
            Dictionary with search results and metadata
        """
        try:
            # GitHub search API uses different pagination (0-indexed)
            search_results = self.github.search_repositories(
                query=query,
                sort=sort,
                order=order
            )
            
            # Calculate total results
            total_count = search_results.totalCount
            
            # Get the requested page
            start_index = (page - 1) * per_page
            end_index = start_index + per_page
            
            repos = list(search_results[start_index:end_index])
            
            # Convert to list of dictionaries
            repo_list = []
            for repo in repos:
                repo_dict = self._repository_to_dict(repo)
                repo_list.append(repo_dict)
            
            result = {
                "total_count": total_count,
                "incomplete_results": search_results.incompleteResults,
                "repositories": repo_list,
                "page": page,
                "per_page": per_page,
                "total_pages": (total_count + per_page - 1) // per_page
            }
            
            logger.info(f"Search '{query}' returned {len(repo_list)} repositories")
            return result
            
        except GithubException as e:
            logger.error(f"Failed to search repositories with query '{query}': {e}")
            raise
    
    def _repository_to_dict(self, repo, detailed: bool = False) -> Dict[str, Any]:
        """
        Convert a GitHub Repository object to a dictionary.
        
        Args:
            repo: GitHub Repository object
            detailed: Whether to include detailed information
            
        Returns:
            Dictionary representation of the repository
        """
        repo_dict = {
            "id": repo.id,
            "name": repo.name,
            "full_name": repo.full_name,
            "description": repo.description,
            "html_url": repo.html_url,
            "clone_url": repo.clone_url,
            "ssh_url": repo.ssh_url,
            "git_url": repo.git_url,
            "owner": {
                "login": repo.owner.login,
                "id": repo.owner.id,
                "type": repo.owner.type,
                "avatar_url": repo.owner.avatar_url,
                "html_url": repo.owner.html_url
            },
            "private": repo.private,
            "fork": repo.fork,
            "created_at": repo.created_at.isoformat() if repo.created_at else None,
            "updated_at": repo.updated_at.isoformat() if repo.updated_at else None,
            "pushed_at": repo.pushed_at.isoformat() if repo.pushed_at else None,
            "size": repo.size,
            "stargazers_count": repo.stargazers_count,
            "watchers_count": repo.watchers_count,
            "language": repo.language,
            "forks_count": repo.forks_count,
            "open_issues_count": repo.open_issues_count,
            "default_branch": repo.default_branch,
            "topics": repo.get_topics() if hasattr(repo, 'get_topics') else [],
            "license": {
                "name": repo.license.name,
                "key": repo.license.key,
                "spdx_id": repo.license.spdx_id,
                "url": repo.license.url
            } if repo.license else None
        }
        
        if detailed:
            # Add additional detailed information
            repo_dict.update({
                "homepage": repo.homepage,
                "has_issues": repo.has_issues,
                "has_projects": repo.has_projects,
                "has_wiki": repo.has_wiki,
                "has_pages": repo.has_pages,
                "has_downloads": repo.has_downloads,
                "archived": repo.archived,
                "disabled": repo.disabled,
                "allow_rebase_merge": repo.allow_rebase_merge,
                "allow_squash_merge": repo.allow_squash_merge,
                "allow_merge_commit": repo.allow_merge_commit,
                "subscribers_count": repo.subscribers_count,
                "network_count": repo.network_count,
                "parent": {
                    "full_name": repo.parent.full_name,
                    "html_url": repo.parent.html_url
                } if repo.parent else None,
                "source": {
                    "full_name": repo.source.full_name,
                    "html_url": repo.source.html_url
                } if repo.source else None
            })
        
        return repo_dict


# Initialize the GitHub service
try:
    github_service = GitHubRepositoryService()
except ValueError as e:
    logger.error(f"Failed to initialize GitHub service: {e}")
    github_service = None


@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint."""
    return jsonify({
        "status": "healthy",
        "service": "GitHub Repository API",
        "github_connected": github_service is not None
    }), 200


@app.route('/api/repositories', methods=['GET'])
def get_repositories():
    """
    Get repositories for the authenticated user or search for repositories.
    
    Query Parameters:
    - token: GitHub personal access token (optional if set in environment)
    - username: Specific username to get repositories for (optional)
    - org: Organization name to get repositories for (optional)
    - type: Repository type ('all', 'owner', 'public', 'private', 'member')
    - sort: Sort field ('created', 'updated', 'pushed', 'full_name')
    - direction: Sort direction ('asc', 'desc')
    - per_page: Number of repositories per page (max 100, default 30)
    - page: Page number (default 1)
    - search: Search query for repository search (optional)
    """
    try:
        # Get query parameters
        token = request.args.get('token')
        username = request.args.get('username')
        org = request.args.get('org')
        repo_type = request.args.get('type', 'all')
        sort = request.args.get('sort', 'created')
        direction = request.args.get('direction', 'desc')
        per_page = min(int(request.args.get('per_page', 30)), 100)
        page = max(int(request.args.get('page', 1)), 1)
        search_query = request.args.get('search')
        
        # Initialize service with token if provided
        service = github_service
        if token:
            service = GitHubRepositoryService(token)
        
        if not service:
            return jsonify({
                "error": "GitHub service not initialized. Please provide a token or set GITHUB_TOKEN environment variable."
            }), 500
        
        # Handle search request
        if search_query:
            result = service.search_repositories(
                query=search_query,
                sort=sort,
                order=direction,
                per_page=per_page,
                page=page
            )
            return jsonify(result), 200
        
        # Handle organization repositories
        if org:
            repositories = service.get_organization_repositories(
                org_name=org,
                repo_type=repo_type,
                sort=sort,
                direction=direction,
                per_page=per_page,
                page=page
            )
        else:
            # Handle user repositories
            repositories = service.get_user_repositories(
                username=username,
                repo_type=repo_type,
                sort=sort,
                direction=direction,
                per_page=per_page,
                page=page
            )
        
        return jsonify({
            "repositories": repositories,
            "count": len(repositories),
            "page": page,
            "per_page": per_page,
            "type": repo_type,
            "sort": sort,
            "direction": direction
        }), 200
        
    except GithubException as e:
        logger.error(f"GitHub API error: {e}")
        return jsonify({
            "error": "GitHub API error",
            "message": str(e),
            "status": e.status if hasattr(e, 'status') else None
        }), e.status if hasattr(e, 'status') else 400
    
    except ValueError as e:
        logger.error(f"Validation error: {e}")
        return jsonify({
            "error": "Validation error",
            "message": str(e)
        }), 400
    
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return jsonify({
            "error": "Internal server error",
            "message": str(e)
        }), 500


@app.route('/api/repositories/<owner>/<repo_name>', methods=['GET'])
def get_repository_details(owner: str, repo_name: str):
    """
    Get detailed information about a specific repository.
    
    Path Parameters:
    - owner: Repository owner (username or organization)
    - repo_name: Repository name
    
    Query Parameters:
    - token: GitHub personal access token (optional if set in environment)
    - detailed: Include detailed information (default: true)
    """
    try:
        # Get query parameters
        token = request.args.get('token')
        detailed = request.args.get('detailed', 'true').lower() == 'true'
        
        # Initialize service with token if provided
        service = github_service
        if token:
            service = GitHubRepositoryService(token)
        
        if not service:
            return jsonify({
                "error": "GitHub service not initialized. Please provide a token or set GITHUB_TOKEN environment variable."
            }), 500
        
        repository = service.get_repository_details(owner, repo_name)
        
        return jsonify({
            "repository": repository,
            "detailed": detailed
        }), 200
        
    except GithubException as e:
        logger.error(f"GitHub API error for {owner}/{repo_name}: {e}")
        return jsonify({
            "error": "GitHub API error",
            "message": str(e),
            "status": e.status if hasattr(e, 'status') else None
        }), e.status if hasattr(e, 'status') else 400
    
    except ValueError as e:
        logger.error(f"Validation error: {e}")
        return jsonify({
            "error": "Validation error",
            "message": str(e)
        }), 400
    
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        return jsonify({
            "error": "Internal server error",
            "message": str(e)
        }), 500


@app.route('/api/scan', methods=['POST'])
def run_scan():
    """
    Triggers the vulnerability remediation pipeline for a given repository.
    This runs the script as a background process.
    """
    data = request.get_json()
    repo_name = data.get('repo_name')
    token = data.get('token') # Get the token from the request

    if not repo_name or not token:
        return jsonify({"error": "repo_name and token are required"}), 400

    scan_id = str(uuid.uuid4())
    SCAN_JOBS[scan_id] = {"status": "running", "results": None, "error": None}

    def run_script(repo, job_id, github_token):
        """Function to run in a separate thread."""
        logger.info(f"Starting vulnerability scan for repository: {repo} (Job ID: {job_id})")
        
        # Define a unique output file for this scan job
        output_file = f"scan_results_{job_id}.json"

        try:
            # Create a copy of the current environment and add the tokens
            env = os.environ.copy()
            env['GITHUB_TOKEN'] = github_token
            # Pass through the OpenAI API key if it exists
            if 'OPENAI_API_KEY' in os.environ:
                env['OPENAI_API_KEY'] = os.environ['OPENAI_API_KEY']

            # Command to run the script within the virtual environment
            command = [
                os.path.join(os.getcwd(), "venv/bin/python"),
                os.path.join(os.getcwd(), "run_remediation_pipeline.py"),
                repo,
                "--output-file",
                os.path.join(os.getcwd(), output_file)
            ]
            
            # Use subprocess.run to wait for the process to complete
            process = subprocess.run(
                command,
                capture_output=True,
                text=True,
                check=False,  # We will check the returncode manually
                env=env,  # Pass the environment with the token to the subprocess
                cwd=os.getcwd()  # Ensure we run from the correct working directory
            )
            
            # Log the full output for debugging
            logger.info(f"Scan process for {job_id} finished with return code: {process.returncode}")
            logger.info(f"Command executed: {' '.join(command)}")
            logger.info(f"Working directory: {os.getcwd()}")
            logger.info(f"Environment variables: GITHUB_TOKEN={'set' if env.get('GITHUB_TOKEN') else 'not set'}, OPENAI_API_KEY={'set' if env.get('OPENAI_API_KEY') else 'not set'}")
            if process.stdout:
                logger.info(f"Scan stdout for {job_id}: {process.stdout[:500]}...")  # Log first 500 chars
            if process.stderr:
                logger.info(f"Scan stderr for {job_id}: {process.stderr[:1000]}...")  # Log first 1000 chars

            if process.returncode == 0:
                logger.info(f"Successfully completed scan for {repo}")
                # Read the results from the output file
                with open(output_file, 'r', encoding='utf-8') as f:
                    scan_results = json.load(f)
                SCAN_JOBS[job_id] = {"status": "completed", "results": scan_results, "error": None}
            else:
                error_message = process.stderr or "Scan script failed with a non-zero exit code."
                logger.error(f"Failed to scan repository {repo}. Error: {error_message}")
                SCAN_JOBS[job_id] = {"status": "failed", "results": None, "error": error_message}

        except Exception as e:
            logger.error(f"An exception occurred while scanning {repo}: {e}")
            SCAN_JOBS[job_id] = {"status": "failed", "results": None, "error": str(e)}
        finally:
            # Clean up the results file
            if os.path.exists(output_file):
                os.remove(output_file)


    # Run the script in a background thread to avoid blocking the API request
    thread = threading.Thread(target=run_script, args=(repo_name, scan_id, token))
    thread.start()

    return jsonify({
        "message": f"Scan initiated for repository {repo_name}.",
        "scan_id": scan_id
    }), 202


@app.route('/api/scan/results/<scan_id>', methods=['GET'])
def get_scan_results(scan_id: str):
    """
    Endpoint for the frontend to poll for scan results.
    """
    job = SCAN_JOBS.get(scan_id)
    if not job:
        return jsonify({"error": "Scan ID not found"}), 404
    
    return jsonify(job), 200


@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors."""
    return jsonify({
        "error": "Not found",
        "message": "The requested endpoint was not found"
    }), 404


@app.errorhandler(405)
def method_not_allowed(error):
    """Handle 405 errors."""
    return jsonify({
        "error": "Method not allowed",
        "message": "The requested method is not allowed for this endpoint"
    }), 405


@app.errorhandler(500)
def internal_error(error):
    """Handle 500 errors."""
    return jsonify({
        "error": "Internal server error",
        "message": "An unexpected error occurred"
    }), 500


if __name__ == '__main__':
    # Development server configuration
    port = int(os.getenv('PORT', 5173))
    debug = os.getenv('FLASK_DEBUG', 'False').lower() == 'true'
    
    logger.info(f"Starting Flask development server on port {port}")
    logger.info("Available endpoints:")
    logger.info("  GET /health - Health check")
    logger.info("  GET /api/repositories - List repositories")
    logger.info("  GET /api/repositories/<owner>/<repo> - Get repository details")
    
    app.run(host='0.0.0.0', port=port, debug=debug)