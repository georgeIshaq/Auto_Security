"""
Scout Agent - Threat Intelligence Knowledge Base Builder

This agent builds a comprehensive vulnerability knowledge base using Redis vector similarity search.
It scrapes threat intelligence, embeds vulnerability data, and provides search APIs for other agents.
"""

import os
import json
import asyncio
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict
from pathlib import Path

import requests
from bs4 import BeautifulSoup
from dotenv import load_dotenv

# Import our MCP client
from .mcp_stdio_client import BrightDataMCPStdioClient

# Add parent directory to path for GitHub client import
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from llama_index.core import Document, Settings, StorageContext
from llama_index.llms.openai import OpenAI
from llama_index.embeddings.openai import OpenAIEmbedding
from llama_index.vector_stores.redis import RedisVectorStore
from llama_index.core import VectorStoreIndex
from llama_index.core.vector_stores.types import MetadataFilters, MetadataFilter, ExactMatchFilter
from redisvl.schema import IndexSchema
import redis

# Load environment variables
load_dotenv()

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

@dataclass
class VulnerabilityData:
    """Structure for vulnerability information"""
    cve_id: str
    description: str
    severity: str
    cvss_score: float
    affected_packages: List[str]
    vulnerability_type: str
    published_date: str
    vector_string: str
    references: List[str]
    exploit_available: bool = False
    patch_available: bool = False

@dataclass
class PatchData:
    """Structure for patch/remediation information"""
    patch_id: str
    vulnerability_type: str
    language: str
    framework: str
    patch_content: str
    description: str
    effectiveness_score: float
    source_url: str
    implementation_complexity: str
    related_cves: List[str]

@dataclass
class ThreatIntelligence:
    """Combined threat intelligence data"""
    content: str
    metadata: Dict[str, Any]
    content_type: str  # 'vulnerability', 'patch', 'exploit', 'pattern'

class ScoutAgent:
    """
    Scout Agent for building and querying threat intelligence knowledge base
    """
    
    def __init__(self, redis_url: str = "redis://localhost:6379"):
        """Initialize Scout Agent with Redis vector stores"""
        self.redis_url = redis_url
        
        # Configure LlamaIndex settings
        Settings.llm = OpenAI(model="gpt-4", temperature=0.1)
        Settings.embed_model = OpenAIEmbedding(model="text-embedding-3-small")
        
        # Create Redis client
        redis_client = redis.from_url(redis_url)
        
        # Define custom schemas for different data types
        vuln_schema = IndexSchema.from_dict({
            "index": {
                "name": "vulnerabilities",
                "prefix": "vuln",
                "key_separator": ":"
            },
            "fields": [
                # Required LlamaIndex fields
                {"type": "tag", "name": "id"},
                {"type": "tag", "name": "doc_id"},
                {"type": "text", "name": "text"},
                # Vector field for OpenAI embeddings (1536 dimensions)
                {
                    "type": "vector",
                    "name": "vector",
                    "attrs": {
                        "dims": 1536,
                        "algorithm": "hnsw",
                        "distance_metric": "cosine"
                    }
                },
                # Custom metadata fields
                {"type": "tag", "name": "cve_id"},
                {"type": "tag", "name": "severity"},
                {"type": "tag", "name": "vulnerability_type"},
                {"type": "tag", "name": "affected_packages"},
                {"type": "tag", "name": "type"},
                {"type": "tag", "name": "source"},
                {"type": "tag", "name": "exploit_available"},
                {"type": "tag", "name": "patch_available"}
            ]
        })
        
        patches_schema = IndexSchema.from_dict({
            "index": {
                "name": "patches",
                "prefix": "patch",
                "key_separator": ":"
            },
            "fields": [
                # Required LlamaIndex fields
                {"type": "tag", "name": "id"},
                {"type": "tag", "name": "doc_id"},
                {"type": "text", "name": "text"},
                # Vector field for OpenAI embeddings (1536 dimensions)
                {
                    "type": "vector",
                    "name": "vector",
                    "attrs": {
                        "dims": 1536,
                        "algorithm": "hnsw",
                        "distance_metric": "cosine"
                    }
                },
                # Custom metadata fields
                {"type": "tag", "name": "patch_id"},
                {"type": "tag", "name": "vulnerability_type"},
                {"type": "tag", "name": "language"},
                {"type": "tag", "name": "framework"},
                {"type": "tag", "name": "type"},
                {"type": "tag", "name": "source"},
                {"type": "tag", "name": "implementation_complexity"},
                {"type": "tag", "name": "related_cves"}
            ]
        })
        
        # Initialize vector stores with custom schemas
        self.vuln_store = RedisVectorStore(
            schema=vuln_schema,
            redis_client=redis_client,
            overwrite=False
        )
        
        self.patches_store = RedisVectorStore(
            schema=patches_schema,
            redis_client=redis_client,
            overwrite=False
        )
        
        # For simplicity, use default schemas for exploits and patterns
        self.exploits_store = RedisVectorStore(redis_client=redis_client, overwrite=False)
        self.patterns_store = RedisVectorStore(redis_client=redis_client, overwrite=False)
        
        # Create storage contexts
        self.vuln_storage_context = StorageContext.from_defaults(vector_store=self.vuln_store)
        self.patches_storage_context = StorageContext.from_defaults(vector_store=self.patches_store)
        self.exploits_storage_context = StorageContext.from_defaults(vector_store=self.exploits_store)
        self.patterns_storage_context = StorageContext.from_defaults(vector_store=self.patterns_store)
        
        # Initialize indices
        try:
            self.vuln_index = VectorStoreIndex.from_vector_store(self.vuln_store)
            self.patches_index = VectorStoreIndex.from_vector_store(self.patches_store)
            self.exploits_index = VectorStoreIndex.from_vector_store(self.exploits_store)
            self.patterns_index = VectorStoreIndex.from_vector_store(self.patterns_store)
        except Exception as e:
            # If indices don't exist yet, create empty ones
            logger.info("Creating new empty indices")
            self.vuln_index = VectorStoreIndex([], storage_context=self.vuln_storage_context)
            self.patches_index = VectorStoreIndex([], storage_context=self.patches_storage_context)
            self.exploits_index = VectorStoreIndex([], storage_context=self.exploits_storage_context)
            self.patterns_index = VectorStoreIndex([], storage_context=self.patterns_storage_context)
        
        # Initialize MCP client for real web data fetching
        self.mcp_client = None
        self._init_mcp_client()
        
        logger.info("Scout Agent initialized with Redis vector stores")

    def _init_mcp_client(self):
        """Initialize BrightData MCP client for real data fetching"""
        try:
            self.mcp_client = BrightDataMCPStdioClient()
            if self.mcp_client.start():
                logger.info("✅ BrightData MCP client initialized successfully")
            else:
                logger.warning("❌ Failed to start BrightData MCP client - falling back to mock data")
                self.mcp_client = None
        except Exception as e:
            logger.warning(f"❌ MCP client initialization failed: {e} - falling back to mock data")
            self.mcp_client = None

    def _prepare_metadata(self, data_dict: Dict[str, Any]) -> Dict[str, Any]:
        """
        Prepare metadata by converting lists to comma-separated strings
        since RedisVectorStore only supports scalar metadata fields
        """
        prepared = {}
        for key, value in data_dict.items():
            if isinstance(value, list):
                # Convert list to comma-separated string
                prepared[key] = ",".join(str(item) for item in value)
            elif isinstance(value, bool):
                # Convert boolean to string
                prepared[key] = str(value).lower()
            elif value is None:
                # Skip None values
                continue
            else:
                # Keep as string
                prepared[key] = str(value)
        return prepared

    def ingest_vulnerability(self, vuln_data: VulnerabilityData) -> bool:
        """
        Ingest vulnerability data into the vector store
        """
        try:
            # Create document with rich content
            content = f"""
            CVE ID: {vuln_data.cve_id}
            Description: {vuln_data.description}
            Severity: {vuln_data.severity} (CVSS: {vuln_data.cvss_score})
            Vulnerability Type: {vuln_data.vulnerability_type}
            Affected Packages: {', '.join(vuln_data.affected_packages)}
            Vector: {vuln_data.vector_string}
            Published: {vuln_data.published_date}
            Exploit Available: {vuln_data.exploit_available}
            Patch Available: {vuln_data.patch_available}
            References: {', '.join(vuln_data.references)}
            """
            
            metadata = asdict(vuln_data)
            metadata.update({
                "type": "vulnerability",
                "ingestion_time": datetime.utcnow().isoformat(),
                "source": "scout_agent"
            })
            
            # Prepare metadata for Redis (convert lists to strings)
            prepared_metadata = self._prepare_metadata(metadata)
            
            doc = Document(text=content.strip(), metadata=prepared_metadata)
            
            # Use index.insert() to add the document
            self.vuln_index.insert(doc)
            
            logger.info(f"Ingested vulnerability: {vuln_data.cve_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to ingest vulnerability {vuln_data.cve_id}: {e}")
            return False

    def ingest_patch(self, patch_data: PatchData) -> bool:
        """
        Ingest patch/remediation data into the vector store
        """
        try:
            content = f"""
            Patch ID: {patch_data.patch_id}
            Vulnerability Type: {patch_data.vulnerability_type}
            Language: {patch_data.language}
            Framework: {patch_data.framework}
            Description: {patch_data.description}
            Implementation Complexity: {patch_data.implementation_complexity}
            Effectiveness Score: {patch_data.effectiveness_score}
            Related CVEs: {', '.join(patch_data.related_cves)}
            
            Patch Content:
            {patch_data.patch_content}
            """
            
            metadata = asdict(patch_data)
            metadata.update({
                "type": "patch",
                "ingestion_time": datetime.utcnow().isoformat(),
                "source": "scout_agent"
            })
            
            # Prepare metadata for Redis (convert lists to strings)
            prepared_metadata = self._prepare_metadata(metadata)
            
            doc = Document(text=content.strip(), metadata=prepared_metadata)
            
            # Use index.insert() to add the document
            self.patches_index.insert(doc)
            
            logger.info(f"Ingested patch: {patch_data.patch_id}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to ingest patch {patch_data.patch_id}: {e}")
            return False

    def find_similar_vulnerabilities(self, query: str, k: int = 5, 
                                   metadata_filter: Optional[Dict] = None) -> List[Dict]:
        """
        Find vulnerabilities similar to the query using vector similarity search
        """
        try:
            # Create metadata filters if provided
            filters = None
            if metadata_filter:
                filter_list = []
                for key, value in metadata_filter.items():
                    filter_list.append(ExactMatchFilter(key=key, value=str(value)))
                filters = MetadataFilters(filters=filter_list)
            
            # Use the query engine for semantic search with filters
            query_engine = self.vuln_index.as_query_engine(
                similarity_top_k=k,
                filters=filters
            )
            response = query_engine.query(query)
            
            # Extract results with metadata
            results = []
            if hasattr(response, 'source_nodes'):
                for node in response.source_nodes:
                    result = {
                        "content": node.text,
                        "metadata": node.metadata,
                        "score": getattr(node, 'score', 0.0)
                    }
                    results.append(result)
            
            logger.info(f"Found {len(results)} similar vulnerabilities for query: {query}")
            return results
            
        except Exception as e:
            logger.error(f"Failed to search vulnerabilities: {e}")
            return []

    def find_proven_patches(self, vulnerability_type: str, language: str = None, 
                          framework: str = None, k: int = 3) -> List[Dict]:
        """
        Find proven patches for a specific vulnerability type
        """
        try:
            # Build query
            query = f"proven fix for {vulnerability_type}"
            if language:
                query += f" in {language}"
            if framework:
                query += f" using {framework}"
            
            # Create metadata filters
            filters = None
            filter_list = [ExactMatchFilter(key="vulnerability_type", value=vulnerability_type)]
            if language:
                filter_list.append(ExactMatchFilter(key="language", value=language))
            if framework:
                filter_list.append(ExactMatchFilter(key="framework", value=framework))
            
            if filter_list:
                filters = MetadataFilters(filters=filter_list)
            
            query_engine = self.patches_index.as_query_engine(
                similarity_top_k=k,
                filters=filters
            )
            response = query_engine.query(query)
            
            results = []
            if hasattr(response, 'source_nodes'):
                for node in response.source_nodes:
                    results.append({
                        "content": node.text,
                        "metadata": node.metadata,
                        "score": getattr(node, 'score', 0.0)
                    })
            
            logger.info(f"Found {len(results)} proven patches for {vulnerability_type}")
            return results
            
        except Exception as e:
            logger.error(f"Failed to search patches: {e}")
            return []

    def get_cve_context(self, package_name: str, version: str = None) -> List[Dict]:
        """
        Get CVE context for a specific package and version
        """
        try:
            query = f"vulnerabilities affecting {package_name}"
            if version:
                query += f" version {version}"
            
            results = self.find_similar_vulnerabilities(
                query, 
                k=10,
                metadata_filter={"affected_packages": package_name} if not version else None
            )
            
            # Filter by version if specified
            if version:
                filtered_results = []
                for result in results:
                    affected_packages = result['metadata'].get('affected_packages', [])
                    if package_name in affected_packages:
                        filtered_results.append(result)
                results = filtered_results
            
            logger.info(f"Found {len(results)} CVEs for {package_name} {version or ''}")
            return results
            
        except Exception as e:
            logger.error(f"Failed to get CVE context: {e}")
            return []

    def scrape_real_vulnerabilities_via_mcp(self, limit: int = 10, packages: List[str] = None) -> List[VulnerabilityData]:
        """
        Scrape real vulnerability data using BrightData MCP
        
        Args:
            limit: Maximum number of vulnerabilities to return
            packages: List of package names to search for specifically
        """
        if not self.mcp_client:
            logger.warning("MCP client not available, falling back to mock data")
            return self.scrape_nvd_cves(limit)
        
        try:
            logger.info(f"Fetching real vulnerability data via MCP (limit: {limit})")
            vulnerabilities = []
            
            # Create search queries - either package-specific or general
            search_queries = []
            if packages:
                # Search for vulnerabilities specific to the packages (limit to 5 max)
                top_packages = packages[:5]
                for package in top_packages:
                    search_queries.append(f'"{package}" vulnerability CVE site:nvd.nist.gov')
                logger.info(f"Using package-specific searches for: {top_packages}")
            else:
                # Fallback to general search
                search_queries = ['"CVE-2024" vulnerability details site:nvd.nist.gov']
                logger.info("Using general CVE search")
            
            all_urls = []
            for query in search_queries:
                search_response = self.mcp_client.search_engine(
                    query, 
                    max_results=3  # Limit to 3 results per package to keep it fast
                )
                
                if not search_response.success:
                    logger.warning(f"MCP search failed for query '{query}': {search_response.error}")
                    continue
                
                # Process search results and extract CVE information
                search_results = search_response.data.get('content', [])
                
                if search_results:
                    # BrightData returns search results as markdown text, not structured URLs
                    search_content = search_results[0].get('text', '') if search_results else ''
                    
                    # Extract specific CVE detail URLs from the markdown search results
                    import re
                    # Look for specific CVE detail page URLs
                    cve_detail_patterns = [
                        r'https://nvd\.nist\.gov/vuln/detail/CVE-[0-9]{4}-[0-9]+',
                        r'https://cve\.mitre\.org/cgi-bin/cvename\.cgi\?name=CVE-[0-9]{4}-[0-9]+',
                    ]
                    
                    for pattern in cve_detail_patterns:
                        found_urls = re.findall(pattern, search_content)
                        all_urls.extend(found_urls)
            
            # Remove duplicates while preserving order
            all_urls = list(dict.fromkeys(all_urls))
            
            logger.info(f"Extracted {len(all_urls)} CVE-related URLs from search results")
            
            # Scrape each relevant CVE URL
            for url in all_urls[:limit]:
                    try:
                        logger.info(f"Scraping CVE URL: {url}")
                        page_response = self.mcp_client.scrape_as_markdown(url)
                        logger.info(f"🌐 MCP scrape success: {page_response.success}")
                        logger.info(f"🌐 MCP response data type: {type(page_response.data)}")
                        logger.info(f"🌐 MCP response data: {page_response.data}")
                        
                        if page_response.success:
                            # Parse the scraped content to extract CVE data
                            content = page_response.data.get('content', [{}])
                            logger.info(f"🌐 Extracted content type: {type(content)}")
                            logger.info(f"🌐 Extracted content: {content}")
                            page_text = content[0].get('text', '') if content else ''
                            
                            vuln_data = self._parse_vulnerability_from_content(
                                page_text,
                                url,
                                f"Vulnerability from {url}",
                                f"Security advisory found at {url}"
                            )
                            if vuln_data:
                                vulnerabilities.append(vuln_data)
                                logger.info(f"Successfully parsed vulnerability: {vuln_data.cve_id}")
                    except Exception as e:
                        logger.warning(f"Failed to scrape URL {url}: {e}")
                        continue
            
            logger.info(f"Successfully fetched {len(vulnerabilities)} real vulnerabilities via MCP")
            
            # If we didn't get enough real data, supplement with mock data
            if len(vulnerabilities) < limit:
                mock_cves = self.scrape_nvd_cves(limit - len(vulnerabilities))
                vulnerabilities.extend(mock_cves)
            
            return vulnerabilities[:limit]
            
        except Exception as e:
            logger.error(f"Failed to fetch real vulnerabilities via MCP: {e}")
            return self.scrape_nvd_cves(limit)

    def scan_repository_for_vulnerabilities(self, repo_name: str, github_token: Optional[str] = None) -> List[VulnerabilityData]:
        """
        Scan a GitHub repository for vulnerabilities based on its dependencies.
        
        Args:
            repo_name: Repository name in format 'owner/repo'
            github_token: GitHub API token (optional, will use env var if not provided)
            
        Returns:
            List of vulnerabilities relevant to the repository's packages
        """
        try:
            # Import GitHub client here to avoid circular imports
            from github_client.github_integration import GitHubIntegration
            
            logger.info(f"Starting repository-aware vulnerability scan for: {repo_name}")
            
            # Initialize GitHub client
            gh_client = GitHubIntegration(github_token)
            
            # Extract packages from repository
            packages = gh_client.extract_packages_from_repo(repo_name)
            logger.info(f"Found {len(packages)} packages in repository: {packages}")
            
            if not packages:
                logger.warning("No packages found, falling back to general vulnerability scan")
                return self.scrape_real_vulnerabilities_via_mcp(limit=10)
            
            # Search for vulnerabilities specific to these packages
            vulnerabilities = self.scrape_real_vulnerabilities_via_mcp(
                limit=15,  # Get more results since we have specific packages
                packages=packages
            )
            
            logger.info(f"Found {len(vulnerabilities)} vulnerabilities for repository packages")
            return vulnerabilities
            
        except ImportError as e:
            logger.error(f"Failed to import GitHub client: {e}")
            return []
        except Exception as e:
            logger.error(f"Failed to scan repository {repo_name}: {e}")
            return []

    def _parse_vulnerability_from_content(self, content: str, url: str, title: str, description: str) -> Optional[VulnerabilityData]:
        """
        Parse vulnerability data from scraped web content using LLM
        """
        logger.info(f"📝 Parsing content from: {url}")
        logger.info(f"📄 Content length: {len(content)} characters")
        logger.info(f"📋 Content preview (first 500 chars): {content[:500]}")
        logger.info(f"🏷️  Title: {title}")
        logger.info(f"📝 Description: {description}")
        
        try:
            # Use OpenAI to extract structured CVE data from the content
            from llama_index.llms.openai import OpenAI
            llm = OpenAI(model="gpt-4", temperature=0.1)
            
            # Send full content - the CVE details are often later in the page
            content_for_llm = content
            
            extraction_prompt = f"""
            You are parsing an NIST NVD (National Vulnerability Database) page. Extract the CVE information and return it as a JSON object.
            
            Look for these specific patterns in the content:
            - CVE ID: Look for "CVE-YYYY-NNNN Detail" headings
            - Description: Look for "Description" section after the CVE detail heading  
            - CVSS Score: Look for "Base Score:" followed by a number
            - Severity: Look for severity ratings like "HIGH", "CRITICAL", "MEDIUM", "LOW"
            - Vector String: Look for "Vector:" followed by CVSS vector strings
            - Affected Software: Look for "Known Affected Software" or product names
            - References: Look for URLs in "References to Advisories" section
            
            Content to parse:
            {content_for_llm}
            
            Return ONLY a valid JSON object with these exact fields:
            {{
                "cve_id": "extracted CVE ID",
                "description": "vulnerability description from Description section", 
                "severity": "extracted severity level",
                "cvss_score": extracted_numeric_score,
                "affected_packages": ["extracted software/product names"],
                "vulnerability_type": "type like 'use after free', 'buffer overflow', etc",
                "published_date": "YYYY-MM-DD from NVD Published Date",
                "vector_string": "CVSS vector string if found",
                "references": ["reference URLs found"],
                "exploit_available": true/false,
                "patch_available": true/false
            }}
            
            If you cannot find clear CVE data, return null.
            """
            
            logger.info(f"🤖 Sending prompt to LLM (length: {len(extraction_prompt)} chars)")
            logger.debug(f"🤖 Full prompt: {extraction_prompt}")
            
            response = llm.complete(extraction_prompt)
            result_text = response.text.strip()
            
            logger.info(f"🤖 LLM response length: {len(result_text)} characters")
            logger.info(f"🤖 LLM raw response: {result_text}")
            
            # Try to parse the JSON response
            if result_text.lower() == "null" or not result_text:
                logger.warning(f"❌ Empty or null response from LLM for {url}")
                return None
                
            # Clean up the response to extract JSON
            if "```json" in result_text:
                result_text = result_text.split("```json")[1].split("```")[0]
            elif "```" in result_text:
                result_text = result_text.split("```")[1].split("```")[0]
            
            result_text = result_text.strip()
            
            if not result_text:
                logger.warning(f"No text content after cleaning for {url}")
                return None
            
            vuln_dict = json.loads(result_text)
            
            # Create VulnerabilityData object
            vuln_data = VulnerabilityData(
                cve_id=vuln_dict.get("cve_id", f"SCRAPED-{int(datetime.now().timestamp())}"),
                description=vuln_dict.get("description", description),
                severity=vuln_dict.get("severity", "MEDIUM"),
                cvss_score=float(vuln_dict.get("cvss_score", 5.0)),
                affected_packages=vuln_dict.get("affected_packages", []),
                vulnerability_type=vuln_dict.get("vulnerability_type", "unknown"),
                published_date=vuln_dict.get("published_date", datetime.now().strftime("%Y-%m-%d")),
                vector_string=vuln_dict.get("vector_string", ""),
                references=vuln_dict.get("references", [url]),
                exploit_available=vuln_dict.get("exploit_available", False),
                patch_available=vuln_dict.get("patch_available", False)
            )
            
            return vuln_data
            
        except Exception as e:
            logger.warning(f"Failed to parse vulnerability from content: {e}")
            return None

    def scrape_nvd_cves(self, limit: int = 10) -> List[VulnerabilityData]:
        """
        Fallback method with sample CVE data for when MCP is not available
        """
        try:
            logger.info(f"Using fallback sample CVE data (limit: {limit})")
            
            # Sample CVE data for fallback
            sample_cves = [
                VulnerabilityData(
                    cve_id="CVE-2023-42363",
                    description="BusyBox before 1.35.0 allows remote attackers to execute arbitrary code if netstat is used",
                    severity="CRITICAL",
                    cvss_score=9.8,
                    affected_packages=["busybox"],
                    vulnerability_type="remote_code_execution",
                    published_date="2023-11-28",
                    vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    references=["https://nvd.nist.gov/vuln/detail/CVE-2023-42363"],
                    exploit_available=True,
                    patch_available=True
                ),
                VulnerabilityData(
                    cve_id="CVE-2023-45853",
                    description="MiniZip in zlib through 1.3 has an integer overflow and resultant heap-based buffer overflow in zipOpenNewFileInZip4_64 via a long filename",
                    severity="HIGH",
                    cvss_score=8.8,
                    affected_packages=["zlib", "minizip"],
                    vulnerability_type="buffer_overflow",
                    published_date="2023-10-14",
                    vector_string="CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                    references=["https://nvd.nist.gov/vuln/detail/CVE-2023-45853"],
                    exploit_available=False,
                    patch_available=True
                ),
                VulnerabilityData(
                    cve_id="CVE-2023-38408",
                    description="The PKCS#11 feature in ssh-agent in OpenSSH before 9.3p2 has an insufficiently trustworthy search path, leading to remote code execution if an agent is forwarded to an attacker-controlled system",
                    severity="HIGH",
                    cvss_score=7.5,
                    affected_packages=["openssh"],
                    vulnerability_type="remote_code_execution",
                    published_date="2023-07-19",
                    vector_string="CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H",
                    references=["https://nvd.nist.gov/vuln/detail/CVE-2023-38408"],
                    exploit_available=False,
                    patch_available=True
                )
            ]
            
            logger.info(f"Generated {len(sample_cves)} sample CVEs")
            return sample_cves[:limit]
            
        except Exception as e:
            logger.error(f"Failed to scrape CVEs: {e}")
            return []

    def scrape_security_patches(self, limit: int = 5) -> List[PatchData]:
        """
        Scrape security patches from various sources
        This is a simplified version - in production you'd use GitHub API, etc.
        """
        try:
            logger.info(f"Generating sample security patches (limit: {limit})")
            
            # Sample patch data for demonstration
            sample_patches = [
                PatchData(
                    patch_id="patch_sql_injection_express_001",
                    vulnerability_type="sql_injection",
                    language="javascript",
                    framework="express",
                    patch_content="""
// Before (vulnerable)
app.get('/users/:id', (req, res) => {
  const query = `SELECT * FROM users WHERE id = ${req.params.id}`;
  db.query(query, (err, results) => {
    res.json(results);
  });
});

// After (secure)
app.get('/users/:id', (req, res) => {
  const query = 'SELECT * FROM users WHERE id = ?';
  db.query(query, [req.params.id], (err, results) => {
    res.json(results);
  });
});
                    """,
                    description="Fix SQL injection by using parameterized queries instead of string concatenation",
                    effectiveness_score=0.95,
                    source_url="https://github.com/example/security-fix-123",
                    implementation_complexity="low",
                    related_cves=["CVE-2023-12345"]
                ),
                PatchData(
                    patch_id="patch_xss_react_001",
                    vulnerability_type="cross_site_scripting",
                    language="javascript",
                    framework="react",
                    patch_content="""
// Before (vulnerable)
function UserProfile({ userBio }) {
  return <div dangerouslySetInnerHTML={{__html: userBio}} />;
}

// After (secure)
import DOMPurify from 'dompurify';

function UserProfile({ userBio }) {
  const sanitizedBio = DOMPurify.sanitize(userBio);
  return <div dangerouslySetInnerHTML={{__html: sanitizedBio}} />;
}
                    """,
                    description="Prevent XSS by sanitizing user input before rendering HTML",
                    effectiveness_score=0.92,
                    source_url="https://github.com/example/xss-fix-456",
                    implementation_complexity="medium",
                    related_cves=["CVE-2023-67890"]
                ),
                PatchData(
                    patch_id="patch_rce_python_001",
                    vulnerability_type="remote_code_execution",
                    language="python",
                    framework="flask",
                    patch_content="""
# Before (vulnerable)
import subprocess
from flask import request

@app.route('/ping')
def ping():
    host = request.args.get('host')
    result = subprocess.run(f'ping -c 1 {host}', shell=True, capture_output=True)
    return result.stdout

# After (secure)
import subprocess
import shlex
from flask import request

@app.route('/ping')
def ping():
    host = request.args.get('host')
    if not host or not host.replace('.', '').replace('-', '').isalnum():
        return "Invalid host", 400
    
    result = subprocess.run(['ping', '-c', '1', host], capture_output=True)
    return result.stdout
                    """,
                    description="Prevent command injection by validating input and avoiding shell=True",
                    effectiveness_score=0.98,
                    source_url="https://github.com/example/rce-fix-789",
                    implementation_complexity="medium",
                    related_cves=["CVE-2023-11111"]
                )
            ]
            
            logger.info(f"Generated {len(sample_patches)} sample patches")
            return sample_patches[:limit]
            
        except Exception as e:
            logger.error(f"Failed to generate patches: {e}")
            return []

    def populate_knowledge_base(self, vuln_limit: int = 10, patch_limit: int = 5):
        """
        Populate the vector stores with initial vulnerability and patch data
        """
        logger.info("Starting knowledge base population...")
        
        # Scrape and ingest vulnerabilities (using MCP if available)
        vulnerabilities = self.scrape_real_vulnerabilities_via_mcp(vuln_limit)
        vuln_success = 0
        for vuln in vulnerabilities:
            if self.ingest_vulnerability(vuln):
                vuln_success += 1
        
        # Scrape and ingest patches
        patches = self.scrape_security_patches(patch_limit)
        patch_success = 0
        for patch in patches:
            if self.ingest_patch(patch):
                patch_success += 1
        
        logger.info(f"Knowledge base populated: {vuln_success}/{len(vulnerabilities)} vulnerabilities, {patch_success}/{len(patches)} patches")
        return {"vulnerabilities": vuln_success, "patches": patch_success}

    def get_statistics(self) -> Dict[str, Any]:
        """
        Get statistics about the knowledge base
        """
        try:
            # Note: In a real implementation, you'd query Redis for actual counts
            # For now, we'll return basic stats
            stats = {
                "status": "active",
                "redis_url": self.redis_url,
                "stores": {
                    "vulnerabilities": "available",
                    "patches": "available", 
                    "exploits": "available",
                    "patterns": "available"
                },
                "last_update": datetime.utcnow().isoformat()
            }
            
            return stats
            
        except Exception as e:
            logger.error(f"Failed to get statistics: {e}")
            return {"status": "error", "error": str(e)}

# Example usage and testing
if __name__ == "__main__":
    async def main():
        # Initialize Scout Agent
        scout = ScoutAgent()
        
        # Populate knowledge base with sample data
        print("Populating knowledge base...")
        results = scout.populate_knowledge_base(vuln_limit=3, patch_limit=3)
        print(f"Population results: {results}")
        
        # Test similarity searches
        print("\n--- Testing Vulnerability Search ---")
        vuln_results = scout.find_similar_vulnerabilities("SQL injection in web application")
        for i, result in enumerate(vuln_results[:2], 1):
            print(f"{i}. CVE: {result['metadata'].get('cve_id', 'Unknown')}")
            print(f"   Score: {result['score']:.3f}")
            print(f"   Type: {result['metadata'].get('vulnerability_type', 'Unknown')}")
        
        print("\n--- Testing Patch Search ---")
        patch_results = scout.find_proven_patches("sql_injection", language="javascript")
        for i, result in enumerate(patch_results[:2], 1):
            print(f"{i}. Patch: {result['metadata'].get('patch_id', 'Unknown')}")
            print(f"   Score: {result['score']:.3f}")
            print(f"   Effectiveness: {result['metadata'].get('effectiveness_score', 'Unknown')}")
        
        print("\n--- Testing CVE Context ---")
        cve_results = scout.get_cve_context("busybox")
        for i, result in enumerate(cve_results[:1], 1):
            print(f"{i}. CVE: {result['metadata'].get('cve_id', 'Unknown')}")
            print(f"   Severity: {result['metadata'].get('severity', 'Unknown')}")
            print(f"   CVSS: {result['metadata'].get('cvss_score', 'Unknown')}")
        
        print("\n--- Statistics ---")
        stats = scout.get_statistics()
        print(json.dumps(stats, indent=2))
    
    # Run the async main function
    asyncio.run(main())
