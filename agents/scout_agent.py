"""
Scout Agent - Threat Intelligence Knowledge Base Builder

This agent builds and queries a vulnerability knowledge base using Redis.
"""

import os
import logging
from datetime import datetime
from typing import List, Dict, Any, Optional

import redis
from llama_index.core import Document, Settings
from llama_index.vector_stores.redis import RedisVectorStore
from llama_index.core import VectorStoreIndex
from llama_index.core.vector_stores.types import MetadataFilters, ExactMatchFilter
from dotenv import load_dotenv

load_dotenv()

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

class ScoutAgent:
    """Agent for building and querying threat intelligence."""
    
    def __init__(self, redis_url: str = "redis://localhost:6379"):
        self.redis_url = redis_url
        redis_client = redis.from_url(redis_url)

        self.vuln_store = RedisVectorStore(index_name="vulnerabilities", redis_client=redis_client)
        self.patches_store = RedisVectorStore(index_name="patches", redis_client=redis_client)

        try:
            self.vuln_index = VectorStoreIndex.from_vector_store(self.vuln_store)
            self.patches_index = VectorStoreIndex.from_vector_store(self.patches_store)
        except Exception:
            logger.info("Creating new empty indices for vulnerabilities and patches.")
            self.vuln_index = VectorStoreIndex.from_documents([], vector_store=self.vuln_store)
            self.patches_index = VectorStoreIndex.from_documents([], vector_store=self.patches_store)

        logger.info("Scout Agent initialized.")

    def find_similar_vulnerabilities(self, query: str, k: int = 3, metadata_filter: Optional[Dict] = None) -> List[Dict]:
        """Find vulnerabilities similar to the query."""
        try:
            filters = self._create_metadata_filters(metadata_filter)
            query_engine = self.vuln_index.as_query_engine(similarity_top_k=k, filters=filters)
            response = query_engine.query(query)
            return self._format_response(response, "vulnerabilities")
        except Exception as e:
            logger.error(f"Failed to search vulnerabilities: {e}")
            return []

    def find_proven_patches(self, vulnerability_type: str, language: Optional[str] = None, k: int = 2) -> List[Dict]:
        """Find proven patches for a specific vulnerability type."""
        try:
            query = f"proven fix for {vulnerability_type} in {language}" if language else f"proven fix for {vulnerability_type}"
            metadata_filter = {"vulnerability_type": vulnerability_type}
            if language:
                metadata_filter["language"] = language
            
            filters = self._create_metadata_filters(metadata_filter)
            query_engine = self.patches_index.as_query_engine(similarity_top_k=k, filters=filters)
            response = query_engine.query(query)
            return self._format_response(response, "patches")
        except Exception as e:
            logger.error(f"Failed to search patches: {e}")
            return []

    def _create_metadata_filters(self, metadata_filter: Optional[Dict]) -> Optional[MetadataFilters]:
        if not metadata_filter:
            return None
        return MetadataFilters(filters=[ExactMatchFilter(key=k, value=str(v)) for k, v in metadata_filter.items()])

    def _format_response(self, response, response_type: str) -> List[Dict]:
        results = []
        if hasattr(response, 'source_nodes'):
            for node in response.source_nodes:
                results.append({
                    "content": node.text,
                    "metadata": node.metadata,
                    "score": getattr(node, 'score', 0.0)
                })
        logger.info(f"Found {len(results)} similar {response_type}.")
        return results
