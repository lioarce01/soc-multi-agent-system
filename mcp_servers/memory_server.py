"""
Memory & Chat MCP Server - Modular Implementation
Exposes investigation history query tools via MCP protocol (streamable_http)
This server is isolated from the main LangGraph application
"""

import sys
from pathlib import Path

# Add parent directory to path for imports (only for data access)
sys.path.insert(0, str(Path(__file__).parent.parent))

# Load environment variables from .env
from dotenv import load_dotenv
load_dotenv(Path(__file__).parent.parent / ".env")

from fastmcp import FastMCP
import logging

# ===== Logging Configuration =====
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("memory_mcp_server")

# ===== Import Modular Components =====
from mcp_servers.core.memory_manager import IsolatedMemoryManager
from mcp_servers.tools.memory_tools import register_memory_tools


# ===== Initialize Memory Manager =====

logger.info("=" * 60)
logger.info("Memory & Chat MCP Server")
logger.info("=" * 60)
logger.info("Initializing memory manager...")

memory_manager = IsolatedMemoryManager()

# Check if initialization was successful
if memory_manager.incident_db is None:
    logger.error("=" * 60)
    logger.error("WARNING: Memory database not initialized!")
    logger.error("Memory features (search, statistics, campaigns) will not work.")
    logger.error("Check the error messages above for details.")
    logger.error("=" * 60)
else:
    logger.info("=" * 60)
    logger.info("Memory manager ready")
    logger.info(f"   Database instance: {type(memory_manager.incident_db).__name__}")
    logger.info(f"   Database ID: {id(memory_manager.incident_db)}")
    logger.info(f"   Embeddings ID: {id(memory_manager.embeddings)}")
    logger.info("=" * 60)


# ===== Initialize FastMCP Server =====

mcp_server = FastMCP(
    name="Memory & Chat MCP Server",
    version="1.0.0"
)


# ===== Register Tools =====

register_memory_tools(mcp_server, memory_manager)


# ===== Run Server =====

if __name__ == "__main__":
    logger.info("=" * 60)
    logger.info("Memory & Chat MCP Server")
    logger.info("=" * 60)
    logger.info(f"Transport: HTTP")
    logger.info(f"Host: 0.0.0.0")
    logger.info(f"Port: 8003")
    logger.info(f"Available Tools:")
    logger.info("  - search_incidents()")
    logger.info("  - get_investigation_statistics()")
    logger.info("  - explain_incident()")
    logger.info("  - find_campaigns()")
    logger.info("  - save_incident()")
    logger.info("  - health_check()")
    logger.info("=" * 60)

    # Final status check before starting server
    if memory_manager.incident_db is None:
        logger.error("=" * 60)
        logger.error("CRITICAL: Memory database failed to initialize!")
        logger.error("=" * 60)
        logger.error("The server will start, but memory features will not work.")
        logger.error("")
        logger.error("To fix this:")
        logger.error("1. Install missing dependencies:")
        logger.error("   pip install langchain-community chromadb sentence-transformers")
        logger.error("")
        logger.error("2. Check the error messages above for specific issues")
        logger.error("")
        logger.error("3. Verify the data directory is writable:")
        logger.error(f"   Directory: {memory_manager.persist_directory}")
        logger.error("=" * 60)
    else:
        logger.info("Server ready - Memory database initialized")
        logger.info("=" * 60)

    logger.info("\nStarting server on http://0.0.0.0:8003...")
    logger.info("Use the health_check() tool to verify initialization status")

    # Run with HTTP transport
    mcp_server.run(transport="http", host="0.0.0.0", port=8003)
