"""
JUGGERNAUT RAIL - Vercel Serverless Handler

Production-ready serverless deployment using real src modules.
Wraps the FastAPI application for Vercel.
"""

import os
import sys

# Add project root to path for imports
project_root = os.path.dirname(os.path.dirname(__file__))
sys.path.insert(0, project_root)

from mangum import Mangum

# Import the real FastAPI application
from src.api.server import app

# Create the serverless handler
handler = Mangum(app, lifespan="auto")
