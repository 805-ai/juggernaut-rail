"""
Vercel Serverless Entry Point for Juggernaut Rail
"""
import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from api.server import app

# Vercel handler
handler = app
