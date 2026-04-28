"""
Helper script to set up .env file
"""

import os
import shutil
from pathlib import Path

def setup_env():
    """Create .env file from example if it doesn't exist"""
    env_file = Path(".env")
    example_file = Path("env.example")
    
    if env_file.exists():
        print("✓ .env file already exists")
        response = input("Do you want to overwrite it? (y/N): ")
        if response.lower() != 'y':
            print("Keeping existing .env file")
            return
    
    if not example_file.exists():
        print("✗ env.example file not found!")
        print("Creating a basic .env file...")
        
        # Create basic .env file
        with open(env_file, 'w') as f:
            f.write("# Aghora Malware Analysis Agent - Environment Variables\n")
            f.write("# Fill in your values below\n\n")
            f.write("# OpenAI API Configuration (Required for AI chat)\n")
            f.write("OPENAI_API_KEY=your-openai-api-key-here\n\n")
            f.write("# Analysis Tool Paths (Optional)\n")
            f.write("DIE_PATH=\n")
            f.write("PESTUDIO_PATH=\n")
            f.write("STRINGS_PATH=\n\n")
            f.write("# Server Configuration (Optional)\n")
            f.write("SERVER_HOST=0.0.0.0\n")
            f.write("SERVER_PORT=8000\n")
            f.write("LOGS_DIR=analysis_logs\n")
            f.write("CHART_AGENT_BASE_URL=http://localhost:8000\n")
        
        print(f"✓ Created {env_file}")
    else:
        # Copy from example
        shutil.copy(example_file, env_file)
        print(f"✓ Created {env_file} from {example_file}")
    
    print("\n📝 Please edit .env and fill in your values:")
    print("   - OPENAI_API_KEY (required for AI chat)")
    print("   - Tool paths (optional, if tools are not in PATH)")
    print("\nThe .env file is automatically loaded by all scripts.")

if __name__ == "__main__":
    print("="*60)
    print("  Aghora Malware Analysis Agent - Environment Setup")
    print("="*60)
    print()
    setup_env()


