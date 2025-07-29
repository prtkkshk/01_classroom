#!/usr/bin/env python3
"""
Script to check for syntax errors in server.py
"""

import ast
import sys

def check_syntax(filename):
    """Check if a Python file has syntax errors"""
    try:
        with open(filename, 'r', encoding='utf-8') as f:
            source = f.read()
        
        # Try to parse the AST
        ast.parse(source)
        print(f"✅ {filename} has no syntax errors")
        return True
    except SyntaxError as e:
        print(f"❌ Syntax error in {filename}:")
        print(f"   Line {e.lineno}: {e.text}")
        print(f"   Error: {e.msg}")
        return False
    except Exception as e:
        print(f"❌ Error reading {filename}: {e}")
        return False

if __name__ == "__main__":
    success = check_syntax("backend/server.py")
    if success:
        print("🎉 Server.py is syntactically correct!")
    else:
        print("🔧 Please fix the syntax errors before deploying")
        sys.exit(1) 