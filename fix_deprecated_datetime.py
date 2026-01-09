#!/usr/bin/env python3
"""Fix deprecated datetime.now(timezone.utc) calls across the codebase"""

import os
import re

def fix_file(filepath):
    """Replace datetime.now(timezone.utc) with datetime.now(timezone.utc)"""
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            content = f.read()
        
        original = content
        
        # Replace datetime.now(timezone.utc) with datetime.now(timezone.utc)
        content = re.sub(r'datetime\.utcnow\(\)', 'datetime.now(timezone.utc)', content)
        
        if content != original:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write(content)
            print(f"✓ Fixed {filepath}")
            return True
        return False
    except Exception as e:
        print(f"✗ Error fixing {filepath}: {e}")
        return False

def main():
    """Scan and fix Python files"""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    fixed_count = 0
    
    # Only scan specific directories
    scan_dirs = ['AI', 'server', 'relay']
    
    for scan_dir in scan_dirs:
        dir_path = os.path.join(base_dir, scan_dir)
        if not os.path.exists(dir_path):
            continue
            
        for root, dirs, files in os.walk(dir_path):
            # Skip __pycache__
            dirs[:] = [d for d in dirs if d != '__pycache__']
            
            for file in files:
                if file.endswith('.py'):
                    filepath = os.path.join(root, file)
                    if fix_file(filepath):
                        fixed_count += 1
    
    print(f"\n{'='*60}")
    print(f"Fixed {fixed_count} files")
    print(f"{'='*60}")

if __name__ == '__main__':
    main()
