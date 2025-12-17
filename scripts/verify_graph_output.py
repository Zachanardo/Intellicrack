
import re
import json
import sys
from pathlib import Path

def verify_html(file_path):
    print(f"Verifying {file_path}...")
    
    if not file_path.exists():
        print("FAIL: File not found.")
        sys.exit(1)
        
    content = file_path.read_text(encoding='utf-8')
    
    # 1. Check for Static Physics Setting
    # Search for "enabled: false" inside a physics block, handling newlines/spaces
    if re.search(r'physics:\s*\{[^}]*enabled:\s*false', content, re.DOTALL):
        print("PASS: Physics explicitly disabled (Static Mode).")
    else:
        print("FAIL: 'physics: { enabled: false }' not found. Graph might be dynamic/laggy.")

    # 2. Extract Nodes JSON
    # Pattern: const nodes = new vis.DataSet([...]);
    # We look for the array content inside the parens
    match = re.search(r'const nodes = new vis\.DataSet\(([\s\S]*?)\);', content)
    if not match:
        print("FAIL: Could not extract nodes JSON data.")
        sys.exit(1)
        
    try:
        nodes_data = json.loads(match.group(1))
    except json.JSONDecodeError as e:
        print(f"FAIL: JSON Decode Error in nodes data: {e}")
        # Print a snippet to debug
        print(f"Snippet: {match.group(1)[:100]}...")
        sys.exit(1)
        
    print(f"PASS: Successfully parsed {len(nodes_data)} nodes.")
    
    if len(nodes_data) < 1000:
        print(f"WARNING: Node count seems low ({len(nodes_data)}). Expected > 10,000 for full architecture.")
    
    # 3. Verify Pre-calculated Layout (X/Y coordinates)
    nodes_with_pos = [n for n in nodes_data if 'x' in n and 'y' in n]
    if len(nodes_with_pos) == 0:
        print("FAIL: No nodes have pre-calculated X/Y coordinates! Browser will define layout (slow).")
    elif len(nodes_with_pos) < len(nodes_data) * 0.9:
         print(f"WARNING: Only {len(nodes_with_pos)}/{len(nodes_data)} nodes have positions.")
    else:
        print(f"PASS: {len(nodes_with_pos)}/{len(nodes_data)} nodes have pre-calculated static positions.")

    # 4. Verify External Dependencies
    external_nodes = [n for n in nodes_data if n.get('group') == 'external']
    if len(external_nodes) == 0:
        print("FAIL: No external dependency nodes found. Filtering might be too strict.")
    else:
        print(f"PASS: Found {len(external_nodes)} external dependency nodes (e.g. imports).")
        # Sample one
        print(f"      Sample external node: {external_nodes[0].get('id')}")

    # 5. Verify Internal Modules
    internal_nodes = [n for n in nodes_data if n.get('group') == 'module']
    if len(internal_nodes) == 0:
        print("FAIL: No internal module nodes found.")
    else:
        print(f"PASS: Found {len(internal_nodes)} internal modules.")

if __name__ == "__main__":
    verify_html(Path("IntellicrackKnowledgeGraph.html"))
