#!/usr/bin/env python3
"""
This file is part of Intellicrack.
Copyright (C) 2025 Zachary Flint

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <https://www.gnu.org/licenses/>.
"""

"""
Minimal test of specific functions without full import chain
"""

import sys


def test_binary_analysis_direct():
    """Test binary analysis by importing the specific module directly."""
    try:
        sys.path.insert(0, '.')
        
        # Import only the specific function we need
        from intellicrack.utils.analysis.binary_analysis import analyze_binary
        
        binary_path = 'test_samples/linux_license_app'
        print(f"Testing direct binary analysis on: {binary_path}")
        
        result = analyze_binary(binary_path)
        
        if result:
            print("✅ Direct binary analysis successful")
            print(f"   File type: {result.get('file_type', 'Unknown')}")
            print(f"   Architecture: {result.get('architecture', 'Unknown')}")
            print(f"   Functions: {len(result.get('functions', []))}")
            print(f"   Imports: {len(result.get('imports', []))}")
            return True
        else:
            print("❌ Direct binary analysis failed")
            return False
            
    except Exception as e:
        print(f"❌ Direct binary analysis error: {e}")
        return False

def test_ai_script_generator_direct():
    """Test AI script generator by importing specific module directly."""
    try:
        # Import specific modules bypassing __init__ imports
        from intellicrack.ai.ai_script_generator import AIScriptGenerator
        
        print("Testing direct AI script generator...")
        
        generator = AIScriptGenerator()
        
        # Simple test request
        script_request = {
            'target_binary': 'test_samples/linux_license_app',
            'method': 'frida',
            'bypass_license': True
        }
        
        result = generator.generate_frida_script(script_request)
        
        if result and result.get('script'):
            print("✅ Direct AI script generation successful")
            script = result['script']
            print(f"   Script length: {len(script)} characters")
            print(f"   Contains license bypass: {'license' in script.lower()}")
            return True
        else:
            print("❌ Direct AI script generation failed")
            return False
            
    except Exception as e:
        print(f"❌ Direct AI script generator error: {e}")
        return False

def test_autonomous_agent_direct():
    """Test autonomous agent by importing specific module directly."""
    try:
        from intellicrack.ai.autonomous_agent import AutonomousAgent
        
        print("Testing direct autonomous agent...")
        
        agent = AutonomousAgent()
        
        # Test request parsing
        user_request = "Generate a Frida script to bypass license checks in test_samples/linux_license_app"
        
        parsed_request = agent._parse_request(user_request)
        
        if parsed_request:
            print("✅ Direct autonomous agent successful")
            print(f"   Binary path: {parsed_request.get('binary_path')}")
            print(f"   Tool: {parsed_request.get('tool')}")
            return True
        else:
            print("❌ Direct autonomous agent failed")
            return False
            
    except Exception as e:
        print(f"❌ Direct autonomous agent error: {e}")
        return False

def main():
    """Test specific functions with minimal imports."""
    print("=== TESTING MINIMAL INTELLICRACK FUNCTIONS ===")
    
    results = []
    
    print("\n1. Testing Direct Binary Analysis:")
    results.append(test_binary_analysis_direct())
    
    print("\n2. Testing Direct AI Script Generator:")
    results.append(test_ai_script_generator_direct())
    
    print("\n3. Testing Direct Autonomous Agent:")
    results.append(test_autonomous_agent_direct())
    
    print(f"\n=== RESULTS: {sum(results)}/{len(results)} tests passed ===")
    
    return results

if __name__ == '__main__':
    main()
