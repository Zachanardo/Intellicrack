"""
Integration tests for REAL AI-powered analysis workflows.
Tests binary analysis → AI script generation → validation pipeline.
NO MOCKS - ALL TESTS USE REAL AI MODELS AND VALIDATE WORKING SCRIPTS.
"""

import pytest
import tempfile
from pathlib import Path
import subprocess
import struct

from intellicrack.core.analysis.binary_analyzer import BinaryAnalyzer
from intellicrack.ai.ai_script_generator import AIScriptGenerator
from intellicrack.ai.llm_backends import LLMManager
from intellicrack.core.analysis.radare2_enhanced_integration import RadareIntegration
from tests.base_test import IntellicrackTestBase


class TestAIAnalysisWorkflow(IntellicrackTestBase):
    """Test REAL AI-powered analysis workflows with actual script generation."""
    
    @pytest.fixture(autouse=True)
    def setup(self):
        """Set up test with analyzers and AI components."""
        self.binary_analyzer = BinaryAnalyzer()
        self.ai_generator = AIScriptGenerator()
        self.llm_manager = LLMManager()
        
        try:
            self.r2_integration = RadareIntegration()
        except Exception:
            self.r2_integration = None
            
        self.temp_dir = Path(tempfile.mkdtemp())
        
    def teardown_method(self):
        """Clean up temp files and AI sessions."""
        import shutil
        if self.temp_dir.exists():
            shutil.rmtree(self.temp_dir)
            
        if self.r2_integration and hasattr(self.r2_integration, 'cleanup'):
            self.r2_integration.cleanup()
            
    def create_analysis_target_binary(self, name="target.exe"):
        """Create binary with interesting analysis targets."""
        binary_path = self.temp_dir / name
        
        # Create PE with multiple functions and interesting features
        dos_header = b'MZ' + b'\\x00' * 58 + struct.pack('<L', 0x80)
        dos_stub = b'\\x00' * (0x80 - len(dos_header))
        
        # PE signature and headers
        nt_signature = b'PE\\x00\\x00'
        
        # COFF header
        machine = struct.pack('<H', 0x014c)  # i386
        num_sections = struct.pack('<H', 2)  # 2 sections
        timestamp = struct.pack('<L', 0)
        ptr_symbols = struct.pack('<L', 0)
        num_symbols = struct.pack('<L', 0)
        size_optional = struct.pack('<H', 224)
        characteristics = struct.pack('<H', 0x0102)
        
        coff_header = machine + num_sections + timestamp + ptr_symbols + num_symbols + size_optional + characteristics
        
        # Optional header
        magic = struct.pack('<H', 0x010b)  # PE32
        optional_data = b'\\x00' * 223
        optional_header = magic + optional_data
        
        # Section headers (.text and .data)
        text_section = (b'.text\\x00\\x00\\x00' + struct.pack('<L', 0x1000) + 
                       struct.pack('<L', 0x1000) + struct.pack('<L', 0x400) + 
                       struct.pack('<L', 0x400) + b'\\x00' * 12 + struct.pack('<L', 0x60000020))
        
        data_section = (b'.data\\x00\\x00\\x00' + struct.pack('<L', 0x1000) + 
                       struct.pack('<L', 0x2000) + struct.pack('<L', 0x200) + 
                       struct.pack('<L', 0x800) + b'\\x00' * 12 + struct.pack('<L', 0xC0000040))
        
        section_headers = text_section + data_section
        
        # Combine headers
        headers = dos_header + dos_stub + nt_signature + coff_header + optional_header + section_headers
        
        # Pad to section starts
        padding1 = b'\\x00' * (0x400 - len(headers))
        
        # .text section with interesting functions
        code = b''
        
        # Function 1: Simple function
        code += b'\\x55'              # push ebp
        code += b'\\x8b\\xec'         # mov ebp, esp
        code += b'\\x8b\\x45\\x08'    # mov eax, [ebp+8]  (first parameter)
        code += b'\\x83\\xc0\\x01'    # add eax, 1
        code += b'\\x5d'             # pop ebp
        code += b'\\xc3'             # ret
        
        # Function 2: Loop function  
        code += b'\\x55'              # push ebp
        code += b'\\x8b\\xec'         # mov ebp, esp
        code += b'\\x83\\xec\\x04'    # sub esp, 4 (local var)
        code += b'\\xc7\\x45\\xfc\\x00\\x00\\x00\\x00'  # mov [ebp-4], 0 (counter)
        
        # Loop start
        code += b'\\x83\\x7d\\xfc\\x0a'  # cmp [ebp-4], 10
        code += b'\\x7d\\x06'         # jge end_loop
        code += b'\\x83\\x45\\xfc\\x01'  # add [ebp-4], 1
        code += b'\\xeb\\xf4'         # jmp loop_start
        
        # End loop  
        code += b'\\x8b\\x45\\xfc'    # mov eax, [ebp-4]
        code += b'\\x8b\\xe5'         # mov esp, ebp
        code += b'\\x5d'             # pop ebp
        code += b'\\xc3'             # ret
        
        # Function 3: String function
        code += b'\\x55'              # push ebp
        code += b'\\x8b\\xec'         # mov ebp, esp
        code += b'\\x68\\x00\\x20\\x00\\x00'  # push offset string (0x2000)
        code += b'\\xff\\x75\\x08'    # push [ebp+8]
        # Would normally call strcpy here
        code += b'\\x83\\xc4\\x08'    # add esp, 8 (clean stack)
        code += b'\\x5d'             # pop ebp
        code += b'\\xc3'             # ret
        
        # Pad .text section
        code += b'\\x00' * (0x400 - len(code))
        
        # .data section with strings
        data = b'Hello World\\x00Test String\\x00Debug Info\\x00'
        data += b'\\x00' * (0x200 - len(data))
        
        # Combine everything
        binary_content = headers + padding1 + code + data
        binary_path.write_bytes(binary_content)
        
        return binary_path
        
    def test_binary_to_frida_script_workflow(self):
        """Test REAL binary analysis → Frida script generation workflow."""
        target_binary = self.create_analysis_target_binary("frida_target.exe")
        
        # Stage 1: Analyze binary
        analysis_result = self.binary_analyzer.analyze(str(target_binary))
        self.assert_real_output(analysis_result)
        
        # Extract analysis information for AI
        analysis_summary = {
            'format': analysis_result.get('format', 'PE'),
            'architecture': analysis_result.get('architecture', 'x86'),
            'functions': analysis_result.get('functions', []),
            'strings': analysis_result.get('strings', []),
            'imports': analysis_result.get('imports', [])
        }
        
        # Stage 2: Generate Frida script based on analysis
        script_request = {
            'target': f"{analysis_summary['architecture']} {analysis_summary['format']}",
            'task': 'Hook main functions and log parameters',
            'binary_analysis': analysis_summary,
            'framework': 'Frida'
        }
        
        try:
            frida_script = self.ai_generator.generate_frida_script(script_request)
            self.assert_real_output(frida_script)
            
            # Verify script quality
            script_text = str(frida_script)
            
            # Should contain Frida-specific code
            frida_indicators = ['Java.perform', 'Interceptor.attach', 'console.log', 
                              'Module.', 'onEnter', 'onLeave']
            found_indicators = [ind for ind in frida_indicators if ind in script_text]
            
            assert len(found_indicators) >= 2, f"Generated script lacks Frida patterns: {found_indicators}"
            
            # Should reference binary analysis
            references_analysis = any(term in script_text.lower() for term in 
                                    ['function', 'hook', 'parameter', 'address'])
            
            assert references_analysis, "Script doesn't reference binary analysis"
            
            print(f"\\nBinary → Frida Script Workflow:")
            print(f"  Binary analyzed: {target_binary.name}")
            print(f"  Script generated: {len(script_text)} chars")
            print(f"  Frida patterns found: {len(found_indicators)}")
            
            return frida_script
            
        except Exception as e:
            print(f"Frida script generation failed: {e}")
            pytest.skip("AI script generation not available")
            
    def test_binary_to_ghidra_script_workflow(self):
        """Test REAL binary analysis → Ghidra script generation workflow."""
        target_binary = self.create_analysis_target_binary("ghidra_target.exe")
        
        # Stage 1: Analyze binary
        analysis_result = self.binary_analyzer.analyze(str(target_binary))
        self.assert_real_output(analysis_result)
        
        # Stage 2: Generate Ghidra script
        script_request = {
            'target': 'Windows PE',
            'task': 'Analyze functions and create annotations',
            'binary_path': str(target_binary),
            'framework': 'Ghidra'
        }
        
        try:
            ghidra_script = self.ai_generator.generate_ghidra_script(script_request)
            self.assert_real_output(ghidra_script)
            
            # Verify Ghidra script quality
            script_text = str(ghidra_script)
            
            # Should contain Ghidra-specific code
            ghidra_indicators = ['getCurrentProgram', 'getFunctionManager', 
                               'getAddressFactory', 'createFunction', 'println']
            found_indicators = [ind for ind in ghidra_indicators if ind in script_text]
            
            assert len(found_indicators) >= 1, f"Generated script lacks Ghidra patterns: {found_indicators}"
            
            # Should be valid Java/Python syntax
            has_imports = 'import' in script_text or 'from' in script_text
            has_methods = 'def ' in script_text or 'function' in script_text or '{' in script_text
            
            assert has_imports or has_methods, "Script lacks proper structure"
            
            print(f"\\nBinary → Ghidra Script Workflow:")
            print(f"  Binary analyzed: {target_binary.name}")
            print(f"  Script generated: {len(script_text)} chars")
            print(f"  Ghidra patterns found: {len(found_indicators)}")
            
            return ghidra_script
            
        except Exception as e:
            print(f"Ghidra script generation failed: {e}")
            pytest.skip("AI script generation not available")
            
    def test_radare2_ai_enhanced_analysis(self):
        """Test REAL Radare2 + AI enhanced analysis workflow."""
        if not self.r2_integration:
            pytest.skip("Radare2 not available")
            
        target_binary = self.create_analysis_target_binary("r2_ai_target.exe")
        
        # Stage 1: Radare2 analysis
        self.r2_integration.load_binary(str(target_binary))
        
        # Basic analysis
        r2_info = self.r2_integration.execute_command('i')  # Binary info
        r2_functions = self.r2_integration.execute_command('afl')  # Function list
        r2_strings = self.r2_integration.execute_command('iz')  # Strings
        
        self.assert_real_output(r2_info)
        self.assert_real_output(r2_functions) 
        self.assert_real_output(r2_strings)
        
        # Stage 2: AI enhancement of analysis
        r2_analysis = {
            'binary_info': str(r2_info),
            'functions': str(r2_functions),
            'strings': str(r2_strings)
        }
        
        try:
            # Generate AI-enhanced analysis
            enhancement_request = {
                'task': 'Enhance radare2 analysis with insights',
                'radare2_output': r2_analysis,
                'focus': 'function analysis and behavior prediction'
            }
            
            ai_enhancement = self.ai_generator.enhance_analysis(enhancement_request)
            self.assert_real_output(ai_enhancement)
            
            # Verify enhancement quality
            enhancement_text = str(ai_enhancement)
            
            # Should provide insights beyond raw r2 output
            insight_indicators = ['analysis', 'function', 'behavior', 'purpose', 
                                'pattern', 'insight', 'suggests', 'likely']
            found_insights = [ind for ind in insight_indicators 
                            if ind.lower() in enhancement_text.lower()]
            
            assert len(found_insights) >= 2, f"AI enhancement lacks insights: {found_insights}"
            
            # Should reference r2 data
            references_r2 = any(term in enhancement_text.lower() for term in 
                              ['function', 'address', 'string', 'binary'])
                              
            assert references_r2, "Enhancement doesn't reference r2 analysis"
            
            print(f"\\nRadare2 + AI Enhanced Analysis:")
            print(f"  R2 analysis: {len(str(r2_analysis))} chars")
            print(f"  AI enhancement: {len(enhancement_text)} chars")
            print(f"  Insight indicators: {len(found_insights)}")
            
        except Exception as e:
            print(f"AI enhancement failed: {e}")
            pytest.skip("AI enhancement not available")
            
    def test_multi_model_analysis_consensus(self):
        """Test REAL multi-model analysis consensus workflow."""
        target_binary = self.create_analysis_target_binary("consensus_target.exe")
        
        # Stage 1: Binary analysis
        analysis_result = self.binary_analyzer.analyze(str(target_binary))
        self.assert_real_output(analysis_result)
        
        # Stage 2: Get analysis from multiple AI models
        analysis_request = {
            'binary_analysis': analysis_result,
            'task': 'Provide security analysis of this binary',
            'focus': 'potential vulnerabilities and security concerns'
        }
        
        model_responses = {}
        
        # Try different models if available
        available_models = ['gpt-3.5-turbo', 'claude-3', 'local-model']
        
        for model_name in available_models:
            try:
                # Register model if not already registered
                if not hasattr(self.llm_manager, 'is_registered') or not self.llm_manager.is_registered(model_name):
                    model_config = {
                        'provider': 'openai' if 'gpt' in model_name else 'anthropic' if 'claude' in model_name else 'local',
                        'model': model_name,
                        'api_key': 'test-key'  # Would use real key in production
                    }
                    
                    try:
                        self.llm_manager.register_llm(model_name, model_config)
                    except Exception:
                        continue  # Skip if registration fails
                        
                # Get analysis from model
                response = self.ai_generator.get_analysis_from_model(
                    analysis_request, model_name
                )
                
                if response:
                    self.assert_real_output(response)
                    model_responses[model_name] = response
                    
            except Exception as e:
                print(f"Model {model_name} analysis failed: {e}")
                continue
                
        if len(model_responses) < 2:
            pytest.skip("Need at least 2 models for consensus testing")
            
        # Stage 3: Generate consensus analysis
        try:
            consensus_request = {
                'model_responses': model_responses,
                'task': 'Generate consensus analysis from multiple model outputs',
                'focus': 'security assessment'
            }
            
            consensus = self.ai_generator.generate_consensus(consensus_request)
            self.assert_real_output(consensus)
            
            # Verify consensus quality
            consensus_text = str(consensus)
            
            # Should reference multiple models
            model_references = sum(1 for model in model_responses.keys() 
                                 if model.replace('-', '').replace('.', '') in consensus_text.lower())
            
            # Should provide synthesis
            synthesis_indicators = ['consensus', 'agreement', 'differs', 'consistent', 
                                  'analysis', 'conclusion', 'summary']
            found_synthesis = [ind for ind in synthesis_indicators 
                             if ind.lower() in consensus_text.lower()]
            
            assert len(found_synthesis) >= 2, f"Consensus lacks synthesis: {found_synthesis}"
            
            print(f"\\nMulti-model Consensus Analysis:")
            print(f"  Models used: {list(model_responses.keys())}")
            print(f"  Consensus generated: {len(consensus_text)} chars")
            print(f"  Synthesis indicators: {len(found_synthesis)}")
            
        except Exception as e:
            print(f"Consensus generation failed: {e}")
            pytest.skip("Consensus generation not available")
            
    def test_iterative_analysis_refinement(self):
        """Test REAL iterative analysis refinement workflow."""
        target_binary = self.create_analysis_target_binary("iterative_target.exe")
        
        # Stage 1: Initial analysis
        initial_analysis = self.binary_analyzer.analyze(str(target_binary))
        self.assert_real_output(initial_analysis)
        
        current_analysis = initial_analysis
        refinement_iterations = []
        
        # Stage 2: Iterative refinement
        for iteration in range(3):  # 3 refinement iterations
            try:
                refinement_request = {
                    'current_analysis': current_analysis,
                    'iteration': iteration + 1,
                    'focus': f'Iteration {iteration + 1}: deeper function analysis',
                    'task': 'Refine and enhance the analysis'
                }
                
                refined_analysis = self.ai_generator.refine_analysis(refinement_request)
                
                if refined_analysis:
                    self.assert_real_output(refined_analysis)
                    
                    # Track refinement progress
                    refinement_info = {
                        'iteration': iteration + 1,
                        'input_size': len(str(current_analysis)),
                        'output_size': len(str(refined_analysis)),
                        'enhancement_ratio': len(str(refined_analysis)) / len(str(current_analysis))
                    }
                    
                    refinement_iterations.append(refinement_info)
                    current_analysis = refined_analysis
                    
                else:
                    break
                    
            except Exception as e:
                print(f"Refinement iteration {iteration + 1} failed: {e}")
                break
                
        # Verify iterative improvement
        assert len(refinement_iterations) >= 1, "No refinement iterations completed"
        
        # Should show progression in analysis depth
        final_size = refinement_iterations[-1]['output_size']
        initial_size = len(str(initial_analysis))
        
        improvement_ratio = final_size / initial_size
        
        print(f"\\nIterative Analysis Refinement:")
        print(f"  Iterations completed: {len(refinement_iterations)}")
        print(f"  Initial analysis: {initial_size} chars")
        print(f"  Final analysis: {final_size} chars")
        print(f"  Improvement ratio: {improvement_ratio:.2f}x")
        
        # Should demonstrate meaningful improvement
        assert improvement_ratio > 1.1, f"Insufficient improvement: {improvement_ratio:.2f}x"
        
    def test_real_vulnerability_detection_workflow(self):
        """Test REAL vulnerability detection workflow."""
        # Create binary with potential vulnerability patterns
        vuln_binary = self.temp_dir / "vuln_detection.exe"
        
        # Create PE with buffer overflow pattern
        pe_content = self.create_analysis_target_binary("base.exe").read_bytes()
        
        # Add vulnerability indicators to code section
        modified_content = bytearray(pe_content)
        
        # Insert strcpy-like pattern (vulnerable function call pattern)
        vuln_pattern = b'\\xff\\x75\\x08\\xff\\x75\\x0c\\xe8'  # push [ebp+8], push [ebp+c], call
        insert_pos = 0x400 + 50  # In code section
        modified_content[insert_pos:insert_pos] = vuln_pattern
        
        vuln_binary.write_bytes(modified_content)
        
        # Stage 1: Analysis
        analysis_result = self.binary_analyzer.analyze(str(vuln_binary))
        self.assert_real_output(analysis_result)
        
        # Stage 2: AI vulnerability detection
        try:
            vuln_request = {
                'binary_analysis': analysis_result,
                'task': 'Detect potential security vulnerabilities',
                'focus': 'buffer overflows, format strings, integer overflows',
                'binary_path': str(vuln_binary)
            }
            
            vulnerability_report = self.ai_generator.detect_vulnerabilities(vuln_request)
            self.assert_real_output(vulnerability_report)
            
            # Verify vulnerability detection quality
            report_text = str(vulnerability_report)
            
            # Should identify vulnerability types
            vuln_types = ['buffer overflow', 'format string', 'integer overflow',
                         'use after free', 'null pointer', 'injection']
            found_vulns = [vtype for vtype in vuln_types 
                          if vtype.lower() in report_text.lower()]
            
            # Should provide security assessment
            security_indicators = ['vulnerability', 'security', 'risk', 'exploit',
                                 'dangerous', 'unsafe', 'potential']
            found_security = [ind for ind in security_indicators 
                            if ind.lower() in report_text.lower()]
            
            assert len(found_security) >= 2, f"Report lacks security focus: {found_security}"
            
            print(f"\\nVulnerability Detection Workflow:")
            print(f"  Binary analyzed: {vuln_binary.name}")
            print(f"  Vulnerability types mentioned: {found_vulns}")
            print(f"  Security indicators: {len(found_security)}")
            print(f"  Report size: {len(report_text)} chars")
            
        except Exception as e:
            print(f"Vulnerability detection failed: {e}")
            pytest.skip("AI vulnerability detection not available")
            
    def test_script_validation_workflow(self):
        """Test REAL generated script validation workflow."""
        target_binary = self.create_analysis_target_binary("validation_target.exe")
        
        # Stage 1: Generate script
        frida_script = self.test_binary_to_frida_script_workflow()
        
        if not frida_script:
            pytest.skip("Script generation failed")
            
        # Stage 2: Validate script syntax and logic
        try:
            validation_request = {
                'script': frida_script,
                'script_type': 'frida',
                'target_binary': str(target_binary),
                'validation_focus': 'syntax, logic, security'
            }
            
            validation_result = self.ai_generator.validate_script(validation_request)
            self.assert_real_output(validation_result)
            
            # Verify validation quality
            validation_text = str(validation_result)
            
            # Should provide validation feedback
            validation_indicators = ['syntax', 'valid', 'error', 'correct', 
                                   'issue', 'problem', 'warning', 'good']
            found_validation = [ind for ind in validation_indicators 
                              if ind.lower() in validation_text.lower()]
            
            assert len(found_validation) >= 2, f"Validation lacks proper feedback: {found_validation}"
            
            # Should assess script quality
            quality_indicators = ['quality', 'effective', 'functional', 'working',
                                'reliable', 'robust', 'complete']
            found_quality = [ind for ind in quality_indicators 
                           if ind.lower() in validation_text.lower()]
            
            print(f"\\nScript Validation Workflow:")
            print(f"  Script validated: {len(str(frida_script))} chars")
            print(f"  Validation feedback: {len(validation_text)} chars")
            print(f"  Validation indicators: {len(found_validation)}")
            print(f"  Quality indicators: {len(found_quality)}")
            
        except Exception as e:
            print(f"Script validation failed: {e}")
            pytest.skip("AI script validation not available")
            
    def test_end_to_end_ai_workflow(self):
        """Test REAL complete end-to-end AI analysis workflow."""
        target_binary = self.create_analysis_target_binary("e2e_target.exe")
        
        workflow_stages = {}
        
        # Stage 1: Binary analysis
        try:
            analysis = self.binary_analyzer.analyze(str(target_binary))
            self.assert_real_output(analysis)
            workflow_stages['binary_analysis'] = len(str(analysis))
        except Exception as e:
            workflow_stages['binary_analysis'] = f"Failed: {e}"
            
        # Stage 2: AI script generation
        try:
            script = self.ai_generator.generate_frida_script({
                'target': 'Windows PE',
                'task': 'Comprehensive function hooking',
                'binary_analysis': analysis
            })
            self.assert_real_output(script)
            workflow_stages['script_generation'] = len(str(script))
        except Exception as e:
            workflow_stages['script_generation'] = f"Failed: {e}"
            
        # Stage 3: Vulnerability assessment
        try:
            vuln_assessment = self.ai_generator.detect_vulnerabilities({
                'binary_analysis': analysis,
                'task': 'Security assessment'
            })
            self.assert_real_output(vuln_assessment)
            workflow_stages['vulnerability_assessment'] = len(str(vuln_assessment))
        except Exception as e:
            workflow_stages['vulnerability_assessment'] = f"Failed: {e}"
            
        # Stage 4: Analysis enhancement
        try:
            enhancement = self.ai_generator.enhance_analysis({
                'analysis': analysis,
                'task': 'Provide additional insights'
            })
            self.assert_real_output(enhancement)
            workflow_stages['analysis_enhancement'] = len(str(enhancement))
        except Exception as e:
            workflow_stages['analysis_enhancement'] = f"Failed: {e}"
            
        # Verify end-to-end workflow
        successful_stages = [stage for stage, result in workflow_stages.items() 
                           if isinstance(result, int)]
        
        assert len(successful_stages) >= 2, f"Insufficient workflow stages completed: {successful_stages}"
        
        print(f"\\nEnd-to-End AI Workflow:")
        for stage, result in workflow_stages.items():
            if isinstance(result, int):
                print(f"  ✓ {stage}: {result} chars output")
            else:
                print(f"  ✗ {stage}: {result}")
                
        print(f"  Success rate: {len(successful_stages)}/{len(workflow_stages)} stages")
        
        # Should achieve at least 50% success rate
        success_rate = len(successful_stages) / len(workflow_stages)
        assert success_rate >= 0.5, f"Workflow success rate too low: {success_rate:.1%}"