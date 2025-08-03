"""
Ghidra Bridge Manager - Programmatic Ghidra Control

Copyright (C) 2025 Zachary Flint

This file is part of Intellicrack.

Intellicrack is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Intellicrack is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Intellicrack.  If not, see <https://www.gnu.org/licenses/>.
"""

import os
import sys
import time
import threading
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple, Union
from contextlib import contextmanager

try:
    import ghidra_bridge
except ImportError:
    ghidra_bridge = None

from ...utils.logger import get_logger
from ...utils.core.path_discovery import discover_ghidra_path
from ..logging.audit_logger import get_audit_logger, AuditEvent, AuditEventType, AuditSeverity

logger = get_logger(__name__)
audit_logger = get_audit_logger()


class GhidraBridgeError(Exception):
    """Exception raised for Ghidra Bridge operations."""
    pass


class GhidraBridgeManager:
    """
    Manager for Ghidra Bridge connections providing programmatic control over Ghidra.
    
    This class provides high-level interface for:
    - Session management and lifecycle control
    - Program loading and analysis
    - Function decompilation and analysis
    - Symbol and cross-reference extraction
    - Memory analysis and patching
    - Script execution
    - Error handling and recovery
    """

    def __init__(self, ghidra_path: Optional[str] = None, server_port: int = 13100):
        """
        Initialize Ghidra Bridge Manager.
        
        Args:
            ghidra_path: Path to Ghidra installation
            server_port: Port for bridge server
        """
        if ghidra_bridge is None:
            raise GhidraBridgeError("ghidra_bridge package not installed")
            
        self.ghidra_path = ghidra_path or discover_ghidra_path()
        self.server_port = server_port
        self.bridge = None
        self.ghidra_process = None
        self.current_program = None
        self.session_active = False
        self.logger = logger
        
        # Validate Ghidra installation
        if not self._validate_ghidra_installation():
            raise GhidraBridgeError("Ghidra installation not found or invalid")

    def _validate_ghidra_installation(self) -> bool:
        """Validate Ghidra installation."""
        if not self.ghidra_path:
            return False
            
        # Check for ghidraRun script
        if os.name == 'nt':
            ghidra_run = os.path.join(self.ghidra_path, "ghidraRun.bat")
        else:
            ghidra_run = os.path.join(self.ghidra_path, "ghidraRun")
            
        return os.path.exists(ghidra_run)

    def start_bridge_server(self, timeout: int = 60) -> bool:
        """
        Start Ghidra with bridge server.
        
        Args:
            timeout: Timeout in seconds
            
        Returns:
            True if server started successfully
        """
        try:
            if self.session_active:
                self.logger.warning("Bridge session already active")
                return True
                
            self.logger.info(f"Starting Ghidra bridge server on port {self.server_port}")
            
            # Start Ghidra in GUI mode first (required for bridge)
            if os.name == 'nt':
                ghidra_cmd = os.path.join(self.ghidra_path, "ghidraRun.bat")
            else:
                ghidra_cmd = os.path.join(self.ghidra_path, "ghidraRun")
                
            cmd = [ghidra_cmd]
            
            self.logger.info(f"Starting Ghidra GUI: {' '.join(cmd)}")
            
            # Start Ghidra process in background
            self.ghidra_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=tempfile.gettempdir()
            )
            
            # Give Ghidra time to start up
            self.logger.info("Waiting for Ghidra to initialize...")
            time.sleep(10)
            
            # Try to connect to existing bridge or start a new one
            start_time = time.time()
            while time.time() - start_time < timeout:
                try:
                    # Try to connect to bridge server
                    self.bridge = ghidra_bridge.GhidraBridge(namespace="intellicrack", connect_to_port=self.server_port)
                    
                    # Test connection
                    test_result = self.bridge.eval("'bridge_connection_test'")
                    if test_result == 'bridge_connection_test':
                        self.session_active = True
                        self.logger.info("Ghidra bridge connected successfully")
                        
                        # Log audit event
                        audit_logger.log_event(AuditEvent(
                            event_type=AuditEventType.TOOL_EXECUTION,
                            severity=AuditSeverity.INFO,
                            description="Ghidra bridge session started",
                            details={
                                "tool": "ghidra_bridge",
                                "port": self.server_port,
                                "ghidra_path": self.ghidra_path
                            }
                        ))
                        
                        return True
                        
                except Exception as e:
                    self.logger.debug(f"Bridge connection attempt failed: {e}")
                    
                    # Try to start bridge server manually if connection fails
                    try:
                        import ghidra_bridge.bridge_server
                        ghidra_bridge.bridge_server.GhidraBridgeServer.start_on_port(self.server_port)
                        self.logger.info(f"Started bridge server on port {self.server_port}")
                    except Exception as server_e:
                        self.logger.debug(f"Failed to start bridge server manually: {server_e}")
                    
                    time.sleep(2)
                    
            self.logger.error("Failed to connect to Ghidra bridge server")
            self.stop_bridge_server()
            return False
            
        except Exception as e:
            self.logger.error(f"Failed to start Ghidra bridge server: {e}")
            return False

    def _create_bridge_script(self) -> str:
        """Create bridge server startup script."""
        script_content = f'''//Bridge server startup script
//@author Intellicrack  
//@category Bridge

import ghidra.app.script.GhidraScript;
import java.net.ServerSocket;
import java.net.Socket;
import java.io.*;

public class StartBridgeServer extends GhidraScript {{
    
    private static final int SERVER_PORT = {self.server_port};
    private ServerSocket serverSocket;
    private boolean isRunning = false;
    
    @Override
    public void run() throws Exception {{
        println("Starting Ghidra Bridge Server on port " + SERVER_PORT);
        
        try {{
            // Create server socket
            serverSocket = new ServerSocket(SERVER_PORT);
            isRunning = true;
            
            println("Bridge server listening on port " + SERVER_PORT);
            println("Waiting for connections...");
            
            // Accept connections
            while (isRunning) {{
                try {{
                    Socket clientSocket = serverSocket.accept();
                    println("Client connected: " + clientSocket.getRemoteSocketAddress());
                    
                    // Handle client in separate thread
                    new Thread(() -> handleClient(clientSocket)).start();
                    
                }} catch (Exception e) {{
                    if (isRunning) {{
                        println("Error accepting connection: " + e.getMessage());
                    }}
                }}
            }}
            
        }} catch (Exception e) {{
            println("Failed to start bridge server: " + e.getMessage());
            e.printStackTrace();
        }} finally {{
            cleanup();
        }}
    }}
    
    private void handleClient(Socket clientSocket) {{
        try {{
            BufferedReader in = new BufferedReader(new InputStreamReader(clientSocket.getInputStream()));
            PrintWriter out = new PrintWriter(clientSocket.getOutputStream(), true);
            
            // Send ready signal
            out.println("GHIDRA_BRIDGE_READY");
            
            String inputLine;
            while ((inputLine = in.readLine()) != null) {{
                if ("PING".equals(inputLine)) {{
                    out.println("PONG");
                }} else if ("SHUTDOWN".equals(inputLine)) {{
                    out.println("SHUTTING_DOWN");
                    isRunning = false;
                    break;
                }} else {{
                    // Echo for now - real bridge implementation would handle commands
                    out.println("RECEIVED: " + inputLine);
                }}
            }}
            
        }} catch (Exception e) {{
            println("Client handler error: " + e.getMessage());
        }} finally {{
            try {{
                clientSocket.close();
            }} catch (Exception e) {{
                // Ignore
            }}
        }}
    }}
    
    private void cleanup() {{
        try {{
            if (serverSocket != null && !serverSocket.isClosed()) {{
                serverSocket.close();
            }}
            println("Bridge server stopped");
        }} catch (Exception e) {{
            println("Cleanup error: " + e.getMessage());
        }}
    }}
}}'''

        script_dir = tempfile.mkdtemp(prefix="ghidra_bridge_")
        script_path = os.path.join(script_dir, "StartBridgeServer.java")
        
        with open(script_path, 'w', encoding='utf-8') as f:
            f.write(script_content)
            
        return script_path

    def stop_bridge_server(self) -> bool:
        """Stop Ghidra bridge server."""
        try:
            if self.bridge:
                try:
                    self.bridge.get_ghidra().shutdown()
                except:
                    pass
                self.bridge = None
                
            if self.ghidra_process:
                self.ghidra_process.terminate()
                try:
                    self.ghidra_process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    self.ghidra_process.kill()
                self.ghidra_process = None
                
            self.current_program = None
            self.session_active = False
            
            self.logger.info("Ghidra bridge server stopped")
            return True
            
        except Exception as e:
            self.logger.error(f"Error stopping bridge server: {e}")
            return False

    @contextmanager
    def bridge_session(self):
        """Context manager for bridge sessions."""
        if not self.start_bridge_server():
            raise GhidraBridgeError("Failed to start bridge server")
            
        try:
            yield self
        finally:
            self.stop_bridge_server()

    def load_program(self, binary_path: str, project_dir: Optional[str] = None) -> bool:
        """
        Load a program into Ghidra.
        
        Args:
            binary_path: Path to binary file
            project_dir: Optional project directory
            
        Returns:
            True if program loaded successfully
        """
        try:
            if not self.session_active:
                raise GhidraBridgeError("Bridge session not active")
                
            binary_path = str(Path(binary_path).resolve())
            
            if not os.path.exists(binary_path):
                raise FileNotFoundError(f"Binary not found: {binary_path}")
                
            self.logger.info(f"Loading program: {binary_path}")
            
            # Create temporary project if needed
            if not project_dir:
                project_dir = tempfile.mkdtemp(prefix="ghidra_project_")
                
            # Use Ghidra's project manager
            project_manager = self.bridge.get_ghidra().framework.getProjectManager()
            project = project_manager.createProject(project_dir, "temp_project", False)
            
            # Import binary
            import_results = project.importFile(binary_path)
            
            if import_results:
                domain_file = import_results[0]
                self.current_program = domain_file.getDomainObject(None, False, False, None)
                
                # Perform auto-analysis
                self._auto_analyze_program()
                
                self.logger.info(f"Program loaded successfully: {self.current_program.getName()}")
                return True
            else:
                self.logger.error("Failed to import binary")
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to load program: {e}")
            return False

    def _auto_analyze_program(self) -> None:
        """Run auto-analysis on the current program."""
        try:
            if not self.current_program:
                return
                
            analyzer_manager = self.bridge.get_ghidra().app.services.AutoAnalysisManager.getAnalysisManager(self.current_program)
            analyzer_manager.startAnalysis(None, True)
            
            # Wait for analysis to complete
            while analyzer_manager.isAnalyzing():
                time.sleep(1)
                
            self.logger.info("Auto-analysis completed")
            
        except Exception as e:
            self.logger.warning(f"Auto-analysis failed: {e}")

    def get_functions(self) -> List[Dict[str, Any]]:
        """
        Get all functions in the current program.
        
        Returns:
            List of function information dictionaries
        """
        try:
            if not self.current_program:
                raise GhidraBridgeError("No program loaded")
                
            functions = []
            function_manager = self.current_program.getFunctionManager()
            
            for func in function_manager.getFunctions(True):
                func_info = {
                    'name': func.getName(),
                    'address': str(func.getEntryPoint()),
                    'size': func.getBody().getNumAddresses(),
                    'signature': func.getPrototypeString(False, False),
                    'parameter_count': func.getParameterCount(),
                    'has_no_return': func.hasNoReturn(),
                    'is_external': func.isExternal(),
                    'calling_convention': str(func.getCallingConventionName()) if func.getCallingConventionName() else None
                }
                functions.append(func_info)
                
            return functions
            
        except Exception as e:
            self.logger.error(f"Failed to get functions: {e}")
            return []

    def decompile_function(self, function_name_or_address: str) -> Optional[Dict[str, Any]]:
        """
        Decompile a specific function.
        
        Args:
            function_name_or_address: Function name or address
            
        Returns:
            Decompilation results dictionary
        """
        try:
            if not self.current_program:
                raise GhidraBridgeError("No program loaded")
                
            # Find function
            function_manager = self.current_program.getFunctionManager()
            func = None
            
            # Try by name first
            func = function_manager.getFunction(function_name_or_address)
            
            # Try by address if name didn't work
            if not func:
                try:
                    addr = self.current_program.getAddressFactory().getAddress(function_name_or_address)
                    func = function_manager.getFunctionAt(addr)
                except:
                    pass
                    
            if not func:
                self.logger.error(f"Function not found: {function_name_or_address}")
                return None
                
            # Initialize decompiler
            decompiler = self.bridge.get_ghidra().app.decompiler.DecompInterface()
            decompiler.openProgram(self.current_program)
            
            try:
                # Decompile function
                results = decompiler.decompileFunction(func, 30, None)
                
                if results and results.decompileCompleted():
                    decompiled_code = results.getDecompiledFunction().getC()
                    high_function = results.getHighFunction()
                    
                    # Extract additional information
                    func_data = {
                        'name': func.getName(),
                        'address': str(func.getEntryPoint()),
                        'size': func.getBody().getNumAddresses(),
                        'decompiled_code': decompiled_code,
                        'signature': func.getPrototypeString(False, False),
                        'parameter_count': func.getParameterCount(),
                        'variables': self._extract_variables(high_function) if high_function else [],
                        'complexity_metrics': self._calculate_complexity(func, decompiled_code),
                        'api_calls': self._extract_api_calls(func),
                        'xrefs_to': self._get_xrefs_to(func),
                        'xrefs_from': self._get_xrefs_from(func)
                    }
                    
                    self.logger.info(f"Successfully decompiled function: {func.getName()}")
                    return func_data
                else:
                    self.logger.error(f"Decompilation failed for: {func.getName()}")
                    return None
                    
            finally:
                decompiler.dispose()
                
        except Exception as e:
            self.logger.error(f"Failed to decompile function: {e}")
            return None

    def _extract_variables(self, high_function) -> List[Dict[str, Any]]:
        """Extract variables from high function."""
        variables = []
        
        try:
            # Parameters
            for i in range(high_function.getFunctionPrototype().getNumParams()):
                param = high_function.getFunctionPrototype().getParam(i)
                variables.append({
                    'name': param.getName(),
                    'type': str(param.getDataType()),
                    'kind': 'parameter',
                    'size': param.getSize()
                })
                
            # Local variables
            symbol_map = high_function.getLocalSymbolMap()
            for symbol in symbol_map.getSymbols():
                variables.append({
                    'name': symbol.getName(),
                    'type': str(symbol.getDataType()),
                    'kind': 'local',
                    'size': symbol.getSize()
                })
                
        except Exception as e:
            self.logger.debug(f"Failed to extract variables: {e}")
            
        return variables

    def _calculate_complexity(self, func, code: str) -> Dict[str, Any]:
        """Calculate function complexity metrics."""
        try:
            metrics = {
                'lines_of_code': len(code.split('\n')) if code else 0,
                'basic_blocks': 0,
                'cyclomatic_complexity': 1,
                'nesting_depth': 0
            }
            
            # Basic blocks
            try:
                bb_model = func.getBasicBlockModel()
                metrics['basic_blocks'] = bb_model.getNumNodes()
            except:
                pass
                
            # Simple cyclomatic complexity calculation
            if code:
                branch_keywords = ['if', 'else', 'while', 'for', 'switch', 'case', '&&', '||']
                for keyword in branch_keywords:
                    metrics['cyclomatic_complexity'] += code.count(keyword)
                    
                # Simple nesting depth
                max_nesting = 0
                current_nesting = 0
                for char in code:
                    if char == '{':
                        current_nesting += 1
                        max_nesting = max(max_nesting, current_nesting)
                    elif char == '}':
                        current_nesting -= 1
                metrics['nesting_depth'] = max_nesting
                
            return metrics
            
        except Exception as e:
            self.logger.debug(f"Failed to calculate complexity: {e}")
            return {'lines_of_code': 0, 'basic_blocks': 0, 'cyclomatic_complexity': 1, 'nesting_depth': 0}

    def _extract_api_calls(self, func) -> List[Dict[str, Any]]:
        """Extract API calls from function."""
        api_calls = []
        
        try:
            for called_func in func.getCalledFunctions(None):
                api_calls.append({
                    'function': called_func.getName(),
                    'address': str(called_func.getEntryPoint()),
                    'is_external': called_func.isExternal(),
                    'library': called_func.getExternalLocation().getLibraryName() if called_func.isExternal() else None
                })
                
        except Exception as e:
            self.logger.debug(f"Failed to extract API calls: {e}")
            
        return api_calls

    def _get_xrefs_to(self, func) -> List[Dict[str, Any]]:
        """Get cross-references to function."""
        xrefs = []
        
        try:
            ref_manager = self.current_program.getReferenceManager()
            for ref in ref_manager.getReferencesTo(func.getEntryPoint()):
                xrefs.append({
                    'from_address': str(ref.getFromAddress()),
                    'type': str(ref.getReferenceType()),
                    'is_primary': ref.isPrimary()
                })
                
        except Exception as e:
            self.logger.debug(f"Failed to get xrefs to: {e}")
            
        return xrefs

    def _get_xrefs_from(self, func) -> List[Dict[str, Any]]:
        """Get cross-references from function."""
        xrefs = []
        
        try:
            ref_manager = self.current_program.getReferenceManager()
            for addr in func.getBody().getAddresses(True):
                for ref in ref_manager.getReferencesFrom(addr):
                    xrefs.append({
                        'to_address': str(ref.getToAddress()),
                        'type': str(ref.getReferenceType()),
                        'is_primary': ref.isPrimary()
                    })
                    
        except Exception as e:
            self.logger.debug(f"Failed to get xrefs from: {e}")
            
        return xrefs

    def get_strings(self) -> List[Dict[str, Any]]:
        """
        Extract strings from the current program.
        
        Returns:
            List of string information dictionaries
        """
        try:
            if not self.current_program:
                raise GhidraBridgeError("No program loaded")
                
            strings = []
            listing = self.current_program.getListing()
            memory = self.current_program.getMemory()
            
            for block in memory.getBlocks():
                if block.isRead() and not block.isWrite():
                    data_iter = listing.getDefinedData(block.getStart(), True)
                    while data_iter.hasNext():
                        data = data_iter.next()
                        if data.hasStringValue():
                            string_info = {
                                'value': data.getDefaultValueRepresentation(),
                                'address': str(data.getAddress()),
                                'length': data.getLength(),
                                'type': str(data.getDataType())
                            }
                            
                            # Categorize string
                            value = string_info['value'].lower()
                            if 'http' in value or 'www.' in value:
                                string_info['category'] = 'url'
                            elif 'error' in value or 'fail' in value:
                                string_info['category'] = 'error_message'
                            elif 'license' in value or 'key' in value:
                                string_info['category'] = 'license_related'
                            else:
                                string_info['category'] = 'other'
                                
                            strings.append(string_info)
                            
            return strings
            
        except Exception as e:
            self.logger.error(f"Failed to get strings: {e}")
            return []

    def get_imports(self) -> List[Dict[str, Any]]:
        """
        Get imported functions and libraries.
        
        Returns:
            List of import information dictionaries
        """
        try:
            if not self.current_program:
                raise GhidraBridgeError("No program loaded")
                
            imports = []
            symbol_table = self.current_program.getSymbolTable()
            
            for symbol in symbol_table.getExternalSymbols():
                imports.append({
                    'name': symbol.getName(),
                    'library': symbol.getParentNamespace().getName(),
                    'address': str(symbol.getAddress()),
                    'symbol_type': str(symbol.getSymbolType())
                })
                
            return imports
            
        except Exception as e:
            self.logger.error(f"Failed to get imports: {e}")
            return []

    def analyze_license_patterns(self) -> Dict[str, Any]:
        """
        Analyze program for license-related patterns.
        
        Returns:
            Dictionary with license analysis results
        """
        try:
            results = {
                'license_functions': [],
                'license_strings': [],
                'crypto_functions': [],
                'time_functions': [],
                'suspicious_patterns': []
            }
            
            if not self.current_program:
                return results
                
            # Find license-related functions
            license_keywords = ['license', 'valid', 'check', 'verify', 'auth', 'trial', 'expire', 'register']
            functions = self.get_functions()
            
            for func in functions:
                func_name = func['name'].lower()
                for keyword in license_keywords:
                    if keyword in func_name:
                        results['license_functions'].append({
                            'function': func,
                            'matched_keyword': keyword,
                            'confidence': self._calculate_license_confidence(func_name, keyword)
                        })
                        break
                        
            # Find license-related strings
            strings = self.get_strings()
            for string_info in strings:
                if string_info['category'] == 'license_related':
                    results['license_strings'].append(string_info)
                    
            # Find crypto-related symbols
            crypto_keywords = ['crypt', 'hash', 'md5', 'sha', 'aes', 'des', 'rsa', 'encrypt', 'decrypt']
            imports = self.get_imports()
            
            for imp in imports:
                imp_name = imp['name'].lower()
                for keyword in crypto_keywords:
                    if keyword in imp_name:
                        results['crypto_functions'].append(imp)
                        break
                        
            return results
            
        except Exception as e:
            self.logger.error(f"Failed to analyze license patterns: {e}")
            return {}

    def _calculate_license_confidence(self, func_name: str, keyword: str) -> float:
        """Calculate confidence score for license function."""
        score = 0.3  # Base score for keyword match
        
        # Higher scores for stronger keywords
        strong_keywords = ['license', 'registration', 'activation']
        if keyword in strong_keywords:
            score += 0.4
            
        # Additional context clues
        if 'check' in func_name and 'valid' in func_name:
            score += 0.2
        if 'get' in func_name or 'set' in func_name:
            score += 0.1
            
        return min(score, 1.0)

    def execute_script(self, script_content: str) -> Dict[str, Any]:
        """
        Execute a Ghidra script via bridge.
        
        Args:
            script_content: Script content to execute
            
        Returns:
            Execution results
        """
        try:
            if not self.session_active:
                raise GhidraBridgeError("Bridge session not active")
                
            # Execute script through bridge
            result = self.bridge.eval(script_content)
            
            return {
                'success': True,
                'result': result,
                'error': None
            }
            
        except Exception as e:
            self.logger.error(f"Script execution failed: {e}")
            return {
                'success': False,
                'result': None,
                'error': str(e)
            }

    def get_memory_info(self) -> Dict[str, Any]:
        """Get memory information from current program."""
        try:
            if not self.current_program:
                raise GhidraBridgeError("No program loaded")
                
            memory = self.current_program.getMemory()
            
            memory_info = {
                'total_size': memory.getSize(),
                'blocks': []
            }
            
            for block in memory.getBlocks():
                block_info = {
                    'name': block.getName(),
                    'start': str(block.getStart()),
                    'end': str(block.getEnd()),
                    'size': block.getSize(),
                    'permissions': {
                        'read': block.isRead(),
                        'write': block.isWrite(),
                        'execute': block.isExecute()
                    },
                    'type': str(block.getType())
                }
                memory_info['blocks'].append(block_info)
                
            return memory_info
            
        except Exception as e:
            self.logger.error(f"Failed to get memory info: {e}")
            return {}

    def __enter__(self):
        """Context manager entry."""
        if not self.start_bridge_server():
            raise GhidraBridgeError("Failed to start bridge server")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit."""
        self.stop_bridge_server()


# Convenience functions for backwards compatibility
def get_bridge_manager(ghidra_path: Optional[str] = None) -> GhidraBridgeManager:
    """Get a Ghidra Bridge Manager instance."""
    return GhidraBridgeManager(ghidra_path)


__all__ = ['GhidraBridgeManager', 'GhidraBridgeError', 'get_bridge_manager']