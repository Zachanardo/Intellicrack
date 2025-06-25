#!/usr/bin/env python3
"""
Protection Analyzer Tool

A tool that can be called by users or LLMs to thoroughly analyze 
software protection schemes and provide detailed findings.
"""

import os
import json
from typing import Dict, Any, Optional, List
from pathlib import Path

from ..models import get_ml_system
from ..models.protection_knowledge_base import get_protection_knowledge_base


class ProtectionAnalyzerTool:
    """
    Analyzes binaries for protection schemes and provides comprehensive findings.
    
    This tool can be:
    1. Called directly by users through the UI
    2. Used by LLMs as a tool to gather protection information
    """
    
    def __init__(self):
        self.ml_system = get_ml_system()
        self.kb = get_protection_knowledge_base()
        
    def analyze(self, binary_path: str, detailed: bool = True) -> Dict[str, Any]:
        """
        Perform comprehensive protection analysis on a binary.
        
        Args:
            binary_path: Path to the binary to analyze
            detailed: Whether to include detailed technical information
            
        Returns:
            Comprehensive analysis results formatted for both human and LLM consumption
        """
        # Verify file exists
        if not os.path.exists(binary_path):
            return {
                "success": False,
                "error": f"File not found: {binary_path}"
            }
        
        # Get ML predictions
        ml_result = self.ml_system.predict(binary_path)
        
        if not ml_result.get('success', False):
            return {
                "success": False,
                "error": ml_result.get('error', 'Analysis failed')
            }
        
        # Build comprehensive analysis
        analysis = {
            "success": True,
            "file_info": self._get_file_info(binary_path),
            "protection_analysis": self._build_protection_analysis(ml_result),
            "technical_details": self._get_technical_details(ml_result) if detailed else None,
            "bypass_guidance": self._get_bypass_guidance(ml_result),
            "tool_recommendations": self._get_tool_recommendations(ml_result),
            "llm_context": self._build_llm_context(ml_result)
        }
        
        return analysis
    
    def _get_file_info(self, binary_path: str) -> Dict[str, Any]:
        """Get basic file information"""
        path = Path(binary_path)
        return {
            "path": str(path.absolute()),
            "name": path.name,
            "size": path.stat().st_size,
            "size_human": self._format_size(path.stat().st_size),
            "extension": path.suffix,
            "directory": str(path.parent)
        }
    
    def _format_size(self, size: int) -> str:
        """Format size in human readable form"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size < 1024.0:
                return f"{size:.2f} {unit}"
            size /= 1024.0
        return f"{size:.2f} TB"
    
    def _build_protection_analysis(self, ml_result: Dict[str, Any]) -> Dict[str, Any]:
        """Build the main protection analysis section"""
        protection_type = ml_result.get('protection_type', 'Unknown')
        
        # Get knowledge base info
        kb_info = self.kb.get_protection_info(protection_type)
        
        analysis = {
            "protection_detected": protection_type,
            "confidence": ml_result.get('confidence', 0),
            "confidence_level": self._get_confidence_level(ml_result.get('confidence', 0)),
            "category": ml_result.get('protection_category', 'unknown'),
            "bypass_difficulty": ml_result.get('bypass_difficulty', 'Unknown'),
            "is_protected": protection_type != "No Protection"
        }
        
        # Add vendor and description if available
        if kb_info:
            analysis["vendor"] = kb_info.vendor
            analysis["description"] = kb_info.description
            analysis["common_applications"] = kb_info.common_applications[:5]
            analysis["versions"] = kb_info.versions
        
        # Add detection details
        if 'detailed_scores' in ml_result:
            # Get top 3 detection candidates
            scores = ml_result['detailed_scores']
            top_candidates = sorted(scores.items(), key=lambda x: x[1], reverse=True)[:3]
            
            analysis["detection_candidates"] = [
                {
                    "scheme": scheme.replace('_', ' ').title(),
                    "score": score,
                    "likelihood": self._score_to_likelihood(score)
                }
                for scheme, score in top_candidates if score > 0.1
            ]
        
        return analysis
    
    def _get_confidence_level(self, confidence: float) -> str:
        """Convert confidence score to human readable level"""
        if confidence >= 0.9:
            return "Very High"
        elif confidence >= 0.75:
            return "High"
        elif confidence >= 0.5:
            return "Medium"
        elif confidence >= 0.25:
            return "Low"
        else:
            return "Very Low"
    
    def _score_to_likelihood(self, score: float) -> str:
        """Convert detection score to likelihood description"""
        if score >= 0.8:
            return "Very Likely"
        elif score >= 0.6:
            return "Likely"
        elif score >= 0.4:
            return "Possible"
        elif score >= 0.2:
            return "Unlikely"
        else:
            return "Very Unlikely"
    
    def _get_technical_details(self, ml_result: Dict[str, Any]) -> Dict[str, Any]:
        """Extract technical details from the analysis"""
        features = ml_result.get('features_summary', {})
        
        details = {
            "binary_characteristics": {
                "file_size": features.get('file_size', 0),
                "entropy": features.get('entropy', 0),
                "is_packed": features.get('has_packing', False),
                "has_anti_debugging": features.get('has_anti_debug', False),
                "protection_complexity": features.get('protection_complexity', 0)
            },
            "ml_model_info": {
                "model_predictions": ml_result.get('model_predictions', {}),
                "feature_count": len(ml_result.get('features_summary', {}))
            }
        }
        
        # Add protection-specific indicators
        protection = ml_result.get('protection_type', '')
        if protection and protection != "No Protection":
            details["protection_indicators"] = self._get_protection_indicators(protection, features)
        
        return details
    
    def _get_protection_indicators(self, protection: str, features: Dict) -> List[str]:
        """Get specific indicators for the detected protection"""
        indicators = []
        
        # Generic indicators
        if features.get('has_packing'):
            indicators.append("Code packing/encryption detected")
        if features.get('has_anti_debug'):
            indicators.append("Anti-debugging techniques present")
        if features.get('protection_complexity', 0) > 0.7:
            indicators.append("High protection complexity")
        
        # Protection-specific indicators
        protection_lower = protection.lower()
        if "hasp" in protection_lower:
            indicators.append("Hardware dongle communication detected")
            indicators.append("HASP API imports found")
        elif "flexlm" in protection_lower:
            indicators.append("License file references detected")
            indicators.append("Network license manager patterns")
        elif "steam" in protection_lower:
            indicators.append("Steam API integration detected")
            indicators.append("CEG wrapping patterns found")
        elif "denuvo" in protection_lower:
            indicators.append("Heavy virtualization detected")
            indicators.append("Multiple integrity check triggers")
        
        return indicators
    
    def _get_bypass_guidance(self, ml_result: Dict[str, Any]) -> Dict[str, Any]:
        """Provide bypass guidance based on the protection"""
        protection = ml_result.get('protection_type', 'Unknown')
        
        if protection == "No Protection":
            return {
                "approach": "No bypass needed",
                "description": "The binary appears to be unprotected. Standard analysis techniques should work.",
                "estimated_time": "N/A",
                "difficulty_score": 0
            }
        
        # Get knowledge base info
        kb_info = self.kb.get_protection_info(protection)
        
        guidance = {
            "approach": "Protection-specific bypass required",
            "estimated_time": self.kb.estimate_bypass_time(protection, "intermediate"),
            "difficulty_score": self._difficulty_to_score(ml_result.get('bypass_difficulty', 'Unknown'))
        }
        
        if kb_info:
            # Get best bypass technique
            if kb_info.bypass_techniques:
                best_technique = max(kb_info.bypass_techniques, key=lambda x: x.success_rate)
                guidance["recommended_technique"] = {
                    "name": best_technique.name,
                    "description": best_technique.description,
                    "success_rate": best_technique.success_rate,
                    "time_estimate": best_technique.time_estimate,
                    "prerequisites": best_technique.prerequisites
                }
            
            # Add analysis tips
            guidance["analysis_tips"] = kb_info.analysis_tips[:5]
            guidance["common_mistakes"] = kb_info.common_mistakes[:3]
        
        return guidance
    
    def _difficulty_to_score(self, difficulty: str) -> int:
        """Convert difficulty to numeric score (0-10)"""
        scores = {
            "Trivial": 1,
            "Low": 3,
            "Medium": 5,
            "High": 7,
            "Very High": 9,
            "Extreme": 10,
            "Unknown": 5
        }
        return scores.get(difficulty, 5)
    
    def _get_tool_recommendations(self, ml_result: Dict[str, Any]) -> List[Dict[str, str]]:
        """Recommend tools based on the protection"""
        protection = ml_result.get('protection_type', 'Unknown')
        
        if protection == "No Protection":
            return [
                {"name": "IDA Pro", "purpose": "Static analysis"},
                {"name": "x64dbg", "purpose": "Dynamic analysis"},
                {"name": "Ghidra", "purpose": "Free alternative to IDA"}
            ]
        
        # Get protection-specific tools
        kb_info = self.kb.get_protection_info(protection)
        if kb_info:
            tools = []
            seen = set()
            
            # Get tools from all techniques
            for technique in kb_info.bypass_techniques:
                for tool in technique.tools_required:
                    if tool not in seen:
                        seen.add(tool)
                        # Categorize tool purpose
                        purpose = self._categorize_tool_purpose(tool, protection)
                        tools.append({"name": tool, "purpose": purpose})
            
            return tools[:6]  # Return top 6 tools
        
        return [{"name": "Unknown", "purpose": "Protection-specific tools needed"}]
    
    def _categorize_tool_purpose(self, tool: str, protection: str) -> str:
        """Categorize the purpose of a tool"""
        tool_lower = tool.lower()
        
        if "unpacker" in tool_lower:
            return "Unpacking/Devirtualization"
        elif "emulator" in tool_lower:
            return "Protection emulation"
        elif "monitor" in tool_lower:
            return "API/Behavior monitoring"
        elif "debugger" in tool_lower or "dbg" in tool_lower:
            return "Dynamic analysis"
        elif "ida" in tool_lower or "ghidra" in tool_lower:
            return "Static analysis"
        elif "hook" in tool_lower or "detours" in tool_lower:
            return "API hooking"
        else:
            return "Protection bypass"
    
    def _build_llm_context(self, ml_result: Dict[str, Any]) -> Dict[str, Any]:
        """Build context specifically formatted for LLM consumption"""
        protection = ml_result.get('protection_type', 'Unknown')
        kb_info = self.kb.get_protection_info(protection)
        
        context = {
            "summary": f"Binary protected with {protection} (confidence: {ml_result.get('confidence', 0):.0%})",
            "protection_type": protection,
            "protection_category": ml_result.get('protection_category', 'unknown'),
            "bypass_difficulty": ml_result.get('bypass_difficulty', 'Unknown'),
            "key_characteristics": []
        }
        
        # Add key characteristics
        features = ml_result.get('features_summary', {})
        if features.get('has_packing'):
            context["key_characteristics"].append("Packed/Encrypted code")
        if features.get('has_anti_debug'):
            context["key_characteristics"].append("Anti-debugging present")
        if features.get('protection_complexity', 0) > 0.7:
            context["key_characteristics"].append("Complex protection scheme")
        
        # Add protection-specific context
        if kb_info:
            context["protection_details"] = {
                "vendor": kb_info.vendor,
                "description": kb_info.description,
                "common_targets": kb_info.common_applications[:3]
            }
            
            # Add bypass approach
            if kb_info.bypass_techniques:
                best = max(kb_info.bypass_techniques, key=lambda x: x.success_rate)
                context["recommended_approach"] = {
                    "technique": best.name,
                    "success_rate": f"{best.success_rate:.0%}",
                    "estimated_time": best.time_estimate
                }
        
        # Add specific guidance for LLM
        context["llm_guidance"] = self._get_llm_specific_guidance(protection)
        
        return context
    
    def _get_llm_specific_guidance(self, protection: str) -> str:
        """Get LLM-specific guidance for the protection"""
        guidance_map = {
            "No Protection": "Binary is unprotected. Focus on understanding functionality rather than bypass.",
            "Sentinel HASP": "Hardware dongle protection. Focus on hasp_login API and feature ID validation.",
            "FlexLM/FlexNet": "Network license manager. Look for license.dat parsing and server communication.",
            "WinLicense/Themida": "Heavy virtualization. Unpacking required before analysis. Check for SecureEngine.",
            "VMProtect": "Code virtualization. Look for .vmp sections and VM handlers.",
            "Steam CEG": "Steam wrapper. Use Steamless or similar for unwrapping. Monitor Steam API calls.",
            "Denuvo": "Extreme protection with 100+ triggers. Professional challenge requiring months.",
            "Microsoft Activation": "Check SoftwareProtectionPlatform registry and KMS communication."
        }
        
        return guidance_map.get(protection, 
                                "Unknown protection. Perform thorough analysis to identify validation mechanisms.")
    
    def format_for_display(self, analysis: Dict[str, Any]) -> str:
        """Format analysis results for human-readable display"""
        if not analysis.get('success'):
            return f"Analysis failed: {analysis.get('error', 'Unknown error')}"
        
        protection = analysis['protection_analysis']
        file_info = analysis['file_info']
        
        output = []
        output.append("=" * 60)
        output.append("PROTECTION ANALYSIS REPORT")
        output.append("=" * 60)
        
        # File info
        output.append(f"\nFile: {file_info['name']}")
        output.append(f"Size: {file_info['size_human']}")
        output.append(f"Path: {file_info['path']}")
        
        # Protection info
        output.append(f"\nProtection Detected: {protection['protection_detected']}")
        output.append(f"Confidence: {protection['confidence']:.0%} ({protection['confidence_level']})")
        output.append(f"Category: {protection['category'].replace('_', ' ').title()}")
        output.append(f"Bypass Difficulty: {protection['bypass_difficulty']}")
        
        if protection.get('vendor'):
            output.append(f"Vendor: {protection['vendor']}")
        
        if protection.get('description'):
            output.append(f"\nDescription: {protection['description']}")
        
        # Detection candidates
        if protection.get('detection_candidates'):
            output.append("\nDetection Candidates:")
            for candidate in protection['detection_candidates']:
                output.append(f"  - {candidate['scheme']}: {candidate['score']:.2f} ({candidate['likelihood']})")
        
        # Bypass guidance
        guidance = analysis.get('bypass_guidance', {})
        if guidance:
            output.append(f"\nBypass Approach: {guidance.get('approach', 'Unknown')}")
            output.append(f"Estimated Time: {guidance.get('estimated_time', 'Unknown')}")
            output.append(f"Difficulty Score: {guidance.get('difficulty_score', 0)}/10")
            
            if 'recommended_technique' in guidance:
                tech = guidance['recommended_technique']
                output.append(f"\nRecommended Technique: {tech['name']}")
                output.append(f"  Success Rate: {tech['success_rate']:.0%}")
                output.append(f"  Time: {tech['time_estimate']}")
        
        # Tools
        tools = analysis.get('tool_recommendations', [])
        if tools:
            output.append("\nRecommended Tools:")
            for tool in tools:
                output.append(f"  - {tool['name']}: {tool['purpose']}")
        
        output.append("\n" + "=" * 60)
        
        return "\n".join(output)


# Tool registration for LLM integration
def register_protection_analyzer_tool():
    """Register this tool for LLM usage"""
    return {
        "name": "analyze_protection",
        "description": "Analyze a binary file to detect and identify software protection schemes",
        "parameters": {
            "type": "object",
            "properties": {
                "file_path": {
                    "type": "string",
                    "description": "Path to the binary file to analyze"
                },
                "detailed": {
                    "type": "boolean",
                    "description": "Include detailed technical information",
                    "default": True
                }
            },
            "required": ["file_path"]
        },
        "handler": lambda params: ProtectionAnalyzerTool().analyze(
            params["file_path"], 
            params.get("detailed", True)
        )
    }