"""
Common AI response parsing utilities.

This module provides shared functions for parsing AI responses across different AI modules.
"""

from typing import Dict, List, Tuple, Optional


def parse_ai_response_sections(response: str, section_keywords: Dict[str, List[str]]) -> Dict[str, List[str]]:
    """
    Parse AI response into categorized sections.
    
    Args:
        response: The AI response text to parse
        section_keywords: Dictionary mapping section names to keyword lists
                         e.g., {'insights': ['vulnerabilit', 'security', 'risk'],
                               'suggestions': ['recommend', 'suggest', 'should']}
    
    Returns:
        Dictionary mapping section names to lists of extracted content
    """
    from .parsing_utils import ResponseLineParser
    
    # Use shared parsing utility
    return ResponseLineParser.parse_lines_by_sections(response, section_keywords)


def parse_security_analysis_response(response: str) -> Tuple[List[str], List[str]]:
    """
    Parse AI response for security analysis insights and suggestions.
    
    Args:
        response: AI response text
        
    Returns:
        Tuple of (insights, suggestions) lists
    """
    section_keywords = {
        'insights': ['vulnerabilit', 'security', 'risk', 'security issue', 'weakness'],
        'suggestions': ['recommend', 'suggest', 'should', 'mitigation', 'fix']
    }

    sections = parse_ai_response_sections(response, section_keywords)
    return sections['insights'], sections['suggestions']


def parse_attack_vector_response(response: str) -> Tuple[List[str], List[str], List[str]]:
    """
    Parse AI response for attack vectors, vulnerabilities, and recommendations.
    
    Args:
        response: AI response text
        
    Returns:
        Tuple of (vulnerabilities, recommendations, attack_vectors) lists
    """
    section_keywords = {
        'vulnerabilities': ['vulnerabilit', 'security issue', 'weakness'],
        'recommendations': ['recommend', 'suggest', 'should', 'mitigation'],
        'attack_vectors': ['attack', 'exploit', 'vector', 'payload']
    }

    sections = parse_ai_response_sections(response, section_keywords)
    return sections['vulnerabilities'], sections['recommendations'], sections['attack_vectors']


def parse_simple_response(response: str, finding_keywords: Optional[List[str]] = None, 
                         recommendation_keywords: Optional[List[str]] = None) -> Tuple[List[str], List[str]]:
    """
    Simple response parser for findings and recommendations.
    
    Args:
        response: The AI response text to parse
        finding_keywords: Keywords to identify findings (default: ['risk', 'vulnerability', 'threat', 'suspicious'])
        recommendation_keywords: Keywords to identify recommendations (default: ['recommend', 'suggest', 'should', 'analyze'])
    
    Returns:
        Tuple of (findings, recommendations) lists
    """
    if finding_keywords is None:
        finding_keywords = ['risk', 'vulnerability', 'threat', 'suspicious']
    if recommendation_keywords is None:
        recommendation_keywords = ['recommend', 'suggest', 'should', 'analyze']
    
    section_keywords = {
        'findings': finding_keywords,
        'recommendations': recommendation_keywords
    }
    
    sections = parse_ai_response_sections(response, section_keywords)
    return sections['findings'], sections['recommendations']
