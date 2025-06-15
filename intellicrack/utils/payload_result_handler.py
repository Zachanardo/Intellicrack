"""
Payload Result Handler

Common utilities for handling payload generation results.
"""

from typing import Any, Dict, Optional, Callable


class PayloadResultHandler:
    """
    Common handler for payload generation results.
    Eliminates duplicate result processing code.
    """
    
    @staticmethod
    def process_payload_result(result: Dict[str, Any], 
                             output_func: Callable[[str], None],
                             save_callback: Optional[Callable[[bytes, Dict[str, Any]], None]] = None) -> bool:
        """
        Process payload generation result with common pattern.
        
        Args:
            result: Payload generation result dictionary
            output_func: Function to call for output (e.g., click.echo, append to list)
            save_callback: Optional callback for saving payload data
            
        Returns:
            True if successful, False otherwise
        """
        if result['success']:
            payload = result['payload']
            metadata = result['metadata']

            output_func("✓ Payload generated successfully!")
            output_func(f"  Size: {metadata['size_bytes']} bytes")
            output_func(f"  Entropy: {metadata['entropy']:.3f}")
            
            # Handle optional metadata fields
            if 'null_bytes' in metadata:
                output_func(f"  Null bytes: {metadata['null_bytes']}")
            if 'bad_chars' in metadata:
                output_func(f"  Bad chars: {len(metadata['bad_chars'])}")
            if 'compatibility_score' in metadata:
                output_func(f"  Compatibility: {metadata['compatibility_score']:.2f}")
            if 'hash_md5' in metadata:
                output_func(f"  MD5: {metadata['hash_md5']}")
            if 'generation_time' in result:
                output_func(f"  Generation time: {result['generation_time']:.2f}s")
            
            # Call save callback if provided
            if save_callback:
                save_callback(payload, metadata)
                
            return True
        else:
            error_msg = result.get('error', 'Unknown error occurred')
            output_func(f"✗ Payload generation failed: {error_msg}")
            return False