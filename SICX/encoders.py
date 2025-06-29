"""
Payload encoding module
Handles various encoding methods for payload obfuscation
"""

import base64
import urllib.parse
import html
import binascii
import codecs
from typing import List, Dict, Any


class PayloadEncoder:
    """Handles encoding of payloads using various methods"""
    
    def __init__(self):
        """Initialize the encoder with available encoding methods"""
        self.encoding_methods = {
            'base64': self._encode_base64,
            'url': self._encode_url,
            'double_url': self._encode_double_url,
            'hex': self._encode_hex,
            'unicode': self._encode_unicode,            'html': self._encode_html,
            'html_decimal': self._encode_html_decimal,
            'html_hex': self._encode_html_hex,
            'javascript': self._encode_javascript,
            'none': lambda x: x
        }
    
    def encode(self, payload: str, encoding_type: str) -> str:
        """
        Encode a payload using the specified encoding method
        
        Args:
            payload: The payload to encode
            encoding_type: The encoding method to use
            
        Returns:
            Encoded payload string
        """
        if encoding_type not in self.encoding_methods:
            # Return original payload for invalid encoding types
            return payload
        
        return self.encoding_methods[encoding_type](payload)
    
    def get_available_encodings(self) -> List[str]:
        """Get list of available encoding methods"""
        return list(self.encoding_methods.keys())
    
    def _encode_base64(self, payload: str) -> str:
        """Encode payload using Base64"""
        try:
            encoded = base64.b64encode(payload.encode('utf-8')).decode('utf-8')
            return encoded
        except Exception:
            return payload
    
    def _encode_url(self, payload: str) -> str:
        """Encode payload using URL encoding"""
        return urllib.parse.quote(payload, safe='')
    
    def _encode_double_url(self, payload: str) -> str:
        """Encode payload using double URL encoding"""
        first_encode = urllib.parse.quote(payload, safe='')
        return urllib.parse.quote(first_encode, safe='')
    
    def _encode_hex(self, payload: str) -> str:
        """Encode payload using hexadecimal encoding"""
        return ''.join([f'\\x{ord(c):02x}' for c in payload])
    
    def _encode_unicode(self, payload: str) -> str:
        """Encode payload using Unicode encoding"""
        return ''.join([f'\\u{ord(c):04x}' for c in payload])
    
    def _encode_html(self, payload: str) -> str:
        """Encode payload using HTML entity encoding"""
        return html.escape(payload)
    
    def _encode_html_decimal(self, payload: str) -> str:
        """Encode payload using HTML decimal entities"""
        return ''.join([f'&#{ord(c)};' for c in payload])
    
    def _encode_html_hex(self, payload: str) -> str:
        """Encode payload using HTML hexadecimal entities"""
        return ''.join([f'&#x{ord(c):x};' for c in payload])
    
    def _encode_javascript(self, payload: str) -> str:
        """Encode payload using JavaScript encoding"""
        result = ""
        for char in payload:
            if char.isalnum():
                result += char
            else:
                result += f'\\x{ord(char):02x}'
        return result
    
    def encode_multiple(self, payload: str, encoding_types: List[str]) -> Dict[str, str]:
        """
        Encode a payload using multiple encoding methods
        
        Args:
            payload: The payload to encode
            encoding_types: List of encoding methods to apply
            
        Returns:
            Dictionary mapping encoding type to encoded payload
        """
        results = {}
        for encoding_type in encoding_types:
            try:
                results[encoding_type] = self.encode(payload, encoding_type)
            except Exception as e:
                results[encoding_type] = f"Error: {str(e)}"
        
        return results
    
    def chain_encodings(self, payload: str, encoding_chain: List[str]) -> str:
        """
        Apply multiple encodings in sequence
        
        Args:
            payload: The payload to encode
            encoding_chain: List of encodings to apply in order
            
        Returns:
            Payload with chained encodings applied
        """
        result = payload
        for encoding_type in encoding_chain:
            result = self.encode(result, encoding_type)
        return result
    
    def decode(self, payload: str, encoding_type: str) -> str:
        """
        Decode a payload (reverse of encoding)
        
        Args:
            payload: The encoded payload
            encoding_type: The encoding method that was used
            
        Returns:
            Decoded payload string
        """
        try:
            if encoding_type == 'base64':
                return base64.b64decode(payload).decode('utf-8')
            elif encoding_type == 'url':
                return urllib.parse.unquote(payload)
            elif encoding_type == 'double_url':
                first_decode = urllib.parse.unquote(payload)
                return urllib.parse.unquote(first_decode)
            elif encoding_type == 'html':
                return html.unescape(payload)
            elif encoding_type == 'hex':
                # Simple hex decode for \x format
                result = ""
                i = 0
                while i < len(payload):
                    if payload[i:i+2] == '\\x' and i+3 < len(payload):
                        hex_char = payload[i+2:i+4]
                        result += chr(int(hex_char, 16))
                        i += 4
                    else:
                        result += payload[i]
                        i += 1
                return result
            elif encoding_type == 'unicode':
                # Simple unicode decode for \u format
                result = ""
                i = 0
                while i < len(payload):
                    if payload[i:i+2] == '\\u' and i+5 < len(payload):
                        unicode_char = payload[i+2:i+6]
                        result += chr(int(unicode_char, 16))
                        i += 6
                    else:
                        result += payload[i]
                        i += 1
                return result
            else:
                return payload
        except Exception:
            return payload
    
    def get_encoding_info(self, encoding_type: str) -> Dict[str, Any]:
        """
        Get information about a specific encoding method
        
        Args:
            encoding_type: The encoding method
            
        Returns:
            Dictionary with encoding information
        """
        info = {
            'base64': {
                'name': 'Base64 Encoding',
                'description': 'Standard Base64 encoding',
                'use_case': 'General purpose obfuscation',
                'reversible': True
            },
            'url': {
                'name': 'URL Encoding',
                'description': 'Percent-encoding for URLs',
                'use_case': 'Web application payloads',
                'reversible': True
            },
            'double_url': {
                'name': 'Double URL Encoding',
                'description': 'URL encoding applied twice',
                'use_case': 'Bypass URL decoding filters',
                'reversible': True
            },
            'hex': {
                'name': 'Hexadecimal Encoding',
                'description': 'Hexadecimal representation with \\x prefix',
                'use_case': 'Low-level payload obfuscation',
                'reversible': True
            },
            'unicode': {
                'name': 'Unicode Encoding',
                'description': 'Unicode escape sequences',
                'use_case': 'JavaScript and web obfuscation',
                'reversible': True
            },
            'html': {
                'name': 'HTML Entity Encoding',
                'description': 'Standard HTML entities',
                'use_case': 'HTML context obfuscation',
                'reversible': True
            },
            'html_decimal': {
                'name': 'HTML Decimal Entities',
                'description': 'Decimal HTML character references',
                'use_case': 'HTML attribute and content obfuscation',
                'reversible': True
            },
            'html_hex': {
                'name': 'HTML Hexadecimal Entities',
                'description': 'Hexadecimal HTML character references',
                'use_case': 'HTML obfuscation with hex values',
                'reversible': True
            },
            'javascript': {
                'name': 'JavaScript Encoding',
                'description': 'JavaScript-style hex escaping',
                'use_case': 'JavaScript string obfuscation',
                'reversible': True
            }
        }
        
        return info.get(encoding_type, {
            'name': encoding_type,
            'description': 'Custom encoding method',
            'use_case': 'Unknown',
            'reversible': False
        })