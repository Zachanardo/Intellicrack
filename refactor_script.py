"""Refactor legacy logging calls to structured logging with extras."""

import ast
import os
from pathlib import Path


class FstringLoggerTransformer(ast.NodeTransformer):
    """Transform f-string based logging calls into structured logging calls."""

    def visit_Call(self, node):
        """Rewrite logging calls that pass f-strings as the primary argument."""
        self.generic_visit(node)

        is_logger_call = False
        logger_instance = None
        log_level_attr = None

        # Case 1: self.logger.level(...)
        if (isinstance(node.func, ast.Attribute) and
                isinstance(node.func.value, ast.Attribute) and
                node.func.value.attr == 'logger' and
                node.func.attr in ['debug', 'info', 'warning', 'error', 'critical']):
            is_logger_call = True
            logger_instance = node.func.value # This is ast.Attribute(value=ast.Name(id='self'), attr='logger')
            log_level_attr = node.func.attr

        # Case 2: logging.level(...)
        elif (isinstance(node.func, ast.Attribute) and
              isinstance(node.func.value, ast.Name) and
              node.func.value.id == 'logging' and
              node.func.attr in ['debug', 'info', 'warning', 'error', 'critical']):
            is_logger_call = True
            logger_instance = node.func.value # This is ast.Name(id='logging')
            log_level_attr = node.func.attr

        if is_logger_call and node.args and isinstance(node.args[0], ast.JoinedStr):
            fstring_node = node.args[0]

            # Extract static parts and dynamic parts
            static_parts = []
            dynamic_parts = {}

            for value in fstring_node.values:
                if isinstance(value, ast.Constant):
                    static_parts.append(value.value)
                elif isinstance(value, ast.FormattedValue):
                    # Capture the original expression for the extra dict value
                    dynamic_parts[ast.unparse(value.value)] = value.value

            # Construct new message string
            new_msg = "".join(static_parts).strip()
            if not new_msg:
                new_msg = "Log message" # Default if f-string was purely dynamic

            # Create new extra dictionary
            extra_dict_keys = []
            extra_dict_values = []
            for key_str, val_node in dynamic_parts.items():
                # Sanitize key for dictionary: replace non-alphanumeric with underscore, convert to lowercase
                sanitized_key = ''.join(c if c.isalnum() else '_' for c in key_str).lower()
                # Ensure key is not empty and is a valid identifier
                if not sanitized_key or not sanitized_key[0].isalpha():
                    sanitized_key = "param_" + sanitized_key.lstrip('_')

                extra_dict_keys.append(ast.Constant(value=sanitized_key))
                extra_dict_values.append(val_node)

            new_extra_dict = ast.Dict(keys=extra_dict_keys, values=extra_dict_values)

            # Create new logging call arguments
            new_args = [ast.Constant(value=new_msg)]
            new_keywords = [ast.keyword(arg='extra', value=new_extra_dict)]

            # Preserve other arguments and keywords
            for arg in node.args[1:]:
                new_args.append(arg)
            for kw in node.keywords:
                if kw.arg != 'extra':
                        new_keywords.append(kw)

            # Reconstruct the function call to ensure the original logger instance is preserved
            new_func = ast.Attribute(value=logger_instance, attr=log_level_attr, ctx=ast.Load())

            new_node = ast.Call(func=new_func, args=new_args, keywords=new_keywords)

            # Copy line numbers and other metadata
            ast.copy_location(new_node, node)
            ast.fix_missing_locations(new_node)

            return new_node
        return node


def refactor_logging_calls(file_path: str) -> None:
    """Rewrite logging calls in the provided file to use structured extras."""
    source_path = Path(file_path)
    source = source_path.read_text(encoding="utf-8")

    tree = ast.parse(source)
    transformer = FstringLoggerTransformer()
    new_tree = transformer.visit(tree)

    new_source = ast.unparse(new_tree)
    source_path.write_text(new_source, encoding="utf-8")


if __name__ == "__main__":
    file_to_refactor = os.path.join(
        "D:\\Intellicrack",
        "intellicrack",
        "plugins",
        "custom_modules",
        "license_server_emulator.py",
    )
    refactor_logging_calls(file_to_refactor)
    print(f"Refactored logging calls in {file_to_refactor}")
