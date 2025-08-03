
import importlib
import pkgutil
from typing import Dict, List, Type

from .base import KeygenTemplate

class KeygenEngine:
    """Manages and executes keygen templates."""

    def __init__(self, templates_path: str = "intellicrack.core.keygen.templates"):
        self.templates_path = templates_path
        self.templates: Dict[str, Type[KeygenTemplate]] = self._discover_templates()

    def _discover_templates(self) -> Dict[str, Type[KeygenTemplate]]:
        """Dynamically discovers keygen templates from the templates directory."""
        templates = {}
        try:
            package = importlib.import_module(self.templates_path)
            for _, name, _ in pkgutil.iter_modules(package.__path__):
                try:
                    module = importlib.import_module(f"{self.templates_path}.{name}")
                    for item_name in dir(module):
                        item = getattr(module, item_name)
                        if isinstance(item, type) and issubclass(item, KeygenTemplate) and item is not KeygenTemplate:
                            instance = item()
                            templates[instance.name] = item
                except Exception as e:
                    print(f"Could not load template from {name}: {e}")
        except Exception as e:
            print(f"Could not discover keygen templates: {e}")
        return templates

    def list_templates(self) -> List[str]:
        """Returns a list of available keygen template names."""
        return list(self.templates.keys())

    def get_template(self, name: str) -> Type[KeygenTemplate]:
        """Returns the class for a given template name."""
        return self.templates.get(name)

    def run(self, template_name: str, params: Dict[str, Any]):
        """Runs a keygen template with the given parameters."""
        template_class = self.get_template(template_name)
        if not template_class:
            raise ValueError(f"Template '{template_name}' not found.")
        
        template_instance = template_class()
        return template_instance.generate(params)
