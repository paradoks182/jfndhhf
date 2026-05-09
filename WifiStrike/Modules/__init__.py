import os
import glob
import importlib.util

__all__ = []

def load_all_modules():
    modules = []
    modules_dir = os.path.dirname(__file__)
    
    for category in os.listdir(modules_dir):
        category_path = os.path.join(modules_dir, category)
        if os.path.isdir(category_path) and not category.startswith("__"):
            for py_file in glob.glob(os.path.join(category_path, "*.py")):
                if not py_file.endswith("__init__.py"):
                    module_name = os.path.basename(py_file)[:-3]
                    modules.append({
                        "name": module_name,
                        "category": category,
                        "path": py_file
                    })
    
    return modules