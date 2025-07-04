#!/usr/bin/env python3
"""
Explore die-python API structure to understand the correct usage
"""

def explore_die_api():
    """Explore the die-python API"""
    try:
        import die
        print("Exploring die-python API...")
        print(f"die module version: {getattr(die, '__version__', 'Unknown')}")
        print(f"die module file: {die.__file__ if hasattr(die, '__file__') else 'Unknown'}")

        # List all attributes of the die module
        print("\nAvailable attributes in 'die' module:")
        attributes = [attr for attr in dir(die) if not attr.startswith('_')]
        for attr in attributes:
            obj = getattr(die, attr)
            print(f"  {attr}: {type(obj)} - {obj.__doc__[:50] if hasattr(obj, '__doc__') and obj.__doc__ else 'No doc'}...")

        # Try to find the main analysis function/class
        for attr in attributes:
            obj = getattr(die, attr)
            if callable(obj):
                print(f"\nTrying to call {attr}...")
                try:
                    # Try different instantiation patterns
                    if attr.lower() in ['scan', 'analyze', 'detect']:
                        print(f"  {attr} appears to be a function")
                    elif hasattr(obj, '__init__'):
                        print(f"  {attr} appears to be a class")
                        instance = obj()
                        print(f"  Successfully created instance of {attr}")

                        # List methods of the instance
                        methods = [method for method in dir(instance) if not method.startswith('_') and callable(getattr(instance, method))]
                        print(f"  Available methods: {methods}")

                except Exception as e:
                    print(f"  Failed to instantiate {attr}: {e}")

        return True
    except ImportError as e:
        print(f"Failed to import die: {e}")
        return False
    except Exception as e:
        print(f"Error exploring API: {e}")
        return False

def test_common_api_patterns():
    """Test common API patterns"""
    try:
        import die
        print("\nTesting common API patterns...")

        # Pattern 1: Direct function call
        try:
            if hasattr(die, 'scan'):
                print("Found 'scan' function")
            if hasattr(die, 'analyze'):
                print("Found 'analyze' function")
            if hasattr(die, 'detect'):
                print("Found 'detect' function")
        except Exception as e:
            print(f"Error testing direct functions: {e}")

        # Pattern 2: Class-based approach
        try:
            possible_classes = ['DIE', 'Die', 'Scanner', 'Analyzer', 'Detector']
            for class_name in possible_classes:
                if hasattr(die, class_name):
                    print(f"Found class: {class_name}")
                    cls = getattr(die, class_name)
                    try:
                        instance = cls()
                        print(f"  Successfully instantiated {class_name}")
                        break
                    except Exception as e:
                        print(f"  Failed to instantiate {class_name}: {e}")
        except Exception as e:
            print(f"Error testing classes: {e}")

        return True
    except Exception as e:
        print(f"Error in API pattern testing: {e}")
        return False

if __name__ == "__main__":
    explore_die_api()
    test_common_api_patterns()