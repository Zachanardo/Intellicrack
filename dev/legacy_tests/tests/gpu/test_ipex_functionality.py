import sys
import torch
import intel_extension_for_pytorch as ipex

print(f"Python: {sys.version}")
print(f"PyTorch: {torch.__version__}")
print(f"IPEX: {ipex.__version__}")
print(f"XPU available: {torch.xpu.is_available()}")

if torch.xpu.is_available():
    device = torch.device('xpu')
    print(f"\nTesting basic tensor operations on {device}:")

    try:
        # Test 1: Basic tensor creation and operations
        print("\n1. Basic tensor operations:")
        x = torch.randn(3, 3).to(device)
        y = torch.randn(3, 3).to(device)
        z = x + y
        print(f"   Tensor addition: SUCCESS")
        print(f"   Result shape: {z.shape}")

        # Test 2: Matrix multiplication
        print("\n2. Matrix multiplication:")
        result = torch.matmul(x, y)
        print(f"   MatMul: SUCCESS")
        print(f"   Result shape: {result.shape}")

        # Test 3: Geometric distribution (the operator that had a warning)
        print("\n3. Testing geometric_ operator (from warning):")
        tensor = torch.ones(5, 5).to(device)
        tensor.geometric_(0.5)  # This is the operator that was overridden
        print(f"   Geometric distribution: SUCCESS")
        print(f"   Sample values: {tensor[:2, :2].cpu()}")

        # Test 4: IPEX optimization (inference mode)
        print("\n4. Testing IPEX model optimization:")
        model = torch.nn.Linear(10, 5).to(device)
        model.eval()  # Set to evaluation mode for inference
        model = ipex.optimize(model)
        input_tensor = torch.randn(2, 10).to(device)
        with torch.no_grad():
            output = model(input_tensor)
        print(f"   IPEX optimize: SUCCESS")
        print(f"   Output shape: {output.shape}")

        # Test 5: Weight prepacking (related to pkg_resources warning)
        print("\n5. Testing weight prepacking:")
        from intel_extension_for_pytorch.nn.utils import _weight_prepack
        print(f"   Weight prepack module imported: SUCCESS")

        print("\n✅ All functionality tests passed!")

    except Exception as e:
        print(f"\n❌ Error during testing: {type(e).__name__}: {e}")
        import traceback
        traceback.print_exc()
else:
    print("❌ XPU not available, cannot test functionality")
