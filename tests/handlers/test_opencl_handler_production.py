"""Production tests for opencl_handler.

Tests validate OpenCL availability detection, platform enumeration, context creation,
device detection, buffer management, program compilation, and fallback compatibility.
"""

import pytest

from intellicrack.handlers import opencl_handler


def test_has_opencl_flag_is_boolean() -> None:
    """HAS_OPENCL is a boolean flag."""
    assert isinstance(opencl_handler.HAS_OPENCL, bool)


def test_opencl_available_flag_is_boolean() -> None:
    """OPENCL_AVAILABLE is a boolean flag."""
    assert isinstance(opencl_handler.OPENCL_AVAILABLE, bool)


def test_opencl_version_is_string_or_none() -> None:
    """OPENCL_VERSION is None or valid version string when OpenCL unavailable."""
    version = opencl_handler.OPENCL_VERSION

    if version is not None:
        assert isinstance(version, str)


def test_module_exports_context_class() -> None:
    """opencl_handler exports Context class."""
    assert hasattr(opencl_handler, "Context")
    assert opencl_handler.Context is not None


def test_module_exports_device_class() -> None:
    """opencl_handler exports Device class."""
    assert hasattr(opencl_handler, "Device")
    assert opencl_handler.Device is not None


def test_module_exports_buffer_class() -> None:
    """opencl_handler exports Buffer class."""
    assert hasattr(opencl_handler, "Buffer")
    assert opencl_handler.Buffer is not None


def test_module_exports_program_class() -> None:
    """opencl_handler exports Program class."""
    assert hasattr(opencl_handler, "Program")
    assert opencl_handler.Program is not None


def test_module_exports_queue_class() -> None:
    """opencl_handler exports Queue class."""
    assert hasattr(opencl_handler, "Queue")
    assert opencl_handler.Queue is not None


def test_module_exports_platform_class() -> None:
    """opencl_handler exports Platform class."""
    assert hasattr(opencl_handler, "Platform")
    assert opencl_handler.Platform is not None


def test_module_exports_create_some_context() -> None:
    """opencl_handler exports create_some_context function."""
    assert hasattr(opencl_handler, "create_some_context")
    assert callable(opencl_handler.create_some_context)


def test_module_exports_get_platforms() -> None:
    """opencl_handler exports get_platforms function."""
    assert hasattr(opencl_handler, "get_platforms")
    assert callable(opencl_handler.get_platforms)


def test_get_platforms_returns_list() -> None:
    """get_platforms() returns a list."""
    platforms = opencl_handler.get_platforms()

    assert isinstance(platforms, list)


def test_get_platforms_with_opencl_unavailable_returns_empty() -> None:
    """get_platforms() returns empty list when OpenCL unavailable."""
    if not opencl_handler.HAS_OPENCL:
        platforms = opencl_handler.get_platforms()

        assert platforms == []


def test_create_some_context_returns_context() -> None:
    """create_some_context() returns a Context object."""
    context = opencl_handler.create_some_context()

    assert context is not None


def test_create_some_context_with_opencl_unavailable_returns_fallback() -> None:
    """create_some_context() returns FallbackContext when OpenCL unavailable."""
    if not opencl_handler.HAS_OPENCL:
        context = opencl_handler.create_some_context()

        assert type(context).__name__ in ("FallbackContext", "Context")


def test_fallback_context_exists_when_opencl_unavailable() -> None:
    """Fallback Context class is available when OpenCL unavailable."""
    if not opencl_handler.HAS_OPENCL:
        assert opencl_handler.Context is not None
        context = opencl_handler.Context()
        assert context is not None


def test_fallback_device_exists_when_opencl_unavailable() -> None:
    """Fallback Device class is available when OpenCL unavailable."""
    if not opencl_handler.HAS_OPENCL:
        assert opencl_handler.Device is not None
        device = opencl_handler.Device()
        assert device is not None


def test_fallback_buffer_exists_when_opencl_unavailable() -> None:
    """Fallback Buffer class is available when OpenCL unavailable."""
    if not opencl_handler.HAS_OPENCL:
        assert opencl_handler.Buffer is not None
        buffer = opencl_handler.Buffer()
        assert buffer is not None


def test_fallback_program_exists_when_opencl_unavailable() -> None:
    """Fallback Program class is available when OpenCL unavailable."""
    if not opencl_handler.HAS_OPENCL:
        assert opencl_handler.Program is not None
        program = opencl_handler.Program()
        assert program is not None


def test_fallback_queue_exists_when_opencl_unavailable() -> None:
    """Fallback Queue class is available when OpenCL unavailable."""
    if not opencl_handler.HAS_OPENCL:
        assert opencl_handler.Queue is not None
        queue = opencl_handler.Queue()
        assert queue is not None


def test_fallback_platform_exists_when_opencl_unavailable() -> None:
    """Fallback Platform class is available when OpenCL unavailable."""
    if not opencl_handler.HAS_OPENCL:
        assert opencl_handler.Platform is not None
        platform = opencl_handler.Platform()
        assert platform is not None


def test_cl_module_is_none_when_opencl_unavailable() -> None:
    """cl module is None when OpenCL unavailable."""
    if not opencl_handler.HAS_OPENCL:
        assert opencl_handler.cl is None


def test_cl_module_exists_when_opencl_available() -> None:
    """cl module exists when OpenCL available."""
    if opencl_handler.HAS_OPENCL:
        assert opencl_handler.cl is not None


def test_all_exports_are_defined() -> None:
    """All items in __all__ are defined in module."""
    for item in opencl_handler.__all__:
        assert hasattr(opencl_handler, item)


def test_flags_consistency() -> None:
    """HAS_OPENCL and OPENCL_AVAILABLE are consistent."""
    assert opencl_handler.HAS_OPENCL == opencl_handler.OPENCL_AVAILABLE


def test_version_consistency_with_availability() -> None:
    """OPENCL_VERSION is None when OpenCL unavailable."""
    if not opencl_handler.HAS_OPENCL:
        assert opencl_handler.OPENCL_VERSION is None


def test_context_creation_does_not_raise() -> None:
    """Context creation does not raise exceptions."""
    try:
        context = opencl_handler.create_some_context()
        assert context is not None
    except Exception as e:
        pytest.fail(f"Context creation raised unexpected exception: {e}")


def test_platform_enumeration_does_not_raise() -> None:
    """Platform enumeration does not raise exceptions."""
    try:
        platforms = opencl_handler.get_platforms()
        assert isinstance(platforms, list)
    except Exception as e:
        pytest.fail(f"Platform enumeration raised unexpected exception: {e}")


def test_fallback_classes_are_distinct() -> None:
    """Fallback classes are distinct types when OpenCL unavailable."""
    if not opencl_handler.HAS_OPENCL:
        context = opencl_handler.Context()
        device = opencl_handler.Device()
        buffer = opencl_handler.Buffer()

        assert type(context).__name__ == "FallbackContext"
        assert type(device).__name__ == "FallbackDevice"
        assert type(buffer).__name__ == "FallbackBuffer"


def test_handler_provides_graceful_degradation() -> None:
    """Handler provides graceful degradation when OpenCL unavailable."""
    platforms = opencl_handler.get_platforms()

    if not opencl_handler.HAS_OPENCL:
        assert platforms == []
    else:
        assert isinstance(platforms, list)


def test_queue_class_exists_or_fallback() -> None:
    """Queue class exists even if pyopencl version varies."""
    if opencl_handler.HAS_OPENCL:
        assert opencl_handler.Queue is not None
    else:
        queue = opencl_handler.Queue()
        assert queue is not None


@pytest.mark.skipif(not opencl_handler.HAS_OPENCL, reason="OpenCL not available")
class TestOpenCLRealComputations:
    """Test actual OpenCL computation capabilities for license cracking."""

    def test_platform_has_devices(self) -> None:
        """OpenCL platforms have at least one device."""
        platforms = opencl_handler.get_platforms()

        assert len(platforms) > 0
        for platform in platforms:
            devices = platform.get_devices()
            assert len(devices) > 0

    def test_device_has_compute_capability(self) -> None:
        """OpenCL devices have compute capabilities."""
        platforms = opencl_handler.get_platforms()

        for platform in platforms:
            devices = platform.get_devices()
            for device in devices:
                assert hasattr(device, "max_compute_units")
                assert device.max_compute_units > 0

    def test_create_context_from_platform(self) -> None:
        """Create OpenCL context from platform device."""
        platforms = opencl_handler.get_platforms()
        platform = platforms[0]
        devices = platform.get_devices()

        ctx = opencl_handler.Context(devices)

        assert ctx is not None
        assert hasattr(ctx, "devices")

    def test_create_command_queue(self) -> None:
        """Create command queue for GPU operations."""
        platforms = opencl_handler.get_platforms()
        platform = platforms[0]
        devices = platform.get_devices()
        ctx = opencl_handler.Context(devices)

        queue = opencl_handler.Queue(ctx)

        assert queue is not None

    def test_simple_buffer_operation(self) -> None:
        """Create and use OpenCL buffer for data transfer."""
        import numpy as np

        platforms = opencl_handler.get_platforms()
        platform = platforms[0]
        devices = platform.get_devices()
        ctx = opencl_handler.Context(devices)
        queue = opencl_handler.Queue(ctx)

        data = np.array([1, 2, 3, 4, 5], dtype=np.int32)
        mf = opencl_handler.cl.mem_flags
        buffer = opencl_handler.Buffer(ctx, mf.READ_WRITE | mf.COPY_HOST_PTR, hostbuf=data)

        assert buffer is not None

        result = np.empty_like(data)
        opencl_handler.cl.enqueue_copy(queue, result, buffer).wait()

        assert np.array_equal(data, result)

    def test_compile_simple_kernel(self) -> None:
        """Compile simple OpenCL kernel for GPU execution."""
        kernel_source = """
        __kernel void simple_add(__global int* a, __global int* b, __global int* c) {
            int gid = get_global_id(0);
            c[gid] = a[gid] + b[gid];
        }
        """

        platforms = opencl_handler.get_platforms()
        platform = platforms[0]
        devices = platform.get_devices()
        ctx = opencl_handler.Context(devices)

        program = opencl_handler.Program(ctx, kernel_source).build()

        assert program is not None
        assert hasattr(program, "simple_add")

    def test_execute_simple_kernel(self) -> None:
        """Execute simple kernel on GPU for computation."""
        import numpy as np

        kernel_source = """
        __kernel void add(__global int* a, __global int* b, __global int* c) {
            int gid = get_global_id(0);
            c[gid] = a[gid] + b[gid];
        }
        """

        platforms = opencl_handler.get_platforms()
        platform = platforms[0]
        devices = platform.get_devices()
        ctx = opencl_handler.Context(devices)
        queue = opencl_handler.Queue(ctx)

        a = np.array([1, 2, 3, 4], dtype=np.int32)
        b = np.array([5, 6, 7, 8], dtype=np.int32)
        c = np.empty_like(a)

        mf = opencl_handler.cl.mem_flags
        a_buf = opencl_handler.Buffer(ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=a)
        b_buf = opencl_handler.Buffer(ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=b)
        c_buf = opencl_handler.Buffer(ctx, mf.WRITE_ONLY, c.nbytes)

        program = opencl_handler.Program(ctx, kernel_source).build()
        program.add(queue, a.shape, None, a_buf, b_buf, c_buf)

        opencl_handler.cl.enqueue_copy(queue, c, c_buf).wait()

        assert np.array_equal(c, np.array([6, 8, 10, 12], dtype=np.int32))

    def test_parallel_brute_force_kernel(self) -> None:
        """Test parallel brute force kernel for license key testing."""
        import numpy as np

        kernel_source = """
        __kernel void check_keys(__global uint* start_key, __global uint* valid_mask, uint target) {
            int gid = get_global_id(0);
            uint key = start_key[0] + gid;

            if ((key ^ 0xDEADBEEF) == target) {
                valid_mask[gid] = 1;
            } else {
                valid_mask[gid] = 0;
            }
        }
        """

        platforms = opencl_handler.get_platforms()
        platform = platforms[0]
        devices = platform.get_devices()
        ctx = opencl_handler.Context(devices)
        queue = opencl_handler.Queue(ctx)

        start_key = np.array([0], dtype=np.uint32)
        target = np.uint32(0x12345678)
        n_keys = 1024
        valid_mask = np.zeros(n_keys, dtype=np.uint32)

        mf = opencl_handler.cl.mem_flags
        start_buf = opencl_handler.Buffer(ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=start_key)
        mask_buf = opencl_handler.Buffer(ctx, mf.WRITE_ONLY, valid_mask.nbytes)

        program = opencl_handler.Program(ctx, kernel_source).build()
        program.check_keys(queue, (n_keys,), None, start_buf, mask_buf, target)

        opencl_handler.cl.enqueue_copy(queue, valid_mask, mask_buf).wait()

        assert isinstance(valid_mask, np.ndarray)
        assert len(valid_mask) == n_keys

    def test_hash_computation_kernel(self) -> None:
        """Test hash computation kernel for serial validation."""
        import numpy as np

        kernel_source = """
        __kernel void simple_hash(__global uint* input, __global uint* output) {
            int gid = get_global_id(0);
            uint val = input[gid];
            val = val ^ (val << 13);
            val = val ^ (val >> 17);
            val = val ^ (val << 5);
            output[gid] = val;
        }
        """

        platforms = opencl_handler.get_platforms()
        platform = platforms[0]
        devices = platform.get_devices()
        ctx = opencl_handler.Context(devices)
        queue = opencl_handler.Queue(ctx)

        input_data = np.array([1, 2, 3, 4, 5, 6, 7, 8], dtype=np.uint32)
        output_data = np.zeros_like(input_data)

        mf = opencl_handler.cl.mem_flags
        input_buf = opencl_handler.Buffer(ctx, mf.READ_ONLY | mf.COPY_HOST_PTR, hostbuf=input_data)
        output_buf = opencl_handler.Buffer(ctx, mf.WRITE_ONLY, output_data.nbytes)

        program = opencl_handler.Program(ctx, kernel_source).build()
        program.simple_hash(queue, input_data.shape, None, input_buf, output_buf)

        opencl_handler.cl.enqueue_copy(queue, output_data, output_buf).wait()

        assert not np.array_equal(input_data, output_data)
        assert all(output_data > 0)

    def test_device_memory_limits(self) -> None:
        """Test device memory allocation limits."""
        platforms = opencl_handler.get_platforms()
        platform = platforms[0]
        devices = platform.get_devices()

        for device in devices:
            assert hasattr(device, "global_mem_size")
            assert device.global_mem_size > 0
            assert hasattr(device, "max_mem_alloc_size")
            assert device.max_mem_alloc_size > 0

    def test_multiple_kernels_same_program(self) -> None:
        """Compile and execute multiple kernels in same program."""
        kernel_source = """
        __kernel void kernel1(__global int* data) {
            data[get_global_id(0)] = 1;
        }
        __kernel void kernel2(__global int* data) {
            data[get_global_id(0)] = 2;
        }
        """

        platforms = opencl_handler.get_platforms()
        platform = platforms[0]
        devices = platform.get_devices()
        ctx = opencl_handler.Context(devices)

        program = opencl_handler.Program(ctx, kernel_source).build()

        assert hasattr(program, "kernel1")
        assert hasattr(program, "kernel2")


@pytest.mark.skipif(not opencl_handler.HAS_OPENCL, reason="OpenCL not available")
class TestOpenCLErrorHandling:
    """Test OpenCL error handling for edge cases."""

    def test_invalid_kernel_compilation_fails(self) -> None:
        """Invalid kernel source code fails compilation."""
        invalid_kernel = "this is not valid opencl code"

        platforms = opencl_handler.get_platforms()
        platform = platforms[0]
        devices = platform.get_devices()
        ctx = opencl_handler.Context(devices)

        with pytest.raises(Exception):
            opencl_handler.Program(ctx, invalid_kernel).build()

    def test_buffer_overflow_protection(self) -> None:
        """Buffer operations detect size mismatches."""
        import numpy as np

        platforms = opencl_handler.get_platforms()
        platform = platforms[0]
        devices = platform.get_devices()
        ctx = opencl_handler.Context(devices)
        queue = opencl_handler.Queue(ctx)

        small_data = np.array([1, 2, 3], dtype=np.int32)
        large_data = np.zeros(100, dtype=np.int32)

        mf = opencl_handler.cl.mem_flags
        buffer = opencl_handler.Buffer(ctx, mf.READ_WRITE | mf.COPY_HOST_PTR, hostbuf=small_data)

        with pytest.raises(Exception):
            opencl_handler.cl.enqueue_copy(queue, large_data, buffer).wait()

    def test_context_creation_with_no_devices_fails(self) -> None:
        """Creating context with empty device list fails."""
        with pytest.raises((ValueError, TypeError, Exception)):
            opencl_handler.Context([])

    def test_kernel_execution_with_wrong_argument_types(self) -> None:
        """Kernel execution with wrong argument types fails."""
        import numpy as np

        kernel_source = """
        __kernel void test(__global int* data) {
            data[get_global_id(0)] = 1;
        }
        """

        platforms = opencl_handler.get_platforms()
        platform = platforms[0]
        devices = platform.get_devices()
        ctx = opencl_handler.Context(devices)
        queue = opencl_handler.Queue(ctx)

        program = opencl_handler.Program(ctx, kernel_source).build()

        with pytest.raises((TypeError, Exception)):
            program.test(queue, (10,), None, "not_a_buffer")
