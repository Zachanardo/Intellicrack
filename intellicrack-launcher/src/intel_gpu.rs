use std::fmt;
use windows::Win32::Graphics::Dxgi::{CreateDXGIFactory1, DXGI_ADAPTER_DESC1, IDXGIFactory1};
use windows::core::Result;

const INTEL_VENDOR_ID: u32 = 0x8086;

#[derive(Debug, Clone)]
pub struct IntelGpuDetails {
    pub device_name: String,
    pub device_id: u32,
    pub vendor_id: u32,
    pub vram_mb: usize,
    pub is_arc: bool,
    pub driver_version: String,
}

impl fmt::Display for IntelGpuDetails {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Intel GPU: {} (Device ID: 0x{:04X}, VRAM: {} MB, Arc: {})",
            self.device_name, self.device_id, self.vram_mb, self.is_arc
        )
    }
}

pub fn detect_intel_arc_gpu() -> Result<Option<IntelGpuDetails>> {
    unsafe {
        let factory: IDXGIFactory1 = CreateDXGIFactory1()?;

        let mut adapter_index = 0;
        while let Ok(adapter) = factory.EnumAdapters1(adapter_index) {
            let desc = adapter.GetDesc1()?;

            if desc.VendorId == INTEL_VENDOR_ID {
                let gpu_details = parse_adapter_desc(&desc)?;
                return Ok(Some(gpu_details));
            }

            adapter_index += 1;
        }

        Ok(None)
    }
}

unsafe fn parse_adapter_desc(desc: &DXGI_ADAPTER_DESC1) -> Result<IntelGpuDetails> {
    let device_name = String::from_utf16_lossy(&desc.Description)
        .trim_end_matches('\0')
        .to_string();

    let is_arc = device_name.to_lowercase().contains("arc");

    let vram_mb = desc.DedicatedVideoMemory / (1024 * 1024);

    let driver_version = format!(
        "{}.{}.{}.{}",
        (desc.Revision >> 24) & 0xFF,
        (desc.Revision >> 16) & 0xFF,
        (desc.Revision >> 8) & 0xFF,
        desc.Revision & 0xFF
    );

    Ok(IntelGpuDetails {
        device_name,
        device_id: desc.DeviceId,
        vendor_id: desc.VendorId,
        vram_mb,
        is_arc,
        driver_version,
    })
}

pub fn get_gpu_info_for_logging(gpu: &IntelGpuDetails) -> String {
    format!(
        "[GPU] {} detected\n\
         [GPU]   - Vendor: Intel (0x{:04X})\n\
         [GPU]   - Device ID: 0x{:04X}\n\
         [GPU]   - VRAM: {} MB\n\
         [GPU]   - Driver: {}\n\
         [GPU]   - Arc GPU: {}",
        gpu.device_name, gpu.vendor_id, gpu.device_id, gpu.vram_mb, gpu.driver_version, gpu.is_arc
    )
}
