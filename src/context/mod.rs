mod host;
mod pvboot;

pub use host::LinuxContext;
pub use pvboot::{
    // Standard Linux 64-bit boot protocol
    Linux64BitBootContext,
    MsrEntry,
    gdt_entry,
    create_boot_msr_entries,
    
    // Paravirt boot protocol
    ParavirtBootContext,
    PvSharedInfo,
    PvVcpuInfo,
    create_linux_final_gdt,
    create_tss_descriptor,
    create_paravirt_msr_entries,
    
    // Constants
    PV_SHARED_INFO_MAGIC,
    PV_SHARED_INFO_VERSION,
    PV_SHARED_INFO_GPA,
    PV_SHARED_GDT_GPA,
    PV_SHARED_IDT_GPA,
    PV_SHARED_TSS_GPA,
    KERNEL_CS,
    KERNEL_DS,
    KERNEL32_CS,
    USER32_CS,
    USER_DS,
    USER_CS,
    TSS_SELECTOR,
    LINUX_GDT_ENTRIES,
    GATE_EPTP_INDEX,
    LINUX_EPTP_INDEX_BASE,
    PV_VCPU_STATE_OFFLINE,
    PV_VCPU_STATE_ONLINE,
    PV_VCPU_STATE_RUNNING,
    PV_VCPU_STATE_IDLE,
    PV_VCPU_STATE_PARKED,
    PV_SHARED_FLAG_GATE_READY,
    PV_SHARED_FLAG_SKIP_GDT_INIT,
    PV_SHARED_FLAG_SKIP_IDT_INIT,
    PV_SHARED_FLAG_SKIP_TSS_INIT,
    PV_SHARED_FLAG_SKIP_LAPIC_INIT,
};

/// Context type for setting up a vCPU.
#[derive(Debug, Clone)]
pub enum VCpuSetupContext {
    /// A first-time boot vcpu context.
    InitialBoot,
    /// Standard Linux 64-bit boot protocol context.
    Linux64BitBoot(Linux64BitBootContext),
    /// Paravirtualized boot context with shared GDT/IDT/TSS.
    ParavirtBoot(ParavirtBootContext),
    /// A host Linux context loaded from the stack pointer when
    /// just dump from jailhouse kernel module.
    HostContext(host::LinuxContext),
}
