mod host;
mod pvboot;

pub use host::LinuxContext;
pub use pvboot::{
    GATE_EPTP_INDEX,
    KERNEL_CS,
    KERNEL_DS,
    KERNEL32_CS,
    LINUX_EPTP_INDEX_BASE,
    LINUX_GDT_ENTRIES,
    // Standard Linux 64-bit boot protocol
    Linux64BitBootContext,
    MsrEntry,
    PV_SHARED_FLAG_GATE_READY,
    PV_SHARED_FLAG_SKIP_GDT_INIT,
    PV_SHARED_FLAG_SKIP_IDT_INIT,
    PV_SHARED_FLAG_SKIP_LAPIC_INIT,
    PV_SHARED_FLAG_SKIP_TSS_INIT,
    PV_SHARED_GDT_GPA,
    PV_SHARED_IDT_GPA,
    PV_SHARED_INFO_GPA,
    // Constants
    PV_SHARED_INFO_MAGIC,
    PV_SHARED_INFO_VERSION,
    PV_SHARED_TSS_GPA,
    PV_VCPU_STATE_IDLE,
    PV_VCPU_STATE_OFFLINE,
    PV_VCPU_STATE_ONLINE,
    PV_VCPU_STATE_PARKED,
    PV_VCPU_STATE_RUNNING,
    // Paravirt boot protocol
    ParavirtBootContext,
    PvSharedInfo,
    PvVcpuInfo,
    TSS_SELECTOR,
    USER_CS,
    USER_DS,
    USER32_CS,
    create_boot_msr_entries,

    create_linux_final_gdt,
    create_paravirt_msr_entries,

    create_tss_descriptor,
    gdt_entry,
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
