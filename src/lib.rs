#![no_std]
#![feature(doc_cfg)]
#![feature(concat_idents)]
#![feature(naked_functions)]
#![doc = include_str!("../README.md")]

#[macro_use]
extern crate log;

extern crate alloc;

pub(crate) mod msr;
#[macro_use]
pub(crate) mod regs;
mod frame;
mod page_table;

mod context;
mod segmentation;
// mod tables;
mod xstate;

mod generated;

cfg_if::cfg_if! {
    if #[cfg(feature = "vmx")] {
        mod vmx;
        use vmx as vender;
        pub use vmx::{VmxExitInfo, VmxExitReason, VmxInterruptInfo, VmxIoExitInfo};
        pub use vmx::invalid_ept;

        pub use vender::VmxArchVCpu;
        pub use vender::VmxArchPerCpuState;
    }
}

pub use context::{
    GATE_EPTP_INDEX,
    KERNEL_CS,
    KERNEL_DS,
    KERNEL32_CS,
    LINUX_EPTP_INDEX_BASE,
    LINUX_GDT_ENTRIES,
    // Standard boot context
    Linux64BitBootContext,
    LinuxContext,
    MsrEntry,
    PV_SHARED_FLAG_GATE_READY,
    PV_SHARED_FLAG_SKIP_GDT_INIT,
    PV_SHARED_FLAG_SKIP_IDT_INIT,
    PV_SHARED_FLAG_SKIP_LAPIC_INIT,
    PV_SHARED_FLAG_SKIP_TSS_INIT,
    PV_SHARED_GDT_GPA,
    PV_SHARED_IDT_GPA,
    PV_SHARED_INFO_GPA,
    // Paravirt constants
    PV_SHARED_INFO_MAGIC,
    PV_SHARED_INFO_VERSION,
    PV_SHARED_TSS_GPA,
    PV_VCPU_STATE_IDLE,
    PV_VCPU_STATE_OFFLINE,
    PV_VCPU_STATE_ONLINE,
    PV_VCPU_STATE_PARKED,
    PV_VCPU_STATE_RUNNING,
    // Paravirt boot context
    ParavirtBootContext,
    PvSharedInfo,
    PvVcpuInfo,
    TSS_SELECTOR,
    USER_CS,
    USER_DS,
    USER32_CS,
    VCpuSetupContext,
    create_boot_msr_entries,

    create_linux_final_gdt,
    create_paravirt_msr_entries,

    create_tss_descriptor,
    gdt_entry,
};
pub use regs::GeneralRegisters;
pub use vender::has_hardware_support;
