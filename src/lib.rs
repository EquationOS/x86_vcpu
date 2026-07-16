#![no_std]
#![feature(doc_cfg)]
#![feature(macro_metavar_expr_concat)]
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
        pub use vmx::{invalid_ept, invalid_ept_all_contexts, invalid_vpid_all_contexts};
        pub use vmx::{POSTED_INTR_VECTOR, PostedInterruptDescriptor};
        pub use vmx::current_posted_interrupt_destination;
        pub use vmx::PendingEvent;
        pub use vmx::{
            EQUATION_PV_FEATURE_APIC_ID, EQUATION_PV_FEATURE_CEDE, EQUATION_PV_FEATURE_IPI,
            EQUATION_PV_FEATURE_CPU_RESIZE, EQUATION_PV_FEATURE_EQGATE_INSTALL,
            EQUATION_PV_FEATURE_EQGATE_INSTALL_REGISTRY,
            EQUATION_PV_FEATURE_HYPERALLOC,
            EQUATION_PV_FEATURE_NO_HLAT_GATE_PGD,
            EQUATION_PV_FEATURE_SHADOW_IDT,
            EQUATION_PV_FEATURE_SMP, EQUATION_PV_FEATURE_TIMER, EquationPvAbi,
        };
        pub use vmx::EqGateResumeContext;
        pub use vmx::VmxInternalExitKind;

        pub use vender::VmxArchVCpu;
        pub use vender::VmxArchPerCpuState;
    }
}

pub use context::{GuestContext, VCpuSetupContext};

pub use regs::GeneralRegisters;
pub use vender::has_hardware_support;
