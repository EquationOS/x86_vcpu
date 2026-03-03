use alloc::vec;
use alloc::vec::Vec;
use axaddrspace::{GuestPhysAddr, HostPhysAddr};

use x86::segmentation::SegmentSelector;
use x86::{Ring, segmentation, task};
use x86_64::VirtAddr;
use x86_64::instructions::tables::{lgdt, lidt, sidt};
use x86_64::registers::control::{Cr0, Cr0Flags, Cr3, Cr3Flags, Cr4, Cr4Flags, Efer, EferFlags};
use x86_64::structures::DescriptorTablePointer;
use x86_64::{addr::PhysAddr, structures::paging::PhysFrame};

use crate::msr::{Msr, MsrEntry};
use crate::regs::GeneralRegisters;
use crate::segmentation::{Segment, SegmentAccessRights};

use super::pvboot::{
    BOOT_GDT_MAX, BOOT_RFLAGS, BOOT_STACK_POINTER, PML4_START, ZERO_PAGE_START,
    create_boot_msr_entries,
};

const SAVED_LINUX_REGS: usize = 8;

/// Constructor for a conventional segment GDT (or LDT) entry. Derived from the kernel's segment.h.
pub fn gdt_entry(flags: u16, base: u32, limit: u32) -> u64 {
    ((u64::from(base) & 0xff00_0000u64) << (56 - 24))
        | ((u64::from(flags) & 0x0000_f0ffu64) << 40)
        | ((u64::from(limit) & 0x000f_0000u64) << (48 - 16))
        | ((u64::from(base) & 0x00ff_ffffu64) << 16)
        | (u64::from(limit) & 0x0000_ffffu64)
}

/// Unified guest context structure that consolidates:
/// - HostContext: Host Linux state loaded from stack
/// - PVGuestContext: Paravirtualized boot with shared GDT/IDT/TSS
///
/// Different constructor methods are provided to initialize for specific use cases.
#[derive(Debug, Clone)]
pub struct GuestContext {
    // ============ General Purpose Registers ============
    pub rsp: u64,
    pub rip: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rdi: u64,
    pub rflags: u64,

    // Callee-saved registers (for HostContext compatibility)
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub rbx: u64,

    // ============ Segment Registers ============
    pub es: Segment,
    pub cs: Segment,
    pub ss: Segment,
    pub ds: Segment,
    pub fs: Segment,
    pub gs: Segment,
    pub tss: Segment,

    // ============ Descriptor Tables ============
    pub gdt: DescriptorTablePointer,
    pub idt: DescriptorTablePointer,

    // ============ Control Registers ============
    pub cr0: Cr0Flags,
    pub cr3: u64,
    pub cr4: Cr4Flags,

    // ============ Model Specific Registers ============
    pub efer: EferFlags,
    pub star: u64,
    pub lstar: u64,
    pub cstar: u64,
    pub fmask: u64,

    pub ia32_sysenter_cs: u64,
    pub ia32_sysenter_esp: u64,
    pub ia32_sysenter_eip: u64,

    pub kernel_gsbase: u64,
    pub pat: u64,
    pub mtrr_def_type: u64,

    pub msr_entries: Vec<MsrEntry>,

    // ============ FPU State ============
    pub fcw: u16,
    pub mxcsr: u32,

    // ============ Paravirt-specific (optional) ============
    pub eptp_list_region_base: Option<HostPhysAddr>,
    pub hlat_ptr: Option<GuestPhysAddr>,
}

impl Default for GuestContext {
    fn default() -> Self {
        Self {
            rsp: 0,
            rip: 0,
            rbp: 0,
            rsi: 0,
            rdi: 0,
            rflags: 0,
            r15: 0,
            r14: 0,
            r13: 0,
            r12: 0,
            rbx: 0,
            es: Segment::invalid(),
            cs: Segment::invalid(),
            ss: Segment::invalid(),
            ds: Segment::invalid(),
            fs: Segment::invalid(),
            gs: Segment::invalid(),
            tss: Segment::invalid(),
            gdt: DescriptorTablePointer {
                limit: 0,
                base: VirtAddr::zero(),
            },
            idt: DescriptorTablePointer {
                limit: 0,
                base: VirtAddr::zero(),
            },
            cr0: Cr0Flags::empty(),
            cr3: 0,
            cr4: Cr4Flags::empty(),
            efer: EferFlags::empty(),
            star: 0,
            lstar: 0,
            cstar: 0,
            fmask: 0,
            ia32_sysenter_cs: 0,
            ia32_sysenter_esp: 0,
            ia32_sysenter_eip: 0,
            kernel_gsbase: 0,
            pat: 0,
            mtrr_def_type: 0,
            msr_entries: vec![],
            fcw: 0x37f,
            mxcsr: 0x1f80,
            eptp_list_region_base: None,
            hlat_ptr: None,
        }
    }
}

fn sgdt() -> DescriptorTablePointer {
    let mut gdt = DescriptorTablePointer {
        limit: 0,
        base: VirtAddr::zero(),
    };
    unsafe {
        core::arch::asm!("sgdt [{0}]", in(reg) &mut gdt, options(nostack, preserves_flags));
    }
    gdt
}

/// Host-related constructors (HostContext compatibility)
impl GuestContext {
    /// Load context from host Linux stack pointer.
    ///
    /// Reads callee-saved registers from the stack and system registers from hardware.
    ///
    /// Note that this function may be called without heap allocation support.
    pub unsafe fn load_from_stack(linux_sp: usize) -> Self {
        let regs = unsafe { core::slice::from_raw_parts(linux_sp as *const u64, SAVED_LINUX_REGS) };
        let gdt = sgdt();

        let mut fs = Segment::from_selector(x86::segmentation::fs(), &gdt);
        let mut gs = Segment::from_selector(x86::segmentation::gs(), &gdt);
        fs.base = Msr::IA32_FS_BASE.read();
        gs.base = regs[0];

        Self {
            rsp: regs.as_ptr_range().end as _,
            r15: regs[1],
            r14: regs[2],
            r13: regs[3],
            r12: regs[4],
            rbx: regs[5],
            rbp: regs[6],
            rip: regs[7],
            rsi: 0,
            rdi: 0,
            rflags: 0,
            es: Segment::from_selector(segmentation::es(), &gdt),
            cs: Segment::from_selector(segmentation::cs(), &gdt),
            ss: Segment::from_selector(segmentation::ss(), &gdt),
            ds: Segment::from_selector(segmentation::ds(), &gdt),
            fs,
            gs,
            tss: Segment::from_selector(unsafe { task::tr() }, &gdt),
            gdt,
            idt: sidt(),
            cr0: Cr0::read(),
            cr3: Cr3::read().0.start_address().as_u64(),
            cr4: Cr4::read(),
            efer: Efer::read(),
            star: Msr::STAR.read(),
            lstar: Msr::LSTAR.read(),
            cstar: Msr::CSTAR.read(),
            fmask: Msr::SYSCALL_MASK.read(),
            ia32_sysenter_cs: Msr::IA32_SYSENTER_CS.read(),
            ia32_sysenter_esp: Msr::IA32_SYSENTER_ESP.read(),
            ia32_sysenter_eip: Msr::IA32_SYSENTER_EIP.read(),
            kernel_gsbase: Msr::KERNEL_GSBASE.read(),
            pat: Msr::IA32_PAT.read(),
            mtrr_def_type: Msr::MTRR_DEF_TYPE.read(),
            msr_entries: vec![],
            fcw: 0x37f,
            mxcsr: 0x1f80,
            eptp_list_region_base: None,
            hlat_ptr: None,
        }
    }

    /// Restore system registers to host Linux state.
    pub fn restore(&self) {
        unsafe {
            Msr::IA32_SYSENTER_CS.write(self.ia32_sysenter_cs);
            Msr::IA32_SYSENTER_ESP.write(self.ia32_sysenter_esp);
            Msr::IA32_SYSENTER_EIP.write(self.ia32_sysenter_eip);

            Efer::write(self.efer);
            Msr::STAR.write(self.star);
            Msr::LSTAR.write(self.lstar);
            Msr::CSTAR.write(self.cstar);
            Msr::SYSCALL_MASK.write(self.fmask);
            Msr::KERNEL_GSBASE.write(self.kernel_gsbase);
            Msr::IA32_PAT.write(self.pat);

            Cr0::write(self.cr0);
            Cr4::write(self.cr4);
            Cr3::write(
                PhysFrame::containing_address(PhysAddr::new(self.cr3)),
                Cr3Flags::empty(),
            );
        }

        let hv_gdt = sgdt();
        let entry_count = (hv_gdt.limit as usize + 1) / size_of::<u64>();
        let hv_gdt_table: &mut [u64] =
            unsafe { core::slice::from_raw_parts_mut(hv_gdt.base.as_mut_ptr(), entry_count) };

        let linux_gdt = &self.gdt;
        let entry_count = (linux_gdt.limit as usize + 1) / size_of::<u64>();
        let linux_gdt_table =
            unsafe { core::slice::from_raw_parts(linux_gdt.base.as_mut_ptr(), entry_count) };

        let tss_idx = self.tss.selector.index() as usize;
        hv_gdt_table[tss_idx] = linux_gdt_table[tss_idx];
        hv_gdt_table[tss_idx + 1] = linux_gdt_table[tss_idx + 1];

        SegmentAccessRights::set_descriptor_type(
            &mut hv_gdt_table[self.tss.selector.index() as usize],
            SegmentAccessRights::TSS_AVAIL,
        );

        unsafe {
            task::load_tr(self.tss.selector);
            lgdt(&self.gdt);
            lidt(&self.idt);

            segmentation::load_es(self.es.selector);
            segmentation::load_cs(self.cs.selector);
            segmentation::load_ss(self.ss.selector);
            segmentation::load_ds(self.ds.selector);
            segmentation::load_fs(self.fs.selector);
            segmentation::load_gs(self.gs.selector);

            Msr::IA32_FS_BASE.write(self.fs.base);
        }
    }

    /// Restore host Linux general-purpose registers and return to Linux.
    pub fn return_to_linux(&self, guest_regs: &GeneralRegisters) -> ! {
        unsafe {
            Msr::IA32_GS_BASE.write(self.gs.base);
            core::arch::asm!(
                "mov rsp, {linux_rsp}",
                "push {linux_rip}",
                "mov rcx, rsp",
                "mov rsp, {guest_regs}",
                "mov [rsp + {guest_regs_size}], rcx",
                restore_regs_from_stack!(),
                "pop rsp",
                "ret",
                linux_rsp = in(reg) self.rsp,
                linux_rip = in(reg) self.rip,
                guest_regs = in(reg) guest_regs,
                guest_regs_size = const core::mem::size_of::<GeneralRegisters>(),
                options(noreturn),
            );
        }
    }
}

impl GuestContext {
    /// Construct a minimal guest64 context for shim kernel.
    ///
    /// Creates a minimal 64-bit guest context with:
    /// - GDT/IDT base = 0 (minimal configuration)
    /// - Simple segment selectors
    /// - No dependency on guest memory
    ///
    /// It is used to initialize the vCPU context for the shim kernel which enters
    /// under Intel's long mode.
    pub fn construct_minimal_guest64(rip: u64, cr3: u64) -> Self {
        Self {
            rsp: 0,
            rip,
            rbp: 0,
            rsi: 0,
            rdi: 0,
            rflags: BOOT_RFLAGS,
            r15: 0,
            r14: 0,
            r13: 0,
            r12: 0,
            rbx: 0,
            es: Segment::invalid(),
            cs: Segment {
                selector: SegmentSelector::new(2, Ring::Ring0),
                base: 0,
                limit: 0xffff,
                access_rights: SegmentAccessRights::ACCESSED
                    | SegmentAccessRights::WRITABLE
                    | SegmentAccessRights::EXECUTABLE
                    | SegmentAccessRights::CODE_DATA
                    | SegmentAccessRights::PRESENT
                    | SegmentAccessRights::LONG_MODE
                    | SegmentAccessRights::GRANULARITY,
            },
            ss: Segment {
                selector: SegmentSelector::new(0, Ring::Ring0),
                base: 0,
                limit: 0xffff,
                access_rights: SegmentAccessRights::ACCESSED
                    | SegmentAccessRights::WRITABLE
                    | SegmentAccessRights::CODE_DATA
                    | SegmentAccessRights::PRESENT
                    | SegmentAccessRights::DB
                    | SegmentAccessRights::GRANULARITY,
            },
            ds: Segment::invalid(),
            fs: Segment::invalid(),
            gs: Segment::invalid(),
            tss: Segment {
                selector: SegmentSelector::new(0, Ring::Ring0),
                base: 0,
                limit: 0,
                access_rights: SegmentAccessRights::ACCESSED
                    | SegmentAccessRights::WRITABLE
                    | SegmentAccessRights::EXECUTABLE
                    | SegmentAccessRights::PRESENT,
            },
            gdt: DescriptorTablePointer {
                limit: 0,
                base: VirtAddr::zero(),
            },
            idt: DescriptorTablePointer {
                limit: 0,
                base: VirtAddr::zero(),
            },
            cr0: Cr0Flags::PROTECTED_MODE_ENABLE
                | Cr0Flags::MONITOR_COPROCESSOR
                | Cr0Flags::EXTENSION_TYPE
                | Cr0Flags::NUMERIC_ERROR
                | Cr0Flags::WRITE_PROTECT
                | Cr0Flags::ALIGNMENT_MASK
                | Cr0Flags::PAGING,
            cr3,
            cr4: Cr4Flags::PHYSICAL_ADDRESS_EXTENSION
                | Cr4Flags::FSGSBASE
                | Cr4Flags::PAGE_GLOBAL
                | Cr4Flags::OSFXSR
                | Cr4Flags::OSXMMEXCPT_ENABLE
                | Cr4Flags::OSXSAVE,
            efer: EferFlags::LONG_MODE_ENABLE | EferFlags::LONG_MODE_ACTIVE,
            // | EferFlags::NO_EXECUTE_ENABLE
            // | EferFlags::SYSTEM_CALL_EXTENSIONS,
            star: 0,
            lstar: 0,
            cstar: 0,
            fmask: 0,
            ia32_sysenter_cs: 0,
            ia32_sysenter_esp: 0,
            ia32_sysenter_eip: 0,
            kernel_gsbase: 0,
            pat: Msr::IA32_PAT.read(),
            mtrr_def_type: Msr::MTRR_DEF_TYPE.read(),
            msr_entries: vec![],
            fcw: 0x37f,
            mxcsr: 0x1f80,
            eptp_list_region_base: None,
            hlat_ptr: None,
        }
    }
}

/// Guest boot context constructors
impl GuestContext {
    /// Construct a standard Linux 64-bit boot protocol context.
    /// This is equivalent to Linux64BitBootContext::default().
    ///
    /// Sets up the minimal boot environment according to Linux boot protocol:
    /// - Boot GDT at 0x500 with 4 entries
    /// - Boot IDT at 0x520
    /// - Page tables at 0x9000
    pub fn construct_linux64bit_boot() -> Self {
        let gdt_table: [u64; BOOT_GDT_MAX] = [
            gdt_entry(0, 0, 0),            // NULL
            gdt_entry(0xa09b, 0, 0xfffff), // CODE
            gdt_entry(0xc093, 0, 0xfffff), // DATA
            gdt_entry(0x808b, 0, 0xfffff), // TSS
        ];

        let code_seg = Segment::from_raw_entry_value(gdt_table[1], 1);
        let data_seg = Segment::from_raw_entry_value(gdt_table[2], 2);
        let tss_seg = Segment::from_raw_entry_value(gdt_table[3], 3);

        Self {
            rsp: BOOT_STACK_POINTER,
            rip: 0,
            rbp: 0,
            rsi: ZERO_PAGE_START,
            rdi: 0,
            rflags: BOOT_RFLAGS,
            r15: 0,
            r14: 0,
            r13: 0,
            r12: 0,
            rbx: 0,
            es: data_seg.clone(),
            cs: code_seg,
            ss: data_seg.clone(),
            ds: data_seg.clone(),
            fs: data_seg.clone(),
            gs: data_seg,
            tss: tss_seg,
            gdt: DescriptorTablePointer {
                limit: (core::mem::size_of_val(&gdt_table) - 1) as u16,
                base: VirtAddr::new(0x500),
            },
            idt: DescriptorTablePointer {
                limit: (core::mem::size_of::<u64>() - 1) as u16,
                base: VirtAddr::new(0x520),
            },
            cr0: Cr0Flags::PROTECTED_MODE_ENABLE
                | Cr0Flags::EXTENSION_TYPE
                | Cr0Flags::NUMERIC_ERROR
                | Cr0Flags::WRITE_PROTECT
                | Cr0Flags::PAGING,
            cr3: PML4_START,
            cr4: Cr4Flags::PHYSICAL_ADDRESS_EXTENSION,
            efer: EferFlags::LONG_MODE_ENABLE
                | EferFlags::LONG_MODE_ACTIVE
                | EferFlags::SYSTEM_CALL_EXTENSIONS
                | EferFlags::NO_EXECUTE_ENABLE,
            star: 0,
            lstar: 0,
            cstar: 0,
            fmask: 0,
            ia32_sysenter_cs: 0,
            ia32_sysenter_esp: 0,
            ia32_sysenter_eip: 0,
            kernel_gsbase: 0,
            pat: Msr::IA32_PAT.read(),
            mtrr_def_type: Msr::MTRR_DEF_TYPE.read(),
            msr_entries: create_boot_msr_entries(),
            fcw: 0x37f,
            mxcsr: 0x1f80,
            eptp_list_region_base: None,
            hlat_ptr: None,
        }
    }
}

/// Utility methods
impl GuestContext {
    /// Set the entry point (RIP).
    pub fn set_rip(&mut self, rip: u64) {
        self.rip = rip;
    }

    /// Set the page table root (CR3).
    pub fn set_cr3(&mut self, cr3: u64) {
        self.cr3 = cr3;
    }

    /// Set the CPU ID (passed in RDI for paravirt boot).
    pub fn set_cpu_id(&mut self, cpu_id: u64) {
        self.rdi = cpu_id;
    }

    /// Set GS base for per-CPU data.
    pub fn set_gs_base(&mut self, base: u64) {
        self.gs.base = base;
    }

    /// Set the GDT base address.
    pub fn set_gdt_base(&mut self, base: u64) {
        self.gdt.base = VirtAddr::new(base);
    }

    /// Set the IDT base address.
    pub fn set_idt_base(&mut self, base: u64) {
        self.idt.base = VirtAddr::new(base);
    }

    /// Set the TSS base address.
    pub fn set_tss_base(&mut self, base: u64) {
        self.tss.base = base;
    }

    /// Set the EPTP list region base address.
    pub fn set_eptp_list_region_base(&mut self, base: HostPhysAddr) {
        self.eptp_list_region_base = Some(base);
    }

    /// Set the HLATP guest physical address.
    pub fn set_hlat_ptr(&mut self, ptr: GuestPhysAddr) {
        self.hlat_ptr = Some(ptr);
    }

    /// Get the EPTP list region base address if set.
    pub fn eptp_list_region_base(&self) -> Option<HostPhysAddr> {
        self.eptp_list_region_base
    }

    /// Get the HLATP guest physical address if set.
    pub fn hlat_ptr(&self) -> Option<GuestPhysAddr> {
        self.hlat_ptr
    }

    /// Load guest general-purpose registers from GeneralRegisters.
    pub fn load_guest_regs(&mut self, regs: &GeneralRegisters) {
        self.r15 = regs.r15;
        self.r14 = regs.r14;
        self.r13 = regs.r13;
        self.r12 = regs.r12;
        self.rbx = regs.rbx;
        self.rbp = regs.rbp;
    }
}
