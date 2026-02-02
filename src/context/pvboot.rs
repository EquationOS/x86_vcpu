//! Boot context definitions for x86_64 virtual machines.
//!
//! This module provides two types of boot contexts:
//! - `Linux64BitBootContext`: Standard Linux 64-bit boot protocol context
//! - `ParavirtBootContext`: Paravirtualized boot context with shared GDT/IDT/TSS
//!
//! The paravirt context is designed for fast guest switching using VMFUNC EPTP switching.

use alloc::vec;
use alloc::vec::Vec;
use axaddrspace::{GuestPhysAddr, HostPhysAddr};
use core::mem;

use x86::Ring;
use x86::segmentation::SegmentSelector;
use x86_64::VirtAddr;
use x86_64::registers::control::{Cr0Flags, Cr4Flags, EferFlags};
use x86_64::structures::DescriptorTablePointer;

use crate::generated::msr_index::*;
use crate::msr::Msr;
use crate::segmentation::{Segment, SegmentAccessRights};

// ============================================================================
// Standard Linux 64-bit Boot Protocol Constants
// ============================================================================

const SAVED_LINUX_REGS: usize = 8;

const BOOT_RFLAGS: u64 = 0x0000_0000_0000_0002u64;
/// Initial stack for the boot CPU.
const BOOT_STACK_POINTER: u64 = 0x8ff0;

/// The 'zero page', a.k.a linux kernel bootparams.
const ZERO_PAGE_START: u64 = 0x7000;

const BOOT_GDT_OFFSET: u64 = 0x500;
const BOOT_IDT_OFFSET: u64 = 0x520;

const BOOT_GDT_MAX: usize = 4;

const EFER_LMA: u64 = 0x400;
const EFER_LME: u64 = 0x100;

const X86_CR0_PE: u64 = 0x1;
const X86_CR0_ET: u64 = 0x10;
const X86_CR0_PG: u64 = 0x8000_0000;
const X86_CR4_PAE: u64 = 0x20;

// Initial pagetables.
const PML4_START: u64 = 0x9000;

// ============================================================================
// Paravirt Boot Protocol Constants
// ============================================================================

/// Magic number for paravirt shared info validation: "AXPV" in little-endian
pub const PV_SHARED_INFO_MAGIC: u32 = 0x5650_5841;

/// Version of the paravirt shared info structure
pub const PV_SHARED_INFO_VERSION: u32 = 1;

/// Guest physical address of the paravirt shared info structure
pub const PV_SHARED_INFO_GPA: u64 = 0x0001_0000;

/// Guest physical address of the shared GDT
pub const PV_SHARED_GDT_GPA: u64 = 0x0001_1000;

/// Guest physical address of the shared IDT
pub const PV_SHARED_IDT_GPA: u64 = 0x0001_2000;

/// Guest physical address of the per-guest TSS
pub const PV_SHARED_TSS_GPA: u64 = 0x0001_3000;

/// Linux kernel's __KERNEL_CS selector (GDT entry 2)
pub const KERNEL_CS: u16 = 0x10;

/// Linux kernel's __KERNEL_DS selector (GDT entry 3)
pub const KERNEL_DS: u16 = 0x18;

/// Linux kernel's __KERNEL32_CS selector (GDT entry 1)
pub const KERNEL32_CS: u16 = 0x08;

/// Linux kernel's __USER32_CS selector (GDT entry 4 + RPL 3)
pub const USER32_CS: u16 = 0x23;

/// Linux kernel's __USER_DS selector (GDT entry 5 + RPL 3)
pub const USER_DS: u16 = 0x2b;

/// Linux kernel's __USER_CS selector (GDT entry 6 + RPL 3)
pub const USER_CS: u16 = 0x33;

/// TSS selector (GDT entry 8)
pub const TSS_SELECTOR: u16 = 0x40;

/// Maximum number of GDT entries in Linux's final GDT
pub const LINUX_GDT_ENTRIES: usize = 16;

/// EPTP index for MicroVM Gate
pub const GATE_EPTP_INDEX: u32 = 0;

/// EPTP index for the first Linux instance
pub const LINUX_EPTP_INDEX_BASE: u32 = 1;

#[derive(Clone)]
pub struct Linux64BitBootContext {
    // General purpose registers
    pub rsp: u64,
    pub rip: u64,
    pub rbp: u64,
    pub rsi: u64,
    pub rflags: u64,

    // Segment registers
    pub es: Segment,
    pub cs: Segment,
    pub ss: Segment,
    pub ds: Segment,
    pub fs: Segment,
    pub gs: Segment,
    pub tss: Segment,
    // Descriptor tables
    pub gdt: DescriptorTablePointer,
    pub idt: DescriptorTablePointer,

    // Control registers & special registers
    pub cr0: Cr0Flags,
    pub cr3: u64,
    pub cr4: Cr4Flags,
    pub efer: EferFlags,

    // Model specific registers
    pub msr_entries: Vec<MsrEntry>,

    // Floating-Point Unit (FPU) registers
    pub fcw: u16,
    pub mxcsr: u32,
}

impl core::fmt::Debug for Linux64BitBootContext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        writeln!(f, "Linux64BitBootContext {{")?;
        writeln!(f, "  rsp: {:#x}", self.rsp)?;
        writeln!(f, "  rip: {:#x}", self.rip)?;
        writeln!(f, "  rbp: {:#x}", self.rbp)?;
        writeln!(f, "  rsi: {:#x}", self.rsi)?;
        writeln!(f, "  rflags: {:#x}", self.rflags)?;
        writeln!(f, "  cs: {}", self.cs)?;
        writeln!(f, "  ds: {}", self.ds)?;
        writeln!(f, "  es: {}", self.es)?;
        writeln!(f, "  fs: {}", self.fs)?;
        writeln!(f, "  gs: {}", self.gs)?;
        writeln!(f, "  ss: {}", self.ss)?;
        writeln!(f, "  tss: {}", self.tss)?;
        writeln!(f, "  gdt: {:?}", self.gdt)?;
        writeln!(f, "  idt: {:?}", self.idt)?;
        writeln!(f, "  cr0: {:#x} {:?}", self.cr0.bits(), self.cr0)?;
        writeln!(f, "  cr3: {:#x}", self.cr3)?;
        writeln!(f, "  cr4: {:?}", self.cr4)?;
        writeln!(f, "  efer: {:?}", self.efer)?;
        writeln!(f, "  msr_entries: {:?}", self.msr_entries)?;
        writeln!(f, "  fcw: {:#x}", self.fcw)?;
        writeln!(f, "  mxcsr: {:#x}", self.mxcsr)?;
        writeln!(f, "}}")
    }
}

/// Constructor for a conventional segment GDT (or LDT) entry. Derived from the kernel's segment.h.
pub fn gdt_entry(flags: u16, base: u32, limit: u32) -> u64 {
    ((u64::from(base) & 0xff00_0000u64) << (56 - 24))
        | ((u64::from(flags) & 0x0000_f0ffu64) << 40)
        | ((u64::from(limit) & 0x000f_0000u64) << (48 - 16))
        | ((u64::from(base) & 0x00ff_ffffu64) << 16)
        | (u64::from(limit) & 0x0000_ffffu64)
}

impl Default for Linux64BitBootContext {
    fn default() -> Self {
        let gdt_table: [u64; BOOT_GDT_MAX] =
            // Configure GDT entries as specified by Linux 64bit boot protocol
            [
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
            rbp: BOOT_STACK_POINTER,
            rsi: ZERO_PAGE_START,
            rflags: BOOT_RFLAGS,
            cs: code_seg,
            ds: data_seg,
            es: data_seg,
            fs: data_seg,
            gs: data_seg,
            ss: data_seg,
            tss: tss_seg,
            gdt: DescriptorTablePointer {
                limit: u16::try_from(mem::size_of_val(&gdt_table)).unwrap() - 1,
                base: VirtAddr::new(BOOT_GDT_OFFSET),
            },
            idt: DescriptorTablePointer {
                limit: u16::try_from(mem::size_of::<u64>()).unwrap() - 1,
                base: VirtAddr::new(BOOT_IDT_OFFSET),
            },
            cr0: Cr0Flags::EXTENSION_TYPE
                | Cr0Flags::PROTECTED_MODE_ENABLE
                | Cr0Flags::PAGING
                | Cr0Flags::NOT_WRITE_THROUGH
                | Cr0Flags::CACHE_DISABLE,
            cr3: PML4_START,
            cr4: Cr4Flags::PHYSICAL_ADDRESS_EXTENSION,
            efer: EferFlags::LONG_MODE_ENABLE | EferFlags::LONG_MODE_ACTIVE,
            msr_entries: create_boot_msr_entries(),
            fcw: 0x37f,
            mxcsr: 0x1f80,
        }
    }
}

impl Linux64BitBootContext {
    pub fn set_rip(&mut self, rip: u64) {
        self.rip = rip;
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct MsrEntry {
    pub index: Msr,
    pub data: u64,
}

/// Creates and populates required MSR entries for booting Linux on X86_64.
pub fn create_boot_msr_entries() -> Vec<MsrEntry> {
    let msr_entry_default = |msr| MsrEntry {
        index: msr,
        data: 0x0,
    };

    vec![
        msr_entry_default(Msr::IA32_SYSENTER_CS),
        msr_entry_default(Msr::IA32_SYSENTER_ESP),
        msr_entry_default(Msr::IA32_SYSENTER_EIP),
        // x86_64 specific msrs, we only run on x86_64 not x86.
        msr_entry_default(Msr::STAR),
        msr_entry_default(Msr::CSTAR),
        msr_entry_default(Msr::KERNEL_GSBASE),
        msr_entry_default(Msr::SYSCALL_MASK),
        msr_entry_default(Msr::LSTAR),
        // end of x86_64 specific code
        msr_entry_default(Msr::IA32_TSC),
        MsrEntry {
            index: Msr::IA32_MISC_ENABLE,
            data: u64::from(MSR_IA32_MISC_ENABLE_FAST_STRING),
        },
        // set default memory type for physical memory outside configured
        // memory ranges to write-back by setting MTRR enable bit (11) and
        // setting memory type to write-back (value 6).
        // https://wiki.osdev.org/MTRR
        MsrEntry {
            index: Msr::MTRR_DEF_TYPE,
            data: (1 << 11) | 0x6,
        },
    ]
}

// ============================================================================
// Paravirt Boot Context
// ============================================================================

/// Linux kernel's final GDT layout.
/// This matches the gdt_page definition in arch/x86/kernel/cpu/common.c.
///
/// Entry layout (x86_64):
/// - 0: NULL descriptor
/// - 1: KERNEL32_CS (32-bit kernel code)
/// - 2: KERNEL_CS (64-bit kernel code) - __KERNEL_CS = 0x10
/// - 3: KERNEL_DS (kernel data) - __KERNEL_DS = 0x18
/// - 4: USER32_CS (32-bit user code)
/// - 5: USER_DS (user data)
/// - 6: USER_CS (64-bit user code)
/// - 7: Reserved
/// - 8-9: TSS (128-bit system segment)
/// - 10-11: LDT (128-bit system segment)
/// - 12-14: TLS segments
/// - 15: CPUNODE
pub fn create_linux_final_gdt() -> [u64; LINUX_GDT_ENTRIES] {
    [
        gdt_entry(0, 0, 0),            // 0: NULL
        gdt_entry(0xcf9b, 0, 0xfffff), // 1: KERNEL32_CS (32-bit code)
        gdt_entry(0xaf9b, 0, 0xfffff), // 2: KERNEL_CS (64-bit code)
        gdt_entry(0xcf93, 0, 0xfffff), // 3: KERNEL_DS (data)
        gdt_entry(0xcffb, 0, 0xfffff), // 4: USER32_CS (32-bit user code)
        gdt_entry(0xcff3, 0, 0xfffff), // 5: USER_DS (user data)
        gdt_entry(0xaffb, 0, 0xfffff), // 6: USER_CS (64-bit user code)
        0,                             // 7: Reserved
        0,
        0, // 8-9: TSS (filled at runtime)
        0,
        0, // 10-11: LDT
        0,
        0,
        0, // 12-14: TLS
        0, // 15: CPUNODE
    ]
}

/// Create a 64-bit TSS descriptor.
/// TSS descriptors are 128-bit (two GDT entries) in long mode.
///
/// # Arguments
/// * `base` - Base address of the TSS structure
/// * `limit` - Size of the TSS minus 1
///
/// # Returns
/// A tuple of (low 64 bits, high 64 bits) for the TSS descriptor
pub fn create_tss_descriptor(base: u64, limit: u32) -> (u64, u64) {
    // TSS descriptor type: 0x89 (64-bit TSS, available)
    let type_attr: u64 = 0x89;
    let present: u64 = 1 << 47;

    let low = (limit as u64 & 0xFFFF)
        | ((base & 0xFFFFFF) << 16)
        | (type_attr << 40)
        | present
        | (((limit as u64 >> 16) & 0xF) << 48)
        | ((base & 0xFF00_0000) << 32);

    let high = base >> 32;

    (low, high)
}

/// Per-vCPU information shared between Gate and Linux.
/// This structure is used for communication about vCPU state.
/// Size: 64 bytes (cache-line aligned for performance)
#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct PvVcpuInfo {
    /// vCPU state (see PV_VCPU_STATE_* constants)
    pub state: u32,
    /// Pending events bitmap
    pub pending_events: u32,
    /// GS base register value (per-CPU data pointer)
    pub gs_base: u64,
    /// FS base register value (TLS pointer)
    pub fs_base: u64,
    /// Kernel GS base (for swapgs)
    pub kernel_gs_base: u64,
    /// Reserved for future use (padding to 64 bytes)
    pub _reserved: [u64; 4],
}

/// vCPU state: offline
pub const PV_VCPU_STATE_OFFLINE: u32 = 0;
/// vCPU state: online and ready to run
pub const PV_VCPU_STATE_ONLINE: u32 = 1;
/// vCPU state: currently running
pub const PV_VCPU_STATE_RUNNING: u32 = 2;
/// vCPU state: idle (no tasks)
pub const PV_VCPU_STATE_IDLE: u32 = 3;
/// vCPU state: parked (yielded CPU)
pub const PV_VCPU_STATE_PARKED: u32 = 4;

/// Shared information structure between Gate and Linux guests.
/// This structure is placed at a fixed guest physical address (PV_SHARED_INFO_GPA).
///
/// The Gate initializes this structure before switching to Linux.
/// Linux reads from it to get configuration and writes to it to communicate with Gate.
#[repr(C)]
#[derive(Debug, Clone)]
pub struct PvSharedInfo {
    /// Magic number for validation: PV_SHARED_INFO_MAGIC ("AXPV")
    pub magic: u32,
    /// Version of this structure: PV_SHARED_INFO_VERSION
    pub version: u32,
    /// Maximum number of vCPUs configured for this guest
    pub max_vcpus: u32,
    /// Currently online vCPUs
    pub online_vcpus: u32,

    /// EPTP index for this Linux guest (in EPTP list)
    pub guest_eptp_index: u32,
    /// EPTP index for MicroVM Gate (for returning to Gate)
    pub gate_eptp_index: u32,

    /// Flags (see PV_SHARED_FLAG_* constants)
    pub flags: u32,
    /// Reserved for alignment
    pub _reserved1: u32,

    /// Guest virtual address of the shared GDT
    pub gdt_vaddr: u64,
    /// Guest virtual address of the shared IDT
    pub idt_vaddr: u64,
    /// Guest virtual address of the per-guest TSS
    pub tss_vaddr: u64,
    /// Guest physical address of boot_params (zero page)
    pub boot_params_gpa: u64,

    /// Linux kernel entry point virtual address
    pub linux_entry: u64,
    /// Linux CR3 (page table root physical address)
    pub linux_cr3: u64,
    /// Linux initial stack pointer
    pub linux_rsp: u64,
    /// Linux kernel command line physical address
    pub cmdline_gpa: u64,

    /// Per-vCPU information array
    pub vcpu_info: [PvVcpuInfo; 32],

    /// Reserved space for future extensions
    pub _reserved2: [u64; 32],
}

/// Flag: Gate has finished initialization
pub const PV_SHARED_FLAG_GATE_READY: u32 = 1 << 0;
/// Flag: Linux should skip GDT initialization
pub const PV_SHARED_FLAG_SKIP_GDT_INIT: u32 = 1 << 1;
/// Flag: Linux should skip IDT initialization
pub const PV_SHARED_FLAG_SKIP_IDT_INIT: u32 = 1 << 2;
/// Flag: Linux should skip TSS initialization
pub const PV_SHARED_FLAG_SKIP_TSS_INIT: u32 = 1 << 3;
/// Flag: Linux should skip LAPIC initialization
pub const PV_SHARED_FLAG_SKIP_LAPIC_INIT: u32 = 1 << 4;

impl Default for PvSharedInfo {
    fn default() -> Self {
        Self {
            magic: PV_SHARED_INFO_MAGIC,
            version: PV_SHARED_INFO_VERSION,
            max_vcpus: 1,
            online_vcpus: 0,
            guest_eptp_index: LINUX_EPTP_INDEX_BASE,
            gate_eptp_index: GATE_EPTP_INDEX,
            flags: PV_SHARED_FLAG_SKIP_GDT_INIT
                | PV_SHARED_FLAG_SKIP_IDT_INIT
                | PV_SHARED_FLAG_SKIP_TSS_INIT,
            _reserved1: 0,
            gdt_vaddr: 0,
            idt_vaddr: 0,
            tss_vaddr: 0,
            boot_params_gpa: ZERO_PAGE_START,
            linux_entry: 0,
            linux_cr3: 0,
            linux_rsp: 0,
            cmdline_gpa: 0x20000,
            vcpu_info: [PvVcpuInfo::default(); 32],
            _reserved2: [0; 32],
        }
    }
}

impl PvSharedInfo {
    /// Validate the magic number and version.
    pub fn is_valid(&self) -> bool {
        self.magic == PV_SHARED_INFO_MAGIC && self.version == PV_SHARED_INFO_VERSION
    }

    /// Check if a specific flag is set.
    pub fn has_flag(&self, flag: u32) -> bool {
        self.flags & flag != 0
    }

    /// Set a flag.
    pub fn set_flag(&mut self, flag: u32) {
        self.flags |= flag;
    }

    /// Clear a flag.
    pub fn clear_flag(&mut self, flag: u32) {
        self.flags &= !flag;
    }
}

/// Paravirtualized boot context.
///
/// Unlike `Linux64BitBootContext` which uses the standard boot protocol GDT layout,
/// this context directly sets up Linux's final GDT/IDT/TSS layout. This allows:
///
/// 1. Multiple guests to share the same GDT/IDT
/// 2. Fast guest switching without re-initializing segment descriptors
/// 3. Simplified Linux boot path (skip GDT/IDT/TSS initialization)
///
/// The key difference from standard boot protocol:
/// - Boot protocol: CS=0x10 (entry 2 = 64-bit code), needs Linux to reload GDT
/// - Paravirt: CS=0x10 matches Linux's __KERNEL_CS, no GDT reload needed
#[derive(Clone)]
pub struct ParavirtBootContext {
    // ============ General Purpose Registers ============
    pub rsp: u64,
    pub rip: u64,
    pub rbp: u64,
    pub rsi: u64, // Pointer to boot_params
    pub rdi: u64, // CPU ID (for AP boot)
    pub rflags: u64,

    // ============ Segment Registers (Linux final layout) ============
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
    pub efer: EferFlags,

    // ============ MSRs ============
    pub msr_entries: Vec<MsrEntry>,

    // ============ FPU State ============
    pub fcw: u16,
    pub mxcsr: u32,

    // ============ Paravirt-specific ============
    /// per-vCPU EPTP list region base address.
    pub eptp_list_region_base: HostPhysAddr,
    /// Guest physical address of HLATP.
    pub hlat_ptr: GuestPhysAddr,
}

impl core::fmt::Debug for ParavirtBootContext {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        writeln!(f, "ParavirtBootContext {{")?;
        writeln!(f, "  rsp: {:#x}", self.rsp)?;
        writeln!(f, "  rip: {:#x}", self.rip)?;
        writeln!(f, "  rbp: {:#x}", self.rbp)?;
        writeln!(f, "  rsi: {:#x} (boot_params)", self.rsi)?;
        writeln!(f, "  rdi: {:#x} (cpu_id)", self.rdi)?;
        writeln!(f, "  rflags: {:#x}", self.rflags)?;
        writeln!(f, "  cs: {} (selector={:#x})", self.cs, self.cs.selector)?;
        writeln!(f, "  ds: {} (selector={:#x})", self.ds, self.ds.selector)?;
        writeln!(f, "  ss: {} (selector={:#x})", self.ss, self.ss.selector)?;
        writeln!(
            f,
            "  gdt: base={:#x}, limit={:#x}",
            self.gdt.base.as_u64(),
            self.gdt.limit
        )?;
        writeln!(
            f,
            "  idt: base={:#x}, limit={:#x}",
            self.idt.base.as_u64(),
            self.idt.limit
        )?;
        writeln!(f, "  cr0: {:#x} {:?}", self.cr0.bits(), self.cr0)?;
        writeln!(f, "  cr3: {:#x}", self.cr3)?;
        writeln!(f, "  cr4: {:?}", self.cr4)?;
        writeln!(f, "  efer: {:?}", self.efer)?;
        writeln!(
            f,
            "  eptp_list_region_base: {:?}",
            self.eptp_list_region_base
        )?;
        writeln!(f, "  hlat_ptr: {:?}", self.hlat_ptr)?;
        writeln!(f, "}}")
    }
}

impl Default for ParavirtBootContext {
    fn default() -> Self {
        // Create Linux's final GDT
        let gdt_table = create_linux_final_gdt();

        // Create segment descriptors using Linux's final selector values
        let code_seg = Segment::from_raw_entry_value(gdt_table[2], 2); // KERNEL_CS = 0x10
        let data_seg = Segment::from_raw_entry_value(gdt_table[3], 3); // KERNEL_DS = 0x18

        // TSS segment (will be properly initialized by Gate)
        // TSS selector = 0x40 = entry 8 in GDT
        let tss_seg = Segment {
            selector: SegmentSelector::new(8, Ring::Ring0),
            base: PV_SHARED_TSS_GPA,
            limit: 0x67, // Minimum TSS size
            access_rights: SegmentAccessRights::from_bits_truncate(0x8b), // 64-bit TSS
        };

        Self {
            rsp: BOOT_STACK_POINTER,
            rip: 0,
            rbp: 0,
            rsi: ZERO_PAGE_START, // boot_params pointer
            rdi: 0,               // CPU ID
            rflags: BOOT_RFLAGS,

            // Use Linux's final segment layout
            cs: code_seg,
            ds: data_seg.clone(),
            es: data_seg.clone(),
            fs: Segment {
                selector: SegmentSelector::from_raw(0),
                base: 0,
                limit: 0,
                access_rights: SegmentAccessRights::from_bits_truncate(0x10000), // Unusable
            },
            gs: Segment {
                selector: SegmentSelector::from_raw(0),
                base: 0,
                limit: 0,
                access_rights: SegmentAccessRights::from_bits_truncate(0x10000), // Unusable
            },
            ss: data_seg,
            tss: tss_seg,

            gdt: DescriptorTablePointer {
                limit: (LINUX_GDT_ENTRIES * 8 - 1) as u16,
                base: VirtAddr::new(PV_SHARED_GDT_GPA),
            },
            idt: DescriptorTablePointer {
                limit: 256 * 16 - 1, // 256 entries, 16 bytes each
                base: VirtAddr::new(PV_SHARED_IDT_GPA),
            },

            // Control registers with optimal settings
            cr0: Cr0Flags::PROTECTED_MODE_ENABLE
                | Cr0Flags::EXTENSION_TYPE
                | Cr0Flags::NUMERIC_ERROR
                | Cr0Flags::WRITE_PROTECT
                | Cr0Flags::PAGING,
            cr3: PML4_START,
            cr4: Cr4Flags::PHYSICAL_ADDRESS_EXTENSION
                | Cr4Flags::OSFXSR
                | Cr4Flags::OSXMMEXCPT_ENABLE
                | Cr4Flags::PAGE_GLOBAL,
            efer: EferFlags::LONG_MODE_ENABLE
                | EferFlags::LONG_MODE_ACTIVE
                | EferFlags::SYSTEM_CALL_EXTENSIONS
                | EferFlags::NO_EXECUTE_ENABLE,

            msr_entries: create_paravirt_msr_entries(),

            fcw: 0x37f,
            mxcsr: 0x1f80,

            eptp_list_region_base: HostPhysAddr::from_usize(0x0),
            hlat_ptr: GuestPhysAddr::from_usize(0x0),
        }
    }
}

impl ParavirtBootContext {
    /// Set the entry point (RIP).
    pub fn set_rip(&mut self, rip: u64) {
        self.rip = rip;
    }

    /// Set the page table root (CR3).
    pub fn set_cr3(&mut self, cr3: u64) {
        self.cr3 = cr3;
    }

    /// Set the CPU ID (passed in RDI).
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
        self.eptp_list_region_base = base;
    }

    /// Set the HLATP guest physical address.
    pub fn set_hlat_ptr(&mut self, ptr: GuestPhysAddr) {
        self.hlat_ptr = ptr;
    }
}

/// Creates MSR entries for paravirt boot.
/// Includes SYSCALL/SYSRET configuration that Linux expects.
pub fn create_paravirt_msr_entries() -> Vec<MsrEntry> {
    let msr_entry_default = |msr| MsrEntry {
        index: msr,
        data: 0x0,
    };

    vec![
        // SYSENTER MSRs (may not be used in 64-bit mode but Linux still initializes them)
        msr_entry_default(Msr::IA32_SYSENTER_CS),
        msr_entry_default(Msr::IA32_SYSENTER_ESP),
        msr_entry_default(Msr::IA32_SYSENTER_EIP),
        // SYSCALL/SYSRET MSRs
        MsrEntry {
            index: Msr::STAR,
            // STAR[47:32] = SYSRET CS selector (USER32_CS)
            // STAR[31:16] = SYSCALL CS selector (KERNEL_CS)
            data: ((USER32_CS as u64) << 48) | ((KERNEL_CS as u64) << 32),
        },
        msr_entry_default(Msr::LSTAR), // SYSCALL target address (set by Linux)
        msr_entry_default(Msr::CSTAR), // Compat SYSCALL target (set by Linux)
        MsrEntry {
            index: Msr::SYSCALL_MASK,
            // Flags to clear on syscall
            data: 0x4700, // Clear TF, IF, DF, AC, NT
        },
        // Kernel GS base (used with swapgs)
        msr_entry_default(Msr::KERNEL_GSBASE),
        // TSC
        msr_entry_default(Msr::IA32_TSC),
        // Misc enable
        MsrEntry {
            index: Msr::IA32_MISC_ENABLE,
            data: u64::from(MSR_IA32_MISC_ENABLE_FAST_STRING),
        },
        // MTRR default type: write-back
        MsrEntry {
            index: Msr::MTRR_DEF_TYPE,
            data: (1 << 11) | 0x6,
        },
    ]
}
