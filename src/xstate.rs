use alloc::alloc::{Layout, alloc_zeroed, dealloc, handle_alloc_error};
use core::ptr::{NonNull, copy_nonoverlapping};

use raw_cpuid::CpuId;
use x86::controlregs::{Xcr0, xcr0 as xcr0_read, xcr0_write};
use x86_64::registers::control::{Cr4, Cr4Flags};

use crate::msr::Msr;

pub const XFEATURE_FP: u64 = 1 << 0;
pub const XFEATURE_SSE: u64 = 1 << 1;
pub const XFEATURE_YMM: u64 = 1 << 2;
pub const XFEATURE_BNDREGS: u64 = 1 << 3;
pub const XFEATURE_BNDCSR: u64 = 1 << 4;
pub const XFEATURE_OPMASK: u64 = 1 << 5;
pub const XFEATURE_ZMM_HI256: u64 = 1 << 6;
pub const XFEATURE_HI16_ZMM: u64 = 1 << 7;
pub const XFEATURE_XTILE_CFG: u64 = 1 << 17;
pub const XFEATURE_XTILE_DATA: u64 = 1 << 18;
pub const XFEATURE_XTILE: u64 = XFEATURE_XTILE_CFG | XFEATURE_XTILE_DATA;
pub const XFEATURE_AVX512: u64 = XFEATURE_OPMASK | XFEATURE_ZMM_HI256 | XFEATURE_HI16_ZMM;
pub const XFEATURE_MPX: u64 = XFEATURE_BNDREGS | XFEATURE_BNDCSR;
pub const XFEATURE_REQUIRED: u64 = XFEATURE_FP;

const XSAVE_AREA_ALIGN: usize = 64;
const XSAVE_LEGACY_AREA_SIZE: usize = 512;

pub struct XState {
    host_xcr0: u64,
    pub(crate) guest_xcr0: u64,
    host_xss: u64,
    guest_xss: u64,
    host_xfd: u64,
    guest_xfd: u64,
    host_xfd_err: u64,
    guest_xfd_err: u64,
    supported_xcr0: u64,
    supported_xss: u64,
    supported_xfd: u64,
    host_xsave: Option<XSaveArea>,
    guest_xsave: Option<XSaveArea>,

    xsave_available: bool,
    xsaves_available: bool,
    xfd_available: bool,
}

impl XState {
    /// Create a new [`XState`] instance with current host state
    pub fn new() -> Self {
        // Check if XSAVE is available
        let xsave_available = Self::xsave_available();
        // Check if XSAVES and XRSTORS (as well as IA32_XSS) are available
        let xsaves_available = if xsave_available {
            Self::xsaves_available()
        } else {
            false
        };

        // Read XCR0 iff XSAVE is available
        let xcr0 = if xsave_available {
            unsafe { xcr0_read().bits() }
        } else {
            0
        };
        // Read IA32_XSS iff XSAVES is available
        let xss = if xsaves_available {
            Msr::IA32_XSS.read()
        } else {
            0
        };
        let xfd_available = Self::xfd_available();
        let xfd = if xfd_available {
            Msr::IA32_XFD.read()
        } else {
            0
        };
        let xfd_err = if xfd_available {
            Msr::IA32_XFD_ERR.read()
        } else {
            0
        };
        let (supported_xcr0, supported_xss) = if xsave_available {
            Self::supported_xfeatures()
        } else {
            (0, 0)
        };
        let supported_xfd = if xfd_available {
            supported_xcr0 & XFEATURE_XTILE
        } else {
            0
        };
        let xsave_area_size = if xsave_available {
            Self::xsave_area_size()
        } else {
            0
        };
        let (mut host_xsave, mut guest_xsave) = if xsave_available {
            (
                Some(XSaveArea::new(xsave_area_size)),
                Some(XSaveArea::new(xsave_area_size)),
            )
        } else {
            (None, None)
        };
        let xstate_mask = Self::xstate_mask(xsaves_available, xcr0, xss);
        if let Some(area) = host_xsave.as_mut() {
            unsafe {
                clear_task_switched();
                save_xstate(area.as_mut_ptr(), xstate_mask, xsaves_available);
            }
        }
        if let (Some(host), Some(guest)) = (host_xsave.as_ref(), guest_xsave.as_mut()) {
            unsafe {
                copy_nonoverlapping(host.as_ptr(), guest.as_mut_ptr(), xsave_area_size);
            }
        }

        Self {
            host_xcr0: xcr0,
            guest_xcr0: xcr0,
            host_xss: xss,
            guest_xss: xss,
            host_xfd: xfd,
            guest_xfd: xfd,
            host_xfd_err: xfd_err,
            guest_xfd_err: xfd_err,
            supported_xcr0,
            supported_xss,
            supported_xfd,
            host_xsave,
            guest_xsave,
            xsave_available,
            xsaves_available,
            xfd_available,
        }
    }

    /// Enable extended processor state management instructions, including XGETBV and XSAVE.
    pub fn enable_xsave() {
        if Self::xsave_available() {
            unsafe { Cr4::write(Cr4::read() | Cr4Flags::OSXSAVE) };
        }
    }

    /// Check if XSAVE is available on the current CPU.
    pub fn xsave_available() -> bool {
        let cpuid = CpuId::new();
        cpuid
            .get_feature_info()
            .map(|f| f.has_xsave())
            .unwrap_or(false)
    }

    /// Check if XSAVES and XRSTORS (as well as IA32_XSS) are available on the current CPU.
    pub fn xsaves_available() -> bool {
        let cpuid = CpuId::new();
        cpuid
            .get_extended_state_info()
            .map(|f| f.has_xsaves_xrstors())
            .unwrap_or(false)
    }

    pub fn xfd_available() -> bool {
        raw_cpuid_count(0x0d, 1).eax & (1 << 4) != 0
    }

    fn supported_xfeatures() -> (u64, u64) {
        let xcr0_res = raw_cpuid_count(0x0d, 0);
        let xss_res = raw_cpuid_count(0x0d, 1);
        let xcr0 = xcr0_res.eax as u64 | ((xcr0_res.edx as u64) << 32);
        let xss = xss_res.ecx as u64 | ((xss_res.edx as u64) << 32);
        (xcr0, xss)
    }

    fn xsave_area_size() -> usize {
        let standard = raw_cpuid_count(0x0d, 0);
        let compacted = raw_cpuid_count(0x0d, 1);
        (standard.ecx as usize)
            .max(standard.ebx as usize)
            .max(compacted.ebx as usize)
            .max(XSAVE_LEGACY_AREA_SIZE)
    }

    fn xstate_mask(xsaves_available: bool, xcr0: u64, xss: u64) -> u64 {
        if xsaves_available { xcr0 | xss } else { xcr0 }
    }

    pub fn is_xcr0_supported(&self, xcr0: u64) -> bool {
        (xcr0 & !self.supported_xcr0) == 0
    }

    pub fn is_xss_supported(&self, xss: u64) -> bool {
        (xss & !self.supported_xss) == 0
    }

    pub fn is_xfd_supported(&self, xfd: u64) -> bool {
        (xfd & !self.supported_xfd) == 0
    }

    pub fn validate_xcr0(xcr0: u64) -> bool {
        if (xcr0 & XFEATURE_REQUIRED) != XFEATURE_REQUIRED {
            return false;
        }
        if (xcr0 & XFEATURE_YMM) != 0 && (xcr0 & XFEATURE_SSE) == 0 {
            return false;
        }
        let mpx = xcr0 & XFEATURE_MPX;
        if mpx != 0 && mpx != XFEATURE_MPX {
            return false;
        }
        let avx512 = xcr0 & XFEATURE_AVX512;
        if avx512 != 0 && ((xcr0 & XFEATURE_YMM) == 0 || avx512 != XFEATURE_AVX512) {
            return false;
        }
        let xtile = xcr0 & XFEATURE_XTILE;
        if xtile != 0 && xtile != XFEATURE_XTILE {
            return false;
        }
        true
    }

    pub fn set_guest_xcr0(&mut self, xcr0: u64) {
        self.guest_xcr0 = xcr0;
    }

    pub fn set_guest_xss(&mut self, xss: u64) {
        self.guest_xss = xss;
    }

    pub fn guest_xss(&self) -> u64 {
        self.guest_xss
    }

    pub fn set_guest_xfd(&mut self, xfd: u64) {
        self.guest_xfd = xfd;
    }

    pub fn guest_xfd(&self) -> u64 {
        self.guest_xfd
    }

    pub fn set_guest_xfd_err(&mut self, xfd_err: u64) {
        self.guest_xfd_err = xfd_err;
    }

    pub fn guest_xfd_err(&self) -> u64 {
        self.guest_xfd_err
    }

    /// Save the current host XCR0 and IA32_XSS values and load the guest values.
    #[allow(unused)]
    pub fn switch_to_guest(&mut self) {
        unsafe {
            if self.xsave_available {
                self.host_xcr0 = xcr0_read().bits();
                if self.xsaves_available {
                    self.host_xss = Msr::IA32_XSS.read();
                }
                if self.xfd_available {
                    self.host_xfd = Msr::IA32_XFD.read();
                    self.host_xfd_err = Msr::IA32_XFD_ERR.read();
                }

                let host_xstate_mask =
                    Self::xstate_mask(self.xsaves_available, self.host_xcr0, self.host_xss);
                if let Some(area) = self.host_xsave.as_mut() {
                    clear_task_switched();
                    save_xstate(area.as_mut_ptr(), host_xstate_mask, self.xsaves_available);
                }

                if self.xsaves_available {
                    Msr::IA32_XSS.write(self.guest_xss);
                }
                xcr0_write(Xcr0::from_bits_unchecked(self.guest_xcr0));
                let guest_xstate_mask =
                    Self::xstate_mask(self.xsaves_available, self.guest_xcr0, self.guest_xss);
                if let Some(area) = self.guest_xsave.as_mut() {
                    restore_xstate(area.as_ptr(), guest_xstate_mask, self.xsaves_available);
                }
                if self.xfd_available {
                    Msr::IA32_XFD.write(self.guest_xfd);
                    Msr::IA32_XFD_ERR.write(self.guest_xfd_err);
                }
            }
        }
    }

    /// Save the current guest XCR0 and IA32_XSS values and load the host values.
    #[allow(unused)]
    pub fn switch_to_host(&mut self) {
        unsafe {
            if self.xsave_available {
                self.guest_xcr0 = xcr0_read().bits();
                if self.xsaves_available {
                    self.guest_xss = Msr::IA32_XSS.read();
                }
                if self.xfd_available {
                    self.guest_xfd = Msr::IA32_XFD.read();
                    self.guest_xfd_err = Msr::IA32_XFD_ERR.read();
                }

                let guest_xstate_mask =
                    Self::xstate_mask(self.xsaves_available, self.guest_xcr0, self.guest_xss);
                if let Some(area) = self.guest_xsave.as_mut() {
                    clear_task_switched();
                    save_xstate(area.as_mut_ptr(), guest_xstate_mask, self.xsaves_available);
                }

                if self.xsaves_available {
                    Msr::IA32_XSS.write(self.host_xss);
                }
                xcr0_write(Xcr0::from_bits_unchecked(self.host_xcr0));
                let host_xstate_mask =
                    Self::xstate_mask(self.xsaves_available, self.host_xcr0, self.host_xss);
                if let Some(area) = self.host_xsave.as_mut() {
                    restore_xstate(area.as_ptr(), host_xstate_mask, self.xsaves_available);
                }
                if self.xfd_available {
                    Msr::IA32_XFD.write(self.host_xfd);
                    Msr::IA32_XFD_ERR.write(self.host_xfd_err);
                }
            }
        }
    }
}

struct XSaveArea {
    ptr: NonNull<u8>,
    layout: Layout,
}

impl XSaveArea {
    fn new(size: usize) -> Self {
        let layout = Layout::from_size_align(size, XSAVE_AREA_ALIGN).unwrap();
        let ptr = unsafe { alloc_zeroed(layout) };
        let ptr = NonNull::new(ptr).unwrap_or_else(|| handle_alloc_error(layout));
        Self { ptr, layout }
    }

    fn as_ptr(&self) -> *const u8 {
        self.ptr.as_ptr()
    }

    fn as_mut_ptr(&mut self) -> *mut u8 {
        self.ptr.as_ptr()
    }
}

impl Drop for XSaveArea {
    fn drop(&mut self) {
        unsafe {
            dealloc(self.ptr.as_ptr(), self.layout);
        }
    }
}

unsafe fn clear_task_switched() {
    unsafe {
        core::arch::asm!("clts", options(nostack, preserves_flags));
    }
}

unsafe fn save_xstate(ptr: *mut u8, mask: u64, xsaves_available: bool) {
    unsafe {
        if xsaves_available {
            xsaves64(ptr, mask);
        } else {
            xsave64(ptr, mask);
        }
    }
}

unsafe fn restore_xstate(ptr: *const u8, mask: u64, xsaves_available: bool) {
    unsafe {
        if xsaves_available {
            xrstors64(ptr, mask);
        } else {
            xrstor64(ptr, mask);
        }
    }
}

unsafe fn xsave64(ptr: *mut u8, mask: u64) {
    unsafe {
        core::arch::asm!(
            "xsave64 [{}]",
            in(reg) ptr,
            in("eax") mask as u32,
            in("edx") (mask >> 32) as u32,
            options(nostack)
        );
    }
}

unsafe fn xrstor64(ptr: *const u8, mask: u64) {
    unsafe {
        core::arch::asm!(
            "xrstor64 [{}]",
            in(reg) ptr,
            in("eax") mask as u32,
            in("edx") (mask >> 32) as u32,
            options(nostack)
        );
    }
}

unsafe fn xsaves64(ptr: *mut u8, mask: u64) {
    unsafe {
        core::arch::asm!(
            "xsaves64 [{}]",
            in(reg) ptr,
            in("eax") mask as u32,
            in("edx") (mask >> 32) as u32,
            options(nostack)
        );
    }
}

unsafe fn xrstors64(ptr: *const u8, mask: u64) {
    unsafe {
        core::arch::asm!(
            "xrstors64 [{}]",
            in(reg) ptr,
            in("eax") mask as u32,
            in("edx") (mask >> 32) as u32,
            options(nostack)
        );
    }
}

struct RawCpuidResult {
    eax: u32,
    ebx: u32,
    ecx: u32,
    edx: u32,
}

fn raw_cpuid_count(leaf: u32, sub_leaf: u32) -> RawCpuidResult {
    let res = unsafe { core::arch::x86_64::__cpuid_count(leaf, sub_leaf) };
    RawCpuidResult {
        eax: res.eax,
        ebx: res.ebx,
        ecx: res.ecx,
        edx: res.edx,
    }
}
