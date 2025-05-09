//! User task management.

use core::{
    alloc::Layout,
    cell::RefCell,
    sync::atomic::{AtomicUsize, Ordering}, time::Duration,
};

use alloc::{
    string::String,
    sync::{Arc, Weak},
};
use axerrno::{LinuxError, LinuxResult};
use axhal::{
    arch::UspaceContext,
    time::{NANOS_PER_MICROS, NANOS_PER_SEC, monotonic_time_nanos},
};
use axmm::{AddrSpace, kernel_aspace};
use axns::{AxNamespace, AxNamespaceIf};
use axprocess::{Pid, Process, ProcessGroup, Session, Thread};
use axsignal::api::{ProcessSignalManager, SignalActions, ThreadSignalManager, WaitQueue};
use axsync::{Mutex, RawMutex};
use axtask::{current, TaskExtRef, TaskInner};
use memory_addr::VirtAddrRange;
use spin::{Once, RwLock};
use weak_map::WeakMap;
use axsignal::SignalActionFlags;

use crate::time::TimeStat;

/// Create a new user task.
pub fn new_user_task(
    name: &str,
    uctx: UspaceContext,
    set_child_tid: Option<&'static mut Pid>,
) -> TaskInner {
    TaskInner::new(
        move || {
            let curr = axtask::current();
            if let Some(tid) = set_child_tid {
                *tid = curr.id().as_u64() as Pid;
            }

            let kstack_top = curr.kernel_stack_top().unwrap();
            info!(
                "Enter user space: entry={:#x}, ustack={:#x}, kstack={:#x}",
                uctx.ip(),
                uctx.sp(),
                kstack_top,
            );
            unsafe { uctx.enter_uspace(kstack_top) }
        },
        name.into(),
        axconfig::plat::KERNEL_STACK_SIZE,
    )
}

/// Task extended data for the monolithic kernel.
pub struct TaskExt {
    /// The time statistics
    pub time: RefCell<TimeStat>,
    /// The thread
    pub thread: Arc<Thread>,
}

impl TaskExt {
    /// Create a new [`TaskExt`].
    pub fn new(thread: Arc<Thread>) -> Self {
        Self {
            time: RefCell::new(TimeStat::new()),
            thread,
        }
    }

    pub(crate) fn time_stat_from_kernel_to_user(&self, current_tick: usize) {
        self.time.borrow_mut().switch_into_user_mode(current_tick);
    }

    pub(crate) fn time_stat_from_user_to_kernel(&self, current_tick: usize) {
        self.time.borrow_mut().switch_into_kernel_mode(current_tick);
    }

    pub(crate) fn time_stat_output(&self) -> (usize, usize) {
        self.time.borrow().output()
    }

    /// Get the [`ThreadData`] associated with this task.
    pub fn thread_data(&self) -> &ThreadData {
        self.thread.data().unwrap()
    }

    /// Get the [`ProcessData`] associated with this task.
    pub fn process_data(&self) -> &ProcessData {
        self.thread.process().data().unwrap()
    }
}

axtask::def_task_ext!(TaskExt);

/// Update the time statistics to reflect a switch from kernel mode to user mode.
pub fn time_stat_from_kernel_to_user() {
    let curr_task = current();
    curr_task
        .task_ext()
        .time_stat_from_kernel_to_user(monotonic_time_nanos() as usize);
}

/// Update the time statistics to reflect a switch from user mode to kernel mode.
pub fn time_stat_from_user_to_kernel() {
    let curr_task = current();
    curr_task
        .task_ext()
        .time_stat_from_user_to_kernel(monotonic_time_nanos() as usize);
}

/// Get the time statistics for the current task.
pub fn time_stat_output() -> (usize, usize, usize, usize) {
    let curr_task = current();
    let (utime_ns, stime_ns) = curr_task.task_ext().time_stat_output();
    (
        utime_ns / NANOS_PER_SEC as usize,
        utime_ns / NANOS_PER_MICROS as usize,
        stime_ns / NANOS_PER_SEC as usize,
        stime_ns / NANOS_PER_MICROS as usize,
    )
}

/// Extended data for [`Thread`].
pub struct ThreadData {
    /// The clear thread tid field
    ///
    /// See <https://manpages.debian.org/unstable/manpages-dev/set_tid_address.2.en.html#clear_child_tid>
    ///
    /// When the thread exits, the kernel clears the word at this address if it is not NULL.
    pub clear_child_tid: AtomicUsize,
    /// the thread signal manager
    pub sig_manager: Arc<ThreadSignalManager<RawMutex, MyWaitQueue>>,
}

impl ThreadData {
    /// Create a new [`ThreadData`].
    #[allow(clippy::new_without_default)]
    pub fn new(proc: Arc<ProcessSignalManager<RawMutex, MyWaitQueue>>) -> Self {
        Self {
            clear_child_tid: AtomicUsize::new(0),
            sig_manager: Arc::new(ThreadSignalManager::new(proc)),
        }
    }

    /// Get the clear child tid field.
    pub fn clear_child_tid(&self) -> usize {
        self.clear_child_tid.load(Ordering::Relaxed)
    }

    /// Set the clear child tid field.
    pub fn set_clear_child_tid(&self, clear_child_tid: usize) {
        self.clear_child_tid
            .store(clear_child_tid, Ordering::Relaxed);
    }
}

/// A Signal axsignal::api::WaitQueue implementation for the process.
#[derive(Default)]
pub struct MyWaitQueue {
    // 使用一个内部的原子计数器来标记是否有通知
    inner: AtomicUsize,
}

impl WaitQueue for MyWaitQueue {
    /// Waits for a notification, with an optional timeout.
    ///
    /// Returns `true` if a notification came, `false` if the timeout expired.
    fn wait_timeout(&self, timeout: Option<Duration>) -> bool {
        // 当前值
        let current = self.inner.load(Ordering::Relaxed);
        
        // 设置等待的起始时间
        let start_time = axhal::time::wall_time();
        
        loop {
            // 检查是否有新通知（值是否改变）
            let now = self.inner.load(Ordering::Acquire);
            if now != current {
                return true; // 收到通知
            }
            
            // 检查是否超时
            if let Some(timeout) = timeout {
                let elapsed = axhal::time::wall_time().saturating_sub(start_time);
                if elapsed >= timeout {
                    return false; // 超时
                }
                
                // 短暂休眠以减少 CPU 使用
                axtask::yield_now();
            } else {
                // 无超时，继续等待
                axtask::yield_now();
            }
        }
    }

    /// Waits for a notification.
    fn wait(&self) {
        self.wait_timeout(None);
    }

    /// Notifies a waiting thread.
    ///
    /// Returns `true` if a thread was notified.
    fn notify_one(&self) -> bool {
        // 增加计数器值，确保所有等待的线程都能观察到变化
        self.inner.fetch_add(1, Ordering::Release);
        
        // 由于无法确定是否真正唤醒了线程，总是返回 true
        // 这是一个简化的实现
        true
    }

    /// Notifies all waiting threads.
    fn notify_all(&self) {
        while self.notify_one() {}
    }
}

/// Extended data for [`Process`].
pub struct ProcessData {
    /// The executable path
    pub exe_path: RwLock<String>,
    /// The virtual memory address space.
    pub aspace: Arc<Mutex<AddrSpace>>,
    /// The resource namespace
    pub ns: AxNamespace,
    /// The user heap bottom
    heap_bottom: AtomicUsize,
    /// The user heap top
    heap_top: AtomicUsize,
    /// 进程信号管理器
    pub sig_manager: Arc<ProcessSignalManager<RawMutex, MyWaitQueue>>
}

impl ProcessData {
    /// Create a new [`ProcessData`].
    pub fn new(exe_path: String, aspace: Arc<Mutex<AddrSpace>>) -> Self {
        let actions = Arc::new(Mutex::new(SignalActions::default()));
        // 默认恢复函数地址，根据你的需求设置合适的值
        let default_restorer = SignalActionFlags::RESTORER.bits() as usize;
        Self {
            exe_path: RwLock::new(exe_path),
            aspace,
            ns: AxNamespace::new_thread_local(),
            heap_bottom: AtomicUsize::new(axconfig::plat::USER_HEAP_BASE),
            heap_top: AtomicUsize::new(axconfig::plat::USER_HEAP_BASE),
            sig_manager: Arc::new(ProcessSignalManager::new(actions, default_restorer)),
        }
    }

    /// Get the bottom address of the user heap.
    pub fn get_heap_bottom(&self) -> usize {
        self.heap_bottom.load(Ordering::Acquire)
    }

    /// Set the bottom address of the user heap.
    pub fn set_heap_bottom(&self, bottom: usize) {
        self.heap_bottom.store(bottom, Ordering::Release)
    }

    /// Get the top address of the user heap.
    pub fn get_heap_top(&self) -> usize {
        self.heap_top.load(Ordering::Acquire)
    }

    /// Set the top address of the user heap.
    pub fn set_heap_top(&self, top: usize) {
        self.heap_top.store(top, Ordering::Release)
    }
}

impl Drop for ProcessData {
    fn drop(&mut self) {
        if !cfg!(target_arch = "aarch64") && !cfg!(target_arch = "loongarch64") {
            // See [`crate::new_user_aspace`]
            let kernel = kernel_aspace().lock();
            self.aspace
                .lock()
                .clear_mappings(VirtAddrRange::from_start_size(kernel.base(), kernel.size()));
        }
    }
}

struct AxNamespaceImpl;
#[crate_interface::impl_interface]
impl AxNamespaceIf for AxNamespaceImpl {
    fn current_namespace_base() -> *mut u8 {
        // Namespace for kernel task
        static KERNEL_NS_BASE: Once<usize> = Once::new();
        let current = axtask::current();
        // Safety: We only check whether the task extended data is null and do not access it.
        if unsafe { current.task_ext_ptr() }.is_null() {
            return *(KERNEL_NS_BASE.call_once(|| {
                let global_ns = AxNamespace::global();
                let layout = Layout::from_size_align(global_ns.size(), 64).unwrap();
                // Safety: The global namespace is a static readonly variable and will not be dropped.
                let dst = unsafe { alloc::alloc::alloc(layout) };
                let src = global_ns.base();
                unsafe { core::ptr::copy_nonoverlapping(src, dst, global_ns.size()) };
                dst as usize
            })) as *mut u8;
        }
        current.task_ext().process_data().ns.base()
    }
}

static THREAD_TABLE: RwLock<WeakMap<Pid, Weak<Thread>>> = RwLock::new(WeakMap::new());
static PROCESS_TABLE: RwLock<WeakMap<Pid, Weak<Process>>> = RwLock::new(WeakMap::new());
static PROCESS_GROUP_TABLE: RwLock<WeakMap<Pid, Weak<ProcessGroup>>> = RwLock::new(WeakMap::new());
static SESSION_TABLE: RwLock<WeakMap<Pid, Weak<Session>>> = RwLock::new(WeakMap::new());

/// Add the thread and possibly its process, process group and session to the
/// corresponding tables.
pub fn add_thread_to_table(thread: &Arc<Thread>) {
    let mut thread_table = THREAD_TABLE.write();
    thread_table.insert(thread.tid(), thread);

    let mut process_table = PROCESS_TABLE.write();
    let process = thread.process();
    if process_table.contains_key(&process.pid()) {
        return;
    }
    process_table.insert(process.pid(), process);

    let mut process_group_table = PROCESS_GROUP_TABLE.write();
    let process_group = process.group();
    if process_group_table.contains_key(&process_group.pgid()) {
        return;
    }
    process_group_table.insert(process_group.pgid(), &process_group);

    let mut session_table = SESSION_TABLE.write();
    let session = process_group.session();
    if session_table.contains_key(&session.sid()) {
        return;
    }
    session_table.insert(session.sid(), &session);
}

/// 根据tid获取线程
pub fn get_thread(tid: Pid) -> LinuxResult<Arc<Thread>> {
    THREAD_TABLE.read().get(&tid).ok_or(LinuxError::ESRCH)
}
/// 根据pid获取进程
pub fn get_process(pid: Pid) -> LinuxResult<Arc<Process>> {
    PROCESS_TABLE.read().get(&pid).ok_or(LinuxError::ESRCH)
}
/// 根据pgid获取进程组
pub fn get_process_group(pgid: Pid) -> LinuxResult<Arc<ProcessGroup>> {
    PROCESS_GROUP_TABLE
        .read()
        .get(&pgid)
        .ok_or(LinuxError::ESRCH)
}
/// 根据sid获取会话
pub fn get_session(sid: Pid) -> LinuxResult<Arc<Session>> {
    SESSION_TABLE.read().get(&sid).ok_or(LinuxError::ESRCH)
}
