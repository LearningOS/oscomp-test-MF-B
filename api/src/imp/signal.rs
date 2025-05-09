
use core::time::Duration;

use axerrno::LinuxError;
use axerrno::LinuxResult;
use axprocess::Pid;
use axsignal::SignalAction;
use axsignal::SignalInfo;
use axsignal::SignalSet;
use axsignal::Signo::{self, SIGKILL, SIGSTOP};
use axtask::current;
use axtask::TaskExtRef;
use linux_raw_sys::general::kernel_sigaction;
use linux_raw_sys::general::SIG_BLOCK;
use linux_raw_sys::general::SIG_SETMASK;
use linux_raw_sys::general::SIG_UNBLOCK;
use starry_core::task::get_process;
use starry_core::task::ProcessData;

use crate::ptr::PtrWrapper;
use crate::ptr::{UserConstPtr, UserPtr};

fn check_sigset_size(size: usize) -> LinuxResult<()> {
    if size != size_of::<SignalSet>() {
        return Err(LinuxError::EINVAL);
    }
    Ok(())
}

pub fn sys_rt_sigprocmask(
    how: i32,
    set: UserConstPtr<SignalSet>,
    oldset: UserPtr<SignalSet>,
    sigsetsize: usize,
) -> LinuxResult<isize> {
    info!("sys_rt_sigprocmask");

    check_sigset_size(sigsetsize)?;

    let current_task = current();
    let sig_manager = &current_task.task_ext().thread_data().sig_manager;

    // 如果 oldset 不为 NULL，将当前信号掩码保存到 oldset 指向的位置
    if let Err(e) = oldset.nullable(|oldset| {
        let old_ptr = oldset.get()?;
        unsafe { old_ptr.write(sig_manager.blocked()) };
        Ok(())
    }) {
        return Err(e);
    }

    // 如果 set 为 NULL，只返回旧的掩码而不修改当前掩码
    if let Some(mut new_set) = set.nullable(|set| {
        let ptr = set.get()?;
        Ok(unsafe { ptr.read() })
    })? {
        new_set.remove(Signo::SIGKILL);
        new_set.remove(Signo::SIGSTOP);
        match how as u32 {
            SIG_BLOCK => {
                sig_manager.with_blocked_mut(|mask| {
                    // SIG_BLOCK: 将指定信号添加到当前信号掩码
                    *mask |= new_set;
                });
            }
            SIG_UNBLOCK => {
                // SIG_UNBLOCK: 从当前信号掩码中移除指定信号
                sig_manager.with_blocked_mut(|mask| {
                    mask.dequeue(&new_set);
                });
            }
            SIG_SETMASK => {
                // SIG_SETMASK: 直接设置新的信号掩码
                sig_manager.with_blocked_mut(|mask| {
                    *mask = new_set;
                });
            }
            _ => return Err(axerrno::LinuxError::EINVAL),
        }
    }
    
    Ok(0)
}

pub fn sys_rt_sigaction(
    signum: i32,
    act: UserConstPtr<SignalAction>,
    oldact: UserPtr<kernel_sigaction>,
    sigsetsize: usize,
) -> LinuxResult<isize> {
    info!("sys_rt_sigaction");
    check_sigset_size(sigsetsize)?;

    let signo = Signo::from_repr(signum as u8).ok_or(LinuxError::EINVAL)?;

    if signo == SIGKILL || signo == SIGSTOP {
        return Err(LinuxError::EINVAL);
    }

    let current = current();
    let process = current.task_ext().process_data();
    let mut process_sig_manager = process.sig_manager.actions.lock();

    if let Ok(Some(mut oldact)) = oldact.nullable(|oldact| {
        let ptr = oldact.get()?;
        unsafe { Ok(ptr.read()) }
    }){
        // 如果 oldact 不为 NULL，将旧的信号处理函数保存到 oldact 指向的位置
        let sig_action = &process_sig_manager[signo];
        sig_action.to_ctype(&mut oldact);
    };

    if let Ok(Some(new_action)) = act.nullable(|act| {
        let ptr = act.get()?;
        unsafe { Ok(ptr.read()) }
    }) {
        // 如果 act 不为 NULL，设置新的信号处理函数
        process_sig_manager[signo] = new_action;
    };
    
    Ok(0)
}

pub fn sys_kill(
    pid: i32,
    sig: i32,
) -> LinuxResult<isize> {
    info!("sys_kill: pid: {}, sig: {}", pid, sig);
    if sig as usize == 0 {
        return Ok(0);
    }

    let signo = match Signo::from_repr(sig as u8) {
        Some(s) => s,
        None => return Err(LinuxError::EINVAL), // 无效的信号
    };

    let sig_info = SignalInfo::new(signo, 0);

    let current = current();
    let thread = &current.task_ext().thread;

    match pid {
        1.. => {
            let process = get_process(pid as Pid)?;
            let sig_manager = &process.data::<ProcessData>().unwrap().sig_manager;
            sig_manager.send_signal(sig_info.clone());
        }
        0 => {
            // 向当前进程组发送信号
            let proc_grop = thread.process().group();
            proc_grop.processes().iter().for_each(|process| {
                let sig_manager = &process.data::<ProcessData>().unwrap().sig_manager;
                sig_manager.send_signal(sig_info.clone());
            });
        }
        -1 => {
            // 向所有进程发送信号
            todo!()
        }
        _ => {
            // 向
            todo!()
        }
        
    }

    Ok(0)
}

pub fn sys_rt_sigtimedwait(
    set: UserConstPtr<SignalSet>,
    info: UserPtr<SignalInfo>,
    timeout: UserConstPtr<Duration>,
    sigsetsize: usize,
) -> LinuxResult<isize> {
    info!("sys_rt_sigtimedwait");
    check_sigset_size(sigsetsize)?;

    // 获取当前线程的信号管理器
    let current = current();
    let sig_manager = &current.task_ext().thread_data().sig_manager;

    // 获取等待的信号集
    let wait_set = match set.nullable(|set| {
        let ptr = set.get()?;
        unsafe { Ok(ptr.read()) }
    })? {
        Some(s) => s,
        None => return Err(LinuxError::EINVAL), // 信号集不能为NULL
    };

    // 获取超时时间，如果提供
    let timeout_duration = timeout.nullable(|timeout| {
        let ptr = timeout.get()?;
        unsafe { Ok(ptr.read()) }
    })?;

    // 等待信号，根据是否有超时参数决定调用方式
    // let received_signal = sig_manager.wait_timeout(wait_set, timeout_duration);
    
    // match received_signal {
    //     Some(signal_info) => {
    //         // 收到信号，将信号信息写入提供的缓冲区
    //         if let Err(e) = info.nullable(|info_ptr| {
    //             if let Ok(ptr) = info_ptr.get() {
    //                 unsafe { ptr.write(signal_info.clone()) };
    //             }
    //             Ok(())
    //         }) {
    //             return Err(e);
    //         }
            
    //         // 返回收到的信号编号
    //         Ok(signal_info.signo() as isize)
    //     },
    //     None => {
    //         // 超时或被中断
    //         Err(LinuxError::EAGAIN)
    //     }
    // }
    Ok(0)
}

