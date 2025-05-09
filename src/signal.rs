use axhal::{arch::TrapFrame, trap::{register_trap_handler, SIGNAL}};
use axtask::{current,TaskExtRef};

#[register_trap_handler(SIGNAL)]
fn handle_signal(tf: &mut TrapFrame,is_user: bool) -> bool {
    if !is_user {
        trace!("Signal handler called in kernel space");
        return true;
    }
    
    let curr = current();
    let thread = curr.task_ext().thread_data();
    let sig_manager = &thread.sig_manager;

    sig_manager.check_signals(tf, None);
    true
}