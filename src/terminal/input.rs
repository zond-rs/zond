use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyModifiers},
    terminal::{disable_raw_mode, enable_raw_mode},
};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use tracing::warn;
use zond_engine::core::handle::ScanHandle;

pub struct InputGuard {
    running: Arc<AtomicBool>,
}

impl Drop for InputGuard {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        let _ = disable_raw_mode();
    }
}

/// Starts a background thread that listens for raw terminal input.
/// Returns an `InputGuard` that disables raw mode when dropped.
pub fn start_listener(handle: ScanHandle) -> InputGuard {
    if let Err(e) = enable_raw_mode() {
        warn!("Failed to enable raw terminal mode: {}", e);
    }

    let running = Arc::new(AtomicBool::new(true));
    let running_clone = running.clone();

    std::thread::spawn(move || {
        while running_clone.load(Ordering::Relaxed) {
            if event::poll(std::time::Duration::from_millis(50)).unwrap_or(false) {
                if let Ok(Event::Key(KeyEvent {
                    code, modifiers, ..
                })) = event::read()
                {
                    match code {
                        KeyCode::Char('q') | KeyCode::Char('Q') => {
                            handle.abort();
                            break;
                        }
                        KeyCode::Char('c') if modifiers.contains(KeyModifiers::CONTROL) => {
                            handle.abort();
                            break;
                        }
                        KeyCode::Esc => {
                            handle.abort();
                            break;
                        }
                        _ => {}
                    }
                }
            }
        }

        let _ = disable_raw_mode();
    });

    InputGuard { running }
}
