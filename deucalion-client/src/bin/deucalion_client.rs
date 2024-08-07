use anyhow::{format_err, Result};

use log::{error, info};

use simplelog::{LevelFilter, SimpleLogger};

use tokio::runtime::Runtime;

use deucalion_client::{process, subscriber::BroadcastFilter, subscriber::Subscriber};

use clap::Parser;

use std::fs;

#[derive(Parser, Debug)]
#[command(about, long_about = None)]
struct Args {
    #[arg(default_value = "deucalion.dll", help = "Path to Deucalion DLL")]
    payload: String,

    #[arg(
        short,
        long,
        help = "Specify a different target exe to inject into. e.g. notepad.exe"
    )]
    target_exe: Option<String>,

    #[arg(
        short,
        long,
        help = "Call LoadLibrary even if the target is already injected."
    )]
    force: bool,

    #[arg(
        short,
        long,
        help = "Attempt to eject Deucalion from the target process. MAY CRASH GAME IF DEUCALION IS STILL RUNNING."
    )]
    eject: bool,

    #[arg(
        short,
        long,
        help = "Specify the PID to target."
    )]
    pid: Option<usize>,

    #[arg(
        short,
        long,
        help = "Enable debug output."
    )]
    debug: bool,

    #[arg(
        short,
        long,
        help = "Run in background after injection."
    )]
    daemonize: bool,

    #[arg(
        long,
        help = "Inject DLL into all found processes."
    )]
    inject_all: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.debug {
        SimpleLogger::init(LevelFilter::Debug, simplelog::Config::default())?;
    } else {
        SimpleLogger::init(LevelFilter::Info, simplelog::Config::default())?;
    }

    let payload_path = std::path::Path::new(&args.payload);

    let target_name = match &args.target_exe {
        Some(target) => target.clone(),
        None => "ffxiv_dx11.exe".into(),
    };

    let pids = process::find_all_pids_by_name(&target_name);

    if pids.is_empty() {
        let pid_file_pattern = format!("deucalion_client_{}_", target_name);
        for entry in std::fs::read_dir(".")? {
            let entry = entry?;
            let file_name = entry.file_name();
            if file_name.to_string_lossy().starts_with(&pid_file_pattern) {
                std::fs::remove_file(entry.path())?;
            }
        }
        return Err(format_err!("Cannot find instance of {}", target_name));
    }

    if args.inject_all {
        for pid in pids {
            inject_and_run(pid, &args, payload_path, &mut handles)?;
        }
    } else {
        let pid = if let Some(pid) = args.pid {
            pid
        } else {
            match pids.len() {
                1 => pids[0],
                _ => {
                    info!("Found multiple instances of {}: {:?}. Selecting first one.", target_name, pids);
                    pids[0]
                }
            }
        };
        inject_and_run(pid, &args, payload_path, &mut handles)?;
    }
    
    for handle in handles {
        handle.join().expect("Failed to join thread");
    }
    
    Ok(())
}

fn inject_and_run(pid: usize, args: &Args, payload_path: &std::path::Path, handles: &mut Vec<JoinHandle<()>>) -> Result<()> {
    let target_exe = args.target_exe.as_deref().unwrap_or("ffxiv_dx11.exe");
    let pid_file = format!("deucalion_client_{}_{}.run", target_exe, pid);

    if args.eject {
        info!("Ejecting Deucalion from {}", pid);
        process::eject_dll(pid, payload_path)?;
        fs::remove_file(&pid_file)?;
        return Ok(());
    }

    info!("Injecting Deucalion into {}", pid);

    if !payload_path.exists() {
        return Err(format_err!("Payload {} not found!", payload_path.display()));
    }

    process::copy_current_process_dacl_to_target(pid)?;
    process::inject_dll(pid, payload_path, args.force)?;

    fs::write(&pid_file, b"")?;
    
    if args.daemonize {

        info!("Running in background.");
        let pid_file = pid_file.clone();
        let debug = args.debug;
        std::thread::spawn(move || {
            run_subscriber(pid, &pid_file, debug);
        });
    } else {
        run_subscriber(pid, &pid_file, args.debug);
    }

    Ok(())
}

fn run_subscriber(pid: usize, pid_file: &str, debug: bool) {
    let subscriber = Subscriber::new();

    let pipe_name = format!(r"\\.\pipe\deucalion-{}", pid as usize);

    let rt = Runtime::new().unwrap();

    rt.block_on(async move {
        if let Err(e) = subscriber
            .listen_forever(
                &pipe_name,
                BroadcastFilter::AllowZoneRecv as u32 | BroadcastFilter::AllowZoneSend as u32,
                move |payload: deucalion::rpc::Payload| {
                    if debug {
                        println!(
                            "OP {:?}, CTX {}, DATA {:?}",
                            payload.op, payload.ctx, payload.data
                        );
                    }
                    Ok(())
                },
            )
            .await
        {
            error!("Error connecting to Deucalion: {e}");
        }
        if let Err(e) = fs::remove_file(pid_file) {
            error!("Failed to remove PID file: {}", e);
        }
    });
}
