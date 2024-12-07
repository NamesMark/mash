use libc::{c_char, execvp, fork, pid_t, waitpid, WEXITSTATUS, WIFEXITED};
use std::ffi::CString;
use std::ptr;

use std::env;
use std::io::{stdin, stdout, Write};
use std::process;

use anyhow::{bail, Result};

const PROMPT: &str = " <3: ";
const BUILTINS: &[(&str, fn(&[&str]) -> Result<()>)] = &[("exit", exit), ("pwd", pwd), ("cd", cd)];

const AND: &str = "&&";

fn main() {
    loop {
        print!("{}", PROMPT);
        stdout().flush().expect("BUG: failed to flush stdout");

        let mut input = String::new();
        match stdin().read_line(&mut input) {
            Ok(_) => {
                let trimd = input.trim();

                if trimd.is_empty() {
                    continue;
                }

                let commands = trimd.split(AND);

                for command in commands {
                    match handle_command(command) {
                        Ok(_) => (),
                        Err(e) => {
                            eprintln!("Command failed: {e}");
                            break;
                        }
                    }
                }
            }
            Err(e) => {
                eprintln!("Error reading input: {}", e);
                break;
            }
        }
    }
}

fn handle_command(command: &str) -> Result<()> {
    let splitd = command.split_ascii_whitespace().collect::<Vec<_>>();
    if splitd.is_empty() {
        return Ok(());
    }

    for (builtin, fun) in BUILTINS {
        if splitd[0].eq_ignore_ascii_case(builtin) {
            return fun(&splitd[1..]);
        }
    }

    handle_external(&splitd[0], &splitd[1..])?;

    Ok(())
}

fn handle_external(program_name: &str, input_args: &[&str]) -> Result<()> {
    let c_args = input_args
        .into_iter()
        .map(|&arg| CString::new(arg).expect("BUG: Failed to make CString"))
        .collect::<Vec<_>>();
    let program = CString::new(program_name).expect("BUG: Failed to make CString");

    // Make args for exevp:
    let mut args: Vec<*const c_char> = vec![program.as_ptr()];
    for c_arg in &c_args {
        args.push(c_arg.as_ptr());
    }
    args.push(ptr::null());

    unsafe {
        // Fork the process
        let pid: pid_t = fork();

        if pid < 0 {
            bail!("Fork failed");
        } else if pid == 0 {
            // In the child
            execvp(program.as_ptr(), args.as_ptr() as *const *const c_char);

            bail!("execvp failed");
        } else {
            // In the parent
            let mut status = 0;
            waitpid(pid, &mut status, 0);

            if WIFEXITED(status) {
                let exit_status = WEXITSTATUS(status);
                match exit_status {
                    0 => (),
                    _ => eprintln!("Child exited with status: {exit_status}"),
                }
                Ok(())
            } else {
                bail!("Child did not exit normally");
            }
        }
    }
}

fn pwd(_: &[&str]) -> Result<()> {
    let pwd = env::current_dir().map(|path| path.display().to_string())?;

    println!("{pwd}");
    Ok(())
}

fn cd(args: &[&str]) -> Result<()> {
    if args.is_empty() {
        bail!("cd: missing argument");
    }
    let path = args[0];
    env::set_current_dir(path)?;
    Ok(())
}

fn exit(_: &[&str]) -> Result<()> {
    println!("Bye!");
    process::exit(0);
}
