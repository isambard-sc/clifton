// SPDX-FileCopyrightText: © 2025 David Llewellyn-Jones <dllewellyn-jones@turing.ac.uk>
// SPDX-License-Identifier: MIT

use std::fmt;
use std::process::Command;

pub struct SshCommand {
    pub proxy_command: bool,
    pub options: Vec<String>,
    pub cert: String,
    pub identity_file: String,
    pub host: String,
}

impl fmt::Display for SshCommand {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        if self.proxy_command {
            fmt.write_str("ProxyCommand=ssh -W %h:%p ")?;
        } else {
            fmt.write_str("ssh ")?;
        }
        for option in self.options.iter() {
            fmt.write_str("-o ")?;
            fmt.write_str(&format!("\"{}\"", option))?;
            fmt.write_str(" ")?;
        }
        fmt.write_str(&format!("-o 'CertificateFile=\"{}\"' ", self.cert))?;
        fmt.write_str(&format!("-i \"{}\" ", self.identity_file).to_string())?;
        fmt.write_str(&self.host.to_string())?;
        Ok(())
    }
}

impl SshCommand {
    pub fn execute(&self) {
        let mut args = Vec::new();
        for option in self.options.iter() {
            args.push("-o".to_string());
            args.push(format!("\"\"{}\"\"", option));
        }

        args.push("-o".to_string());
        args.push(format!("\"\"CertificateFile \"{}\"\"\"", self.cert));

        args.push("-i".to_string());
        args.push(self.identity_file.clone());

        args.push(self.host.clone());

        let child = Command::new("ssh").args(args).spawn();
        match child {
            Ok(mut id) => {
                id.wait().unwrap_or_default();
            }
            Err(err) => {
                eprintln!("Failed to execute process: {}", err)
            }
        }
    }
}
