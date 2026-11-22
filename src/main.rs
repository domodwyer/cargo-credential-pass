#![allow(clippy::default_constructed_unit_structs)]

//   Copyright 2024 Dominic Dwyer (dom@itsallbroken.com)
//
//   Licensed under the Apache License, Version 2.0 (the "License"); you may not
//   use this file except in compliance with the License. You may obtain a copy
//   of the License at
//
//       http://www.apache.org/licenses/LICENSE-2.0
//
//   Unless required by applicable law or agreed to in writing, software
//   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
//   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
//   License for the specific language governing permissions and limitations
//   under the License.

use clap::CommandFactory;

mod dispatch;
mod pass;

pub fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    let args_str = args.iter().map(|v| v.as_str()).collect::<Vec<_>>();

    // Show credential arg help text if asked.
    if args_str.contains(&"--help") || args_str.contains(&"-h") {
        dispatch::Config::command()
            .print_long_help()
            .expect("cannot print help");
        return;
    }

    match args_str.as_slice() {
        [_, "--cargo-plugin"] => cargo_credential::main(dispatch::Dispatch {}),
        [name, ..] => print_into(Some(name)),
        [..] => print_into(None),
    }
}

fn print_into(name: Option<&str>) {
    eprintln!("Hi there!");
    eprintln!();
    eprintln!(
        "This is a credential helper for cargo that reads registry \
                tokens from the 'pass' secret store."
    );
    eprintln!();
    eprintln!("Configure cargo to use this binary, and then run 'cargo login':");
    eprintln!();
    eprintln!("\thttps://doc.rust-lang.org/cargo/reference/registry-authentication.html");
    eprintln!();
    eprintln!(
        "Run {} --help to see more options.",
        name.unwrap_or("this command with")
    );
    eprintln!();
}
