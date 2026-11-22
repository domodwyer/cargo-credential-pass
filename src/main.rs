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

mod dispatch;
mod pass;

pub fn main() {
    let args = std::env::args().collect::<Vec<_>>();
    let args_str = args.iter().map(|v| v.as_str()).collect::<Vec<_>>();

    match args_str.as_slice() {
        [_, "--cargo-plugin"] => cargo_credential::main(dispatch::Dispatch {}),
        _ => print_help(),
    }
}

fn print_help() {
    eprintln!("Hi there!");
    eprintln!();
    eprintln!(
        "This is a credential helper for cargo that reads registry \
                tokens from the 'pass' secret store."
    );
    eprintln!();
    eprintln!(
        "Configure cargo to use this binary, and then run 'cargo login \
        --token <mytoken>' to initialise it:"
    );
    eprintln!();
    eprintln!("\thttps://doc.rust-lang.org/cargo/reference/registry-authentication.html");
    eprintln!();
}
