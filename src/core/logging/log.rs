/*
* The MIT License (MIT)

* Copyright (c) 2023-present Artemis Mirai <artemismirai@waifu.club>

* Permission is hereby granted, free of charge, to any person obtaining a
* copy of this software and associated documentation files (the "Software"),
* to deal in the Software without restriction, including without limitation
* the rights to use, copy, modify, merge, publish, distribute, sublicense,
* and/or sell copies of the Software, and to permit persons to whom the
* Software is furnished to do so, subject to the following conditions:

* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.

* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
* OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
* FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
* DEALINGS IN THE SOFTWARE.
*/

// -- imports --
use colored::*;
use std::{
    fmt::Display,
    io::{
        self,
        Read,
        Write,
    },
    process,
};

/// Base styled logs object. Object stores `debug`
/// boolean which dictates whether or not anything should
/// actually be logged to stdout or not.
pub struct Logger {
    debug: bool,
}

// -- core implementation --
impl Logger {
    /// Creates a new `Logger` object based on a
    /// `debug` boolean that determines whether or
    /// not anything should actually be logged.
    pub fn new(debug: bool) -> Self {
        Self { debug }
    }

    /// Writes information to stdout.
    pub fn info<S: Display>(&self, s: S) {
        if self.debug {
            println!("{} {}", "(info)".bright_yellow(), s);
        }
    }

    /// Writes a warn to stdout.
    pub fn warn<S: Display>(&self, s: S) {
        if self.debug {
            println!("{} {}", "(warn)".bright_red(), s);
        }
    }

    /// Writes a fatal log to stdout, then panics. Doesn't
    /// care if the logger is in debug mode or not because
    /// users should always see fatal logs.
    pub fn fatal<S: Display>(&self, s: S) -> ! {
        println!("{} {}", "(FATAL)".red(), s);
        process::exit(1);
    }

    /// Writes a success message to stdout.
    pub fn success<S: Display>(&self, s: S) {
        if self.debug {
            println!("{} {}", "(success)".bright_green(), s);
        }
    }

    /// Gets user input from stdin.
    pub fn input(&self) -> String {
        let mut i = String::new();
        io::stdout()
            .flush()
            .expect("Failed to flush standard output!");
        io::stdin()
            .read_to_string(&mut i)
            .expect("Failed to read input!");

        i.trim().to_string()
    }
}
