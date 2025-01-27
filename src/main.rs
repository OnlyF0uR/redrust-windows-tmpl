use std::{ffi::OsStr, os::windows::ffi::OsStrExt};

use windows::{
    core::{Result, PCWSTR},
    Win32::{
        Foundation::CloseHandle,
        Storage::FileSystem::{
            CreateFileW, WriteFile, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, FILE_GENERIC_WRITE,
            FILE_SHARE_READ,
        },
    },
};

fn main() -> Result<()> {
    let file_name: Vec<u16> = OsStr::new("example.txt")
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let h_file = unsafe {
        CreateFileW(
            PCWSTR(file_name.as_ptr()),
            FILE_GENERIC_WRITE.0,
            FILE_SHARE_READ,
            None,
            CREATE_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            None,
        )?
    };

    let content = "Hello, world!";

    let mut bytes_written = 0;
    unsafe {
        WriteFile(
            h_file,
            Some(content.as_bytes()),
            Some(&mut bytes_written),
            None,
        )?;
    }

    unsafe {
        let _ = CloseHandle(h_file);
    }

    println!("File created and written successfully!");
    Ok(())
}
