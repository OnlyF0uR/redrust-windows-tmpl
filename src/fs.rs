use std::{ffi::OsStr, os::windows::ffi::OsStrExt};

use windows::{
    core::{Result, PCWSTR},
    Win32::{
        Foundation::{CloseHandle, GENERIC_READ},
        Storage::FileSystem::{
            CreateFileW, GetFileSizeEx, ReadFile, WriteFile, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
            FILE_FLAG_SEQUENTIAL_SCAN, FILE_GENERIC_WRITE, FILE_SHARE_READ, OPEN_EXISTING,
        },
    },
};

pub fn cw_file(path: &str, content: &[u8]) -> Result<()> {
    let file_name: Vec<u16> = OsStr::new(path)
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

    let mut bytes_written = 0;
    unsafe {
        WriteFile(h_file, Some(content), Some(&mut bytes_written), None)?;
    }

    unsafe {
        CloseHandle(h_file)?;
    }

    println!("File created and written successfully!");
    Ok(())
}

pub fn r_file(path: &str) -> Result<Vec<u8>> {
    let file_name: Vec<u16> = OsStr::new(path)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect();

    let h_file = unsafe {
        CreateFileW(
            PCWSTR(file_name.as_ptr()),
            GENERIC_READ.0,
            FILE_SHARE_READ,
            None,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
            None,
        )?
    };

    let mut file_size = 0i64;
    unsafe {
        GetFileSizeEx(h_file, &mut file_size)?;
    }

    let mut buffer = vec![0u8; file_size as usize];
    let mut bytes_read = 0u32;

    unsafe {
        ReadFile(
            h_file,
            Some(buffer.as_mut_slice()),
            Some(&mut bytes_read),
            None,
        )?;
    }

    unsafe {
        CloseHandle(h_file)?;
    }

    buffer.truncate(bytes_read as usize);
    Ok(buffer)
}
