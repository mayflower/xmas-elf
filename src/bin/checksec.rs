extern crate xmas_elf;

use std::path::Path;
use std::env;
use std::process;
use xmas_elf::ElfFile;
use xmas_elf::dynamic;
use xmas_elf::sections;

// Note if running on a 32bit system, then reading Elf64 files probably will not
// work (maybe if the size of the file in bytes is < u32::Max).

// Helper function to open a file and read it into a buffer.
// Allocates the buffer.
fn open_file<P: AsRef<Path>>(name: P) -> Vec<u8> {
    use std::fs::File;
    use std::io::Read;

    let mut f = File::open(name).unwrap();
    let mut buf = Vec::new();
    assert!(f.read_to_end(&mut buf).unwrap() > 0);
    buf
}

fn display_binary_information<P: AsRef<Path>>(binary_path: P) {
    let buf = open_file(binary_path);
    let elf_file = ElfFile::new(&buf).unwrap();
    let mut bind_now = false;
    let mut stack_canary = false;
    let mut pie = false;

    let mut sect_iter = elf_file.section_iter();
    // Skip the first (dummy) section
    sect_iter.next();
    for sect in sect_iter {
        bind_now = match sect.get_data(&elf_file) {
            Ok(sections::SectionData::Dynamic64(ds)) => ds.iter().any(
                |d| d.get_tag().map(|t| t == dynamic::Tag::BindNow).unwrap_or(false)
            ),
            _ => bind_now
        };
        pie = match sect.get_data(&elf_file) {
            Ok(sections::SectionData::Dynamic64(ds)) => ds.iter().any(
                |d| d.get_tag().map(
                    |t| t == dynamic::Tag::Flags1 && d.get_val().map(
                        |f| f & dynamic::FLAG_1_PIE != 0x0
                    ).unwrap_or(false)
                ).unwrap_or(false)
            ),
            _ => pie
        };

        stack_canary = match sect.get_data(&elf_file) {
            Ok(sections::SectionData::DynSymbolTable64(st)) => st.iter().any(
                |e| e.get_name(&elf_file).map(|n| n == "__stack_chk_fail").unwrap_or(false)
            ),
            _ => stack_canary
        };
    }

    println!("BIND_NOW: {}", bind_now);
    println!("STACK_CANARY: {}", stack_canary);
    println!("PIE: {}", pie);
}

// TODO make this whole thing more library-like
fn main() {
    let mut args = env::args();
    let program_name = args.next();

    if let Some(binary_path) = args.next() {
        display_binary_information(binary_path);
    } else {
        println!("usage: {} <binary_path>", program_name.unwrap());
        process::exit(1);
    }
}
