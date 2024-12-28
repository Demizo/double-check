use std::{collections::HashMap, time::SystemTime};
use std::error::Error;
use std::env;
use chrono::{DateTime, Local};
use clap::{Arg, Command, builder::PathBufValueParser};
use walkdir::WalkDir;

struct FileInfo {
    path: String,
    size: u64,
    modified: SystemTime
}

fn main() -> Result<(), Box<dyn Error>> {
    let arguments = Command::new("Duplicate Finder")
        .version("0.0.1")
        .about("Finds duplicate files")
        .arg(Arg::new("directory")
            .short('d')
            .long("directory")
            .help("The root directory to search from")
            .value_parser(PathBufValueParser::default())
        )
        .get_matches();
    
    let default_dir = env::current_dir()?;
    let directory = arguments.get_one("directory").unwrap_or(&default_dir);

    println!("Searching '{}' for duplicate files...", directory.to_str().unwrap());

    let mut filenames = HashMap::new();
    
    let mut dup_byte_size = 0;
    for file in WalkDir::new(directory)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|e| !e.file_type().is_dir()) {
        let f_name = String::from(file.file_name().to_string_lossy());
        let name_entry = filenames.entry(f_name.clone()).or_insert(Vec::new());
        name_entry.push(FileInfo{path: file.path().to_str().unwrap_or("").into(), size: file.metadata()?.len(), modified: file.metadata()?.modified()?});

        if name_entry.len() == 2 {
            println!("{}:", f_name);
            for file in name_entry {
                let modified_time: DateTime<Local> = file.modified.into();
                println!("- '{}', size: {}, modified: {}", file.path, file.size, modified_time.format("%Y/%m/%d %T"));
                dup_byte_size += file.size;
            }
        }
    }

    println!("{} bytes of duplicate files", dup_byte_size);

    Ok(())
}
