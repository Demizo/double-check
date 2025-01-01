use chrono::{DateTime, Local};
use clap::ArgAction;
use clap::{builder::PathBufValueParser, Arg, Command};
use crc::{Crc, CRC_32_ISO_HDLC};
use glob::Pattern;
use std::collections::HashMap;
use std::error::Error;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::num::ParseIntError;
use std::process::exit;
use std::{env, fs};
use walkdir::{DirEntry, WalkDir};

const CHECK_SIZE: i64 = 100000;

enum UserChoice {
    KEEP(Vec<u64>),
    SKIP,
    CHECK,
    INVALID,
    EXIT,
}

fn delete_files(files: &Vec<DirEntry>, delete_indices: Vec<u64>, use_trash: bool) {
    for index in delete_indices {
        let file = files.get(index as usize).unwrap();
        let delete_result;
        if use_trash {
            // Move file to trash
            delete_result = trash::delete(file.path()).ok();
        } else {
            // Directly delete file
            delete_result = fs::remove_file(file.path()).ok();
        }
        if let Some(_) = delete_result {
            println!("Deleted {}...", file.path().to_string_lossy());
        } else {
            println!("Failed to delete {}!", file.path().to_string_lossy());
        }
    }
}

fn prompt_user(files: &Vec<DirEntry>) -> std::io::Result<UserChoice> {
    for (index, file) in files.iter().enumerate() {
        let file_uri = format!(
            "file:///{}",
            file.path().to_string_lossy().replace('\\', "/")
        );
        let folder_uri = format!(
            "file:///{}",
            file.path()
                .parent()
                .unwrap()
                .to_string_lossy()
                .replace('\\', "/")
        );
        // Print as URI link
        println!(
            "{}: \x1b]8;;{}\x1b\\{}\x1b]8;;\x1b\\ [\x1b]8;;{}\x1b\\{}\x1b]8;;\x1b\\]",
            index,
            file_uri,
            file.path().to_string_lossy(),
            folder_uri,
            "Open Folder"
        );
    }
    println!("none: (default)");
    println!("--------------------------------------------------");
    println!("check: verify the full file contents are identical");

    print!("\nEnter the index (or indices) of files to DELETE (comma-separated): ");
    std::io::stdout().flush()?; // Flush the output to ensure prompt is displayed

    let mut input = String::new();
    std::io::stdin().read_line(&mut input)?;
    let input = input.trim();

    if input.is_empty() || input.eq("none") {
        println!("Skipping: All files kept");
        return Ok(UserChoice::SKIP);
    }

    if input.eq("check") {
        println!("Checking file hashes...");
        for file in files {
            let bytes = fs::read(file.path())?;
            let hash = sha256::digest(bytes);
            let datetime: DateTime<Local> = file.metadata().unwrap().modified().unwrap().into();
            println!("{}:", file.path().to_string_lossy());
            println!(
                "Sha256 Hash: {}, Modified Time: {}",
                hash,
                datetime.format("%Y-%m-%d %H:%M:%S")
            );
        }
        return Ok(UserChoice::CHECK);
    }

    if input.eq("exit") {
        return Ok(UserChoice::EXIT);
    }

    if let Ok(indices_to_keep) = input
        .split(',')
        .map(|s| s.trim().parse::<u64>())
        .collect::<Result<Vec<_>, ParseIntError>>()
    {
        if indices_to_keep.len() > 0 {
            for index in indices_to_keep.iter() {
                if *index >= files.len().try_into().unwrap() {
                    println!("Error: {} is an invalid index!", index);
                    return Ok(UserChoice::INVALID);
                }
            }
            return Ok(UserChoice::KEEP(indices_to_keep));
        }
    }

    println!("Error: Unknown input!");
    return Ok(UserChoice::INVALID);
}

fn main() -> Result<(), Box<dyn Error>> {
    let arguments = Command::new("Duplicate Finder")
        .version("0.0.1")
        .about("Finds duplicate files")
        .arg(
            Arg::new("directory")
                .short('d')
                .long("directory")
                .help("The root directory to search from")
                .value_parser(PathBufValueParser::default()),
        )
        .arg(
            Arg::new("exclude")
                .short('e')
                .long("exclude")
                .help("List of patterns to exclude")
                .value_delimiter(','),
        )
        .arg(
            Arg::new("use_trash")
                .short('t')
                .long("use-trash")
                .help("Move deleted files to the system trash")
                .action(ArgAction::SetTrue),
        )
        .get_matches();

    let default_dir = env::current_dir()?;
    let directory = arguments.get_one("directory").unwrap_or(&default_dir);
    let exclude_patterns: Vec<Pattern> = arguments
        .get_many::<String>("exclude")
        .unwrap_or_default()
        .filter_map(|pattern| Pattern::new(pattern).ok())
        .collect();
    let use_trash = arguments.get_flag("use_trash");

    println!(
        "Searching '{}' for duplicate files...",
        directory.to_str().unwrap()
    );

    let mut file_sizes = HashMap::new();

    for file in WalkDir::new(directory)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|e| !e.file_type().is_dir())
    {
        // Skip excluded files
        if exclude_patterns
            .iter()
            .any(|pattern| pattern.matches_path(file.path()))
        {
            continue;
        }

        let file_size = file_sizes
            .entry(file.metadata()?.len())
            .or_insert(Vec::new());
        file_size.push(file);
    }

    let duplicate_file_sizes: HashMap<_, _> =
        file_sizes.into_iter().filter(|x| x.1.len() > 1).collect();

    let mut duplicates = Vec::new();
    let crc32 = Crc::<u32>::new(&CRC_32_ISO_HDLC);

    for entry in duplicate_file_sizes {
        let mut file_checksums = HashMap::new();
        for dir_entry in entry.1 {
            let bytes;
            if dir_entry.metadata()?.len() <= (CHECK_SIZE * 2).try_into()? {
                bytes = fs::read(dir_entry.path())?;
            } else {
                let mut file = File::open(dir_entry.path())?;
                let mut first_bytes = vec![0; CHECK_SIZE.try_into()?];
                file.read_exact(&mut first_bytes)?;

                file.seek(SeekFrom::End(-CHECK_SIZE))?;
                let mut last_bytes = vec![0; CHECK_SIZE.try_into()?];
                file.read(&mut last_bytes)?;
                first_bytes.extend(last_bytes.iter());
                bytes = first_bytes;
            }

            let checksum = crc32.checksum(&bytes);
            let checksum_entry = file_checksums.entry(checksum).or_insert(Vec::new());
            checksum_entry.push(dir_entry);
        }

        let duplicate_file_checksums: HashMap<_, _> = file_checksums
            .into_iter()
            .filter(|x| x.1.len() > 1)
            .collect();
        duplicates.extend(duplicate_file_checksums.values().cloned());
    }

    let total_duplicates = duplicates.len();
    if total_duplicates > 0 {
        println!("\nType 'exit' to quit the program...");
        for (index, files) in duplicates.iter().enumerate() {
            loop {
                println!("\nPotential duplicate ({}/{})", index + 1, total_duplicates);
                match prompt_user(files)? {
                    UserChoice::KEEP(delete_indices) => {
                        delete_files(files, delete_indices, use_trash);
                        break;
                    }
                    UserChoice::SKIP => break,
                    UserChoice::CHECK => continue, // The user triggered a check so prompt them again
                    UserChoice::INVALID => continue,
                    UserChoice::EXIT => exit(0),
                }
            }
        }
    } else {
        println!("No duplicates found.");
    }

    Ok(())
}
