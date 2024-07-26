use std::{error::Error, fs::File, io::{BufWriter, IsTerminal, Write}, path::PathBuf, slice};

use exe::{self, VecPE, PE};
use openssl::{
    pkcs7::{Pkcs7, Pkcs7Flags},
    stack::Stack,
};
use pretty_hex::pretty_hex_write;

fn extract_pkcs7_from_pe(file: &PathBuf) -> Result<Vec<u8>, Box<dyn Error>> {
    // 判断文件是否存在
    if !file.exists() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::NotFound,
            format!("{} 文件不存在", file.to_str().unwrap()),
        )
        .into());
    }

    // 解析 PE 文件，获取签名数据
    let image = VecPE::from_disk_file(file.to_str().unwrap())?;
    let security_directory =
        image.get_data_directory(exe::ImageDirectoryEntry::Security)?;
    let signature_data =
        exe::Buffer::offset_to_ptr(&image, security_directory.virtual_address.into())?; // security_data_directory rva is equivalent to file offset

    Ok(unsafe {
        let vec = std::slice::from_raw_parts(signature_data, security_directory.size as usize).to_vec();    // cloned
        vec.into_iter().skip(8).collect()   // _WIN_CERTIFICATE->bCertificate
    })
}

fn cli() -> clap::Command {
    use clap::{arg, value_parser, Command};

    Command::new("pe-sign")
        .version("0.1.0")
        .about("A tool for verifying PE file signatures")
        .author("REinject")
        .help_template("{name} ({version}) - {author}\n{about}\n{all-args}")
        .subcommand_required(true)
        .subcommand(
            Command::new("extract")
                .about("Extract the certificate of a PE file")
                .args(&[
                    arg!([FILE])
                        .value_parser(value_parser!(PathBuf))
                        .required(true),
                    arg!(-o --output <FILE> "Write to file instead of stdout")
                        .value_parser(value_parser!(PathBuf)),
                    arg!(--pem "Extract and convert certificate to pem format"),
                ]),
        )
        .subcommand(
            Command::new("verify")
                .about("Check the digital signature of a PE file for validity")
                .arg(
                    arg!([FILE])
                        .value_parser(value_parser!(PathBuf))
                        .required(true),
                ),
        )
}

fn main() -> Result<(), Box<dyn Error>> {
    // 解析参数
    let matches = cli().get_matches();

    match matches.subcommand() {
        Some(("extract", sub_matches)) => {
            let file = sub_matches.get_one::<PathBuf>("FILE").unwrap();
            let pem = sub_matches.get_flag("pem");

            let mut extracted_bin: Vec<u8> = vec![];

            // 从文件解析 pkcs7 签名数据
            let pkcs7_bin = extract_pkcs7_from_pe(file)?;

            if pem {
                // der 转换为 pem
                let pkcs7 = Pkcs7::from_der(&pkcs7_bin)?;
                let pkcs7_pem_bin = pkcs7.to_pem()?;
                extracted_bin.extend(pkcs7_pem_bin);
            }
            else {
                extracted_bin.extend(pkcs7_bin);
            }
            
            // 输出到文件
            let is_terminal = std::io::stdout().is_terminal();
            let output = sub_matches.get_one::<PathBuf>("output");
            let mut out_writer = BufWriter::new(match output {
                Some(output) => Box::new(File::create(output)?) as Box<dyn Write>,
                None =>Box::new(std::io::stdout()) as Box<dyn Write>,
            });
            
            if output.is_none() && !pem && is_terminal {
                let mut str = String::new();
                pretty_hex_write(&mut str, &extracted_bin)?;
                out_writer.write_all(str.as_bytes())?;
            }
            else {
                out_writer.write_all(&extracted_bin)?;
            }

            Ok(())
        },
        Some(("verify", sub_matches)) => {
            let file = sub_matches.get_one::<PathBuf>("FILE").unwrap();

            // 解析 PE 文件，获取签名数据
            let pkcs7_bin = extract_pkcs7_from_pe(file)?;

            // 解析 pkcs7
            let pkcs7 = Pkcs7::from_der(&pkcs7_bin)?;

            // 打印签名者信息
            let mut empty_certs = Stack::new().unwrap();
            let signer_certs = pkcs7
                .signers(&mut empty_certs, Pkcs7Flags::NOVERIFY | Pkcs7Flags::NOCHAIN | Pkcs7Flags::NOSIGS)
                .unwrap();

            for cert in signer_certs.iter() {
                println!("{:#?}", cert.subject_name());
            }

            Ok(())
        }
        _ => unreachable!("subcommand_required is true"),
    }
}
