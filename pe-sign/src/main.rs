use std::{error::Error, path::PathBuf, slice};

use exe::{self, VecPE, PE};
use openssl::{
    pkcs7::{Pkcs7, Pkcs7Flags},
    stack::Stack,
};

fn cli() -> clap::Command {
    use clap::{arg, value_parser, Command};

    Command::new("pe-sign")
        .version("0.1.0")
        .about("A tool for verifying PE file signatures")
        .author("REinject")
        .help_template("{name} ({version}) - {author}\n{about}\n{all-args}")
        .subcommand_required(true)
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
        Some(("verify", sub_matches)) => {
            let file = sub_matches.get_one::<PathBuf>("FILE").unwrap();

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
            let signature_data =
                unsafe { slice::from_raw_parts(signature_data, security_directory.size as usize) };
            let signature_data = &signature_data[8..]; // _WIN_CERTIFICATE->bCertificate

            // 解析 pkcs7
            let pkcs7 = Pkcs7::from_der(signature_data)?;

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
