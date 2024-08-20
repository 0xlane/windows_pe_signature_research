use std::{
    error::Error,
    ffi::c_long,
    fmt::Display,
    fs::File,
    io::{BufWriter, IsTerminal, Write},
    path::PathBuf,
    ptr::null_mut,
};

use chrono::{Local, NaiveDateTime};
use exe::{self, VecPE, PE};
use foreign_types::{ForeignType, ForeignTypeRef};
use openssl::{
    asn1::{Asn1ObjectRef, Asn1OctetStringRef, Asn1StringRef, Asn1TimeRef},
    cms::{CMSOptions, CmsContentInfo},
    hash::MessageDigest,
    nid::Nid,
    pkcs7::{Pkcs7, Pkcs7Flags, Pkcs7SignerInfo},
    stack::{Stack, StackRef},
    x509::{store::X509StoreBuilder, verify::X509VerifyFlags, X509PurposeRef, X509},
};
use openssl_sys::{
    d2i_ASN1_TYPE, NID_commonName, NID_pkcs9_countersignature, NID_pkcs9_signingTime,
    OPENSSL_sk_num, OPENSSL_sk_value, PKCS7_get_signed_attribute, X509_ATTRIBUTE_get0_object,
    X509_ATTRIBUTE_get0_type, PKCS7_SIGNER_INFO, V_ASN1_OBJECT, V_ASN1_OCTET_STRING,
    V_ASN1_SEQUENCE, V_ASN1_UTCTIME,
};
use pretty_hex::pretty_hex_write;

const EMBEDDED_SIGNATURE_OID: &[u8] = &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0x37, 0x02, 0x04, 0x01]; // 1.3.6.1.4.1.311.2.4.1  szOID_NESTED_SIGNATURE
const SIGNING_TIME_OID: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x09, 0x05]; // 1.2.840.113549.1.9.5 signingTime

fn extract_pkcs7_from_pe(file: &PathBuf) -> Result<Option<Vec<u8>>, Box<dyn Error>> {
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
    let security_directory = image.get_data_directory(exe::ImageDirectoryEntry::Security)?;

    // va = 0 表示无签名
    if security_directory.virtual_address.0 == 0x00 {
        return Ok(None);
    }

    let signature_data =
        exe::Buffer::offset_to_ptr(&image, security_directory.virtual_address.into())?; // security_data_directory rva is equivalent to file offset

    Ok(Some(unsafe {
        let vec =
            std::slice::from_raw_parts(signature_data, security_directory.size as usize).to_vec(); // cloned
        vec.into_iter().skip(8).collect() // _WIN_CERTIFICATE->bCertificate
    }))
}

fn extract_pkcs7_embedded<'a>(cert_bin: &'a [u8]) -> Option<&'a [u8]> {
    match cert_bin
        .windows(EMBEDDED_SIGNATURE_OID.len())
        .position(|w| w == EMBEDDED_SIGNATURE_OID)
    {
        Some(pos) => {
            let sequence_pos = pos + EMBEDDED_SIGNATURE_OID.len() + 4;
            let mut header_len = 1;

            let size = if cert_bin[sequence_pos + 1] >= 0b10000000 {
                // 长编码
                let len = (cert_bin[sequence_pos + 1] & 0b01111111) as usize;
                header_len += 1 + len;
                let size_bin =
                    &mut cert_bin[sequence_pos + 1 + 1..sequence_pos + 1 + 1 + len].to_vec();
                size_bin.reverse(); // big endian to little endian
                size_bin.resize(8, 0x0); // align to usize
                usize::from_le_bytes(unsafe { *(size_bin.as_ptr() as *const [u8; 8]) })
            } else {
                // 短编码
                header_len += 1;
                cert_bin[sequence_pos + 1] as usize
            };

            Some(&cert_bin[sequence_pos..sequence_pos + header_len + size])
        }
        None => None,
    }
}

fn extract_signing_time<'a>(cert_bin: &'a [u8]) -> Option<&'a [u8]> {
    match cert_bin
        .windows(SIGNING_TIME_OID.len())
        .position(|w| w == SIGNING_TIME_OID)
    {
        Some(pos) => {
            let utctime_pos = pos + SIGNING_TIME_OID.len() + 4;

            let size = cert_bin[utctime_pos - 1] as usize;
            if size < cert_bin.len() - utctime_pos {
                Some(&cert_bin[utctime_pos..utctime_pos + size])
            } else {
                None
            }
        }
        None => None,
    }
}

fn extract_signing_time_from_tstinfo<'a>(cert_bin: &'a [u8]) -> Option<&'a [u8]> {
    for pos in 0..cert_bin.len() - 1 {
        if cert_bin[pos] == 0x18 && cert_bin[pos + 1] >= 0x0F && cert_bin[pos + 1] <= 0x13 {
            let time_pos = pos + 2;
            let size = cert_bin[time_pos - 1] as usize;
            if size < cert_bin.len() - time_pos {
                return Some(&cert_bin[time_pos..time_pos + size]);
            }
        }
    }

    None
}

extern "C" {
    pub fn d2i_PKCS7_SIGNER_INFO(
        a: *mut *mut PKCS7_SIGNER_INFO,
        pp: *mut *const u8,
        length: c_long,
    ) -> *mut PKCS7_SIGNER_INFO;
}

fn extract_authtiencode(cert_bin: &[u8]) -> Option<(String, String)> {
    unsafe {
        let asn1_type =
            d2i_ASN1_TYPE(null_mut(), &mut cert_bin.as_ptr(), cert_bin.len() as _).as_ref()?;
        if asn1_type.type_ == V_ASN1_SEQUENCE {
            let data_seq = Asn1StringRef::from_ptr(asn1_type.value.sequence);
            let data_len = data_seq.len();
            if data_len > 0 && cert_bin.len() > data_len {
                // 跳过 SpcIndirectDataContent->data 得到 SpcIndirectDataContent->messageDigest
                let message_digest_bin = &cert_bin[data_len..];
                // 跳过 seq header
                let message_digest_bin = &message_digest_bin[2..];
                // 解析 digestAlgorithm
                let digest_algo_obj_bin_len = message_digest_bin[3] as usize;
                let digest_algo_obj_bin = &message_digest_bin[2..2 + 2 + digest_algo_obj_bin_len];
                let asn1_type = d2i_ASN1_TYPE(
                    null_mut(),
                    &mut digest_algo_obj_bin.as_ptr(),
                    digest_algo_obj_bin.len() as _,
                )
                .as_ref()?;
                if asn1_type.type_ == V_ASN1_OBJECT {
                    let digest_algo_obj = Asn1ObjectRef::from_ptr(asn1_type.value.object);
                    let digest_algo_str = digest_algo_obj.to_string();
                    // 跳过 SpcIndirectDataContent->messageDigest->digestAlgorithm 得到 SpcIndirectDataContent->messageDigest -> digest
                    let digest_algo_seq_len = message_digest_bin[1] as usize;
                    let digest_octet_str_bin = &message_digest_bin[2 + digest_algo_seq_len..];
                    let asn1_type = d2i_ASN1_TYPE(
                        null_mut(),
                        &mut digest_octet_str_bin.as_ptr(),
                        digest_octet_str_bin.len() as _,
                    )
                    .as_ref()?;
                    if asn1_type.type_ == V_ASN1_OCTET_STRING {
                        let digest_octet_str =
                            Asn1OctetStringRef::from_ptr(asn1_type.value.octet_string);
                        let authenticode = to_hex_str(digest_octet_str.as_slice());
                        return Some((digest_algo_str, authenticode));
                    }
                }
            }
        }
    }

    None
}

#[allow(dead_code)]
#[derive(Debug, PartialEq, Eq)]
enum CertificateStatus {
    Valid,            // 证书有效
    Expired,          // 证书已过期
    Untrusted,        // 证书不受信任
    ChainInvalid,     // 证书链验证失败
    InvalidSignature, // 证书签名无效
    Unknown,          // 未知错误或状态
}

impl Display for CertificateStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

fn to_hex_str<T>(bytes: &T) -> String
where
    T: AsRef<[u8]> + ?Sized,
{
    let x = bytes.as_ref();

    x.iter()
        .map(|v| format!("{:02x}", v))
        .collect::<Vec<String>>()
        .join("")
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
                    arg!(--embed "Extract embedded certificate"),
                ]),
        )
        .subcommand(
            Command::new("verify")
                .about("Check the digital signature of a PE file for validity")
                .args(&[
                    arg!([FILE])
                        .value_parser(value_parser!(PathBuf))
                        .required(true),
                    arg!(--"no-check-time" "Ignore certificate validity time"),
                ]),
        )
}

fn main() -> Result<(), Box<dyn Error>> {
    // 解析参数
    let matches = cli().get_matches();

    match matches.subcommand() {
        Some(("extract", sub_matches)) => {
            let file = sub_matches.get_one::<PathBuf>("FILE").unwrap();
            let pem = sub_matches.get_flag("pem");
            let embedded = sub_matches.get_flag("embed");

            let mut extracted_bin: Vec<u8> = vec![];

            // 从文件解析 pkcs7 签名数据
            let mut pkcs7_bin = extract_pkcs7_from_pe(file)?.expect("unsigned pe file.");
            if embedded {
                pkcs7_bin = extract_pkcs7_embedded(&pkcs7_bin)
                    .expect("no embedded certificate.")
                    .to_vec();
            }

            if pem {
                // der 转换为 pem
                let pkcs7 = Pkcs7::from_der(&pkcs7_bin)?;
                let pkcs7_pem_bin = pkcs7.to_pem()?;
                extracted_bin.extend(pkcs7_pem_bin);
            } else {
                extracted_bin.extend(pkcs7_bin);
            }

            // 输出到文件
            let is_terminal = std::io::stdout().is_terminal();
            let output = sub_matches.get_one::<PathBuf>("output");
            let mut out_writer = BufWriter::new(match output {
                Some(output) => Box::new(File::create(output)?) as Box<dyn Write>,
                None => Box::new(std::io::stdout()) as Box<dyn Write>,
            });

            if output.is_none() && !pem && is_terminal {
                let mut str = String::new();
                pretty_hex_write(&mut str, &extracted_bin)?;
                out_writer.write_all(str.as_bytes())?;
            } else {
                out_writer.write_all(&extracted_bin)?;
            }

            Ok(())
        }
        Some(("verify", sub_matches)) => {
            let file = sub_matches.get_one::<PathBuf>("FILE").unwrap();
            let no_check_time = sub_matches.get_flag("no-check-time");

            let mut pkcs7s = vec![];

            // 解析 PE 文件，获取签名数据
            let pkcs7_bin = extract_pkcs7_from_pe(file)?.expect("unsigned pe file.");

            pkcs7s.push(Pkcs7::from_der(&pkcs7_bin)?);

            if let Some(embed) = extract_pkcs7_embedded(&pkcs7_bin) {
                pkcs7s.push(Pkcs7::from_der(&embed)?);
            }

            for pkcs7 in pkcs7s {
                // 加载 cacert
                let cacert_bin = std::fs::read(".\\cacert.pem")?;
                let mut store_builder = X509StoreBuilder::new()?;
                let ca_certs = X509::stack_from_pem(&cacert_bin)?;
                for ca_cert in ca_certs {
                    store_builder.add_cert(ca_cert)?;
                }
                let purpose_idx = X509PurposeRef::get_by_sname("any")?;
                let x509_purposeref = X509PurposeRef::from_idx(purpose_idx)?;
                store_builder.set_purpose(x509_purposeref.purpose())?;
                if no_check_time {
                    store_builder.set_flags(X509VerifyFlags::NO_CHECK_TIME)?;
                }
                let store = store_builder.build();

                // 从 signedData 提取 indata
                let indata = unsafe {
                    let x = pkcs7.as_ptr();
                    let signed_data = (*x).d.sign;
                    let other = (*(*signed_data).contents).d.other;
                    let authenticode_seq =
                        Asn1StringRef::from_ptr((*other).value.sequence).as_slice();

                    // seq value
                    if authenticode_seq[1] >= 0b10000000 {
                        // 长编码
                        let len = (authenticode_seq[1] & 0b01111111) as usize;
                        authenticode_seq[1 + 1 + len..].to_vec()
                    } else {
                        // 短编码
                        authenticode_seq[1 + 1..].to_vec()
                    }
                };

                let mut empty_certs = Stack::new().unwrap();
                let status = match pkcs7.verify(
                    &empty_certs,
                    &store,
                    Some(&indata),
                    None,
                    Pkcs7Flags::empty(),
                ) {
                    Ok(()) => CertificateStatus::Valid,
                    Err(err) => {
                        let mut tmp = CertificateStatus::Unknown;
                        for e in err.errors() {
                            if let Some(data) = e.data() {
                                if data.contains("expired") {
                                    tmp = CertificateStatus::Expired;
                                    break;
                                } else if data.contains("unable to get local issuer certificate") {
                                    tmp = CertificateStatus::Untrusted;
                                    break;
                                } else if data.contains("self-signed certificate") {
                                    tmp = CertificateStatus::Untrusted;
                                    break;
                                }
                                println!("[WARN] {}", data);
                            }
                        }
                        tmp
                    }
                };

                // 打印签名者信息
                let signer_cert = &pkcs7
                    .signers(
                        &mut empty_certs,
                        Pkcs7Flags::NOVERIFY | Pkcs7Flags::NOCHAIN | Pkcs7Flags::NOSIGS,
                    )
                    .unwrap()[0];

                let subject_name = signer_cert.subject_name();
                // println!("{:#?}", subject_name);

                let comm_name = subject_name
                    .entries_by_nid(Nid::from_raw(NID_commonName))
                    .next()
                    .expect("Common Name (CN) not found in the subject name")
                    .data()
                    .as_utf8()
                    .unwrap();
                let version = signer_cert.version();
                let algorithm = signer_cert.signature_algorithm().object().to_string();
                let sn = signer_cert.serial_number().to_bn().unwrap();
                let sn = to_hex_str(&sn.to_vec());
                let fingerprint = to_hex_str(&signer_cert.digest(MessageDigest::sha1())?);
                let start_time = NaiveDateTime::parse_from_str(
                    &signer_cert.not_before().to_string(),
                    "%b %d %H:%M:%S %Y GMT",
                )
                .unwrap()
                .and_utc()
                .with_timezone(&Local);
                let end_time = NaiveDateTime::parse_from_str(
                    &signer_cert.not_after().to_string(),
                    "%b %d %H:%M:%S %Y GMT",
                )
                .unwrap()
                .and_utc()
                .with_timezone(&Local);

                let mut signing_time = None;
                unsafe {
                    let signed = pkcs7.signed().unwrap().as_ptr().as_ref().unwrap();
                    let signer_infos = StackRef::<Pkcs7SignerInfo>::from_ptr(signed.signer_info);
                    let signer_info = signer_infos.get(0).unwrap();
                    let mut tmp_time = None;
                    let auth_attrs = signer_info.as_ptr().as_ref().unwrap().auth_attr;
                    let num = OPENSSL_sk_num(auth_attrs as _);

                    // 先从证书认证属性中获取 signingTime
                    for i in 0..num {
                        let attr = OPENSSL_sk_value(auth_attrs as _, i);
                        let obj = Asn1ObjectRef::from_ptr(X509_ATTRIBUTE_get0_object(attr as _));
                        // println!("{}", obj.nid().as_raw());
                        if obj.nid().as_raw() == NID_pkcs9_signingTime {
                            let asn1_time =
                                X509_ATTRIBUTE_get0_type(attr as _, 0).as_ref().unwrap();
                            if asn1_time.type_ == V_ASN1_UTCTIME {
                                signing_time = Some(
                                    NaiveDateTime::parse_from_str(
                                        &Asn1TimeRef::from_ptr(asn1_time.value.utctime as _)
                                            .to_string(),
                                        "%b %d %H:%M:%S %Y GMT",
                                    )
                                    .unwrap()
                                    .and_utc()
                                    .with_timezone(&Local),
                                );
                                break;
                            }
                        }
                    }

                    // 一般需要在副署签名中找签名时间
                    if signing_time.is_none() {
                        // 副署信息在未认证属性中寻找
                        let unauth_attrs = signer_info.as_ptr().as_ref().unwrap().unauth_attr;
                        let num = OPENSSL_sk_num(unauth_attrs as _);
                        for i in 0..num {
                            let attr = OPENSSL_sk_value(unauth_attrs as _, i);
                            let obj =
                                Asn1ObjectRef::from_ptr(X509_ATTRIBUTE_get0_object(attr as _));

                            // 是副署属性
                            if obj.nid().as_raw() == NID_pkcs9_countersignature {
                                let asn1_cs =
                                    X509_ATTRIBUTE_get0_type(attr as _, 0).as_ref().unwrap();
                                if asn1_cs.type_ == V_ASN1_SEQUENCE {
                                    // 从副署签名者信息中解析签名时间
                                    let cs_seq =
                                        Asn1StringRef::from_ptr(asn1_cs.value.sequence).as_slice();
                                    let si = d2i_PKCS7_SIGNER_INFO(
                                        null_mut(),
                                        &mut cs_seq.as_ptr(),
                                        cs_seq.len().try_into().unwrap(),
                                    );
                                    match PKCS7_get_signed_attribute(si, NID_pkcs9_signingTime)
                                        .as_ref()
                                    {
                                        Some(asn1_time) => {
                                            if asn1_time.type_ == V_ASN1_UTCTIME {
                                                let utctime = Asn1TimeRef::from_ptr(
                                                    asn1_time.value.utctime as _,
                                                );
                                                signing_time = Some(
                                                    NaiveDateTime::parse_from_str(
                                                        &utctime.to_string(),
                                                        "%b %d %H:%M:%S %Y GMT",
                                                    )
                                                    .unwrap()
                                                    .and_utc()
                                                    .with_timezone(&Local),
                                                );
                                                break;
                                            }
                                        }
                                        None => continue,
                                    }
                                }
                            } else if obj.to_string() == "1.3.6.1.4.1.311.3.3.1" {
                                // 没有副署属性，但是有 1.3.6.1.4.1.311.3.3.1 属性
                                let asn1_oz =
                                    X509_ATTRIBUTE_get0_type(attr as _, 0).as_ref().unwrap();
                                if asn1_oz.type_ == V_ASN1_SEQUENCE {
                                    // 先直接找 signingTime
                                    let oz_seq =
                                        Asn1StringRef::from_ptr(asn1_oz.value.sequence).as_slice();
                                    match extract_signing_time(oz_seq) {
                                        Some(signing_time_bin) => {
                                            let signing_time_str =
                                                String::from_utf8(signing_time_bin.to_vec())
                                                    .unwrap();
                                            tmp_time = Some(
                                                NaiveDateTime::parse_from_str(
                                                    &signing_time_str,
                                                    "%y%m%d%H%M%SZ",
                                                )
                                                .unwrap()
                                                .and_utc()
                                                .with_timezone(&Local),
                                            );
                                            break;
                                        }
                                        None => {
                                            // 找不到 signingTime，需要从 id-smime-ct-TSTInfo->contentInfo->content 中提取
                                            let mut cms = CmsContentInfo::from_der(&oz_seq)?;
                                            let mut tstinfo = Vec::new();
                                            cms.verify(
                                                None,
                                                None,
                                                None,
                                                Some(&mut tstinfo),
                                                CMSOptions::NOVERIFY,
                                            )
                                            .unwrap();
                                            match extract_signing_time_from_tstinfo(&tstinfo) {
                                                Some(signing_time_bin) => {
                                                    let signing_time_str = String::from_utf8(
                                                        signing_time_bin.to_vec(),
                                                    )
                                                    .unwrap();
                                                    signing_time = Some(
                                                        NaiveDateTime::parse_from_str(
                                                            &signing_time_str,
                                                            "%Y%m%d%H%M%S%.3fZ",
                                                        )
                                                        .unwrap()
                                                        .and_utc()
                                                        .with_timezone(&Local),
                                                    );
                                                    break;
                                                }
                                                None => continue,
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    if signing_time.is_none() && tmp_time.is_some() {
                        signing_time = tmp_time;
                    }
                }

                let (_, authenticode) = extract_authtiencode(&indata).unwrap();

                println!(
                    r"Certificate:
    CN: {}
    Status: {}
    Version: V{}
    SN: {}
    Fingerprint: {}
    Algorithm: {}
    ValidityPeriod: {} - {}
    SigningTime: {}
    Authenticode: {}
==============================================================",
                    comm_name,
                    status,
                    version,
                    sn,
                    fingerprint,
                    algorithm,
                    start_time,
                    end_time,
                    signing_time
                        .and_then(|t| Some(t.to_string()))
                        .unwrap_or("Unknown".to_owned()),
                    authenticode
                );
            }

            Ok(())
        }
        _ => unreachable!("subcommand_required is true"),
    }
}
