// Same imports
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{BufRead, BufReader};
use std::process::Command;
use std::sync::{Arc, Mutex, mpsc::channel};
use std::time::{Instant, Duration};
use clap::{Arg, Command as ClapCommand};
use trust_dns_resolver::Resolver;
use trust_dns_resolver::config::*;
use rand::seq::SliceRandom;
use threadpool::ThreadPool;
use colored::*;

#[derive(Clone)]
enum PortsInput {
    Raw(String),
    Expanded(Vec<u16>),
}

fn print_banner() {
    println!("{}", r#"
 ____        _            _                     
/ ___| _   _| |__   ___  | |_ _ __ __ _ _ __ ___ 
\___ \| | | | '_ \ / _ \ | __| '__/ _` | '_ ` _ \
 ___) | |_| | |_) |  __/ | |_| | | (_| | | | | | |
|____/ \__,_|_.__/ \___|  \__|_|  \__,_|_| |_| |_|

"#.bright_blue());
    println!("{}", "          Subdomain + IP Port Mapper".bright_green());
    println!();
}

fn resolve_domain(domain: &str) -> Option<String> {
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_secs(5);
    opts.attempts = 3;

    let resolver = Resolver::new(ResolverConfig::default(), opts).ok()?;
    resolver.lookup_ip(domain).ok()?.iter().next().map(|ip| ip.to_string())
}

fn resolve_domain_with_custom_resolvers(domain: &str, resolvers: &[String]) -> Option<String> {
    let resolver_ip = resolvers.choose(&mut rand::thread_rng())?;
    let mut opts = ResolverOpts::default();
    opts.timeout = Duration::from_secs(5);
    opts.attempts = 3;

    let resolver = Resolver::new(
        ResolverConfig::from_parts(
            None,
            vec![],
            NameServerConfigGroup::from_ips_clear(&[resolver_ip.parse().ok()?], 53, true),
        ),
        opts,
    ).ok()?;

    resolver.lookup_ip(domain).ok()?.iter().next().map(|ip| ip.to_string())
}

fn parse_ports(port_str: &str) -> PortsInput {
    if port_str.trim().contains('-') && !port_str.contains(',') {
        PortsInput::Raw(port_str.to_string())
    } else {
        let mut ports = Vec::new();
        for part in port_str.split(',') {
            if part.contains('-') {
                let bounds: Vec<&str> = part.split('-').collect();
                if bounds.len() == 2 {
                    if let (Ok(start), Ok(end)) = (bounds[0].parse::<u16>(), bounds[1].parse::<u16>()) {
                        if start <= end {
                            ports.extend(start..=end);
                        }
                    }
                }
            } else if let Ok(port) = part.parse::<u16>() {
                ports.push(port);
            }
        }
        PortsInput::Expanded(ports)
    }
}

fn scan_ip_with_rustscan(ip: &str, ports_input: &PortsInput) -> Vec<u16> {
    let (port_flag, port_value) = match ports_input {
        PortsInput::Raw(raw) => ("-r", raw.clone()),
        PortsInput::Expanded(ports) => ("-p", ports.iter().map(|p| p.to_string()).collect::<Vec<String>>().join(",")),
    };

    let output = Command::new("rustscan")
        .args([
            "--ulimit", "5000",
            "-b", "3500",
            "--scan-order", "random",
            "-g",
            "-a", ip,
            port_flag,
            &port_value,
            "--", "-Pn"
        ])
        .output()
        .expect("Failed to execute rustscan");

    let stdout = String::from_utf8_lossy(&output.stdout);

    println!("[*] Scanning IP: {}", ip);
    println!("[*] Ports argument: {}", port_value);
    println!("[*] RustScan raw output:\n{}", stdout);

    let mut open_ports = Vec::new();

    for line in stdout.lines() {
        if let Some((_, ports_part)) = line.split_once("->") {
            let ports_part = ports_part.trim();
            if ports_part.starts_with('[') && ports_part.ends_with(']') {
                let ports_inside = &ports_part[1..ports_part.len() - 1];
                for port_str in ports_inside.split(',') {
                    if let Ok(port) = port_str.trim().parse::<u16>() {
                        open_ports.push(port);
                    }
                }
            }
        }
    }

    open_ports
}

fn main() {
    let start_time = Instant::now();
    print_banner();

    let matches = ClapCommand::new("SubPortMap")
        .version("2.1")
        .author("Recon Tool")
        .about("Subdomain IP and Port Mapper using RustScan")
        .arg(Arg::new("target").short('t').long("target").num_args(1).help("Single domain to scan"))
        .arg(Arg::new("file").short('f').long("file").num_args(1).help("File of subdomains"))
        .arg(Arg::new("output").short('o').long("output").num_args(1).help("Output file name"))
        .arg(Arg::new("ports")
            .long("ports")
            .required(true)
            .num_args(1)
            .help("Comma-separated ports or range to scan, e.g., 80,443 or 0-65535"))
        .arg(Arg::new("resolvers")
            .long("resolvers")
            .num_args(1)
            .help("File of custom DNS resolvers"))
        .arg(Arg::new("resolver_threads")
            .long("resolver-threads")
            .num_args(1)
            .help("Number of resolver threads (default 20)"))
        .arg(Arg::new("scanner_threads")
            .long("scanner-threads")
            .num_args(1)
            .help("Number of scanner threads (default 50)"))
        .get_matches();

    let mut domains = Vec::new();

    if let Some(domain) = matches.get_one::<String>("target") {
        domains.push(domain.to_string());
    }

    if let Some(file_path) = matches.get_one::<String>("file") {
        let file = File::open(file_path).expect("Unable to open file");
        let reader = BufReader::new(file);
        for line in reader.lines().flatten() {
            domains.push(line);
        }
    }

    if domains.is_empty() {
        eprintln!("{}", "No targets provided. Use -t or -f.".red());
        std::process::exit(1);
    }

    let ports_input = matches.get_one::<String>("ports").unwrap();
    let parsed_ports = parse_ports(ports_input);

    let resolvers: Option<Vec<String>> = matches.get_one::<String>("resolvers").map(|resolver_file| {
        let file = File::open(resolver_file).expect("Unable to open resolver file");
        BufReader::new(file)
            .lines()
            .flatten()
            .collect()
    });

    let resolver_threads = matches.get_one::<String>("resolver_threads").and_then(|s| s.parse::<usize>().ok()).unwrap_or(20);
    let scanner_threads = matches.get_one::<String>("scanner_threads").and_then(|s| s.parse::<usize>().ok()).unwrap_or(50);

    let domain_ip_map: Arc<Mutex<HashMap<String, String>>> = Arc::new(Mutex::new(HashMap::new()));
    let resolver_pool = ThreadPool::new(resolver_threads);
    let (resolver_tx, resolver_rx) = channel();

    for domain in &domains {
        let domain = domain.clone();
        let resolvers_clone = resolvers.clone();
        let map_clone = Arc::clone(&domain_ip_map);
        let resolver_tx = resolver_tx.clone();
        resolver_pool.execute(move || {
            let ip = if let Some(ref resolvers) = resolvers_clone {
                resolve_domain_with_custom_resolvers(&domain, resolvers)
            } else {
                resolve_domain(&domain)
            };
            if let Some(ip) = ip {
                map_clone.lock().unwrap().insert(domain.clone(), ip);
            }
            resolver_tx.send(()).expect("Failed to send resolver complete");
        });
    }

    drop(resolver_tx);
    for _ in resolver_rx {}

    let map = domain_ip_map.lock().unwrap();
    let unique_ips: HashSet<String> = map.values().cloned().collect();

    let ip_ports_map: Arc<Mutex<HashMap<String, Vec<u16>>>> = Arc::new(Mutex::new(HashMap::new()));
    let scanner_pool = ThreadPool::new(scanner_threads);
    let (scanner_tx, scanner_rx) = channel();

    for ip in unique_ips {
        let ip_clone = ip.clone();
        let ports_clone = parsed_ports.clone();
        let map_clone = Arc::clone(&ip_ports_map);
        let scanner_tx = scanner_tx.clone();
        scanner_pool.execute(move || {
            let ports = scan_ip_with_rustscan(&ip_clone, &ports_clone);
            map_clone.lock().unwrap().insert(ip_clone, ports);
            scanner_tx.send(()).expect("Failed to send scanner complete");
        });
    }

    drop(scanner_tx);
    for _ in scanner_rx {}

    let output_file = matches.get_one::<String>("output").map(|s| s.as_str()).unwrap_or("output.txt");
    let ip_ports = ip_ports_map.lock().unwrap();
    let mut output_set = HashSet::new();

    for (domain, ip) in map.iter() {
        if let Some(ports) = ip_ports.get(ip) {
            for port in ports {
                println!("{}", format!("{domain}:{port}").green());
                output_set.insert(format!("{domain}:{port}"));
            }
        }
    }

    let output = output_set.into_iter().collect::<Vec<String>>().join("\n");
    fs::write(output_file, output).expect("Failed to write output file");

    let duration = start_time.elapsed();
    println!("\n{} {}", "Scan complete in:".yellow(), format!("{:.2?}", duration).bright_green());
    println!("{}", format!("Results saved to {}", output_file).bright_cyan());
}
