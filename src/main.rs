use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::path::Path;
use std::str::FromStr;
use std::time::Duration;

use anyhow::{anyhow, bail, Result};
use clap::{arg, command};
use cloudflare::endpoints::dns::{DnsContent, DnsRecord};
use cloudflare::endpoints::{dns, zone};
use cloudflare::framework::{
    async_api::{ApiClient, Client},
    auth::Credentials,
    Environment, HttpApiClientConfig, OrderDirection,
};
use serde::{Deserialize, Serialize};
use tokio::time;

#[derive(Debug, Serialize, Deserialize)]
struct Config {
    /// Cloudflare token (required)
    token: String,

    /// Update interval in seconds (default: 600)
    interval: Option<u64>,
    /// TTL in seconds (default: auto)
    ttl: Option<u32>,
}

#[tokio::main]
async fn main() -> Result<()> {
    // parse args
    let matches = command!()
        .arg(
            arg!(-c --config <FILE> "Config file")
                .required(true)
                .allow_invalid_utf8(true),
        )
        .arg(
            arg!([domains] "File with list of domains to update")
                .required(true)
                .allow_invalid_utf8(true),
        )
        .arg(arg!(-n --"dry-run" "Dry run, don't actually write changes"))
        .get_matches();
    let config_path = matches.value_of_os("config").unwrap();
    let domain_list_path = matches.value_of_os("domains").unwrap();
    let dry_run = matches.is_present("dry-run");

    // load config
    let config = load_config(&config_path)?;
    let token = config.token.clone();
    let interval = config.interval.unwrap_or(0);

    // instantiate cloudflare client
    let credentials: Credentials = Credentials::UserAuthToken { token };
    let api_client = Client::new(
        credentials,
        HttpApiClientConfig::default(),
        Environment::Production,
    )?;

    // preload zone list
    let mut zone_map = HashMap::new();
    for (zone_domain, zone_id) in list_zones(&api_client)
        .await?
        .iter()
        .map(|zone| (zone.name.clone(), zone.id.clone()))
    {
        let dns_list: HashMap<_, _> = list_dns_records(&zone_id, &api_client)
            .await?
            .into_iter()
            .filter_map(|record| {
                Some((
                    match record.content {
                        DnsContent::A { .. } => record.name.clone(),
                        _ => return None,
                    },
                    record,
                ))
            })
            .collect();
        zone_map.insert(zone_domain, (zone_id, dns_list));
    }

    // load domain list
    let mut domain_list = load_domain_list(&domain_list_path)?
        .into_iter()
        .map(|domain| {
            let (ref zone_id, ref record_map) =
                zone_map.get(extract_zone(&domain).unwrap()).unwrap();
            let dns_record = record_map.get(&domain).cloned();
            (domain, zone_id, dns_record)
        })
        .collect::<Vec<(String, _, _)>>();

    if interval > 0 {
        let mut interval = time::interval(Duration::from_secs(interval));

        loop {
            interval.tick().await;

            println!("Checking DNS records...");

            match populate_ips(&mut domain_list, &api_client, dry_run, config.ttl).await {
                Err(e) => println!("Error encountered: {:?}", e),
                _ => (),
            };
        }
    } else {
        println!("Checking DNS records...");
        populate_ips(&mut domain_list, &api_client, dry_run, config.ttl).await
    }
}

async fn populate_ips<ApiClientType: ApiClient>(
    // list of (domain, zone_id, dns record)
    domain_list: &mut [(String, &String, Option<DnsRecord>)],
    api_client: &ApiClientType,
    dry_run: bool,
    ttl: Option<u32>,
) -> Result<()> {
    let global_ipv4_addr = get_global_ipv4_addr().await?;

    for (fqdn, zone_id, record) in domain_list.iter_mut() {
        if let Some(record) = record {
            let record_ip = match record.content {
                DnsContent::A { content: ip } => ip,
                _ => unreachable!("We already filtered out non-A records"),
            };

            if record_ip.ne(&global_ipv4_addr) {
                let param = dns::UpdateDnsRecordParams {
                    ttl,
                    proxied: Some(false),
                    name: fqdn,
                    content: dns::DnsContent::A {
                        content: global_ipv4_addr,
                    },
                };
                println!("Updating record for {} to {:?}", fqdn, param);
                if !dry_run {
                    update_dns_record(zone_id, &record.id, param, api_client).await?;
                }
            } else {
                println!("Matching record found for {}", fqdn);
            }
        } else {
            let param = dns::CreateDnsRecordParams {
                ttl,
                priority: None,
                proxied: Some(false),
                name: fqdn,
                content: dns::DnsContent::A {
                    content: global_ipv4_addr,
                },
            };
            println!("Creating record for {}: {:?}", fqdn, param);
            if !dry_run {
                *record = Some(create_dns_record(zone_id, param, api_client).await?);
            }
        }
    }

    Ok(())
}

fn load_config<P: AsRef<Path>>(config_path: P) -> Result<Config> {
    let bytes = std::fs::read(config_path)?;
    Ok(toml::from_slice(&bytes)?)
}

/// Extracts example.com from aa.bb.cc.example.com
fn extract_zone(name: &str) -> Option<&str> {
    let second_dot = name.rmatch_indices('.').skip(1).next()?.0;
    Some(name.split_at(second_dot + 1).1)
}

const CLOUDFLARE_IP_ENDPOINT: &str = "https://1.1.1.1/cdn-cgi/trace";

async fn get_global_ipv4_addr() -> Result<Ipv4Addr> {
    let body = reqwest::get(CLOUDFLARE_IP_ENDPOINT).await?.text().await?;
    let ip_str = body
        .lines()
        .filter_map(|s| s.strip_prefix("ip="))
        .next()
        .ok_or(anyhow!("Malformed cloudflare response"))?;
    match Ipv4Addr::from_str(&ip_str) {
        Ok(res) => Ok(res),
        Err(err) => bail!(err),
    }
}

fn load_domain_list<P: AsRef<Path>>(path: P) -> Result<Vec<String>> {
    let data = std::fs::read_to_string(path)?;
    let list = data
        .split("\n")
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect::<Vec<String>>();
    Ok(list)
}

async fn list_zones<ApiClientType: ApiClient>(
    api_client: &ApiClientType,
) -> Result<Vec<zone::Zone>> {
    let response = api_client
        .request(&zone::ListZones {
            params: zone::ListZonesParams {
                ..Default::default()
            },
        })
        .await;
    match response {
        Ok(res) => Ok(res.result),
        Err(err) => bail!(err),
    }
}

async fn list_dns_records<ApiClientType: ApiClient>(
    zone_identifier: &str,
    api_client: &ApiClientType,
) -> Result<Vec<dns::DnsRecord>> {
    let response = api_client
        .request(&dns::ListDnsRecords {
            zone_identifier,
            params: dns::ListDnsRecordsParams {
                direction: Some(OrderDirection::Ascending),
                ..Default::default()
            },
        })
        .await;
    match response {
        Ok(res) => Ok(res.result),
        Err(err) => bail!(err),
    }
}

async fn create_dns_record<'a, ApiClientType: ApiClient>(
    zone_identifier: &str,
    params: dns::CreateDnsRecordParams<'a>,
    api_client: &ApiClientType,
) -> Result<DnsRecord> {
    let response = api_client
        .request(&dns::CreateDnsRecord {
            zone_identifier,
            params,
        })
        .await;
    match response {
        Ok(res) => Ok(res.result),
        Err(err) => bail!(err),
    }
}

async fn update_dns_record<'a, ApiClientType: ApiClient>(
    zone_identifier: &str,
    identifier: &str,
    params: dns::UpdateDnsRecordParams<'a>,
    api_client: &ApiClientType,
) -> Result<dns::DnsRecord> {
    let response = api_client
        .request(&dns::UpdateDnsRecord {
            zone_identifier,
            identifier,
            params,
        })
        .await;
    match response {
        Ok(res) => Ok(res.result),
        Err(err) => bail!(err),
    }
}
