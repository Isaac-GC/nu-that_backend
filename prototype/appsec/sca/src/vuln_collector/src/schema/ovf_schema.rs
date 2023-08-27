use serde::{Deserialize, Serialize};
use chrono::{DateTime, Utc};

#[derive(Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Ecosystem {
    Go,

    #[serde(rename="npm")]
    Npm,

    #[serde(rename="OSS-Fuzz")]
    OssFuzz,
    PyPI,
    RubyGems,

    #[serde(rename="crates.io")]
    CratesIO,
    Packagist,
    Maven,
    NuGet,
    Linux,
    Debian,
    Hex,
    Android,
}

#[derive(Debug, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(rename_all = "UPPERCASE")]
pub enum Database {
    Go,
    Osv,
    Pysec,
    Rustsec,
    Gsd,
    Ghsa,
    Lbsec,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum RangeType {
    Unspecified,
    Git,
    Semver,
    Ecosystem,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[non_exhaustive]
pub enum Event {
    Introduced(String),
    Fixed(String),
    Limit(String),
    LastAffected(String),
}

#[derive(Debug, Serialize, Deserialize)]
pub enum SeverityType {
    #[serde(rename = "UNSPECIFIED")]
    Unspecified,

    #[serde(rename = "CVSS_V3")]
    CVSSv3,
}


#[derive(Debug, Serialize, Deserialize)]
pub struct Severity {
    #[serde(rename = "type")]
    pub severity_type: SeverityType,
    pub score: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Package {
    pub ecosystem: Ecosystem,
    pub name: String,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub purl: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Ranges {
    #[serde(rename = "type")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub range_type: Option<RangeType>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo: Option<String>, 
    pub events: Vec<Event>, 

    #[serde(skip_serializing_if = "Option::is_none")]
    pub database_specific: Option<Database>,
}

// #[derive(Debug, Serialize, Deserialize)]
// pub struct Events {
//     pub introduced: String,
//     pub fixed: String,
//     pub last_affected: String,
//     pub limit: String,
// }

#[derive(Debug, Serialize, Deserialize)]
pub struct EcosystemSpecific {
    #[serde(skip_serializing_if = "Option::is_none")]
    functions: Option<Vec<String>>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    keywords: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    categories: Option<Vec<String>>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    severity: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DatabaseSpecific {
    #[serde(skip_serializing_if = "Option::is_none")]
    cwe_ids: Option<Vec<String>>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    github_reviewed: Option<bool>,

    #[serde(skip_serializing_if = "Option::is_none")]
    categories: Option<Vec<String>>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    severity: Option<String>,
}


#[derive(Debug, Serialize, Deserialize)]
pub struct Affected {
    pub package: Package,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub ranges: Option<Vec<Ranges>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub versions: Option<Vec<String>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub ecosystem_specific: Option<EcosystemSpecific>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub database_specific: Option<DatabaseSpecific>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum ReferenceType {
    #[serde(rename = "NONE")]
    Undefined,
    Web,
    Advisory,
    Report,
    Fix,
    Package,
    Article,
}


#[derive(Debug, Serialize, Deserialize)]
pub struct References {
    #[serde(rename = "type")]
    pub reference_type: ReferenceType,
    pub url: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Credits {
    pub name: String,
    pub contact: Vec<String>
}

#[derive(Debug, Serialize, Deserialize)]
pub struct OvfFormat {
    pub schema_version: String,
    pub id: String,
    pub modified: DateTime<Utc>,
    pub published: String,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub withdrawn: Option<DateTime<Utc>>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aliases: Option<Vec<String>>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub related: Option<Vec<String>>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub summary: Option<String>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub severity: Option<Vec<Severity>>,
    pub affected: Vec<Affected>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub references: Option<Vec<References>>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credits: Option<Vec<Credits>>,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub database_specific: Option<DatabaseSpecific>,
}