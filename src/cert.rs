// SPDX-FileCopyrightText: © 2024 Matt Williams <matt.williams@bristol.ac.uk>
// SPDX-License-Identifier: MIT

use anyhow::{Context, Result};
use itertools::Itertools;
use serde::{Deserialize, Deserializer, Serialize};
use std::collections::HashMap;

pub enum CertificateSignResponse {
    V2(CertificateSignResponseV2),
    V3(CertificateSignResponseV3),
}

/// Last used in Conch 0.3
#[derive(Deserialize)]
pub struct CertificateSignResponseV2 {
    pub certificate: ssh_key::Certificate,
    platforms: Resources,
    projects: ProjectsV2,
    short_name: String,
    user: String,
}

/// First used in Conch 0.4
#[derive(Deserialize)]
pub struct CertificateSignResponseV3 {
    pub certificate: ssh_key::Certificate,
    resources: Resources,
    associations: Associations,
    user: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Associations {
    Projects(Projects),
    Resources(HashMap<String, ResourceAssociation>),
}

// Waiting on https://github.com/serde-rs/serde/issues/745
impl<'de> Deserialize<'de> for CertificateSignResponse {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        // First get the object as generic JSON
        let value = serde_json::Value::deserialize(deserializer)?;
        #[derive(Deserialize)]
        struct Version {
            version: u64,
        }
        // Extract the `version` member
        let version = Version::deserialize(&value)
            .map_err(serde::de::Error::custom)?
            .version;

        // Re-deserialise to the correct struct based on the version number
        match version {
            2 => CertificateSignResponseV2::deserialize(&value).map(CertificateSignResponse::V2),
            3 => CertificateSignResponseV3::deserialize(&value).map(CertificateSignResponse::V3),
            v => Err(serde::de::Error::invalid_value(
                serde::de::Unexpected::Unsigned(v),
                &"2 or 3",
            )),
        }
        .map_err(serde::de::Error::custom)
    }
}

#[derive(Deserialize)]
pub struct CaOidcResponse {
    pub issuer: url::Url,
    pub client_id: oauth2::ClientId,
    #[serde(deserialize_with = "CaOidcResponse::check_version", rename = "version")]
    _version: u32,
}

impl CaOidcResponse {
    /// The version of the response that the CA should return.
    const VERSION: u32 = 1;
    fn check_version<'de, D>(deserializer: D) -> Result<u32, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let v = u32::deserialize(deserializer)?;
        let expected = Self::VERSION;
        if v != expected {
            return Err(serde::de::Error::custom(format!(
                "mismatched version `{v}` for OIDC details response, expected `{expected}`"
            )));
        }
        Ok(v)
    }
}

type ProjectsV2 = HashMap<String, Vec<String>>;

#[derive(Clone, Debug, PartialEq, PartialOrd, Ord, Hash, Eq, Deserialize, Serialize)]
pub struct ResourceAssociation {
    pub username: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct Project {
    pub name: String,
    pub resources: HashMap<String, ResourceAssociation>,
}

type Projects = HashMap<String, Project>;

type Resources = HashMap<String, Resource>;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Resource {
    pub alias: String,
    #[serde(with = "http_serde::authority")]
    pub hostname: http::uri::Authority,
    #[serde(with = "http_serde::option::authority")]
    pub proxy_jump: Option<http::uri::Authority>,
}

#[derive(Deserialize, Serialize)]
pub struct CertificateConfigCache {
    resources: Resources,
    pub associations: Associations,
    pub user: String,
    pub identity: std::path::PathBuf,
}

impl CertificateConfigCache {
    pub fn from_response(r: &CertificateSignResponse, identity: std::path::PathBuf) -> Self {
        match r {
            CertificateSignResponse::V2(CertificateSignResponseV2 {
                certificate: _,
                platforms,
                projects,
                short_name,
                user,
            }) => CertificateConfigCache {
                resources: platforms.clone(),
                associations: Associations::Projects(
                    projects
                        .iter()
                        .map(|(project_id, resource_ids)| {
                            (
                                project_id.to_string(),
                                Project {
                                    name: "".to_string(),
                                    resources: resource_ids
                                        .iter()
                                        .map(|resource_id| {
                                            (
                                                resource_id.to_string(),
                                                ResourceAssociation {
                                                    username: format!(
                                                        "{}.{}",
                                                        &short_name, project_id
                                                    ),
                                                },
                                            )
                                        })
                                        .collect(),
                                },
                            )
                        })
                        .collect(),
                ),
                user: user.clone(),
                identity,
            },
            CertificateSignResponse::V3(r) => CertificateConfigCache {
                resources: r.resources.clone(),
                associations: r.associations.clone(),
                user: r.user.clone(),
                identity,
            },
        }
    }

    /// Get a resource from a resource ID
    pub fn resource(&self, resource_id: &String) -> Result<&Resource> {
        self.resources.get(resource_id).context(format!(
            "Could not find resource details for `{}`",
            resource_id
        ))
    }

    /// Create the SSH config `Host` line for a given resource association
    fn user_host_spec(
        &self,
        prefix: Option<&String>,
        resource_id: &String,
        resource: &ResourceAssociation,
    ) -> Result<String> {
        let alias = &self.resource(resource_id)?.alias;
        let alias = if let Some(prefix) = prefix {
            format!("{}.{}", prefix, alias)
        } else {
            alias.to_string()
        };
        let project_config = format!(
            "Host {alias}\n\
                        \tUser {}\n",
            &resource.username,
        );
        Ok(project_config)
    }

    /// Make a list of SSH config `Host` entries for a set of resource associations
    /// The optional prefix will be plcd in fron of the Host alias name
    fn user_host_specs_for_resource_associations(
        &self,
        prefix: Option<&String>,
        resource_associations: &HashMap<String, ResourceAssociation>,
    ) -> Result<Vec<String>> {
        resource_associations
            .iter()
            .sorted()
            .map(|(resource_id, resource)| self.user_host_spec(prefix, resource_id, resource))
            .collect::<Result<Vec<_>>>()
    }

    pub fn ssh_config(&self) -> Result<String> {
        let jump_configs = self
            .resources
            .iter()
            .sorted_by_key(|x| x.0)
            .map(|(_, c)| {
                if let Some(proxy_jump) = &c.proxy_jump {
                    let jump_alias = format!("jump.{}", &c.alias);
                    let jump_config = format!(
                        "Host {jump_alias}\n\
                                \tHostname {}\n\
                                \tIdentityFile \"{1}\"\n\
                                \tCertificateFile \"{1}-cert.pub\"\n\
                                \tServerAliveInterval 60\n\
                            \n",
                        proxy_jump,
                        self.identity.display(),
                    );
                    let host_config = format!(
                        "Host *.{0} {0} !{jump_alias}\n\
                                \tHostname {1}\n\
                                \tProxyJump %r@{jump_alias}\n\
                                \tIdentityFile \"{2}\"\n\
                                \tCertificateFile \"{2}-cert.pub\"\n\
                                \tAddKeysToAgent yes\n\
                                \tServerAliveInterval 60\n\
                            \n",
                        &c.alias,
                        &c.hostname,
                        self.identity.display(),
                    );
                    format!("{}{}", jump_config, host_config)
                } else {
                    format!(
                        "Host *.{0} {0}\n\
                                \tHostname {1}\n\
                                \tIdentityFile \"{2}\"\n\
                                \tCertificateFile \"{2}-cert.pub\"\n\
                                \tAddKeysToAgent yes\n\
                                \tServerAliveInterval 60\n\
                            \n",
                        &c.alias,
                        &c.hostname,
                        self.identity.display(),
                    )
                }
            })
            .collect::<Vec<String>>()
            .join("");

        let alias_configs = match &self.associations {
            Associations::Projects(projects) => projects
                .iter()
                .sorted_by_key(|x| x.0)
                .map(|(project_id, project)| {
                    Ok(self
                        .user_host_specs_for_resource_associations(
                            Some(project_id),
                            &project.resources,
                        )?
                        .join("\n"))
                })
                .collect::<Result<Vec<_>>>()?,
            Associations::Resources(resource_associations) => {
                self.user_host_specs_for_resource_associations(None, resource_associations)?
            }
        };
        let config = jump_configs + &alias_configs.join("\n");
        let config = "# CLIFTON MANAGED\n".to_string() + &config;
        Ok(config)
    }
}
