// SPDX-FileCopyrightText: © 2024 Matt Williams <matt.williams@bristol.ac.uk>
// SPDX-License-Identifier: MIT

use anyhow::{Context, Result};
use itertools::Itertools as _;
use serde::{Deserialize, Deserializer, Serialize};
use std::time::SystemTime;
use std::{collections::HashMap, io::Write as _};

#[allow(clippy::large_enum_variant)]
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

#[derive(Clone, Debug, PartialEq, PartialOrd, Ord, Eq, Deserialize, Serialize)]
pub struct ResourceAssociation {
    pub username: String,
    pub certificate: ssh_key::Certificate,
}

type ProjectsV2 = HashMap<String, Vec<String>>;
type Projects = HashMap<String, Project>;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct Project {
    pub name: String,
    pub resources: HashMap<String, ResourceAssociation>,
}

type Resources = HashMap<String, Resource>;

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Resource {
    pub alias: String,
    #[serde(with = "http_serde::authority")]
    pub hostname: http::uri::Authority,
    #[serde(with = "http_serde::option::authority")]
    pub proxy_jump: Option<http::uri::Authority>,
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

#[derive(Deserialize, Serialize)]
pub struct CertificateConfigCache {
    resources: Resources,
    pub associations: AssociationsCache,
    pub user: String,
    pub identity: std::path::PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum AssociationsCache {
    Projects(ProjectsCache),
    Resources(HashMap<String, ResourceAssociationCache>),
}

type ProjectsCache = HashMap<String, ProjectCache>;

#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
pub struct ProjectCache {
    pub name: String,
    pub resources: HashMap<String, ResourceAssociationCache>,
}

#[derive(Clone, Debug, PartialEq, PartialOrd, Ord, Eq, Deserialize, Serialize)]
pub struct ResourceAssociationCache {
    pub username: String,
    pub certificate: std::path::PathBuf,
}

/// Write the certificate file to disk
fn write_certificate(
    certificate: &ssh_key::Certificate,
    path: &std::path::Path,
    slug: &String,
) -> Result<std::path::PathBuf> {
    let cert_file_path =
        path.join(std::ffi::OsString::from(format!("{}-cert.pub", &slug,)).as_os_str());
    let mut f = std::fs::OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;

        f = f.mode(0o600).clone(); // u=rw,g=,o=
    }
    f.write(true)
        .truncate(true)
        .create(true)
        .open(&cert_file_path)
        .context(format!(
            "Could not open certificate file `{}` for writing.",
            &cert_file_path.display()
        ))?
        .write_all(
            certificate
                .to_openssh()
                .context("Could not convert certificate to OpenSSH format.")?
                .as_ref(),
        )
        .context("Could not write certificate file.")?;
    Ok(cert_file_path)
}

impl CertificateSignResponse {
    /// Convert the certificate signing response to a object, saving
    /// the certificate contents to disk.
    pub fn cache(
        self,
        identity: std::path::PathBuf,
        certificate_dir: &std::path::PathBuf,
    ) -> Result<CertificateConfigCache> {
        std::fs::create_dir_all(certificate_dir)?;
        match &self {
            CertificateSignResponse::V2(CertificateSignResponseV2 {
                certificate,
                platforms,
                projects,
                short_name,
                user,
            }) => Ok(CertificateConfigCache {
                resources: platforms.clone(),
                associations: AssociationsCache::Projects(
                    projects
                        .iter()
                        .map(|(project_id, resource_ids)| {
                            Ok((
                                project_id.to_string(),
                                ProjectCache {
                                    name: "".to_string(),
                                    resources: resource_ids
                                        .iter()
                                        .map(|resource_id| {
                                            Ok((
                                                resource_id.to_string(),
                                                ResourceAssociationCache {
                                                    username: format!(
                                                        "{}.{}",
                                                        &short_name, project_id
                                                    ),
                                                    certificate: {
                                                        let slug = format!(
                                                            "{}.{}",
                                                            &project_id,
                                                            &platforms
                                                                .get(resource_id)
                                                                .context(format!(
                                                                    "Could not find resource details for `{}`",
                                                                    resource_id
                                                                ))?
                                                                .alias
                                                        );
                                                        write_certificate(
                                                            certificate,
                                                            certificate_dir,
                                                            &slug,
                                                        )?
                                                    },
                                                },
                                            ))
                                        })
                                        .collect::<Result<_>>()?,
                                },
                            ))
                        })
                        .collect::<Result<_>>()?,
                ),
                user: user.clone(),
                identity,
            }),
            CertificateSignResponse::V3(r) => Ok(CertificateConfigCache {
                resources: r.resources.clone(),
                associations: match &r.associations {
                    Associations::Resources(rs) => AssociationsCache::Resources(
                        rs.iter()
                            .map(|(resource_id, ra)| {
                                Ok((
                                    resource_id.clone(),
                                    ResourceAssociationCache {
                                        username: ra.username.clone(),
                                        certificate: write_certificate(
                                            &ra.certificate,
                                            certificate_dir,
                                            &r.resources.get(resource_id)
                                                .context(format!(
                                                    "Could not find resource details for `{}`",
                                                    resource_id
                                                ))?
                                                .alias,
                                        )?,
                                    },
                                ))
                            })
                            .collect::<Result<_>>()?,
                    ),
                    Associations::Projects(ps) => AssociationsCache::Projects(
                        ps.iter()
                            .map(|(project_id, p)| {
                                Ok((
                                    project_id.clone(),
                                    ProjectCache {
                                        name: p.name.clone(),
                                        resources: p
                                            .resources
                                            .iter()
                                            .map(|(resource_id, ra)| {
                                                Ok((
                                                    resource_id.clone(),
                                                    ResourceAssociationCache {
                                                        username: ra.username.clone(),
                                                        certificate: write_certificate(
                                                            &ra.certificate,
                                                            certificate_dir,
                                                            &format!(
                                                                "{}.{}",
                                                                &project_id,
                                                                &r.resources
                                                                    .get(resource_id)
                                                                    .context(format!(
                                                                        "Could not find resource details for `{}`",
                                                                        resource_id
                                                                    ))?
                                                                    .alias
                                                            ),
                                                        )?,
                                                    },
                                                ))
                                            })
                                            .collect::<Result<_>>()?,
                                    },
                                ))
                            })
                            .collect::<Result<_>>()?,
                    ),
                },
                user: r.user.clone(),
                identity,
            }),
        }
    }
}

impl CertificateConfigCache {
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
        resource: &ResourceAssociationCache,
    ) -> Result<String> {
        let alias = &self.resource(resource_id)?.alias;
        let alias = if let Some(prefix) = prefix {
            format!("{}.{}", prefix, alias)
        } else {
            alias.to_string()
        };
        let project_jump_config = format!(
            "Host jump.{alias}\n\
                        \tCertificateFile \"{}\"\n",
            &resource.certificate.display(),
        );
        let project_config = format!(
            "Host {alias}\n\
                        \tUser {}\n\
                        \tCertificateFile \"{}\"\n",
            &resource.username,
            &resource.certificate.display(),
        );
        Ok(format!("{}{}", project_jump_config, project_config))
    }

    /// Make a list of SSH config `Host` entries for a set of resource associations
    /// The optional prefix will be placed in front of the Host alias name
    fn user_host_specs_for_resource_associations(
        &self,
        prefix: Option<&String>,
        resource_associations: &HashMap<String, ResourceAssociationCache>,
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
                    let jump_alias = format!("jump.*.{}", &c.alias);
                    let jump_config = format!(
                        "Host {jump_alias}\n\
                                \tHostname {}\n\
                                \tIdentityFile \"{1}\"\n",
                        proxy_jump,
                        self.identity.display(),
                    );
                    let host_config = format!(
                        "Host *.{0} !{jump_alias}\n\
                                \tHostname {1}\n\
                                \tProxyJump %r@jump.%n\n\
                                \tIdentityFile \"{2}\"\n\
                                \tAddKeysToAgent yes\n",
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
                                \tAddKeysToAgent yes\n\
                            \n",
                        &c.alias,
                        &c.hostname,
                        self.identity.display(),
                    )
                }
            })
            .collect::<Vec<String>>()
            .join("\n");

        let alias_configs = match &self.associations {
            AssociationsCache::Projects(projects) => projects
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
            AssociationsCache::Resources(resource_associations) => {
                self.user_host_specs_for_resource_associations(None, resource_associations)?
            }
        };
        let config = jump_configs + "\n" + &alias_configs.join("\n");
        let config = "# CLIFTON MANAGED\n".to_string() + &config;
        Ok(config)
    }

    pub fn first_expiry(&self) -> Option<SystemTime> {
        // We are, in prinicple, returned many certificates. Find the one with the soonest expiry time and print it.
        match &self.associations {
            AssociationsCache::Projects(projects) => projects
                .values()
                .filter_map(|p| {
                    p.resources
                        .iter()
                        .filter_map(|(_, ra)| {
                            ssh_key::Certificate::read_file(ra.certificate.as_path()).ok()
                        })
                        .map(|cert| cert.valid_before_time())
                        .min()
                })
                .min(),
            AssociationsCache::Resources(resources) => resources
                .values()
                .filter_map(|ra| ssh_key::Certificate::read_file(ra.certificate.as_path()).ok())
                .map(|cert| cert.valid_before_time())
                .min(),
        }
    }
}
