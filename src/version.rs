// SPDX-FileCopyrightText: © 2024 Matt Williams <matt.williams@bristol.ac.uk>
// SPDX-License-Identifier: MIT

use std::io::BufReader;

use anyhow::{Context, Result};

struct Release {
    version: semver::Version,
    date: chrono::NaiveDate,
}

impl Release {
    fn since(&self) -> chrono::TimeDelta {
        chrono::Local::now().date_naive() - self.date
    }
}

fn version() -> Result<semver::Version> {
    crate::version().parse().context(format!(
        "Could not parse version number '{}'",
        crate::version()
    ))
}

pub fn check_for_new_version(url: url::Url, grace_days: i64) -> Result<()> {
    let warning = anstyle::Style::new().bold();
    if !version()?.pre.is_empty() {
        eprintln!(
            "{warning}Warning: You are running a pre-release version of Clifton: {}{warning:#}",
            version()?
        );
        return Ok(());
    }
    let release = get_latest_release(url).context("Could not get latest release.")?;
    if release.version > version()? && release.since().num_days() >= grace_days {
        let since = {
            let days = release.since().num_days();
            match (days / 7, days % 7) {
                (0, 1) => format!("1 day"),
                (0, days) => format!("{} days", &days),
                (1, _) => format!("1 week"),
                (weeks, _) => format!("{} weeks", &weeks),
            }
        };
        eprintln!(
            "{warning}There is a new version of Clifton available.{warning:#} \
            {} was released {} ago. \
            Visit https://clifton.readthedocs.io/stable/install/ for installation instructions.",
            &release.version, &since
        );
        if release.version.major > version()?.major {
            eprintln!(
                "{warning}The new version is a major update. \
                Your current version may stop working if you do not upgrade.{warning:#}"
            );
        }
    }
    Ok(())
}

fn get_latest_release(url: url::Url) -> Result<Release> {
    let releases = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .context("Could not build HTTP client.")?
        .get(url)
        .send()
        .context("Could not get list of released versions.")?;
    atom_syndication::Feed::read_from(BufReader::new(releases))?
        .entries()
        .iter()
        .filter_map(|e| {
            if let Ok(version) = semver::Version::parse(&e.title.value) {
                Some(Release {
                    version,
                    date: e.updated.date_naive(),
                })
            } else {
                None
            }
        })
        .max_by_key(|r| r.version.clone())
        .context("Could not get maximum version.")
}

#[cfg(test)]
mod tests {
    use super::*;
    use atom_syndication::{Entry, Feed, Text};
    use mockito::Server;

    #[test]
    fn test_check_version() -> Result<()> {
        let mut server = Server::new();
        let mock = server
            .mock("GET", "/releases")
            .with_status(200)
            .with_header("content-type", "text/json")
            .with_body(
                Feed {
                    entries: vec![
                        Entry {
                            title: Text {
                                value: "100.0.0".to_string(),
                                ..Default::default()
                            },
                            updated: chrono::Local::now().fixed_offset()
                                - chrono::TimeDelta::days(5),
                            ..Default::default()
                        },
                        Entry {
                            title: Text {
                                value: "0.1.0".to_string(),
                                ..Default::default()
                            },
                            updated: "1970-01-01T12:00:00+00:00".parse()?,
                            ..Default::default()
                        },
                    ],
                    ..Default::default()
                }
                .to_string(),
            )
            .expect_at_least(1)
            .create();
        let url: url::Url = format!("{}/releases", server.url()).parse()?;
        let r = get_latest_release(url.clone())?;
        assert_eq!(
            r.version,
            "100.0.0".parse().context("Could not parse version.")?
        );
        assert_eq!(r.since().num_days(), 5);
        check_for_new_version(url.clone(), 2)?;
        mock.assert();
        Ok(())
    }
}
