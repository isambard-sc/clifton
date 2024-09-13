// SPDX-FileCopyrightText: © 2024 Matt Williams <matt.williams@bristol.ac.uk>
// SPDX-License-Identifier: MIT

use anyhow::{Context, Result};
use serde::Deserialize;

#[derive(Deserialize, Clone)]
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
    let release = get_latest_release(url).context("Could not get latest release.")?;
    if release.version > version()? && release.since().num_days() >= grace_days {
        eprintln!(
            "There is a new version of Clifton available. \
            {} was released {} days ago. \
            Visit https://github.com/isambard-sc/clifton/releases/tag/{0} to download it.",
            &release.version,
            &release.since().num_days()
        );
        if release.version.major > version()?.major {
            eprintln!(
                "The new version is a major update. \
                Your current version may stop working if you do not upgrade."
            );
        }
    }
    Ok(())
}

fn get_latest_release(url: url::Url) -> Result<Release> {
    let releases: Vec<Release> = reqwest::blocking::Client::builder()
        .timeout(std::time::Duration::from_secs(5))
        .build()
        .context("Could not build HTTP client.")?
        .get(url)
        .send()
        .context("Could not get list of released versions.")?
        .json()
        .context("Could not parse JSON response.")?;
    releases
        .iter()
        .max_by_key(|r| &r.version)
        .context("Could not get maximum version.")
        .cloned()
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito::Server;
    use serde_json::json;

    #[test]
    fn test_check_version() -> Result<()> {
        let mut server = Server::new();
        let mock = server
            .mock("GET", "/releases")
            .with_status(200)
            .with_header("content-type", "text/json")
            .with_body(
                json!([
                    {
                        "version": "100.0.0",
                        "date": chrono::Local::now().date_naive() - chrono::TimeDelta::days(5)
                    },
                    {
                        "version": "0.1.0",
                        "date": "1970-01-01"
                    }
                ])
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
