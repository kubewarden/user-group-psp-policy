use crate::LOG_DRAIN;

use serde::{Deserialize, Serialize};
use slog::info;
use std::collections::HashSet;

#[derive(Serialize, Deserialize, Default, Debug)]
#[serde(default)]
pub(crate) struct IDRange {
    pub min: i64,
    pub max: i64,
}

#[derive(Serialize, Deserialize, Default, Debug)]
#[serde(default)]
pub(crate) struct RuleStrategy {
    pub rule: String,
    pub ranges: Vec<IDRange>,
}
// Describe the settings your policy expects when
// loaded by the policy server.
#[derive(Serialize, Deserialize, Default, Debug)]
#[serde(default)]
pub(crate) struct Settings {
    pub run_as_user: RuleStrategy,
    pub run_as_group: RuleStrategy,
    pub supplemental_groups: RuleStrategy,
}

impl kubewarden::settings::Validatable for Settings {
    fn validate(&self) -> Result<(), String> {
        info!(LOG_DRAIN, "starting settings validation");
        let allowed_rules_values: HashSet<String> = vec![
            "RunAsAny".to_string(),
            "MustRunAs".to_string(),
            "MustRunAsNonRoot".to_string(),
        ]
        .into_iter()
        .collect();
        let allowed_group_rules_values: HashSet<String> = vec![
            "RunAsAny".to_string(),
            "MustRunAs".to_string(),
            "MayRunAs".to_string(),
        ]
        .into_iter()
        .collect();

        if !allowed_rules_values.contains(&self.run_as_user.rule) {
            return Err(String::from("Invalid RunAsUser rule."));
        } else if &self.run_as_user.rule == "MustRunAs" && self.run_as_user.ranges.is_empty() {
            return Err(String::from("Missing ID Range"));
        }
        if !allowed_group_rules_values.contains(&self.run_as_group.rule) {
            return Err(String::from("Invalid RunAsGroup rule."));
        } else if &self.run_as_group.rule == "MustRunAs" && self.run_as_group.ranges.is_empty() {
            return Err(String::from("Missing ID Range"));
        }
        if !allowed_group_rules_values.contains(&self.supplemental_groups.rule) {
            return Err(String::from("Invalid SupplementalGroups rule."));
        } else if &self.supplemental_groups.rule == "MustRunAs"
            && self.supplemental_groups.ranges.is_empty()
        {
            return Err(String::from("Missing ID Range"));
        }
        for range in &self.run_as_user.ranges {
            if range.min > range.max {
                return Err(String::from("Min value greater than max value"));
            }
        }
        for range in &self.run_as_group.ranges {
            if range.min > range.max {
                return Err(String::from("Min value greater than max value"));
            }
        }
        for range in &self.supplemental_groups.ranges {
            if range.min > range.max {
                return Err(String::from("Min value greater than max value"));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use kubewarden_policy_sdk::settings::Validatable;

    #[test]
    fn validate_settings() -> Result<(), ()> {
        let settings = Settings {
            run_as_user: RuleStrategy {
                rule: String::from("RunAsAny"),
                ranges: vec![IDRange { min: 1, max: 10 }],
            },
            run_as_group: RuleStrategy {
                rule: String::from("RunAsAny"),
                ranges: vec![IDRange { min: 1, max: 10 }],
            },
            supplemental_groups: RuleStrategy {
                rule: String::from("RunAsAny"),
                ranges: vec![IDRange { min: 1, max: 10 }],
            },
        };

        assert!(settings.validate().is_ok());
        Ok(())
    }

    #[test]
    fn validate_run_as_user_rule_values() -> Result<(), ()> {
        let allowed_rules_values = ["RunAsAny", "MustRunAs", "MustRunAsNonRoot"];
        for rule in allowed_rules_values {
            let settings = Settings {
                run_as_user: RuleStrategy {
                    rule: String::from(rule),
                    ranges: vec![IDRange { min: 1, max: 10 }],
                },
                run_as_group: RuleStrategy {
                    rule: String::from("RunAsAny"),
                    ranges: vec![IDRange { min: 1, max: 10 }],
                },
                supplemental_groups: RuleStrategy {
                    rule: String::from("RunAsAny"),
                    ranges: vec![IDRange { min: 1, max: 10 }],
                },
            };

            assert!(settings.validate().is_ok());
        }
        Ok(())
    }

    #[test]
    fn validate_run_as_groups_and_supplemental_groups_rule_values() -> Result<(), ()> {
        let allowed_rules_values = ["RunAsAny", "MustRunAs", "MayRunAs"];
        for rule in allowed_rules_values {
            let settings = Settings {
                run_as_user: RuleStrategy {
                    rule: String::from("RunAsAny"),
                    ranges: vec![IDRange { min: 1, max: 10 }],
                },
                run_as_group: RuleStrategy {
                    rule: String::from(rule),
                    ranges: vec![IDRange { min: 1, max: 10 }],
                },
                supplemental_groups: RuleStrategy {
                    rule: String::from("RunAsAny"),
                    ranges: vec![IDRange { min: 1, max: 10 }],
                },
            };

            assert!(settings.validate().is_ok());

            let settings = Settings {
                run_as_user: RuleStrategy {
                    rule: String::from("RunAsAny"),
                    ranges: vec![IDRange { min: 1, max: 10 }],
                },
                run_as_group: RuleStrategy {
                    rule: String::from("RunAsAny"),
                    ranges: vec![IDRange { min: 1, max: 10 }],
                },
                supplemental_groups: RuleStrategy {
                    rule: String::from(rule),
                    ranges: vec![IDRange { min: 1, max: 10 }],
                },
            };

            assert!(settings.validate().is_ok());
        }
        Ok(())
    }

    #[test]
    fn validate_run_as_user_rule_invalid_values() -> Result<(), ()> {
        let allowed_rules_values = ["MayRunAs", "foo", "1234", "!@#$@#"];
        for rule in allowed_rules_values {
            let settings = Settings {
                run_as_user: RuleStrategy {
                    rule: String::from(rule),
                    ranges: vec![IDRange { min: 1, max: 10 }],
                },
                run_as_group: RuleStrategy {
                    rule: String::from("RunAsAny"),
                    ranges: vec![IDRange { min: 1, max: 10 }],
                },
                supplemental_groups: RuleStrategy {
                    rule: String::from("RunAsAny"),
                    ranges: vec![IDRange { min: 1, max: 10 }],
                },
            };

            assert!(
                settings.validate().is_err(),
                "User rule should not accept '{}' as rule value",
                rule
            );
        }
        Ok(())
    }

    #[test]
    fn validate_run_as_group_rule_invalid_values() -> Result<(), ()> {
        let allowed_rules_values = ["MustRunAsNonRoot", "foo", "1234", "!@#$@#"];
        for rule in allowed_rules_values {
            let settings = Settings {
                run_as_user: RuleStrategy {
                    rule: String::from("RunAsAny"),
                    ranges: vec![IDRange { min: 1, max: 10 }],
                },
                run_as_group: RuleStrategy {
                    rule: String::from(rule),
                    ranges: vec![IDRange { min: 1, max: 10 }],
                },
                supplemental_groups: RuleStrategy {
                    rule: String::from("RunAsAny"),
                    ranges: vec![IDRange { min: 1, max: 10 }],
                },
            };

            assert!(
                settings.validate().is_err(),
                "Group rule should not accept '{}' as rule value",
                rule
            );

            let settings = Settings {
                run_as_user: RuleStrategy {
                    rule: String::from("RunAsAny"),
                    ranges: vec![IDRange { min: 1, max: 10 }],
                },
                run_as_group: RuleStrategy {
                    rule: String::from("RunAsAny"),
                    ranges: vec![IDRange { min: 1, max: 10 }],
                },
                supplemental_groups: RuleStrategy {
                    rule: String::from(rule),
                    ranges: vec![IDRange { min: 1, max: 10 }],
                },
            };

            assert!(
                settings.validate().is_err(),
                "Supplemental group rule should not accept '{}' as rule value",
                rule
            );
        }
        Ok(())
    }

    #[test]
    fn validate_id_range_min_should_be_greater_than_max() -> Result<(), ()> {
        let settings = Settings {
            run_as_user: RuleStrategy {
                rule: String::from("RunAsAny"),
                ranges: vec![IDRange { min: 11, max: 10 }],
            },
            run_as_group: RuleStrategy {
                rule: String::from("RunAsAny"),
                ranges: vec![IDRange { min: 1, max: 10 }],
            },
            supplemental_groups: RuleStrategy {
                rule: String::from("RunAsAny"),
                ranges: vec![IDRange { min: 1, max: 10 }],
            },
        };

        assert!(
            settings.validate().is_err(),
            "RunAsUser minimum ID Range value should be less than the max value"
        );

        let settings = Settings {
            run_as_user: RuleStrategy {
                rule: String::from("RunAsAny"),
                ranges: vec![IDRange { min: 1, max: 10 }],
            },
            run_as_group: RuleStrategy {
                rule: String::from("RunAsAny"),
                ranges: vec![IDRange { min: 11, max: 10 }],
            },
            supplemental_groups: RuleStrategy {
                rule: String::from("RunAsAny"),
                ranges: vec![IDRange { min: 1, max: 10 }],
            },
        };

        assert!(
            settings.validate().is_err(),
            "RunAsGroup minimum ID Range value should be less than the max value"
        );

        let settings = Settings {
            run_as_user: RuleStrategy {
                rule: String::from("RunAsAny"),
                ranges: vec![IDRange { min: 1, max: 10 }],
            },
            run_as_group: RuleStrategy {
                rule: String::from("RunAsAny"),
                ranges: vec![IDRange { min: 1, max: 10 }],
            },
            supplemental_groups: RuleStrategy {
                rule: String::from("RunAsAny"),
                ranges: vec![IDRange { min: 1, max: 10 }, IDRange { min: 11, max: 10 }],
            },
        };

        assert!(
            settings.validate().is_err(),
            "SupplementalGroups minimum ID Range value should be less than the max value"
        );
        Ok(())
    }

    #[test]
    fn one_range_is_necessary() -> Result<(), ()> {
        let settings = Settings {
            run_as_user: RuleStrategy {
                rule: String::from("MustRunAs"),
                ranges: vec![],
            },
            run_as_group: RuleStrategy {
                rule: String::from("RunAsAny"),
                ranges: vec![IDRange { min: 1, max: 10 }],
            },
            supplemental_groups: RuleStrategy {
                rule: String::from("RunAsAny"),
                ranges: vec![IDRange { min: 1, max: 10 }],
            },
        };

        assert!(
            settings.validate().is_err(),
            "MustRunAs rule requires at least one ID range"
        );

        let settings = Settings {
            run_as_user: RuleStrategy {
                rule: String::from("RunAsAny"),
                ranges: vec![IDRange { min: 1, max: 10 }],
            },
            run_as_group: RuleStrategy {
                rule: String::from("MustRunAs"),
                ranges: vec![],
            },
            supplemental_groups: RuleStrategy {
                rule: String::from("RunAsAny"),
                ranges: vec![IDRange { min: 1, max: 10 }],
            },
        };

        assert!(
            settings.validate().is_err(),
            "MustRunAs rule requires at least one ID range"
        );

        let settings = Settings {
            run_as_user: RuleStrategy {
                rule: String::from("RunAsAny"),
                ranges: vec![IDRange { min: 1, max: 10 }],
            },
            run_as_group: RuleStrategy {
                rule: String::from("RunAsAny"),
                ranges: vec![IDRange { min: 1, max: 10 }],
            },
            supplemental_groups: RuleStrategy {
                rule: String::from("MustRunAs"),
                ranges: vec![],
            },
        };

        assert!(
            settings.validate().is_err(),
            "MustRunAs rule requires at least one ID range"
        );

        Ok(())
    }
}
