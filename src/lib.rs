use lazy_static::lazy_static;

use guest::prelude::*;
use kubewarden_policy_sdk::host_capabilities::oci::get_manifest_and_config;
use kubewarden_policy_sdk::wapc_guest as guest;

use anyhow::{anyhow, Result};
use k8s_openapi::api::core::v1 as apicore;

extern crate kubewarden_policy_sdk as kubewarden;
use kubewarden::{logging, protocol_version_guest, request::ValidationRequest, validate_settings};

mod settings;
use settings::{Rule, Settings};

use slog::{o, warn, Logger};

lazy_static! {
    static ref LOG_DRAIN: Logger = Logger::root(
        logging::KubewardenDrain::new(),
        o!("policy" => "user-group-policy")
    );
}

#[no_mangle]
pub extern "C" fn wapc_init() {
    register_function("validate", validate);
    register_function("validate_settings", validate_settings::<Settings>);
    register_function("protocol_version", protocol_version_guest);
}

trait GenericSecurityContext {
    fn run_as_user(&self) -> Option<i64>;
    fn set_run_as_user(&mut self, run_as_user: Option<i64>);
    fn run_as_non_root(&self) -> Option<bool>;
    fn set_run_as_non_root(&mut self, run_as_non_root: Option<bool>);
    fn run_as_group(&self) -> Option<i64>;
    fn set_run_as_group(&mut self, run_as_group: Option<i64>);
}

impl GenericSecurityContext for apicore::SecurityContext {
    fn run_as_user(&self) -> Option<i64> {
        self.run_as_user
    }

    fn set_run_as_user(&mut self, run_as_user: Option<i64>) {
        self.run_as_user = run_as_user;
    }

    fn run_as_group(&self) -> Option<i64> {
        self.run_as_group
    }

    fn set_run_as_group(&mut self, run_as_group: Option<i64>) {
        self.run_as_group = run_as_group;
    }

    fn run_as_non_root(&self) -> Option<bool> {
        self.run_as_non_root
    }

    fn set_run_as_non_root(&mut self, run_as_non_root: Option<bool>) {
        self.run_as_non_root = run_as_non_root;
    }
}

impl GenericSecurityContext for apicore::PodSecurityContext {
    fn run_as_user(&self) -> Option<i64> {
        self.run_as_user
    }

    fn set_run_as_user(&mut self, run_as_user: Option<i64>) {
        self.run_as_user = run_as_user;
    }

    fn run_as_group(&self) -> Option<i64> {
        self.run_as_group
    }

    fn set_run_as_group(&mut self, run_as_group: Option<i64>) {
        self.run_as_group = run_as_group;
    }

    fn run_as_non_root(&self) -> Option<bool> {
        self.run_as_non_root
    }

    fn set_run_as_non_root(&mut self, run_as_non_root: Option<bool>) {
        self.run_as_non_root = run_as_non_root;
    }
}

fn get_user_group_uid_from_image_configuration(
    container_image_config: Option<oci_spec::image::ImageConfiguration>,
) -> Result<(Option<i64>, Option<i64>)> {
    if let Some(image_config) = container_image_config {
        if let Some(user) = image_config.config().clone().unwrap_or_default().user() {
            let user_group: Vec<&str> = user.split(':').collect();
            if let Ok(user_id) = user_group[0].parse::<i64>() {
                if user_group.len() == 2 {
                    if let Ok(group_id) = user_group[1].parse::<i64>() {
                        return Ok((Some(user_id), Some(group_id)));
                    } else {
                        return Err(anyhow!(
                            "Invalid group ID in the container image configuration: \"{}\"",
                            user_group[1]
                        ));
                    }
                }
                return Ok((Some(user_id), None));
            } else {
                return Err(anyhow!(
                    "Invalid user ID in the container image configuration: \"{}\"",
                    user_group[0]
                ));
            }
        }
    }
    Ok((None, None))
}

fn enforce_run_as_user_rule<T>(
    security_context_option: Option<T>,
    validation_request: &ValidationRequest<Settings>,
    container_image_config: Option<oci_spec::image::ImageConfiguration>,
) -> Result<Option<T>>
where
    T: GenericSecurityContext + std::default::Default,
{
    let container_user_group_uid =
        get_user_group_uid_from_image_configuration(container_image_config)?;
    let mut security_context = security_context_option.unwrap_or_default();
    match validation_request.settings.run_as_user.rule {
        Rule::MustRunAs => {
            if let (Some(user_id), _) = container_user_group_uid {
                if !validation_request.settings.run_as_user.is_valid_id(user_id) {
                    return Err(anyhow!(
                        "User ID defined in the container image is outside defined ranges"
                    ));
                }
            }
            if validation_request.settings.run_as_user.overwrite
                || security_context.run_as_user().is_none()
            {
                let default_user_id = validation_request.settings.run_as_user.ranges[0].min;
                security_context.set_run_as_user(Some(default_user_id));
                return Ok(Some(security_context));
            }
            if let Some(user_id) = security_context.run_as_user() {
                if !validation_request.settings.run_as_user.is_valid_id(user_id) {
                    return Err(anyhow!("User ID outside defined ranges"));
                }
            }
        }
        Rule::MustRunAsNonRoot => {
            if let (Some(user_id), _) = container_user_group_uid {
                if user_id == 0 {
                    return Err(anyhow!(
                        "User ID defined in the container image cannot be root ID (0)"
                    ));
                }
            }
            if let Some(run_as_non_root) = security_context.run_as_non_root() {
                if !run_as_non_root {
                    return Err(anyhow!("RunAsNonRoot should be set to true"));
                }
            }
            if let Some(user_id) = security_context.run_as_user() {
                if user_id == 0 {
                    return Err(anyhow!(
                        "Invalid user ID: cannot run container with root ID (0)"
                    ));
                }
            }
            security_context.set_run_as_non_root(Some(true));
            return Ok(Some(security_context));
        }
        _ => {}
    }
    Ok(None)
}

fn enforce_container_image_group(
    validation_request: &ValidationRequest<Settings>,
    container_image_config: Option<oci_spec::image::ImageConfiguration>,
) -> Result<()>
where
{
    let container_user_group_uid =
        get_user_group_uid_from_image_configuration(container_image_config)?;
    if let (_, Some(group_id)) = container_user_group_uid {
        if !validation_request
            .settings
            .run_as_group
            .is_valid_id(group_id)
        {
            return Err(anyhow!(
                "Group ID defined in the container image is outside defined ranges"
            ));
        }
    }
    Ok(())
}

fn enforce_run_as_group<T>(
    security_context_option: Option<T>,
    validation_request: &ValidationRequest<Settings>,
    container_image_config: Option<oci_spec::image::ImageConfiguration>,
) -> Result<Option<T>>
where
    T: GenericSecurityContext + std::default::Default,
{
    let mut security_context = security_context_option.unwrap_or_default();
    match validation_request.settings.run_as_group.rule {
        Rule::MustRunAs => {
            enforce_container_image_group(validation_request, container_image_config)?;
            if validation_request.settings.run_as_group.overwrite
                || security_context.run_as_group().is_none()
            {
                let default_group_id = validation_request.settings.run_as_group.ranges[0].min;
                security_context.set_run_as_group(Some(default_group_id));
                return Ok(Some(security_context));
            }
            if let Some(group_id) = security_context.run_as_group() {
                if !validation_request
                    .settings
                    .run_as_group
                    .is_valid_id(group_id)
                {
                    return Err(anyhow!("Group ID is outside defined ranges"));
                }
            }
        }
        Rule::MayRunAs => {
            enforce_container_image_group(validation_request, container_image_config)?;
            if let Some(group_id) = security_context.run_as_group() {
                if !validation_request
                    .settings
                    .run_as_group
                    .is_valid_id(group_id)
                {
                    return Err(anyhow!("Group ID is outside defined ranges"));
                }
            }
        }
        _ => {}
    }
    Ok(None)
}

fn enforce_supplemental_groups(
    security_context_option: Option<apicore::PodSecurityContext>,
    validation_request: &ValidationRequest<Settings>,
) -> Result<Option<apicore::PodSecurityContext>> {
    let mut security_context = security_context_option.unwrap_or_default();
    match validation_request.settings.supplemental_groups.rule {
        Rule::MustRunAs => {
            if validation_request.settings.supplemental_groups.overwrite
                || security_context.supplemental_groups.is_none()
            {
                let default_group_id =
                    validation_request.settings.supplemental_groups.ranges[0].min;
                security_context.supplemental_groups = Some(vec![default_group_id]);
                return Ok(Some(security_context));
            }
            if let Some(group_ids) = security_context.supplemental_groups {
                for group_id in group_ids {
                    if !validation_request
                        .settings
                        .supplemental_groups
                        .is_valid_id(group_id)
                    {
                        return Err(anyhow!("Group ID is outside defined ranges"));
                    }
                }
            }
        }
        Rule::MayRunAs => {
            if let Some(group_ids) = security_context.supplemental_groups {
                for group_id in group_ids {
                    if !validation_request
                        .settings
                        .supplemental_groups
                        .is_valid_id(group_id)
                    {
                        return Err(anyhow!("Group ID is outside defined ranges"));
                    }
                }
            }
        }
        _ => (),
    }
    Ok(None)
}

fn enforce_container_security_policies(
    container: &mut apicore::Container,
    validation_request: &ValidationRequest<Settings>,
) -> Result<bool> {
    let container_image_config = if validation_request
        .settings
        .validate_container_image_configuration
    {
        let container_image = container.image.as_ref().unwrap();
        let response = get_manifest_and_config(container_image)?;
        if *response.config.os() != oci_spec::image::Os::Windows {
            Some(response.config)
        } else {
            warn!(LOG_DRAIN, "Windows containers are not supported by the policy. Skipping container image configuration user validation."; "image" => &container_image);
            None
        }
    } else {
        None
    };

    let mut mutated: bool = false;
    let mutate_request = enforce_run_as_user_rule(
        container.security_context.clone(),
        validation_request,
        container_image_config.clone(),
    )?;
    if mutate_request.is_some() {
        mutated = true;
        container.security_context = mutate_request;
    }
    let mutate_request = enforce_run_as_group(
        container.security_context.clone(),
        validation_request,
        container_image_config,
    )?;
    if mutate_request.is_some() {
        mutated = true;
        container.security_context = mutate_request;
    }
    Ok(mutated)
}

fn enforce_pod_spec_security_policies(
    podspec: &mut apicore::PodSpec,
    validation_request: &ValidationRequest<Settings>,
) -> Result<bool> {
    let mut mutated: bool = false;
    let mutate_request =
        enforce_run_as_user_rule(podspec.security_context.clone(), validation_request, None)?;
    if mutate_request.is_some() {
        mutated = true;
        podspec.security_context = mutate_request;
    }
    let mutate_request =
        enforce_run_as_group(podspec.security_context.clone(), validation_request, None)?;
    if mutate_request.is_some() {
        mutated = true;
        podspec.security_context = mutate_request;
    }
    Ok(mutated)
}

fn validate(payload: &[u8]) -> CallResult {
    let validation_request: ValidationRequest<Settings> = ValidationRequest::new(payload)?;
    match validation_request.extract_pod_spec_from_object() {
        Ok(pod_spec) => {
            if let Some(mut pod_spec) = pod_spec {
                let mut mutated: bool = false;

                // first, check that all containers are valid, and mutate if necessary
                //
                if let Some(init_containers) = pod_spec.init_containers.as_mut() {
                    for init_container in init_containers.iter_mut() {
                        match enforce_container_security_policies(
                            init_container,
                            &validation_request,
                        ) {
                            Ok(mutate_request) => mutated = mutated || mutate_request,
                            Err(error) => {
                                return kubewarden::reject_request(
                                    Some(error.to_string()),
                                    None,
                                    None,
                                    None,
                                )
                            }
                        }
                    }
                }
                for container in pod_spec.containers.iter_mut() {
                    match enforce_container_security_policies(container, &validation_request) {
                        Ok(mutate_request) => mutated = mutated || mutate_request,
                        Err(error) => {
                            return kubewarden::reject_request(
                                Some(error.to_string()),
                                None,
                                None,
                                None,
                            )
                        }
                    }
                }

                // if all containers are valid, their securityContext has precendence over the
                // pod.spec.securityContext. Hence, do nothing.
                // If containers are invalid, also mutate pod.spec.securityContext:
                if mutated {
                    match enforce_pod_spec_security_policies(&mut pod_spec, &validation_request) {
                        Ok(mutate_request) => mutated = mutated || mutate_request,
                        Err(error) => {
                            return kubewarden::reject_request(
                                Some(error.to_string()),
                                None,
                                None,
                                None,
                            )
                        }
                    }
                }

                match enforce_supplemental_groups(
                    pod_spec.security_context.clone(),
                    &validation_request,
                ) {
                    Ok(mutate_security_context) => {
                        if mutate_security_context.is_some() {
                            mutated = true;
                            pod_spec.security_context = mutate_security_context;
                        }
                    }
                    Err(msg) => {
                        return kubewarden::reject_request(Some(msg.to_string()), None, None, None);
                    }
                }

                if mutated {
                    return kubewarden::mutate_pod_spec_from_request(validation_request, pod_spec);
                } else {
                    return kubewarden::accept_request();
                }
            };
            // If there is not pod spec, just accept it. There is no data to be
            // validated.
            kubewarden::accept_request()
        }
        Err(_) => kubewarden::reject_request(
            Some("Cannot parse validation request".to_string()),
            None,
            None,
            None,
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use k8s_openapi::api::core::v1::SecurityContext;
    use kubewarden::request::KubernetesAdmissionRequest;
    use rstest::rstest;

    use jsonpath_lib as jsonpath;
    use kubewarden_policy_sdk::response::ValidationResponse;
    use kubewarden_policy_sdk::test::Testcase;
    use oci_spec::image::{ConfigBuilder, ImageConfigurationBuilder};
    use settings::Settings;
    use settings::{IDRange, RuleStrategy};

    #[test]
    fn may_run_as_should_accept_request_if_supplemental_group_id_is_valid() -> Result<(), ()> {
        let request_file = "test_data/pod_creation_valid_supplemental_group.json";
        let tc = Testcase {
            name: String::from(
                "MayRunAs should accept request when valid SupplementalGroups value is set",
            ),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings {
                run_as_user: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                run_as_group: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                supplemental_groups: RuleStrategy {
                    rule: Rule::MayRunAs,
                    ranges: vec![IDRange {
                        min: 1000,
                        max: 4000,
                    }],
                    ..Default::default()
                },
                ..Default::default()
            },
        };
        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Request should not be mutated"
        );
        Ok(())
    }

    #[test]
    fn may_run_as_should_reject_request_if_supplemental_group_is_invalid() -> Result<(), ()> {
        let request_file = "test_data/pod_creation_invalid_supplemental_group.json";
        let tc = Testcase {
            name: String::from(
                "MayRunAs should reject request when no SupplementalGroups value is invalid",
            ),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: Settings {
                run_as_user: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                run_as_group: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                supplemental_groups: RuleStrategy {
                    rule: Rule::MayRunAs,
                    ranges: vec![IDRange {
                        min: 2000,
                        max: 2500,
                    }],
                    ..Default::default()
                },
                ..Default::default()
            },
        };
        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Request should not be mutated"
        );
        Ok(())
    }

    #[test]
    fn may_run_as_should_accept_request_if_supplemental_group_is_not_defined() -> Result<(), ()> {
        let request_file = "test_data/pod_creation_must_run_as_with_no_value.json";
        let tc = Testcase {
            name: String::from(
                "MayRunAs should accept request when no SupplementalGroups value is set",
            ),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings {
                run_as_user: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                run_as_group: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                supplemental_groups: RuleStrategy {
                    rule: Rule::MayRunAs,
                    ranges: vec![IDRange {
                        min: 2000,
                        max: 2500,
                    }],
                    ..Default::default()
                },
                ..Default::default()
            },
        };
        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Request should not be mutated"
        );
        Ok(())
    }

    #[test]
    fn must_run_as_should_mutate_request_when_supplemental_group_id_is_not_defined(
    ) -> Result<(), ()> {
        let request_file = "test_data/pod_creation_must_run_as_with_no_value.json";
        let tc = Testcase {
            name: String::from(
                "'MustRunAs' should mutate request when supplemental group ID is missing",
            ),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings {
                run_as_user: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                run_as_group: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                supplemental_groups: RuleStrategy {
                    rule: Rule::MustRunAs,
                    ranges: vec![
                        IDRange {
                            min: 1500,
                            max: 2000,
                        },
                        IDRange {
                            min: 2500,
                            max: 3000,
                        },
                    ],
                    ..Default::default()
                },
                ..Default::default()
            },
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_some(),
            "MustRunAs should mutate request"
        );
        let supplemental_groups_json = jsonpath::select(
            res.mutated_object.as_ref().unwrap(),
            "$.spec.securityContext.supplementalGroups[*]",
        )
        .unwrap();
        assert_eq!(
            supplemental_groups_json,
            vec![1500],
            "MustRunAs should add the 'supplementalGroups' when it is not defined"
        );
        Ok(())
    }

    #[test]
    fn must_run_as_should_accept_when_supplemental_group_id_is_valid() -> Result<(), ()> {
        let request_file = "test_data/pod_creation_valid_supplemental_group.json";
        let tc = Testcase {
            name: String::from(
                "'MustRunAs' should accept request when supplemental group ID is valid",
            ),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings {
                run_as_user: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                run_as_group: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                supplemental_groups: RuleStrategy {
                    rule: Rule::MustRunAs,
                    ranges: vec![
                        IDRange {
                            min: 1500,
                            max: 2000,
                        },
                        IDRange {
                            min: 2500,
                            max: 3000,
                        },
                    ],
                    ..Default::default()
                },
                ..Default::default()
            },
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "MustRunAs should not mutate request"
        );
        Ok(())
    }

    #[test]
    fn must_run_as_should_reject_when_supplemental_group_id_is_invalid() -> Result<(), ()> {
        let request_file = "test_data/pod_creation_invalid_supplemental_group.json";
        let tc = Testcase {
            name: String::from(
                "'MustRunAs' should reject request when supplemental group ID is invalid",
            ),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: Settings {
                run_as_user: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                run_as_group: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                supplemental_groups: RuleStrategy {
                    rule: Rule::MustRunAs,
                    ranges: vec![
                        IDRange {
                            min: 1500,
                            max: 2000,
                        },
                        IDRange {
                            min: 2500,
                            max: 3000,
                        },
                    ],
                    ..Default::default()
                },
                ..Default::default()
            },
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "MustRunAs should not mutate request"
        );
        Ok(())
    }

    #[test]
    fn must_run_as_non_root_should_reject_request_when_run_as_non_root_is_false() -> Result<(), ()>
    {
        let request_file = "test_data/pod_creation_run_as_non_root_is_false.json";
        let tc = Testcase {
            name: String::from("MustRunAsNonRoot should reject request if 'runAsNonRoot' is false"),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: Settings {
                run_as_user: RuleStrategy {
                    rule: Rule::MustRunAsNonRoot,
                    ranges: vec![],
                    ..Default::default()
                },
                run_as_group: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                supplemental_groups: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                ..Default::default()
            },
        };
        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Request should not be mutated"
        );
        Ok(())
    }

    #[test]
    fn must_run_as_non_root_should_mutate_request_when_run_as_user_is_not_defined() -> Result<(), ()>
    {
        let request_file = "test_data/pod_creation_must_run_as_with_no_user_id.json";
        let tc = Testcase {
            name: String::from(
                "MustRunAsNonRoot should add 'runAsNonRoot' when 'runAsUser' is not defined",
            ),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings {
                run_as_user: RuleStrategy {
                    rule: Rule::MustRunAsNonRoot,
                    ranges: vec![],
                    ..Default::default()
                },
                run_as_group: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                supplemental_groups: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                ..Default::default()
            },
        };
        let res = tc.eval(validate).unwrap();
        assert!(res.mutated_object.is_some(), "Request should be mutated");
        let run_as_non_root_json = jsonpath::select(
            res.mutated_object.as_ref().unwrap(),
            "$.spec.containers[*].securityContext.runAsNonRoot",
        )
        .unwrap();
        assert_eq!(
            run_as_non_root_json,
            vec![true],
            "MustRunAsNonRoot should add the 'runAsNonRoot' in the containers when no 'runAsUser' is not defined"
        );
        let run_as_non_root_json = jsonpath::select(
            res.mutated_object.as_ref().unwrap(),
            "$.spec.initContainers[*].securityContext.runAsNonRoot",
        )
        .unwrap();
        assert_eq!(
            run_as_non_root_json,
            vec![true],
            "MustRunAsNonRoot should add the 'runAsNonRoot' in the initContainers when no 'runAsUser' is not defined"
        );
        Ok(())
    }

    #[test]
    fn must_run_as_non_root_should_reject_zero_as_user_id() -> Result<(), ()> {
        let request_file = "test_data/pod_creation_zero_user_id.json";
        let tc = Testcase {
            name: String::from("MustRunAsNonRoot rule does not allow 0 as user ID"),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: Settings {
                run_as_user: RuleStrategy {
                    rule: Rule::MustRunAsNonRoot,
                    ranges: vec![],
                    ..Default::default()
                },
                run_as_group: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                supplemental_groups: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                ..Default::default()
            },
        };
        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Request should not be mutated"
        );
        Ok(())
    }

    #[test]
    fn may_run_as_should_accept_request_if_group_id_is_valid() -> Result<(), ()> {
        let request_file = "test_data/pod_creation_must_run_as_with_group_id.json";
        let tc = Testcase {
            name: String::from("MayRunAs should accept request when valid RunAsGroup value is set"),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings {
                run_as_user: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                run_as_group: RuleStrategy {
                    rule: Rule::MayRunAs,
                    ranges: vec![IDRange {
                        min: 1000,
                        max: 2500,
                    }],
                    ..Default::default()
                },
                supplemental_groups: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                ..Default::default()
            },
        };
        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Request should not be mutated"
        );
        Ok(())
    }

    #[test]
    fn may_run_as_should_reject_request_if_run_as_group_value_is_invalid() -> Result<(), ()> {
        let request_file = "test_data/pod_creation_must_run_as_with_invalid_value.json";
        let tc = Testcase {
            name: String::from("MayRunAs should mutate object when no RunAsGroup value is invalid"),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: Settings {
                run_as_user: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                run_as_group: RuleStrategy {
                    rule: Rule::MayRunAs,
                    ranges: vec![IDRange {
                        min: 2000,
                        max: 2500,
                    }],
                    ..Default::default()
                },
                supplemental_groups: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                ..Default::default()
            },
        };
        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Request should not be mutated"
        );
        Ok(())
    }

    #[test]
    fn may_run_as_should_accecpt_request_if_run_as_group_is_not_defined() -> Result<(), ()> {
        let request_file = "test_data/pod_creation_must_run_as_with_no_value.json";
        let tc = Testcase {
            name: String::from("MayRunAs should not mutate object when no RunAsGroup value is set"),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings {
                run_as_user: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                run_as_group: RuleStrategy {
                    rule: Rule::MayRunAs,
                    ranges: vec![IDRange {
                        min: 2000,
                        max: 2500,
                    }],
                    ..Default::default()
                },
                supplemental_groups: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                ..Default::default()
            },
        };
        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Request should not be mutated"
        );
        Ok(())
    }

    #[test]
    fn must_run_as_rule_should_mutate_pod_when_no_values_id() -> Result<(), ()> {
        let request_file = "test_data/pod_creation_must_run_as_with_no_value.json";
        let tc = Testcase {
            name: String::from("MustRunAs should mutate object when invalid values are set"),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings {
                run_as_user: RuleStrategy {
                    rule: Rule::MustRunAs,
                    ranges: vec![IDRange {
                        min: 1500,
                        max: 2000,
                    }],
                    ..Default::default()
                },
                run_as_group: RuleStrategy {
                    rule: Rule::MustRunAs,
                    ranges: vec![IDRange {
                        min: 2000,
                        max: 2500,
                    }],
                    ..Default::default()
                },
                supplemental_groups: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                ..Default::default()
            },
        };

        let res = tc.eval(validate).unwrap();
        assert!(res.mutated_object.is_some(), "Request should be mutated");
        let user_id_json = jsonpath::select(
            res.mutated_object.as_ref().unwrap(),
            "$.spec.containers[*].securityContext.runAsUser",
        )
        .unwrap();
        assert_eq!(
            user_id_json,
            vec![1500],
            "MustRunAs should mutate object when invalid user ID is set"
        );

        let group_id_json = jsonpath::select(
            res.mutated_object.as_ref().unwrap(),
            "$.spec.containers[*].securityContext.runAsGroup",
        )
        .unwrap();
        assert_eq!(
            group_id_json,
            vec![2000],
            "MustRunAs should mutate object when invalid group ID is set"
        );
        let user_id_json = jsonpath::select(
            res.mutated_object.as_ref().unwrap(),
            "$.spec.initContainers[*].securityContext.runAsUser",
        )
        .unwrap();
        assert_eq!(
            user_id_json,
            vec![1500],
            "MustRunAs should mutate object when invalid user ID is set"
        );

        let group_id_json = jsonpath::select(
            res.mutated_object.as_ref().unwrap(),
            "$.spec.initContainers[*].securityContext.runAsGroup",
        )
        .unwrap();
        assert_eq!(
            group_id_json,
            vec![2000],
            "MustRunAs should mutate object when invalid group ID is set"
        );

        Ok(())
    }

    #[test]
    fn must_run_as_rule_should_reject_request_when_invaid_values_id() -> Result<(), ()> {
        let request_file = "test_data/pod_creation_must_run_as_with_invalid_value.json";
        let tc = Testcase {
            name: String::from("MustRunAs should mutate object when invalid values are set"),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: Settings {
                run_as_user: RuleStrategy {
                    rule: Rule::MustRunAs,
                    ranges: vec![IDRange {
                        min: 1500,
                        max: 2000,
                    }],
                    ..Default::default()
                },
                run_as_group: RuleStrategy {
                    rule: Rule::MustRunAs,
                    ranges: vec![IDRange {
                        min: 2000,
                        max: 2500,
                    }],
                    ..Default::default()
                },
                supplemental_groups: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                ..Default::default()
            },
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Request should not be mutated"
        );
        Ok(())
    }

    #[test]
    fn must_run_as_should_reject_when_group_id_is_invalid() -> Result<(), ()> {
        let request_file = "test_data/pod_creation_must_run_as_with_invalid_group_id.json";
        let tc = Testcase {
            name: String::from("'MustRunAs' should reject request when group ID is invalid"),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: Settings {
                run_as_user: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                run_as_group: RuleStrategy {
                    rule: Rule::MustRunAs,
                    ranges: vec![
                        IDRange {
                            min: 1500,
                            max: 2000,
                        },
                        IDRange {
                            min: 2500,
                            max: 3000,
                        },
                    ],
                    ..Default::default()
                },
                supplemental_groups: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                ..Default::default()
            },
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "MustRunAs should not mutate request when no group ID is invalid"
        );
        Ok(())
    }

    #[test]
    fn must_run_as_should_reject_when_user_id_is_invalid() -> Result<(), ()> {
        let request_file = "test_data/pod_creation_must_run_as_with_invalid_user_id.json";
        let tc = Testcase {
            name: String::from("'MustRunAs' should reject request when user ID is invalid"),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: Settings {
                run_as_user: RuleStrategy {
                    rule: Rule::MustRunAs,
                    ranges: vec![
                        IDRange {
                            min: 1500,
                            max: 2000,
                        },
                        IDRange {
                            min: 2500,
                            max: 3000,
                        },
                    ],
                    ..Default::default()
                },
                run_as_group: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                supplemental_groups: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                ..Default::default()
            },
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "MustRunAs should not mutate request when no user ID is invalid"
        );
        Ok(())
    }

    #[test]
    fn must_run_as_should_mutate_when_no_group_id_is_defined_adding_first_range_min_value(
    ) -> Result<(), ()> {
        let request_file = "test_data/pod_creation_must_run_as_with_no_group_id.json";
        let tc = Testcase {
            name: String::from("'MustRunAs' should mutate when no group ID is defined"),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings {
                run_as_user: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                run_as_group: RuleStrategy {
                    rule: Rule::MustRunAs,
                    ranges: vec![
                        IDRange {
                            min: 1500,
                            max: 2000,
                        },
                        IDRange {
                            min: 2500,
                            max: 3000,
                        },
                    ],
                    ..Default::default()
                },
                supplemental_groups: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                ..Default::default()
            },
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_some(),
            "MustRunAs should mutate request when no group ID is defined"
        );
        let json = jsonpath::select(
            res.mutated_object.as_ref().unwrap(),
            "$.spec.containers[*].securityContext.runAsGroup",
        )
        .unwrap();
        assert_eq!(
            json,
            vec![1500],
            "Mutated group ID is not the first range's min value"
        );
        let json = jsonpath::select(
            res.mutated_object.as_ref().unwrap(),
            "$.spec.initContainers[*].securityContext.runAsGroup",
        )
        .unwrap();
        assert_eq!(
            json,
            vec![1500],
            "Mutated group ID is not the first range's min value"
        );
        Ok(())
    }

    #[test]
    fn must_run_as_should_mutate_when_no_user_id_is_defined_adding_first_range_min_value(
    ) -> Result<(), ()> {
        let request_file = "test_data/pod_creation_must_run_as_with_no_user_id.json";
        let tc = Testcase {
            name: String::from("'MustRunAs' should mutate when no user ID is defined"),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings {
                run_as_user: RuleStrategy {
                    rule: Rule::MustRunAs,
                    ranges: vec![
                        IDRange {
                            min: 1500,
                            max: 2000,
                        },
                        IDRange {
                            min: 2500,
                            max: 3000,
                        },
                    ],
                    ..Default::default()
                },
                run_as_group: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                supplemental_groups: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                ..Default::default()
            },
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_some(),
            "MustRunAs should mutate request when no user ID is defined"
        );
        let json = jsonpath::select(
            res.mutated_object.as_ref().unwrap(),
            "$.spec.containers[*].securityContext.runAsUser",
        )
        .unwrap();
        assert_eq!(
            json,
            vec![1500],
            "Mutated user ID is not the first range's min value"
        );
        let json = jsonpath::select(
            res.mutated_object.as_ref().unwrap(),
            "$.spec.initContainers[*].securityContext.runAsUser",
        )
        .unwrap();
        assert_eq!(
            json,
            vec![1500],
            "Mutated user ID is not the first range's min value"
        );
        Ok(())
    }

    #[test]
    fn must_run_as_should_accept_when_valid_group_id_is_defined() -> Result<(), ()> {
        let request_file = "test_data/pod_creation_must_run_as_with_group_id.json";
        let tc = Testcase {
            name: String::from(
                "MustRunAs should not mutate request when valid group ID is defined",
            ),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings {
                run_as_user: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                run_as_group: RuleStrategy {
                    rule: Rule::MustRunAs,
                    ranges: vec![IDRange {
                        min: 1500,
                        max: 2000,
                    }],
                    ..Default::default()
                },
                supplemental_groups: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                ..Default::default()
            },
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "MustRunAs should not mutate request when valid group ID is defined"
        );
        assert!(
            res.accepted,
            "MustRunAs should accept request when valid group ID is defined"
        );
        Ok(())
    }

    #[test]
    fn must_run_as_should_accept_when_valid_user_id_is_defined() -> Result<(), ()> {
        let request_file = "test_data/pod_creation_must_run_as_with_user_id.json";
        let tc = Testcase {
            name: String::from("MustRunAs should not mutate request when valid user ID is defined"),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings {
                run_as_user: RuleStrategy {
                    rule: Rule::MustRunAs,
                    ranges: vec![IDRange {
                        min: 1500,
                        max: 2000,
                    }],
                    ..Default::default()
                },
                run_as_group: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                supplemental_groups: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                ..Default::default()
            },
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "MustRunAs should not mutate request when valid user ID is defined"
        );
        assert!(
            res.accepted,
            "MustRunAs should accept request when valid user ID is defined"
        );
        Ok(())
    }

    #[test]
    fn must_run_as_should_accept_when_valid_user_id_is_defined_and_wrong_podsecuritycontext(
    ) -> Result<(), ()> {
        let request_file =
            "test_data/pod_creation_must_run_as_with_user_id_wrong_podsecuritycontext.json";
        let tc = Testcase {
            name: String::from("MustRunAs should not mutate request when valid user ID is defined"),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings {
                run_as_user: RuleStrategy {
                    rule: Rule::MustRunAs,
                    ranges: vec![IDRange {
                        min: 1500,
                        max: 2000,
                    }],
                    ..Default::default()
                },
                run_as_group: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                supplemental_groups: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                ..Default::default()
            },
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "MustRunAs should not mutate request when valid user ID is defined"
        );
        assert!(
            res.accepted,
            "MustRunAs should accept request when valid user ID is defined"
        );
        Ok(())
    }

    #[test]
    fn must_run_as_should_mutate_when_valid_user_id_is_defined_and_wrong_podsecuritycontext_and_overwrite(
    ) -> Result<(), ()> {
        let request_file =
            "test_data/pod_creation_must_run_as_with_user_id_wrong_podsecuritycontext.json";
        let tc = Testcase {
            name: String::from("MustRunAs should not mutate request when valid user ID is defined"),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings {
                run_as_user: RuleStrategy {
                    rule: Rule::MustRunAs,
                    ranges: vec![IDRange {
                        min: 1500,
                        max: 2000,
                    }],
                    overwrite: true,
                },
                run_as_group: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                supplemental_groups: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                ..Default::default()
            },
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_some(),
            "MustRunAs should mutate request"
        );
        let pod_securitycontext_json = jsonpath::select(
            res.mutated_object.as_ref().unwrap(),
            "$.spec.securityContext.runAsUser",
        )
        .unwrap();
        assert_eq!(
            pod_securitycontext_json,
            vec![1500],
            "MustRunAs should add the 'supplementalGroups' when it is not defined"
        );
        Ok(())
    }

    #[test]
    fn run_as_any_should_not_mutate_pod() -> Result<(), ()> {
        let request_file = "test_data/pod_creation_run_as_any.json";
        let tc = Testcase {
            name: String::from("RunAsAny should not mutate object"),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings {
                run_as_user: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                run_as_group: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                supplemental_groups: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                ..Default::default()
            },
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "RunAsAny should not mutate request"
        );

        Ok(())
    }

    #[test]
    fn must_run_as_should_mutate_supplemental_group_if_overwrite_is_set() -> Result<(), ()> {
        let request_file = "test_data/pod_creation_valid_supplemental_group.json";
        let tc = Testcase {
            name: String::from("'MustRunAs' should mutate request when overwrite is 'true'"),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings {
                run_as_user: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                run_as_group: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                supplemental_groups: RuleStrategy {
                    rule: Rule::MustRunAs,
                    ranges: vec![
                        IDRange {
                            min: 1500,
                            max: 2000,
                        },
                        IDRange {
                            min: 2500,
                            max: 3000,
                        },
                    ],
                    overwrite: true,
                },
                ..Default::default()
            },
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_some(),
            "MustRunAs should mutate request"
        );
        let supplemental_groups_json = jsonpath::select(
            res.mutated_object.as_ref().unwrap(),
            "$.spec.securityContext.supplementalGroups[*]",
        )
        .unwrap();
        assert_eq!(
            supplemental_groups_json,
            vec![1500],
            "MustRunAs should change 'supplementalGroups' when 'overwrite' setting is true"
        );
        Ok(())
    }

    #[test]
    fn may_run_as_should_not_mutate_supplemental_group_if_overwrite_is_set() -> Result<(), ()> {
        let request_file = "test_data/pod_creation_valid_supplemental_group.json";
        let tc = Testcase {
            name: String::from("'MayRunAs' should not mutate request when overwrite is 'true'"),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings {
                run_as_user: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                run_as_group: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                supplemental_groups: RuleStrategy {
                    rule: Rule::MayRunAs,
                    ranges: vec![IDRange {
                        min: 1000,
                        max: 4000,
                    }],
                    overwrite: true,
                },
                ..Default::default()
            },
        };
        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Overwrite should not mutate request"
        );
        Ok(())
    }

    #[test]
    fn must_run_as_should_mutate_groups_if_overwrite_is_set() -> Result<(), ()> {
        let request_file = "test_data/pod_creation_must_run_as_with_group_id.json";
        let tc = Testcase {
            name: String::from("'MustRunAs' should mutate groups when overwrite is 'true'"),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings {
                run_as_user: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                run_as_group: RuleStrategy {
                    rule: Rule::MustRunAs,
                    ranges: vec![
                        IDRange {
                            min: 1000,
                            max: 2000,
                        },
                        IDRange {
                            min: 2500,
                            max: 3000,
                        },
                    ],
                    overwrite: true,
                },
                supplemental_groups: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                ..Default::default()
            },
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_some(),
            "MustRunAs should mutate request"
        );
        let json = jsonpath::select(
            res.mutated_object.as_ref().unwrap(),
            "$.spec.containers[*].securityContext.runAsGroup",
        )
        .unwrap();
        assert_eq!(
            json,
            vec![1000],
            "MustRunAs should change 'runAsGroup' when 'overwrite' setting is true"
        );

        let json = jsonpath::select(
            res.mutated_object.as_ref().unwrap(),
            "$.spec.initContainers[*].securityContext.runAsGroup",
        )
        .unwrap();
        assert_eq!(
            json,
            vec![1000],
            "MustRunAs should change 'runAsGroup' when 'overwrite' setting is true"
        );
        Ok(())
    }

    #[test]
    fn may_run_as_should_not_mutate_group_if_overwrite_is_set() -> Result<(), ()> {
        let request_file = "test_data/pod_creation_must_run_as_with_group_id.json";
        let tc = Testcase {
            name: String::from("'MayRunAs' should mutate request when overwrite is 'true'"),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings {
                run_as_user: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                run_as_group: RuleStrategy {
                    rule: Rule::MayRunAs,
                    ranges: vec![
                        IDRange {
                            min: 1000,
                            max: 2000,
                        },
                        IDRange {
                            min: 2500,
                            max: 3000,
                        },
                    ],
                    overwrite: true,
                },
                supplemental_groups: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                ..Default::default()
            },
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "MayRunAs should not mutate request"
        );
        Ok(())
    }

    #[test]
    fn must_run_as_should_mutate_user_id_when_overwrite_is_true() -> Result<(), ()> {
        let request_file = "test_data/pod_creation_must_run_as_with_user_id.json";
        let tc = Testcase {
            name: String::from("MustRunAs should mutate request 'overwrite' is set"),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings {
                run_as_user: RuleStrategy {
                    rule: Rule::MustRunAs,
                    ranges: vec![IDRange {
                        min: 1000,
                        max: 2000,
                    }],
                    overwrite: true,
                },
                run_as_group: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                supplemental_groups: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                ..Default::default()
            },
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_some(),
            "MustRunAs should mutate request when 'overwrite' is set"
        );
        let json = jsonpath::select(
            res.mutated_object.as_ref().unwrap(),
            "$.spec.containers[*].securityContext.runAsUser",
        )
        .unwrap();
        assert_eq!(
            json,
            vec![1000],
            "Mutated user ID should be the first range's min value"
        );
        let json = jsonpath::select(
            res.mutated_object.as_ref().unwrap(),
            "$.spec.initContainers[*].securityContext.runAsUser",
        )
        .unwrap();
        assert_eq!(
            json,
            vec![1000],
            "Mutated user ID should be the first range's min value"
        );
        Ok(())
    }

    #[test]
    fn must_run_as_non_root_should_reject_deployment_with_zero_as_user_id() -> Result<(), ()> {
        let request_file = "test_data/deployment_root_user.json";
        let tc = Testcase {
            name: String::from("MustRunAsNonRoot rule does not allow 0 as user ID"),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: Settings {
                run_as_user: RuleStrategy {
                    rule: Rule::MustRunAsNonRoot,
                    ranges: vec![],
                    ..Default::default()
                },
                run_as_group: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                supplemental_groups: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                ..Default::default()
            },
        };
        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Request should not be mutated"
        );
        Ok(())
    }

    #[test]
    fn must_run_as_non_root_should_reject_cronjob_with_zero_as_user_id() -> Result<(), ()> {
        let request_file = "test_data/cronjob_root_user.json";
        let tc = Testcase {
            name: String::from("MustRunAsNonRoot rule does not allow 0 as user ID"),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: Settings {
                run_as_user: RuleStrategy {
                    rule: Rule::MustRunAsNonRoot,
                    ranges: vec![],
                    ..Default::default()
                },
                run_as_group: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                supplemental_groups: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                ..Default::default()
            },
        };
        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Request should not be mutated"
        );
        Ok(())
    }

    #[test]
    fn must_run_as_non_root_should_reject_daemonset_with_zero_as_user_id() -> Result<(), ()> {
        let request_file = "test_data/daemonset_root_user.json";
        let tc = Testcase {
            name: String::from("MustRunAsNonRoot rule does not allow 0 as user ID"),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: Settings {
                run_as_user: RuleStrategy {
                    rule: Rule::MustRunAsNonRoot,
                    ranges: vec![],
                    ..Default::default()
                },
                run_as_group: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                supplemental_groups: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                ..Default::default()
            },
        };
        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Request should not be mutated"
        );
        Ok(())
    }

    #[test]
    fn must_run_as_non_root_should_reject_job_with_zero_as_user_id() -> Result<(), ()> {
        let request_file = "test_data/job_root_user.json";
        let tc = Testcase {
            name: String::from("MustRunAsNonRoot rule does not allow 0 as user ID"),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: Settings {
                run_as_user: RuleStrategy {
                    rule: Rule::MustRunAsNonRoot,
                    ranges: vec![],
                    ..Default::default()
                },
                run_as_group: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                supplemental_groups: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                ..Default::default()
            },
        };
        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Request should not be mutated"
        );
        Ok(())
    }

    #[test]
    fn must_run_as_non_root_should_reject_replicaset_with_zero_as_user_id() -> Result<(), ()> {
        let request_file = "test_data/replicaset_root_user.json";
        let tc = Testcase {
            name: String::from("MustRunAsNonRoot rule does not allow 0 as user ID"),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: Settings {
                run_as_user: RuleStrategy {
                    rule: Rule::MustRunAsNonRoot,
                    ranges: vec![],
                    ..Default::default()
                },
                run_as_group: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                supplemental_groups: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                ..Default::default()
            },
        };
        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Request should not be mutated"
        );
        Ok(())
    }

    #[test]
    fn must_run_as_non_root_should_reject_replicationcontroller_with_zero_as_user_id(
    ) -> Result<(), ()> {
        let request_file = "test_data/replicationcontroller_root_user.json";
        let tc = Testcase {
            name: String::from("MustRunAsNonRoot rule does not allow 0 as user ID"),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: Settings {
                run_as_user: RuleStrategy {
                    rule: Rule::MustRunAsNonRoot,
                    ranges: vec![],
                    ..Default::default()
                },
                run_as_group: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                supplemental_groups: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                ..Default::default()
            },
        };
        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Request should not be mutated"
        );
        Ok(())
    }

    #[test]
    fn must_run_as_non_root_should_reject_statefulset_with_zero_as_user_id() -> Result<(), ()> {
        let request_file = "test_data/statefulset_root_user.json";
        let tc = Testcase {
            name: String::from("MustRunAsNonRoot rule does not allow 0 as user ID"),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: Settings {
                run_as_user: RuleStrategy {
                    rule: Rule::MustRunAsNonRoot,
                    ranges: vec![],
                    ..Default::default()
                },
                run_as_group: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                supplemental_groups: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                ..Default::default()
            },
        };
        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "Request should not be mutated"
        );
        Ok(())
    }

    fn check_if_response_has_mutate_object_and_set_run_as_non_root(
        test_res: anyhow::Result<ValidationResponse>,
    ) -> Result<(), ()> {
        assert!(test_res.is_ok(), "The validate function failed.");
        let res = test_res.unwrap();
        assert!(res.mutated_object.is_some(), "Request should be mutated");
        let run_as_non_root_json = jsonpath::select(
            res.mutated_object.as_ref().unwrap(),
            "$.spec.template.spec.containers[*].securityContext.runAsNonRoot",
        )
        .unwrap();
        assert_eq!(
            run_as_non_root_json,
            vec![true],
            "MustRunAsNonRoot should add the 'runAsNonRoot' in the containers when no 'runAsUser' is not defined"
        );
        Ok(())
    }

    #[test]
    fn must_run_as_non_root_should_mutate_deployment_request_when_run_as_user_is_not_defined(
    ) -> Result<(), ()> {
        let request_file = "test_data/deployment_with_no_securitycontext.json";
        let tc = Testcase {
            name: String::from(
                "MustRunAsNonRoot should add 'runAsNonRoot' when 'runAsUser' is not defined",
            ),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings {
                run_as_user: RuleStrategy {
                    rule: Rule::MustRunAsNonRoot,
                    ranges: vec![],
                    ..Default::default()
                },
                run_as_group: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                supplemental_groups: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                ..Default::default()
            },
        };
        let test_res = tc.eval(validate);
        check_if_response_has_mutate_object_and_set_run_as_non_root(test_res)
    }

    #[test]
    fn must_run_as_non_root_should_mutate_replicaset_request_when_run_as_user_is_not_defined(
    ) -> Result<(), ()> {
        let request_file = "test_data/replicaset_with_no_securitycontext.json";
        let tc = Testcase {
            name: String::from(
                "MustRunAsNonRoot should add 'runAsNonRoot' when 'runAsUser' is not defined",
            ),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings {
                run_as_user: RuleStrategy {
                    rule: Rule::MustRunAsNonRoot,
                    ranges: vec![],
                    ..Default::default()
                },
                run_as_group: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                supplemental_groups: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                ..Default::default()
            },
        };
        let test_res = tc.eval(validate);
        check_if_response_has_mutate_object_and_set_run_as_non_root(test_res)
    }

    #[test]
    fn must_run_as_non_root_should_mutate_daemonset_request_when_run_as_user_is_not_defined(
    ) -> Result<(), ()> {
        let request_file = "test_data/daemonset_with_no_securitycontext.json";
        let tc = Testcase {
            name: String::from(
                "MustRunAsNonRoot should add 'runAsNonRoot' when 'runAsUser' is not defined",
            ),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings {
                run_as_user: RuleStrategy {
                    rule: Rule::MustRunAsNonRoot,
                    ranges: vec![],
                    ..Default::default()
                },
                run_as_group: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                supplemental_groups: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                ..Default::default()
            },
        };
        let test_res = tc.eval(validate);
        check_if_response_has_mutate_object_and_set_run_as_non_root(test_res)
    }

    #[test]
    fn must_run_as_non_root_should_mutate_statefulset_request_when_run_as_user_is_not_defined(
    ) -> Result<(), ()> {
        let request_file = "test_data/statefulset_with_no_securitycontext.json";
        let tc = Testcase {
            name: String::from(
                "MustRunAsNonRoot should add 'runAsNonRoot' when 'runAsUser' is not defined",
            ),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings {
                run_as_user: RuleStrategy {
                    rule: Rule::MustRunAsNonRoot,
                    ranges: vec![],
                    ..Default::default()
                },
                run_as_group: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                supplemental_groups: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                ..Default::default()
            },
        };
        let test_res = tc.eval(validate);
        check_if_response_has_mutate_object_and_set_run_as_non_root(test_res)
    }

    #[test]
    fn must_run_as_non_root_should_mutate_replicationcontroller_request_when_run_as_user_is_not_defined(
    ) -> Result<(), ()> {
        let request_file = "test_data/replicationcontroller_with_no_securitycontext.json";
        let tc = Testcase {
            name: String::from(
                "MustRunAsNonRoot should add 'runAsNonRoot' when 'runAsUser' is not defined",
            ),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings {
                run_as_user: RuleStrategy {
                    rule: Rule::MustRunAsNonRoot,
                    ranges: vec![],
                    ..Default::default()
                },
                run_as_group: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                supplemental_groups: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                ..Default::default()
            },
        };
        let test_res = tc.eval(validate);
        check_if_response_has_mutate_object_and_set_run_as_non_root(test_res)
    }

    #[test]
    fn must_run_as_non_root_should_mutate_cronjob_request_when_run_as_user_is_not_defined(
    ) -> Result<(), ()> {
        let request_file = "test_data/cronjob_with_no_securitycontext.json";
        let tc = Testcase {
            name: String::from(
                "MustRunAsNonRoot should add 'runAsNonRoot' when 'runAsUser' is not defined",
            ),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings {
                run_as_user: RuleStrategy {
                    rule: Rule::MustRunAsNonRoot,
                    ranges: vec![],
                    ..Default::default()
                },
                run_as_group: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                supplemental_groups: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                ..Default::default()
            },
        };
        let test_res = tc.eval(validate);
        assert!(test_res.is_ok(), "The validate function failed.");
        let res = test_res.unwrap();
        assert!(res.mutated_object.is_some(), "Request should be mutated");
        let run_as_non_root_json = jsonpath::select(
            res.mutated_object.as_ref().unwrap(),
            "$.spec.jobTemplate.spec.template.spec.containers[*].securityContext.runAsNonRoot",
        )
        .unwrap();
        assert_eq!(
            run_as_non_root_json,
            vec![true],
            "MustRunAsNonRoot should add the 'runAsNonRoot' in the containers when no 'runAsUser' is not defined"
        );
        Ok(())
    }

    #[test]
    fn must_run_as_non_root_should_mutate_job_request_when_run_as_user_is_not_defined(
    ) -> Result<(), ()> {
        let request_file = "test_data/job_with_no_securitycontext.json";
        let tc = Testcase {
            name: String::from(
                "MustRunAsNonRoot should add 'runAsNonRoot' when 'runAsUser' is not defined",
            ),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings {
                run_as_user: RuleStrategy {
                    rule: Rule::MustRunAsNonRoot,
                    ranges: vec![],
                    ..Default::default()
                },
                run_as_group: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                supplemental_groups: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                ..Default::default()
            },
        };
        let test_res = tc.eval(validate);
        check_if_response_has_mutate_object_and_set_run_as_non_root(test_res)
    }

    #[test]
    fn must_run_as_should_mutate_deployment_with_podspec_securitycontext_without_values(
    ) -> Result<(), ()> {
        let request_file = "test_data/deployment_with_no_securitycontext.json";
        let tc = Testcase {
            name: String::from("MustRunAs should mutate object when invalid values are set"),
            fixture_file: String::from(request_file),
            expected_validation_result: true,
            settings: Settings {
                run_as_user: RuleStrategy {
                    rule: Rule::MustRunAs,
                    ranges: vec![IDRange {
                        min: 1500,
                        max: 2000,
                    }],
                    ..Default::default()
                },
                run_as_group: RuleStrategy {
                    rule: Rule::MustRunAs,
                    ranges: vec![IDRange {
                        min: 2000,
                        max: 2500,
                    }],
                    ..Default::default()
                },
                supplemental_groups: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                ..Default::default()
            },
        };

        let res = tc.eval(validate).unwrap();
        assert!(res.mutated_object.is_some(), "Request should be mutated");
        let user_id_json = jsonpath::select(
            res.mutated_object.as_ref().unwrap(),
            "$.spec.template.spec.securityContext.runAsUser",
        )
        .unwrap();
        assert_eq!(
            user_id_json,
            vec![1500],
            "MustRunAs should mutate object when invalid user ID is set"
        );

        let group_id_json = jsonpath::select(
            res.mutated_object.as_ref().unwrap(),
            "$.spec.template.spec.securityContext.runAsGroup",
        )
        .unwrap();
        assert_eq!(
            group_id_json,
            vec![2000],
            "MustRunAs should mutate object when invalid group ID is set"
        );
        Ok(())
    }

    #[test]
    fn must_run_as_should_reject_deployment_with_podspec_securitycontext_with_invalid_values(
    ) -> Result<(), ()> {
        let request_file = "test_data/deployment_with_user.json";
        let tc = Testcase {
            name: String::from("MustRunAs should mutate object when invalid values are set"),
            fixture_file: String::from(request_file),
            expected_validation_result: false,
            settings: Settings {
                run_as_user: RuleStrategy {
                    rule: Rule::MustRunAs,
                    ranges: vec![IDRange {
                        min: 1500,
                        max: 2000,
                    }],
                    ..Default::default()
                },
                run_as_group: RuleStrategy {
                    rule: Rule::MustRunAs,
                    ranges: vec![IDRange {
                        min: 2000,
                        max: 2500,
                    }],
                    ..Default::default()
                },
                supplemental_groups: RuleStrategy {
                    rule: Rule::RunAsAny,
                    ranges: vec![],
                    ..Default::default()
                },
                ..Default::default()
            },
        };

        let res = tc.eval(validate).unwrap();
        assert!(
            res.mutated_object.is_none(),
            "MustRunAs should not mutate request when user ID is invalid"
        );
        Ok(())
    }

    #[rstest]
    #[case("65533", Rule::MustRunAs, 65533, 65533, None)]
    #[case(
        "65534",
        Rule::MustRunAs,
        65533,
        65533,
        Some("User ID defined in the container image is outside defined ranges")
    )]
    #[case("65533:65533", Rule::MustRunAs, 65533, 65533, None)]
    #[case(
        "myuser:65533",
        Rule::MustRunAs,
        65534,
        65534,
        Some("Invalid user ID in the container image configuration: \"myuser\"")
    )]
    #[case(
        "myuser:mygroup",
        Rule::MustRunAs,
        65534,
        65534,
        Some("Invalid user ID in the container image configuration: \"myuser\"")
    )]
    #[case(
        "65533:mygroup",
        Rule::MustRunAs,
        65534,
        65534,
        Some("Invalid group ID in the container image configuration: \"mygroup\"")
    )]
    #[case("65533", Rule::MustRunAsNonRoot, 65533, 65533, None)]
    #[case("65533:65533", Rule::MustRunAsNonRoot, 65533, 65533, None)]
    #[case(
        "myuser:65533",
        Rule::MustRunAsNonRoot,
        65534,
        65534,
        Some("Invalid user ID in the container image configuration: \"myuser\"")
    )]
    #[case(
        "myuser:mygroup",
        Rule::MustRunAsNonRoot,
        65534,
        65534,
        Some("Invalid user ID in the container image configuration: \"myuser\"")
    )]
    #[case(
        "65533:mygroup",
        Rule::MustRunAsNonRoot,
        65534,
        65534,
        Some("Invalid group ID in the container image configuration: \"mygroup\"")
    )]
    #[case(
        "0",
        Rule::MustRunAsNonRoot,
        65533,
        65533,
        Some("User ID defined in the container image cannot be root ID (0)")
    )]
    #[case(
        "0:65533",
        Rule::MustRunAsNonRoot,
        65533,
        65533,
        Some("User ID defined in the container image cannot be root ID (0)")
    )]
    #[case(
        "",
        Rule::MustRunAs,
        65533,
        65533,
        Some("Invalid user ID in the container image configuration: \"\"")
    )]
    fn enforce_run_as_user_rule_in_container_image(
        #[case] user_group: &str,
        #[case] rule: Rule,
        #[case] min: i64,
        #[case] max: i64,
        #[case] error: Option<&str>,
    ) {
        let config = ConfigBuilder::default()
            .user(user_group)
            .build()
            .expect("Failed to build configuration");
        let image_config = ImageConfigurationBuilder::default()
            .config(config)
            .build()
            .expect("Failed to build image configuration");
        let validation_request = ValidationRequest {
            settings: Settings {
                run_as_user: RuleStrategy {
                    rule,
                    ranges: vec![IDRange { min, max }],
                    ..Default::default()
                },
                ..Default::default()
            },
            request: KubernetesAdmissionRequest {
                ..Default::default()
            },
        };
        let security_context = Some(SecurityContext {
            run_as_user: Some(min),
            ..Default::default()
        });
        let result =
            enforce_run_as_user_rule(security_context, &validation_request, Some(image_config));
        match error {
            Some(e) => {
                let error = result.expect_err("Expected error but got success");
                assert_eq!(error.to_string(), e,);
            }
            None => {
                assert!(
                    result.is_ok(),
                    "Expected success but got error: {}",
                    result.expect_err("Cannot get error")
                );
            }
        }
    }

    #[rstest]
    #[case("65533", Rule::MustRunAs, 65533, 65533, None)]
    #[case("65534", Rule::MustRunAs, 65533, 65533, None)]
    #[case("65533:65533", Rule::MustRunAs, 65533, 65533, None)]
    #[case(
        "myuser:65533",
        Rule::MustRunAs,
        65533,
        65533,
        Some("Invalid user ID in the container image configuration: \"myuser\"")
    )]
    #[case(
        "myuser:mygroup",
        Rule::MustRunAs,
        65534,
        65534,
        Some("Invalid user ID in the container image configuration: \"myuser\"")
    )]
    #[case(
        "65533:mygroup",
        Rule::MustRunAs,
        65533,
        65533,
        Some("Invalid group ID in the container image configuration: \"mygroup\"")
    )]
    #[case(
        "65533:65534",
        Rule::MustRunAs,
        65533,
        65533,
        Some("Group ID defined in the container image is outside defined ranges")
    )]
    #[case(
        "65533:65532",
        Rule::MustRunAs,
        65533,
        65533,
        Some("Group ID defined in the container image is outside defined ranges")
    )]
    fn enforce_run_as_group_rule_in_container_image(
        #[case] user_group: &str,
        #[case] rule: Rule,
        #[case] min: i64,
        #[case] max: i64,
        #[case] error: Option<&str>,
    ) {
        let config = ConfigBuilder::default()
            .user(user_group)
            .build()
            .expect("Failed to build configuration");
        let image_config = ImageConfigurationBuilder::default()
            .config(config)
            .build()
            .expect("Failed to build image configuration");
        let validation_request = ValidationRequest {
            settings: Settings {
                run_as_group: RuleStrategy {
                    rule,
                    ranges: vec![IDRange { min, max }],
                    ..Default::default()
                },
                ..Default::default()
            },
            request: KubernetesAdmissionRequest {
                ..Default::default()
            },
        };
        let security_context = Some(SecurityContext {
            run_as_group: Some(min),
            ..Default::default()
        });
        let result =
            enforce_run_as_group(security_context, &validation_request, Some(image_config));
        match error {
            Some(e) => {
                let error = result.expect_err("Expected error but got success");
                assert_eq!(error.to_string(), e,);
            }
            None => {
                assert!(
                    result.is_ok(),
                    "Expected success but got error: {}",
                    result.expect_err("Cannot get error")
                );
            }
        }
    }
}
