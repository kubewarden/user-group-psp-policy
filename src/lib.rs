use lazy_static::lazy_static;

use guest::prelude::*;
use kubewarden_policy_sdk::host_capabilities::oci::get_manifest_and_config;
use kubewarden_policy_sdk::wapc_guest as guest;

use anyhow::Result;
use k8s_openapi::api::core::v1 as apicore;

extern crate kubewarden_policy_sdk as kubewarden;
use kubewarden::{logging, protocol_version_guest, request::ValidationRequest, validate_settings};

mod settings;
use settings::{Rule, Settings};

use slog::{Logger, o, warn};
mod error;
use error::ValidationError;

lazy_static! {
    static ref LOG_DRAIN: Logger = Logger::root(
        logging::KubewardenDrain::new(),
        o!("policy" => "user-group-policy")
    );
}

#[unsafe(no_mangle)]
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
) -> Result<(Option<i64>, Option<i64>), ValidationError> {
    if let Some(image_config) = container_image_config
        && let Some(user) = image_config.config().clone().unwrap_or_default().user()
    {
        let user_group: Vec<&str> = user.split(':').collect();
        if let Ok(user_id) = user_group[0].parse::<i64>() {
            if user_group.len() == 2 {
                if let Ok(group_id) = user_group[1].parse::<i64>() {
                    return Ok((Some(user_id), Some(group_id)));
                } else {
                    return Err(ValidationError::ImageConfigGroupId(
                        user_group[1].to_owned(),
                    ));
                }
            }
            return Ok((Some(user_id), None));
        } else {
            return Err(ValidationError::ImageConfigUserId(user_group[0].to_owned()));
        }
    }
    Ok((None, None))
}

fn enforce_run_as_user_rule<T>(
    security_context_option: Option<T>,
    validation_request: &ValidationRequest<Settings>,
    container_image_config: Option<oci_spec::image::ImageConfiguration>,
) -> Result<Option<T>, ValidationError>
where
    T: GenericSecurityContext + std::default::Default,
{
    let container_user_group_uid =
        get_user_group_uid_from_image_configuration(container_image_config)?;
    let mut security_context = security_context_option.unwrap_or_default();
    match validation_request.settings.run_as_user.rule {
        Rule::MustRunAs => {
            if let (Some(user_id), _) = container_user_group_uid
                && !validation_request.settings.run_as_user.is_valid_id(user_id)
            {
                return Err(ValidationError::ImageConfigUserIdOutsideRanges);
            }
            if validation_request.settings.run_as_user.overwrite
                || (security_context.run_as_user().is_none()
                    && !validation_request.settings.validate_only)
            {
                let default_user_id = validation_request.settings.run_as_user.ranges[0].min;
                security_context.set_run_as_user(Some(default_user_id));
                return Ok(Some(security_context));
            }
            if let Some(user_id) = security_context.run_as_user()
                && !validation_request.settings.run_as_user.is_valid_id(user_id)
            {
                return Err(ValidationError::UserIdOutsideRanges);
            }
            if validation_request.settings.validate_only {
                return Err(ValidationError::MissingUserId);
            }
        }
        Rule::MustRunAsNonRoot => {
            if let (Some(user_id), _) = container_user_group_uid
                && user_id == 0
            {
                return Err(ValidationError::ImageConfigUserIdCannotBeRoot);
            }
            if let Some(run_as_non_root) = security_context.run_as_non_root()
                && !run_as_non_root
            {
                return Err(ValidationError::ShouldRunAsNonRoot);
            }
            if let Some(user_id) = security_context.run_as_user()
                && user_id == 0
            {
                return Err(ValidationError::CannotUseRootUserId);
            }
            if validation_request.settings.validate_only {
                return Err(ValidationError::ShouldRunAsNonRoot);
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
) -> Result<(), ValidationError>
where
{
    let container_user_group_uid =
        get_user_group_uid_from_image_configuration(container_image_config)?;
    if let (_, Some(group_id)) = container_user_group_uid
        && !validation_request
            .settings
            .run_as_group
            .is_valid_id(group_id)
    {
        return Err(ValidationError::ImageConfigGroupIdOutsideRanges);
    }
    Ok(())
}

fn enforce_run_as_group<T>(
    security_context_option: Option<T>,
    validation_request: &ValidationRequest<Settings>,
    container_image_config: Option<oci_spec::image::ImageConfiguration>,
) -> Result<Option<T>, ValidationError>
where
    T: GenericSecurityContext + std::default::Default,
{
    let mut security_context = security_context_option.unwrap_or_default();
    match validation_request.settings.run_as_group.rule {
        Rule::MustRunAs => {
            enforce_container_image_group(validation_request, container_image_config)?;
            if validation_request.settings.run_as_group.overwrite
                || (security_context.run_as_group().is_none()
                    && !validation_request.settings.validate_only)
            {
                let default_group_id = validation_request.settings.run_as_group.ranges[0].min;
                security_context.set_run_as_group(Some(default_group_id));
                return Ok(Some(security_context));
            }
            if let Some(group_id) = security_context.run_as_group()
                && !validation_request
                    .settings
                    .run_as_group
                    .is_valid_id(group_id)
            {
                return Err(ValidationError::GroupIdOutsideRanges);
            }
            if validation_request.settings.validate_only {
                return Err(ValidationError::MissingGroupId);
            }
        }
        Rule::MayRunAs => {
            enforce_container_image_group(validation_request, container_image_config)?;
            if let Some(group_id) = security_context.run_as_group()
                && !validation_request
                    .settings
                    .run_as_group
                    .is_valid_id(group_id)
            {
                return Err(ValidationError::GroupIdOutsideRanges);
            }
        }
        _ => {}
    }
    Ok(None)
}

fn enforce_supplemental_groups(
    security_context_option: Option<apicore::PodSecurityContext>,
    validation_request: &ValidationRequest<Settings>,
) -> Result<Option<apicore::PodSecurityContext>, ValidationError> {
    let mut security_context = security_context_option.unwrap_or_default();
    match validation_request.settings.supplemental_groups.rule {
        Rule::MustRunAs => {
            if validation_request.settings.supplemental_groups.overwrite
                || (security_context.supplemental_groups.is_none()
                    && !validation_request.settings.validate_only)
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
                        return Err(ValidationError::GroupIdOutsideRanges);
                    }
                }
            }
            if validation_request.settings.validate_only {
                return Err(ValidationError::MissingSupplementalGroupId);
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
                        return Err(ValidationError::GroupIdOutsideRanges);
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
                                );
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
                            );
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
                            );
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

    use jsonpath_lib as jsonpath;
    use k8s_openapi::api::core::v1::{PodSecurityContext, SecurityContext};
    use kubewarden::{
        request::KubernetesAdmissionRequest, response::ValidationResponse, settings::Validatable,
    };
    use oci_spec::image::{ConfigBuilder, ImageConfigurationBuilder};
    use rstest::rstest;

    use crate::settings::{IDRange, RuleStrategy, Settings};

    fn get_must_run_as_rule(overwrite: bool) -> settings::RuleStrategy {
        RuleStrategy {
            rule: Rule::MustRunAs,
            ranges: vec![
                settings::IDRange {
                    min: 1500,
                    max: 2000,
                },
                IDRange {
                    min: 2500,
                    max: 3000,
                },
            ],
            overwrite,
        }
    }

    fn get_run_as_any_rule() -> settings::RuleStrategy {
        RuleStrategy {
            rule: Rule::RunAsAny,
            ranges: vec![],
            ..Default::default()
        }
    }

    fn get_may_run_as_rule(overwrite: bool) -> settings::RuleStrategy {
        RuleStrategy {
            rule: Rule::MayRunAs,
            ranges: vec![IDRange {
                min: 1000,
                max: 4000,
            }],
            overwrite,
        }
    }

    fn get_must_run_as_non_root_rule() -> settings::RuleStrategy {
        RuleStrategy {
            rule: Rule::MustRunAsNonRoot,
            ranges: vec![],
            ..Default::default()
        }
    }

    fn get_pod_security_context_expected_mutation() -> PodSecurityContext {
        get_pod_security_context(Some(vec![1500]))
    }

    fn get_pod_security_context(
        supplemental_groups: Option<std::vec::Vec<i64>>,
    ) -> PodSecurityContext {
        PodSecurityContext {
            supplemental_groups,
            ..Default::default()
        }
    }

    fn get_security_context(
        run_as_user: Option<i64>,
        run_as_non_root: Option<bool>,
    ) -> SecurityContext {
        SecurityContext {
            run_as_user,
            run_as_non_root,
            ..Default::default()
        }
    }

    fn get_security_context_with_no_user(run_as_group: Option<i64>) -> SecurityContext {
        SecurityContext {
            run_as_group,
            ..Default::default()
        }
    }

    fn get_security_context_expected_mutation_for_group_must_run_as() -> SecurityContext {
        SecurityContext {
            run_as_group: Some(1500),
            ..Default::default()
        }
    }

    fn get_security_context_expected_mutation_must_run_as() -> SecurityContext {
        get_security_context(Some(1500), None)
    }

    fn get_security_context_expected_mutation_must_run_as_non_root() -> SecurityContext {
        get_security_context(None, Some(true))
    }

    fn perform_validation_call(settings: Settings, request_file: &str) -> ValidationResponse {
        let validation_request = ValidationRequest::<Settings> {
            settings,
            request: serde_json::from_slice(
                std::fs::read(request_file)
                    .expect("Cannot read fixture file")
                    .as_slice(),
            )
            .expect("Cannot parse fixture file"),
        };

        serde_json::from_slice(
            validate(
                serde_json::to_vec(&validation_request)
                    .expect("Cannot serialize validation request")
                    .as_slice(),
            )
            .expect("The validate function failed.")
            .as_slice(),
        )
        .expect("Cannot parse validation response")
    }

    #[rstest]
    #[case::may_run_as_supplemental_group_id_inside_range(
        Some(vec![ 1600, 2600 ]),
        get_may_run_as_rule(false),
        None,
        None,
        false
    )]
    #[case::may_run_as_supplemental_group_id_outside_range(
        Some(vec![999, 4001]),
        get_may_run_as_rule(false),
        Some(ValidationError::GroupIdOutsideRanges),
        None,
        false
    )]
    #[case::may_run_as_supplemental_group_missing(
        None,
        get_may_run_as_rule(false),
        None,
        None,
        false
    )]
    #[case::must_run_as_supplemental_group_id_missing(
        None,
        get_must_run_as_rule(false),
        None,
        Some(get_pod_security_context_expected_mutation()),
        false
    )]
    #[case::must_run_as_supplemental_group_id_is_missing_validate_only(
        None,
        get_must_run_as_rule(false),
        Some(ValidationError::MissingSupplementalGroupId),
        None,
        true
    )]
    #[case::must_run_as_supplemental_group_id_inside_ranges(
        Some(vec![1600, 2600]),
        get_must_run_as_rule(false),
        None,
        None,
        false
    )]
    #[case::must_run_as_supplemental_group_id_outside_ranges(
        Some(vec![9000]),
        get_must_run_as_rule(false),
        Some(ValidationError::GroupIdOutsideRanges),
        None,
        false
    )]
    #[case::must_run_as_supplemental_group_inside_ranges_overwrite(
        Some(vec![1600, 2600]),
        get_must_run_as_rule(true),
        None,
        Some(get_pod_security_context_expected_mutation()),
        false
    )]
    #[case::must_run_as_supplemental_group_inside_range_overwrite_and_validate_only(
        Some(vec![1600, 2600]),
        get_must_run_as_rule(true),
        None,
        Some(get_pod_security_context_expected_mutation()),
        true
    )]
    #[case::may_run_as_supplemental_group_inside_range_overwrite(
        Some(vec![1600, 2600]),
        get_may_run_as_rule(true),
        None,
        None,
        false
    )]
    fn test_supplemental_group_rules(
        #[case] supplemental_groups: Option<std::vec::Vec<i64>>,
        #[case] supplemental_groups_strategy: settings::RuleStrategy,
        #[case] expected_error: Option<ValidationError>,
        #[case] expected_mutation: Option<PodSecurityContext>,
        #[case] validate_only: bool,
    ) {
        let security_context = Some(get_pod_security_context(supplemental_groups));
        let validation_request = &ValidationRequest {
            settings: Settings {
                supplemental_groups: supplemental_groups_strategy,
                validate_only,
                ..Default::default()
            },
            request: KubernetesAdmissionRequest::default(),
        };
        let result = enforce_supplemental_groups(security_context, validation_request);
        if let Some(expected_error) = expected_error {
            assert_eq!(result.expect_err("Missing expected error"), expected_error);
        } else {
            let mutated_security_context = result.expect("Expected Ok result");
            assert_eq!(mutated_security_context, expected_mutation);
        }
    }

    #[rstest]
    #[case::must_run_as_group_id_inside_ranges(
        Some(1500),
        get_must_run_as_rule(false),
        None,
        None,
        false
    )]
    #[case::must_run_as_missing_group(
        None,
        get_must_run_as_rule(false),
        None,
        Some(get_security_context_expected_mutation_for_group_must_run_as()),
        false
    )]
    #[case::must_run_as_missing_group_validation_mode(
        None,
        get_must_run_as_rule(false),
        Some(ValidationError::MissingGroupId),
        None,
        true
    )]
    #[case::must_run_as_group_outside_ranges(
        Some(500),
        get_must_run_as_rule(false),
        Some(ValidationError::GroupIdOutsideRanges),
        None,
        false
    )]
    #[case::run_as_any_missing_group(None, get_run_as_any_rule(), None, None, false)]
    #[case::must_run_as_group_id_inside_ranges_overwrite(
        Some(2000),
        get_must_run_as_rule(true),
        None,
        Some(get_security_context_expected_mutation_for_group_must_run_as()),
        false
    )]
    #[case::may_run_as_group_id_inside_ranges(
        Some(1500),
        get_may_run_as_rule(false),
        None,
        None,
        false
    )]
    #[case::may_run_as_group_id_outside_ranges(
        Some(500),
        get_may_run_as_rule(false),
        Some(ValidationError::GroupIdOutsideRanges),
        None,
        false
    )]
    #[case::must_run_as_group_id_inside_ranges_overwrite_validation_only(
        Some(2000),
        get_must_run_as_rule(true),
        None,
        Some(get_security_context_expected_mutation_for_group_must_run_as()),
        true
    )]
    #[case::may_run_as_missing_group_id(None, get_may_run_as_rule(false), None, None, false)]
    #[case::may_run_as_group_id_and_overwrite(
        Some(1500),
        get_may_run_as_rule(true),
        None,
        None,
        false
    )]
    fn test_group_rules(
        #[case] run_as_group: Option<i64>,
        #[case] run_as_group_strategy: settings::RuleStrategy,
        #[case] expected_error: Option<ValidationError>,
        #[case] expected_mutation: Option<SecurityContext>,
        #[case] validate_only: bool,
    ) {
        let security_context = Some(get_security_context_with_no_user(run_as_group));
        let validation_request = &ValidationRequest {
            settings: Settings {
                run_as_group: run_as_group_strategy,
                validate_only,
                ..Default::default()
            },
            request: KubernetesAdmissionRequest::default(),
        };
        let result = enforce_run_as_group(security_context, validation_request, None);
        if let Some(expected_error) = expected_error {
            assert_eq!(result.expect_err("Missing error"), expected_error);
        } else {
            let mutated_security_context = result.expect("Expected Ok result");
            assert_eq!(mutated_security_context, expected_mutation);
        }
    }

    #[rstest]
    #[case::must_run_as_with_user_in_ranges(
        Some(1500),
        None,
        get_must_run_as_rule(false),
        None,
        None,
        false
    )]
    #[case::must_run_as_with_user_outside_ranges(
        Some(500),
        None,
        get_must_run_as_rule(false),
        Some(ValidationError::UserIdOutsideRanges),
        None,
        false
    )]
    #[case::must_run_as_with_missing_user_id(
        None,
        None,
        get_must_run_as_rule(false),
        None,
        Some(get_security_context_expected_mutation_must_run_as()),
        false
    )]
    #[case::must_run_as_with_missing_user_id_in_validation_mode(
        None,
        None,
        get_must_run_as_rule(false),
        Some(ValidationError::MissingUserId),
        None,
        true
    )]
    #[case::run_as_any_with_missing_user_id(None, None, get_run_as_any_rule(), None, None, false)]
    #[case::must_run_as_with_user_and_overwrite_is_set(
        Some(2000),
        None,
        get_must_run_as_rule(true),
        None,
        Some(get_security_context_expected_mutation_must_run_as()),
        false
    )]
    #[case::must_run_as_non_root_with_run_as_non_root_set_false(
        Some(1000),
        Some(false),
        get_must_run_as_non_root_rule(),
        Some(ValidationError::ShouldRunAsNonRoot),
        None,
        false
    )]
    #[case::must_run_as_non_root_with_missing_run_as_non_root(
        None,
        None,
        get_must_run_as_non_root_rule(),
        None,
        Some(get_security_context_expected_mutation_must_run_as_non_root()),
        false
    )]
    #[case::must_run_as_non_root_with_missing_run_as_non_root_and_validation_mode(
        None,
        None,
        get_must_run_as_non_root_rule(),
        Some(ValidationError::ShouldRunAsNonRoot),
        None,
        true
    )]
    #[case::must_run_as_non_root_with_using_root_user(
        Some(0),
        Some(true),
        get_must_run_as_non_root_rule(),
        Some(ValidationError::CannotUseRootUserId),
        None,
        false
    )]
    #[case::must_run_as_with_user_id_and_overwrite_is_true(
        Some(1600),
        None,
        get_must_run_as_rule(true),
        None,
        Some(get_security_context_expected_mutation_must_run_as()),
        false
    )]
    fn test_user_rules(
        #[case] run_as_user: Option<i64>,
        #[case] run_as_non_root: Option<bool>,
        #[case] run_as_user_strategy: settings::RuleStrategy,
        #[case] expected_error: Option<ValidationError>,
        #[case] expected_mutation: Option<SecurityContext>,
        #[case] validate_only: bool,
    ) {
        let security_context = Some(get_security_context(run_as_user, run_as_non_root));

        let settings = Settings {
            run_as_user: run_as_user_strategy,
            validate_only,
            ..Default::default()
        };
        // let's be sure we built valid settings
        let settings_validation = settings.validate();
        assert!(
            settings_validation.is_ok(),
            "Settings are not valid {:?}",
            settings_validation
        );

        let validation_request = &ValidationRequest {
            settings,
            request: KubernetesAdmissionRequest::default(),
        };

        let result = enforce_run_as_user_rule(security_context, validation_request, None);
        if let Some(expected_error) = expected_error {
            assert_eq!(result.expect_err("Missing error"), expected_error);
        } else {
            let mutated_security_context = result.expect("Expected Ok result");
            assert_eq!(mutated_security_context, expected_mutation);
        }
    }

    #[test]
    fn must_run_as_rule_should_mutate_pod_when_no_values_id() -> Result<(), ()> {
        let settings = Settings {
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
            ..Default::default()
        };

        let res = perform_validation_call(
            settings,
            "test_data/pod_creation_must_run_as_with_no_value.json",
        );
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
    fn must_run_as_rule_should_reject_request_when_invaid_values_id() {
        let settings = Settings {
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
            ..Default::default()
        };

        let res = perform_validation_call(
            settings,
            "test_data/pod_creation_must_run_as_with_invalid_value.json",
        );
        assert!(
            res.mutated_object.is_none(),
            "Request should not be mutated"
        );
    }

    #[test]
    fn must_run_as_should_accept_when_valid_user_id_is_defined_and_wrong_podsecuritycontext() {
        let settings = Settings {
            run_as_user: RuleStrategy {
                rule: Rule::MustRunAs,
                ranges: vec![IDRange {
                    min: 1500,
                    max: 2000,
                }],
                ..Default::default()
            },
            ..Default::default()
        };

        let res = perform_validation_call(
            settings,
            "test_data/pod_creation_must_run_as_with_user_id_wrong_podsecuritycontext.json",
        );
        assert!(
            res.mutated_object.is_none(),
            "MustRunAs should not mutate request when valid user ID is defined"
        );
        assert!(
            res.accepted,
            "MustRunAs should accept request when valid user ID is defined"
        );
    }

    #[test]
    fn must_run_as_should_mutate_when_valid_user_id_is_defined_and_wrong_podsecuritycontext_and_overwrite()
     {
        let settings = Settings {
            run_as_user: RuleStrategy {
                rule: Rule::MustRunAs,
                ranges: vec![IDRange {
                    min: 1500,
                    max: 2000,
                }],
                overwrite: true,
            },
            ..Default::default()
        };

        let res = perform_validation_call(
            settings,
            "test_data/pod_creation_must_run_as_with_user_id_wrong_podsecuritycontext.json",
        );
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
    }

    #[rstest]
    #[case::deployment("test_data/deployment_root_user.json")]
    #[case::cronjob("test_data/cronjob_root_user.json")]
    #[case::daemonset("test_data/daemonset_root_user.json")]
    #[case::job("test_data/job_root_user.json")]
    #[case::replicaset("test_data/replicaset_root_user.json")]
    #[case::replicationcontroller("test_data/replicationcontroller_root_user.json")]
    #[case::statefulset("test_data/statefulset_root_user.json")]
    fn must_run_as_non_root_should_reject_workload_with_zero_as_user_id(
        #[case] request_file: &str,
    ) {
        let settings = Settings {
            run_as_user: RuleStrategy {
                rule: Rule::MustRunAsNonRoot,
                ranges: vec![],
                ..Default::default()
            },
            ..Default::default()
        };
        let res = perform_validation_call(settings, request_file);
        assert!(
            res.mutated_object.is_none(),
            "Request should not be mutated"
        );
    }

    #[rstest]
    #[case::deployment(
        "test_data/deployment_with_no_securitycontext.json",
        "$.spec.template.spec.containers[*].securityContext.runAsNonRoot"
    )]
    #[case::replicaset(
        "test_data/replicaset_with_no_securitycontext.json",
        "$.spec.template.spec.containers[*].securityContext.runAsNonRoot"
    )]
    #[case::daemonset(
        "test_data/daemonset_with_no_securitycontext.json",
        "$.spec.template.spec.containers[*].securityContext.runAsNonRoot"
    )]
    #[case::statefulset(
        "test_data/statefulset_with_no_securitycontext.json",
        "$.spec.template.spec.containers[*].securityContext.runAsNonRoot"
    )]
    #[case::replicationcontroller(
        "test_data/replicationcontroller_with_no_securitycontext.json",
        "$.spec.template.spec.containers[*].securityContext.runAsNonRoot"
    )]
    #[case::job(
        "test_data/job_with_no_securitycontext.json",
        "$.spec.template.spec.containers[*].securityContext.runAsNonRoot"
    )]
    #[case::cronjob(
        "test_data/cronjob_with_no_securitycontext.json",
        "$.spec.jobTemplate.spec.template.spec.containers[*].securityContext.runAsNonRoot"
    )]
    fn must_run_as_non_root_should_mutate_highlevel_workload_kind_request_when_run_as_user_is_not_defined(
        #[case] request_file: &str,
        #[case] json_validation_path: &str,
    ) {
        let settings = Settings {
            run_as_user: RuleStrategy {
                rule: Rule::MustRunAsNonRoot,
                ranges: vec![],
                ..Default::default()
            },
            ..Default::default()
        };

        let response = perform_validation_call(settings, request_file);

        assert!(
            response.mutated_object.is_some(),
            "Request should be mutated"
        );
        let run_as_non_root_json = jsonpath::select(
            response.mutated_object.as_ref().unwrap(),
            json_validation_path,
        )
        .unwrap();
        assert_eq!(
            run_as_non_root_json,
            vec![true],
            "MustRunAsNonRoot should add the 'runAsNonRoot' in the containers when no 'runAsUser' is not defined"
        );
    }

    #[test]
    fn must_run_as_should_mutate_deployment_with_podspec_securitycontext_without_values() {
        let settings = Settings {
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
            ..Default::default()
        };
        let res = perform_validation_call(
            settings,
            "test_data/deployment_with_no_securitycontext.json",
        );

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
    }

    #[test]
    fn must_run_as_should_reject_deployment_with_podspec_securitycontext_with_invalid_values() {
        let settings = Settings {
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
            ..Default::default()
        };
        let res = perform_validation_call(settings, "test_data/deployment_with_user.json");
        assert!(
            res.mutated_object.is_none(),
            "MustRunAs should not mutate request when user ID is invalid"
        );
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
