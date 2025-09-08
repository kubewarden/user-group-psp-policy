use thiserror::Error;

#[derive(Error, Eq, PartialEq, Debug)]
pub enum ValidationError {
    #[error("User ID outside defined ranges")]
    UserIdOutsideRanges,
    #[error("Group ID is outside defined ranges")]
    GroupIdOutsideRanges,
    #[error("RunAsNonRoot should be set to true")]
    ShouldRunAsNonRoot,
    #[error("Invalid user ID: cannot run container with root ID (0)")]
    CannotUseRootUserId,
    #[error("Invalid group ID in the container image configuration: \"{0}\"")]
    ImageConfigGroupId(String),
    #[error("Invalid user ID in the container image configuration: \"{0}\"")]
    ImageConfigUserId(String),
    #[error("User ID defined in the container image is outside defined ranges")]
    ImageConfigUserIdOutsideRanges,
    #[error("User ID defined in the container image cannot be root ID (0)")]
    ImageConfigUserIdCannotBeRoot,
    #[error("Group ID defined in the container image is outside defined ranges")]
    ImageConfigGroupIdOutsideRanges,
}
