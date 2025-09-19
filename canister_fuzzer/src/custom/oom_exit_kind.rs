use crate::libafl::Error;
use crate::libafl::executors::ExitKind;
use crate::libafl::feedbacks::ExitKindLogic;
use std::borrow::Cow;

/// Name used by `OomFeedback`
pub const OOM_FEEDBACK_NAME: &str = "OomFeedback";

/// Logic which finds all [`ExitKind::Oom`] exits interesting
#[derive(Debug, Copy, Clone)]
pub struct OomLogic;

impl ExitKindLogic for OomLogic {
    const NAME: Cow<'static, str> = Cow::Borrowed(OOM_FEEDBACK_NAME);

    fn check_exit_kind(kind: &ExitKind) -> Result<bool, Error> {
        Ok(matches!(kind, ExitKind::Oom))
    }
}
