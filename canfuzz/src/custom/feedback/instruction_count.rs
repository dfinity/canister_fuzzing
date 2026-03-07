//! Feedback for instruction count maximization.
//!
//! [`InstructionCountFeedback`] marks an input as "interesting" when it increases the
//! maximum observed instruction count, guiding the fuzzer toward inputs that consume
//! more IC instructions.

use crate::custom::observer::instruction_count::{
    INSTRUCTION_COUNT_OBSERVER_NAME, InstructionCountObserver,
};
use crate::libafl::executors::ExitKind;
use crate::libafl::feedbacks::{Feedback, StateInitializer};
use crate::libafl::state::HasExecutions;
use crate::libafl::{Error, HasNamedMetadata};
use serde::Serialize;
use std::borrow::Cow;

use crate::libafl_bolts::Named;
use crate::libafl_bolts::tuples::MatchNameRef;
use crate::libafl_bolts::tuples::{Handle, MatchName};

/// A libafl feedback that considers an input interesting when it achieves a new maximum
/// instruction count, as reported by the [`InstructionCountObserver`].
#[derive(Serialize, Clone, Debug)]
pub struct InstructionCountFeedback<'a> {
    handle: Handle<InstructionCountObserver<'a>>,
}

impl InstructionCountFeedback<'_> {
    #[must_use]
    pub fn new() -> Self {
        Self {
            handle: Handle::new(Cow::Borrowed(INSTRUCTION_COUNT_OBSERVER_NAME)),
        }
    }
}

impl Default for InstructionCountFeedback<'_> {
    fn default() -> Self {
        Self::new()
    }
}

impl Named for InstructionCountFeedback<'_> {
    #[inline]
    fn name(&self) -> &Cow<'static, str> {
        self.handle.name()
    }
}

impl<S> StateInitializer<S> for InstructionCountFeedback<'_> {
    fn init_state(&mut self, _state: &mut S) -> Result<(), Error> {
        Ok(())
    }
}

impl<EM, I, OT, S> Feedback<EM, I, OT, S> for InstructionCountFeedback<'_>
where
    S: HasNamedMetadata + HasExecutions,
    OT: MatchName,
{
    #[allow(clippy::wrong_self_convention)]
    fn is_interesting(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _input: &I,
        observers: &OT,
        _exit_kind: &ExitKind,
    ) -> Result<bool, Error> {
        let observer: &InstructionCountObserver = observers.get(&self.handle).unwrap();
        Ok(observer.get_ref().increased)
    }

    fn append_metadata(
        &mut self,
        _state: &mut S,
        _manager: &mut EM,
        _observers: &OT,
        _testcase: &mut crate::libafl::corpus::Testcase<I>,
    ) -> Result<(), Error> {
        Ok(())
    }
}
