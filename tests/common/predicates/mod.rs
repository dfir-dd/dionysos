use assert_cmd::assert::IntoOutputPredicate;
use libdionysos::OutputFormat;
use predicates_core::Predicate;

pub (crate) mod json;

pub (crate) trait DionysosPredicate<P>: IntoOutputPredicate<P> where P: Predicate<[u8]> {
    fn expected_format(&self) -> OutputFormat;
}