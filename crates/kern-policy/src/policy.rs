//! Policy representation, selectors, and applicability.

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;

use kern_core::{CapabilityName, ConstraintSet, DeviceId, NormalizedActionProposal, SubjectId};

/// Identifies a policy.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PolicyId(String);

impl PolicyId {
    /// Wraps an identifier string.
    pub fn new(id: impl Into<String>) -> Self {
        Self(id.into())
    }

    /// Borrows the underlying identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for PolicyId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Which values a policy dimension covers.
///
/// `AnyOf` is selector disjunction, and it cannot be expressed as several
/// policies: policies compose by `meet`, so two policies naming one subject
/// each would intersect their constraints rather than cover either subject.
///
/// Deliberately not a language. No globs, no regular expressions, no boolean
/// expression trees, no scripting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Selector<T> {
    /// Matches every value.
    Any,
    /// Matches one value.
    Exactly(T),
    /// Matches any value in this set.
    AnyOf(BTreeSet<T>),
}

impl<T: Ord> Selector<T> {
    /// Builds an `AnyOf` selector, or `None` if the set is empty.
    ///
    /// An empty `AnyOf` can never match, so the policy could never apply. That
    /// is fail-closed but almost certainly a configuration mistake, so it is
    /// refused rather than accepted as a policy that silently does nothing.
    pub fn any_of<I: IntoIterator<Item = T>>(values: I) -> Option<Self> {
        let set: BTreeSet<T> = values.into_iter().collect();
        if set.is_empty() {
            None
        } else {
            Some(Self::AnyOf(set))
        }
    }

    /// True when this selector covers `value`.
    pub fn matches(&self, value: &T) -> bool {
        match self {
            Self::Any => true,
            Self::Exactly(expected) => expected == value,
            Self::AnyOf(set) => set.contains(value),
        }
    }
}

/// A policy could not be built.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyError {
    /// [`Policy::new`] was handed a constraint set granting unbounded authority.
    ///
    /// A constraint set with no constraints normalizes to TOP, so an empty or
    /// missing bounds block at a configuration boundary would otherwise become
    /// "everything permitted", silently. Unbounded authority has its own
    /// constructor, [`Policy::unbounded`], so it must be written on purpose.
    ImplicitUnboundedAuthority {
        /// The policy that would have granted it.
        id: PolicyId,
    },
}

impl fmt::Display for PolicyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ImplicitUnboundedAuthority { id } => write!(
                f,
                "policy `{id}` has no constraints; use Policy::unbounded to grant unbounded authority on purpose"
            ),
        }
    }
}

impl core::error::Error for PolicyError {}

/// Selectors bound to a constraint set. Nothing more.
///
/// Applicability is the grant: a policy that applies contributes its
/// constraints, and a subject with no applicable policy has no authority.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Policy {
    id: PolicyId,
    subject: Selector<SubjectId>,
    device: Selector<DeviceId>,
    capability: Selector<CapabilityName>,
    constraints: ConstraintSet,
}

impl Policy {
    /// Builds a constrained policy, refusing one that grants unbounded
    /// authority by accident.
    pub fn new(
        id: PolicyId,
        subject: Selector<SubjectId>,
        device: Selector<DeviceId>,
        capability: Selector<CapabilityName>,
        constraints: ConstraintSet,
    ) -> Result<Self, PolicyError> {
        if constraints.is_unconstrained() {
            return Err(PolicyError::ImplicitUnboundedAuthority { id });
        }
        Ok(Self {
            id,
            subject,
            device,
            capability,
            constraints,
        })
    }

    /// Builds a policy granting unbounded authority within its selectors.
    ///
    /// Legitimate and occasionally necessary. It exists as its own constructor
    /// so that granting unbounded physical authority is a deliberate, greppable
    /// act rather than the consequence of an empty configuration block.
    pub fn unbounded(
        id: PolicyId,
        subject: Selector<SubjectId>,
        device: Selector<DeviceId>,
        capability: Selector<CapabilityName>,
    ) -> Self {
        Self {
            id,
            subject,
            device,
            capability,
            constraints: ConstraintSet::unconstrained(),
        }
    }

    /// This policy's identifier.
    pub fn id(&self) -> &PolicyId {
        &self.id
    }

    /// The subjects this policy covers.
    pub fn subject(&self) -> &Selector<SubjectId> {
        &self.subject
    }

    /// The devices this policy covers.
    pub fn device(&self) -> &Selector<DeviceId> {
        &self.device
    }

    /// The capabilities this policy covers.
    pub fn capability(&self) -> &Selector<CapabilityName> {
        &self.capability
    }

    /// The authority this policy contributes where it applies.
    pub fn constraints(&self) -> &ConstraintSet {
        &self.constraints
    }

    /// True when this policy applies to `proposal`.
    ///
    /// Exact conjunction of the three selectors. No precedence, no priority, no
    /// first-match, no deny-overrides, and no dependence on insertion order.
    pub fn applies_to(&self, proposal: &NormalizedActionProposal) -> bool {
        self.subject.matches(proposal.actor())
            && self.device.matches(proposal.device())
            && self.capability.matches(proposal.capability())
    }
}

/// A policy could not be added to a set.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicySetError {
    /// Two policies share an identifier.
    ///
    /// Overwriting silently would let one policy's authority disappear because
    /// of a copy-pasted name.
    DuplicatePolicyId {
        /// The repeated identifier.
        id: PolicyId,
    },
}

impl fmt::Display for PolicySetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicatePolicyId { id } => write!(f, "duplicate policy id `{id}`"),
        }
    }
}

impl core::error::Error for PolicySetError {}

/// The policies an authority evaluates against, keyed by identifier.
///
/// Ordered by [`PolicyId`], so iteration and the resulting applied-policy list
/// never depend on insertion order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct PolicySet {
    policies: BTreeMap<PolicyId, Policy>,
}

impl PolicySet {
    /// An empty set, which grants no authority to anyone.
    pub fn new() -> Self {
        Self::default()
    }

    /// Adds a policy, refusing to overwrite an existing identifier.
    pub fn insert(&mut self, policy: Policy) -> Result<(), PolicySetError> {
        if self.policies.contains_key(policy.id()) {
            return Err(PolicySetError::DuplicatePolicyId {
                id: policy.id().clone(),
            });
        }
        self.policies.insert(policy.id().clone(), policy);
        Ok(())
    }

    /// Builds a set from many policies.
    pub fn from_policies<I>(policies: I) -> Result<Self, PolicySetError>
    where
        I: IntoIterator<Item = Policy>,
    {
        let mut set = Self::new();
        for policy in policies {
            set.insert(policy)?;
        }
        Ok(set)
    }

    /// The policies that apply to `proposal`, in identifier order.
    pub fn applicable(&self, proposal: &NormalizedActionProposal) -> Vec<&Policy> {
        self.policies
            .values()
            .filter(|policy| policy.applies_to(proposal))
            .collect()
    }

    /// Every policy, in identifier order.
    pub fn iter(&self) -> impl Iterator<Item = &Policy> {
        self.policies.values()
    }

    /// How many policies the set holds.
    pub fn len(&self) -> usize {
        self.policies.len()
    }

    /// True when the set holds no policies, and therefore grants nothing.
    pub fn is_empty(&self) -> bool {
        self.policies.is_empty()
    }
}
