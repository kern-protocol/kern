//! Turning current authority into governed execution.
//!
//! ```text
//! prepare   enforce -> reserve record -> digest -> ExecutionId -> Prepared record
//!             every failure here is a GovernError, and nothing was sent
//!
//! submit    check_authority -> executor.submit exactly once -> apply outcome
//!             authority lost here ends the attempt as NotStarted, unsent
//!
//! tick      check_authority per record -> mark lapses -> instruct the executor
//!             -> drain observations
//! ```

use alloc::boxed::Box;
use alloc::vec::Vec;

use kern_core::{EnforcerSessionId, MonotonicClock, NormalizedActionProposal, Uptime};
use kern_enforcer::{AuthorityStatusError, ChallengeSource, EnforcerStore, LeaseHandle};

use crate::command::{CommandDigest, SemanticCommand};
use crate::contract::{
    CancelRequestOutcome, ExecutionObservation, Executor, ExecutorDeclaration,
    ExecutorObservations, ExecutorQuery, ExecutorReconcile, LapseAction, ObservationOrdering,
    ObservationPoll, ObservedReport, QueryOutcome, ReconcileOutcome, SubmitOutcome,
};
use crate::error::{ConfigError, GovernError, ResolveDisputeError};
use crate::id::{ExecutionId, ExecutionIdSource};
use crate::journal::{ResolutionSource, Transition, TransitionKind, TransitionSubject};
use crate::record::ExecutionRecord;
use crate::state::{
    AuthorityLapseReason, CancelRefusal, CancellationState, ExecutionState, LastKnown,
    NotStartedReason, TerminalOutcome, UnknownPhase,
};

/// What the governor does about operations discovered after a restart.
///
/// Required at construction, with no default. A fresh session holds no authority
/// for any pre-restart operation, so nothing authorizes their continuation — but
/// whether to instruct a machine that Kern cannot identify is a physical
/// decision, and it belongs to the deployment rather than to a library default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StartupPolicy {
    /// Issue the configured lapse instruction for every unattributed operation.
    LapseDiscovered,
    /// Record what was discovered and instruct nothing.
    ReportOnly,
}

/// Governor configuration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GovernorConfig {
    /// How many execution records the fixed-capacity table holds.
    pub capacity: usize,
    /// How many transitions the journal holds before it starts dropping detail.
    pub journal_capacity: usize,
    /// The instruction issued to the executor when authority lapses.
    pub lapse_action: LapseAction,
    /// What to do about operations discovered by reconciliation that no record
    /// matches.
    pub startup_policy: StartupPolicy,
    /// How many observations one tick may drain, so a chatty adapter cannot
    /// starve the lapse pass.
    pub observation_budget: usize,
}

/// Whether the adapter can currently observe the executor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkState {
    /// The adapter is reporting.
    Connected,
    /// The adapter reported it cannot see the executor.
    Disconnected {
        /// When Kern learned this, in local uptime.
        since: Uptime,
    },
}

/// What one governor pass did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TickReport {
    /// Executions whose authority was found to have lapsed in this pass.
    pub lapses_detected: u32,
    /// Lapse instructions issued to the executor.
    pub lapse_requests_issued: u32,
    /// Lapsed executions Kern holds no operation identity for, so it could
    /// instruct nothing.
    pub lapse_skipped_no_operation: u32,
    /// Observations applied.
    pub observations_applied: u32,
    /// Observations dropped as older than what was already applied.
    pub observations_dropped_stale: u32,
    /// Observations naming an operation no record matches.
    pub observations_unmatched: u32,
    /// Executions that entered an unknown state in this pass.
    pub entered_unknown: u32,
    /// Disputes opened by contradictory terminal evidence.
    pub disputes_opened: u32,
    /// True when the store handed in belongs to a different enforcer session.
    ///
    /// Every active execution is lapsed as `AuthorityMissing` in that case,
    /// which is the truth, and this flag makes the wiring fault visible.
    pub session_mismatch: bool,
    /// Link health after the pass.
    pub link: LinkState,
    /// How many journal entries the pass produced.
    pub journal_len: u32,
    /// True when journal detail was dropped.
    pub journal_overflowed: bool,
}

impl TickReport {
    fn new(link: LinkState) -> Self {
        Self {
            lapses_detected: 0,
            lapse_requests_issued: 0,
            lapse_skipped_no_operation: 0,
            observations_applied: 0,
            observations_dropped_stale: 0,
            observations_unmatched: 0,
            entered_unknown: 0,
            disputes_opened: 0,
            session_mismatch: false,
            link,
            journal_len: 0,
            journal_overflowed: false,
        }
    }
}

/// What one reconciliation pass found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReconcileSummary {
    /// Discovered operations that already matched a record.
    pub attributed: u32,
    /// Records whose lost submission was rebound by an echoed identifier.
    pub resolved: u32,
    /// Discovered operations Kern cannot attribute to any record.
    pub unattributed: u32,
    /// Lapse instructions issued for unattributed operations.
    pub lapse_requests_issued: u32,
    /// Whether the adapter's enumeration was exhaustive.
    ///
    /// When false, absence proves nothing and no record was resolved by
    /// omission.
    pub complete: bool,
    /// False when the adapter cannot enumerate operations.
    pub supported: bool,
    /// True when the adapter could not reach the executor.
    pub disconnected: bool,
}

/// Ties current authority to execution, and authority lapse to instruction.
///
/// # What it is not
///
/// Not a runtime, not a scheduler, not a safety system. It performs no I/O of
/// its own, spawns nothing, and blocks on nothing. Every pass is driven by a
/// host call.
///
/// # The store is borrowed per call, never held
///
/// Installing a lease needs `&mut EnforcerStore`. A governor that owned or
/// borrowed the store for its lifetime would make it impossible to install or
/// supersede authority while executions are active.
pub struct ExecutionGovernor<O, C, S> {
    session: EnforcerSessionId,
    clock: C,
    ids: S,
    declaration: ExecutorDeclaration,
    lapse_action: LapseAction,
    startup_policy: StartupPolicy,
    observation_budget: usize,
    records: Box<[Option<ExecutionRecord<O>>]>,
    journal: Vec<Transition>,
    journal_capacity: usize,
    journal_overflowed: bool,
    dropped_transitions: u64,
    link: LinkState,
}

impl<O, C, S> ExecutionGovernor<O, C, S>
where
    O: Clone + Eq,
    C: MonotonicClock,
    S: ExecutionIdSource,
{
    /// Builds a governor for one enforcer session and one adapter.
    ///
    /// The declaration is read once, here. An adapter that cannot perform the
    /// configured lapse action is refused now, so a lapse can never discover at
    /// the worst moment that its instruction does nothing.
    pub fn new(
        session: EnforcerSessionId,
        config: GovernorConfig,
        clock: C,
        ids: S,
        declaration: ExecutorDeclaration,
    ) -> Result<Self, ConfigError> {
        if config.capacity == 0 {
            return Err(ConfigError::ZeroCapacity);
        }
        if config.journal_capacity == 0 {
            return Err(ConfigError::ZeroJournalCapacity);
        }
        if config.observation_budget == 0 {
            return Err(ConfigError::ZeroObservationBudget);
        }
        if !declaration
            .supported_lapse_actions
            .supports(config.lapse_action)
        {
            return Err(ConfigError::LapseActionUnsupported {
                required: config.lapse_action,
            });
        }

        Ok(Self {
            session,
            clock,
            ids,
            declaration,
            lapse_action: config.lapse_action,
            startup_policy: config.startup_policy,
            observation_budget: config.observation_budget,
            records: (0..config.capacity)
                .map(|_| None)
                .collect::<Vec<_>>()
                .into(),
            journal: Vec::with_capacity(config.journal_capacity),
            journal_capacity: config.journal_capacity,
            journal_overflowed: false,
            dropped_transitions: 0,
            link: LinkState::Connected,
        })
    }

    /// The session this governor was built for.
    pub fn session(&self) -> &EnforcerSessionId {
        &self.session
    }

    /// What the adapter declared at construction.
    pub fn declaration(&self) -> ExecutorDeclaration {
        self.declaration
    }

    /// The instruction issued when authority lapses.
    pub fn lapse_action(&self) -> LapseAction {
        self.lapse_action
    }

    /// Link health as of the last pass.
    pub fn link(&self) -> LinkState {
        self.link
    }

    /// The transitions the most recent pass produced.
    ///
    /// Cleared at the start of every pass, so a host that wants complete
    /// provenance drains it between calls. A prepare and its submit are one
    /// pass.
    pub fn journal(&self) -> &[Transition] {
        &self.journal
    }

    /// True when the journal dropped detail during the last pass.
    pub fn journal_overflowed(&self) -> bool {
        self.journal_overflowed
    }

    /// How many transitions have been dropped over this governor's life.
    ///
    /// Lost provenance detail is counted, never silent. No authority transition
    /// and no lapse instruction is ever among what is lost: those happen in the
    /// record and at the adapter.
    pub fn dropped_transitions(&self) -> u64 {
        self.dropped_transitions
    }

    /// The record for one execution, if it is still held.
    pub fn record(&self, execution: ExecutionId) -> Option<&ExecutionRecord<O>> {
        self.records
            .iter()
            .flatten()
            .find(|record| record.execution_id() == execution)
    }

    /// Every record the table holds.
    pub fn records(&self) -> impl Iterator<Item = &ExecutionRecord<O>> {
        self.records.iter().flatten()
    }

    /// How many records are in a state that is not terminal.
    pub fn active_count(&self) -> usize {
        self.records
            .iter()
            .flatten()
            .filter(|record| !record.execution().is_terminal())
            .count()
    }

    /// Authorizes an operation and reserves a record for it.
    ///
    /// # A successful preparation is not an authority reservation
    ///
    /// It means the operation was authorized *at preparation time*. Authority may
    /// expire or be superseded before the preparation is submitted, and
    /// [`PreparedExecution::submit`] re-checks liveness immediately before it
    /// invokes the executor.
    ///
    /// # Nothing is sent
    ///
    /// Whichever way this returns, no adapter has been called. That is why every
    /// failure here is a [`GovernError`] and the submitting method returns no
    /// `Result` at all.
    pub fn prepare<'g, 'p, M, R>(
        &'g mut self,
        store: &EnforcerStore<M, R>,
        handle: &LeaseHandle,
        operation: &'p NormalizedActionProposal,
    ) -> Result<PreparedExecution<'g, 'p, O, C, S>, GovernError>
    where
        M: MonotonicClock,
        R: ChallengeSource,
    {
        self.reset_journal();

        if store.session() != &self.session {
            return Err(GovernError::SessionMismatch);
        }

        // Authority first, before any resource is spent on the request.
        store.enforce(handle, operation)?;

        let index = self.reserve_slot()?;
        let digest = CommandDigest::compute(operation)?;
        // Identifiers are drawn last, so a request that fails for any other
        // reason never burns one.
        let execution_id = self
            .ids
            .next_execution_id()
            .map_err(|_| GovernError::IdentifierExhausted)?;

        let now = self.clock.uptime();
        self.records[index] = Some(ExecutionRecord::new(
            execution_id,
            handle.clone(),
            digest,
            now,
        ));
        self.push(
            TransitionSubject::Execution(execution_id),
            now,
            TransitionKind::Prepared { digest },
        );

        Ok(PreparedExecution {
            governor: self,
            operation,
            index,
            execution_id,
            digest,
            settled: false,
        })
    }

    /// Re-checks authority for every active execution and instructs the executor
    /// about any that lapsed.
    ///
    /// Detection is pull-based: there is no timer and no thread. Lapse latency is
    /// the host's tick period plus the adapter's own latency, and the report says
    /// what this pass found rather than pretending the latency is zero.
    ///
    /// There is no early return. One operation the adapter cannot handle never
    /// prevents lapse handling for the others.
    pub fn tick<E, M, R>(&mut self, store: &EnforcerStore<M, R>, executor: &mut E) -> TickReport
    where
        E: Executor<OperationId = O>,
        M: MonotonicClock,
        R: ChallengeSource,
    {
        self.reset_journal();
        let mut report = TickReport::new(self.link);
        self.authority_pass(store, &mut report);
        self.lapse_pass(executor, &mut report);
        self.finish(report)
    }

    /// [`Self::tick`], then drains whatever the adapter has to report.
    ///
    /// Separate because an adapter without observations is legal: its executions
    /// simply stay unknown after submission, which is the truth rather than a
    /// gap.
    pub fn tick_observed<E, M, R>(
        &mut self,
        store: &EnforcerStore<M, R>,
        executor: &mut E,
    ) -> TickReport
    where
        E: Executor<OperationId = O> + ExecutorObservations,
        M: MonotonicClock,
        R: ChallengeSource,
    {
        self.reset_journal();
        let mut report = TickReport::new(self.link);
        self.authority_pass(store, &mut report);
        self.lapse_pass(executor, &mut report);
        self.observation_pass(executor, &mut report);
        self.finish(report)
    }

    /// Asks the adapter about executions Kern has lost the result of.
    ///
    /// Only reaches executions Kern holds an operation identity for. A lost
    /// *submission* acknowledgement leaves no identity to ask about, so this can
    /// never resolve one; see [`Self::reconcile`].
    ///
    /// Nothing here is resolved by elapsed time.
    pub fn query_unknown<E>(&mut self, executor: &mut E) -> u32
    where
        E: Executor<OperationId = O> + ExecutorQuery,
    {
        self.reset_journal();
        let mut report = TickReport::new(self.link);
        let mut resolved = 0;

        for index in 0..self.records.len() {
            let Some(operation) = self.records[index].as_ref().and_then(|record| {
                matches!(
                    record.execution(),
                    ExecutionState::Unknown {
                        phase: UnknownPhase::Result,
                        ..
                    }
                )
                .then(|| record.operation().cloned())
                .flatten()
            }) else {
                continue;
            };

            match executor.query(&operation) {
                QueryOutcome::Observed(observation) => {
                    self.apply_observation(observation, &mut report);
                    resolved += 1;
                }
                QueryOutcome::Unknown | QueryOutcome::Unsupported => {}
                QueryOutcome::Disconnected => {
                    let now = self.clock.uptime();
                    self.mark_disconnected(now, &mut report);
                    break;
                }
            }
        }

        self.finish(report);
        resolved
    }

    /// Asks the adapter what the executor is still running.
    ///
    /// # After a restart
    ///
    /// A fresh session holds no authority for any pre-restart operation, and Kern
    /// holds no records for them either — those died with the process. Discovered
    /// operations that match nothing are reported as unattributed and are never
    /// given a record: a record's provenance fields would have to be invented,
    /// and invented provenance is worse than none.
    ///
    /// With [`StartupPolicy::LapseDiscovered`], each unattributed operation is
    /// instructed with [`AuthorityLapseReason::AuthorityMissing`], which is
    /// literally the case.
    pub fn reconcile<E>(&mut self, executor: &mut E) -> ReconcileSummary
    where
        E: Executor<OperationId = O> + ExecutorReconcile,
    {
        self.reset_journal();
        let now = self.clock.uptime();
        let mut summary = ReconcileSummary {
            attributed: 0,
            resolved: 0,
            unattributed: 0,
            lapse_requests_issued: 0,
            complete: false,
            supported: true,
            disconnected: false,
        };

        let report = match executor.reconcile_active_operations() {
            ReconcileOutcome::Report(report) => report,
            ReconcileOutcome::Unsupported => {
                summary.supported = false;
                self.push(
                    TransitionSubject::Adapter,
                    now,
                    TransitionKind::ReconciliationUnsupported,
                );
                return summary;
            }
            ReconcileOutcome::Disconnected => {
                summary.disconnected = true;
                let mut tick = TickReport::new(self.link);
                self.mark_disconnected(now, &mut tick);
                return summary;
            }
        };

        summary.complete = report.complete;

        for (operation, echoed) in report.discovered {
            if self.index_of_operation(&operation).is_some() {
                summary.attributed += 1;
                continue;
            }

            // An echoed identifier is the only bridge back to a record whose
            // submission acknowledgement was lost, and only when the adapter
            // declared that it echoes one.
            let rebound = self
                .declaration
                .echoes_execution_id
                .then_some(echoed)
                .flatten();
            if let Some(index) = rebound.and_then(|id| self.index_of_lost_submission(id)) {
                let record = self.records[index]
                    .as_mut()
                    .expect("index came from a match");
                record.bind_operation(operation.clone());
                // Membership in an active-operation enumeration is the adapter's
                // report that the operation is running now.
                record.set_running();
                record.observed_at(now);
                let execution_id = record.execution_id();
                self.push(
                    TransitionSubject::Execution(execution_id),
                    now,
                    TransitionKind::UnknownResolvedByReconcile,
                );
                summary.attributed += 1;
                summary.resolved += 1;
                continue;
            }

            summary.unattributed += 1;
            if self.startup_policy == StartupPolicy::LapseDiscovered {
                let outcome = executor.on_authority_lapse(
                    &operation,
                    self.lapse_action,
                    AuthorityLapseReason::AuthorityMissing,
                );
                summary.lapse_requests_issued += 1;
                self.push(
                    TransitionSubject::Adapter,
                    now,
                    TransitionKind::LapseRequestedForUnattributed,
                );
                self.push(
                    TransitionSubject::Adapter,
                    now,
                    TransitionKind::CancellationRequestOutcome(outcome),
                );
            }
        }

        self.push(
            TransitionSubject::Adapter,
            now,
            TransitionKind::ReconciliationDiscovered {
                attributed: summary.attributed,
                unattributed: summary.unattributed,
                complete: summary.complete,
            },
        );
        summary
    }

    /// Settles contradictory terminal evidence by explicit attribution.
    ///
    /// The only exit from [`ExecutionState::Disputed`]. Kern records which result
    /// was attested to and where the attestation came from; it does not decide
    /// for itself which physical result was true.
    pub fn resolve_dispute(
        &mut self,
        execution: ExecutionId,
        outcome: TerminalOutcome,
        source: ResolutionSource,
    ) -> Result<(), ResolveDisputeError> {
        self.reset_journal();
        let now = self.clock.uptime();

        let index = self
            .records
            .iter()
            .position(|slot| matches!(slot, Some(record) if record.execution_id() == execution))
            .ok_or(ResolveDisputeError::NoSuchExecution)?;

        let record = self.records[index]
            .as_mut()
            .expect("index came from a match");
        if !matches!(record.execution(), ExecutionState::Disputed { .. }) {
            return Err(ResolveDisputeError::NotDisputed);
        }

        record.set_terminal(outcome, now);
        self.push(
            TransitionSubject::Execution(execution),
            now,
            TransitionKind::DisputeResolved { outcome, source },
        );
        Ok(())
    }

    // -- passes ---------------------------------------------------------------

    fn authority_pass<M, R>(&mut self, store: &EnforcerStore<M, R>, report: &mut TickReport)
    where
        M: MonotonicClock,
        R: ChallengeSource,
    {
        let session_ok = store.session() == &self.session;
        report.session_mismatch = !session_ok;
        let now = self.clock.uptime();

        for index in 0..self.records.len() {
            let Some(record) = self.records[index].as_ref() else {
                continue;
            };
            if record.execution().is_terminal() || record.authority().is_lapsed() {
                continue;
            }

            let execution_id = record.execution_id();
            // A store from another session holds no authority for this
            // execution, which is exactly what AuthorityMissing means.
            let status = if session_ok {
                store.check_authority(record.handle())
            } else {
                Err(AuthorityStatusError::AuthorityMissing)
            };

            let Err(error) = status else {
                continue;
            };
            let reason = AuthorityLapseReason::from(error);
            self.records[index]
                .as_mut()
                .expect("index came from a match")
                .mark_lapsed(reason, now);
            report.lapses_detected += 1;
            self.push(
                TransitionSubject::Execution(execution_id),
                now,
                TransitionKind::AuthorityLapsed(reason),
            );
        }
    }

    fn lapse_pass<E>(&mut self, executor: &mut E, report: &mut TickReport)
    where
        E: Executor<OperationId = O>,
    {
        let now = self.clock.uptime();

        for index in 0..self.records.len() {
            let Some(record) = self.records[index].as_ref() else {
                continue;
            };
            if record.execution().is_terminal() || record.lapse_handled() {
                continue;
            }
            let Some(reason) = record.authority().lapse_reason() else {
                continue;
            };
            let execution_id = record.execution_id();
            let operation = record.operation().cloned();

            // Marked before the call, so one instruction per execution holds
            // even if the adapter misbehaves.
            self.records[index]
                .as_mut()
                .expect("index came from a match")
                .mark_lapse_handled();

            let Some(operation) = operation else {
                // A lost submission leaves no operation identity, so there is
                // nothing to instruct. Kern says so rather than pretending.
                report.lapse_skipped_no_operation += 1;
                self.push(
                    TransitionSubject::Execution(execution_id),
                    now,
                    TransitionKind::LapseNotRequestedNoOperation,
                );
                continue;
            };

            self.records[index]
                .as_mut()
                .expect("index came from a match")
                .set_cancellation(CancellationState::Requested { at: now });
            self.push(
                TransitionSubject::Execution(execution_id),
                now,
                TransitionKind::CancellationRequested(self.lapse_action),
            );

            let outcome = executor.on_authority_lapse(&operation, self.lapse_action, reason);
            report.lapse_requests_issued += 1;

            let state = match outcome {
                CancelRequestOutcome::Accepted => CancellationState::RequestAccepted { at: now },
                CancelRequestOutcome::AlreadyTerminal => {
                    CancellationState::Refused(CancelRefusal::AlreadyTerminal)
                }
                CancelRequestOutcome::Rejected => {
                    CancellationState::Refused(CancelRefusal::Rejected)
                }
                CancelRequestOutcome::Unsupported => {
                    CancellationState::Refused(CancelRefusal::Unsupported)
                }
                CancelRequestOutcome::Unknown => CancellationState::RequestUnknown,
            };
            self.records[index]
                .as_mut()
                .expect("index came from a match")
                .set_cancellation(state);
            self.push(
                TransitionSubject::Execution(execution_id),
                now,
                TransitionKind::CancellationRequestOutcome(outcome),
            );
        }
    }

    fn observation_pass<E>(&mut self, executor: &mut E, report: &mut TickReport)
    where
        E: Executor<OperationId = O> + ExecutorObservations,
    {
        for _ in 0..self.observation_budget {
            match executor.poll_observation() {
                ObservationPoll::Observation(observation) => {
                    let now = self.clock.uptime();
                    self.mark_connected(now);
                    self.apply_observation(observation, report);
                }
                ObservationPoll::Idle => {
                    let now = self.clock.uptime();
                    self.mark_connected(now);
                    break;
                }
                ObservationPoll::Disconnected => {
                    let now = self.clock.uptime();
                    self.mark_disconnected(now, report);
                    break;
                }
            }
        }
        report.link = self.link;
    }

    fn apply_observation(&mut self, observation: ExecutionObservation<O>, report: &mut TickReport) {
        let now = self.clock.uptime();
        let Some(index) = self.index_of_operation(&observation.operation) else {
            report.observations_unmatched += 1;
            self.push(
                TransitionSubject::Adapter,
                now,
                TransitionKind::UnmatchedObservation,
            );
            return;
        };

        let execution_id = self.records[index]
            .as_ref()
            .expect("index came from a match")
            .execution_id();
        let subject = TransitionSubject::Execution(execution_id);

        {
            let record = self.records[index]
                .as_mut()
                .expect("index came from a match");
            record.observed_at(now);

            // A declared sequence is the only ordering Kern trusts. Without one
            // it falls back to the state lattice below.
            if self.declaration.ordering == ObservationOrdering::Sequenced {
                if let (Some(seen), Some(last)) = (observation.sequence, record.last_sequence()) {
                    if seen <= last {
                        report.observations_dropped_stale += 1;
                        self.push(subject, now, TransitionKind::StaleObservationDropped);
                        return;
                    }
                }
                record.set_last_sequence(observation.sequence);
            }
        }

        report.observations_applied += 1;
        match observation.report {
            ObservedReport::Running => self.apply_running(index, subject, now, report),
            ObservedReport::Completed => {
                self.apply_terminal(index, TerminalOutcome::Completed, subject, now, report)
            }
            ObservedReport::Failed(class) => {
                self.apply_terminal(index, TerminalOutcome::Failed(class), subject, now, report)
            }
            ObservedReport::Cancelled => {
                self.apply_terminal(index, TerminalOutcome::Cancelled, subject, now, report)
            }
        }
    }

    fn apply_running(
        &mut self,
        index: usize,
        subject: TransitionSubject,
        now: Uptime,
        report: &mut TickReport,
    ) {
        let record = self.records[index]
            .as_mut()
            .expect("index came from a match");
        match record.execution() {
            ExecutionState::Prepared
            | ExecutionState::Submitted
            | ExecutionState::Unknown { .. } => {
                record.set_running();
                self.push(subject, now, TransitionKind::ObservedRunning);
            }
            ExecutionState::Running => {}
            // Running after a terminal result is a report about the past.
            _ => {
                report.observations_applied -= 1;
                report.observations_dropped_stale += 1;
                self.push(subject, now, TransitionKind::StaleObservationDropped);
            }
        }
    }

    fn apply_terminal(
        &mut self,
        index: usize,
        outcome: TerminalOutcome,
        subject: TransitionSubject,
        now: Uptime,
        report: &mut TickReport,
    ) {
        let record = self.records[index]
            .as_mut()
            .expect("index came from a match");
        let state = record.execution();

        match state {
            ExecutionState::Disputed { .. } => {
                self.push(subject, now, TransitionKind::DisputeObservedAgain);
                return;
            }
            ExecutionState::NotStarted(_) => {
                report.observations_applied -= 1;
                report.observations_dropped_stale += 1;
                self.push(subject, now, TransitionKind::StaleObservationDropped);
                return;
            }
            _ => {}
        }

        if let Some(first) = state.terminal_outcome() {
            if first == outcome {
                // The same result again says nothing new.
                return;
            }
            // Contradictory evidence. Kern refuses to choose, and refuses to
            // hide the contradiction behind a flag a caller might not read.
            record.set_disputed(first, outcome);
            report.disputes_opened += 1;
            self.push(
                subject,
                now,
                TransitionKind::DisputeOpened {
                    first,
                    conflicting: outcome,
                },
            );
            return;
        }

        record.set_terminal(outcome, now);
        let cancellation = record.cancellation();
        self.push(subject, now, TransitionKind::Terminal(outcome));

        if cancellation.is_outstanding() {
            if outcome == TerminalOutcome::Cancelled {
                let record = self.records[index]
                    .as_mut()
                    .expect("index came from a match");
                record.set_cancellation(CancellationState::Confirmed { at: now });
                self.push(subject, now, TransitionKind::CancellationConfirmed);
            } else {
                let record = self.records[index]
                    .as_mut()
                    .expect("index came from a match");
                record.set_cancellation(CancellationState::Moot);
                self.push(subject, now, TransitionKind::CancellationMoot);
            }
        }
    }

    fn mark_connected(&mut self, now: Uptime) {
        if matches!(self.link, LinkState::Disconnected { .. }) {
            self.link = LinkState::Connected;
            // A restored link is not evidence about any machine: nothing that
            // became unknown is resolved here.
            self.push(
                TransitionSubject::Adapter,
                now,
                TransitionKind::LinkRestored,
            );
        }
    }

    /// Loss of observation is loss of knowledge, never evidence of failure.
    fn mark_disconnected(&mut self, now: Uptime, report: &mut TickReport) {
        if !matches!(self.link, LinkState::Disconnected { .. }) {
            self.link = LinkState::Disconnected { since: now };
            self.push(
                TransitionSubject::Adapter,
                now,
                TransitionKind::LinkDisconnected,
            );
        }

        for index in 0..self.records.len() {
            let Some(record) = self.records[index].as_ref() else {
                continue;
            };
            if record.execution().is_terminal() || record.operation().is_none() {
                continue;
            }
            if matches!(
                record.execution(),
                ExecutionState::Unknown {
                    phase: UnknownPhase::Result,
                    ..
                }
            ) {
                continue;
            }
            let Some(last_known) = record.execution().as_last_known() else {
                continue;
            };
            let execution_id = record.execution_id();

            self.records[index]
                .as_mut()
                .expect("index came from a match")
                .set_unknown(UnknownPhase::Result, last_known);
            report.entered_unknown += 1;
            self.push(
                TransitionSubject::Execution(execution_id),
                now,
                TransitionKind::BecameUnknown {
                    phase: UnknownPhase::Result,
                    last_known,
                },
            );
        }
        report.link = self.link;
    }

    // -- storage and journal --------------------------------------------------

    /// Finds room for one record.
    ///
    /// A free slot first. Otherwise the oldest **terminal** record's storage is
    /// reclaimed: its attempt is over and its provenance has already been
    /// journalled. Records that are not terminal are never reclaimed, and neither
    /// is an unknown one — uncertainty is the last thing to throw away.
    fn reserve_slot(&mut self) -> Result<usize, GovernError> {
        if let Some(index) = self.records.iter().position(Option::is_none) {
            return Ok(index);
        }

        let reclaimable = self
            .records
            .iter()
            .enumerate()
            .filter_map(|(index, slot)| {
                slot.as_ref()
                    .filter(|record| record.execution().is_terminal())
                    .map(|record| (index, record.prepared_at()))
            })
            .min_by_key(|(_, prepared_at)| *prepared_at)
            .map(|(index, _)| index);

        let index = reclaimable.ok_or(GovernError::CapacityExhausted)?;
        let now = self.clock.uptime();
        let execution_id = self.records[index]
            .as_ref()
            .expect("index came from a match")
            .execution_id();
        self.records[index] = None;
        self.push(
            TransitionSubject::Execution(execution_id),
            now,
            TransitionKind::RecordReclaimed,
        );
        Ok(index)
    }

    fn index_of_operation(&self, operation: &O) -> Option<usize> {
        self.records
            .iter()
            .position(|slot| matches!(slot, Some(record) if record.operation() == Some(operation)))
    }

    fn index_of_lost_submission(&self, execution: ExecutionId) -> Option<usize> {
        self.records.iter().position(|slot| {
            matches!(
                slot,
                Some(record)
                    if record.execution_id() == execution
                        && matches!(
                            record.execution(),
                            ExecutionState::Unknown {
                                phase: UnknownPhase::Submission,
                                ..
                            }
                        )
            )
        })
    }

    fn reset_journal(&mut self) {
        self.journal.clear();
        self.journal_overflowed = false;
    }

    /// Appends one entry, or counts it as dropped.
    ///
    /// Never allocates beyond the capacity chosen at construction, and never
    /// fails a caller: provenance detail is the only thing an overflow costs.
    fn push(&mut self, subject: TransitionSubject, at: Uptime, kind: TransitionKind) {
        if self.journal.len() < self.journal_capacity {
            self.journal.push(Transition { subject, at, kind });
        } else {
            self.journal_overflowed = true;
            self.dropped_transitions = self.dropped_transitions.saturating_add(1);
        }
    }

    fn finish(&self, mut report: TickReport) -> TickReport {
        report.journal_len = self.journal.len() as u32;
        report.journal_overflowed = self.journal_overflowed;
        report.link = self.link;
        report
    }
}

/// What a submission did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SubmitReceipt {
    execution_id: ExecutionId,
    command_digest: CommandDigest,
    state: ExecutionState,
    executor_invoked: bool,
}

impl SubmitReceipt {
    /// The execution this receipt is about.
    pub fn execution_id(&self) -> ExecutionId {
        self.execution_id
    }

    /// Names the operation the execution was prepared for.
    pub fn command_digest(&self) -> &CommandDigest {
        &self.command_digest
    }

    /// The execution state as of this call.
    pub fn state(&self) -> ExecutionState {
        self.state
    }

    /// Whether the adapter was called at all.
    ///
    /// False for [`NotStartedReason::AuthorityLost`] and
    /// [`NotStartedReason::Abandoned`]: no physical effect is possible from this
    /// attempt. True for a rejection, an acceptance, and an unknown submission.
    pub fn executor_invoked(&self) -> bool {
        self.executor_invoked
    }
}

/// An authorized, recorded attempt that has not been handed to an executor.
///
/// # Not an authority reservation
///
/// Holding one proves the operation was authorized when it was prepared. It
/// promises nothing about later. [`Self::submit`] re-checks authority liveness
/// immediately before invoking the executor, and refuses without invoking
/// anything if that authority is gone.
///
/// # Why it borrows the governor exclusively
///
/// So the sequence "check authority, then invoke" cannot be interleaved with
/// anything. While a preparation is outstanding there is no second preparation,
/// no tick, and no reconciliation through that governor. Concurrency is not a
/// Phase 5 requirement, and no raw pointer or interior mutability is used to
/// pretend otherwise.
///
/// The store is deliberately *not* borrowed: the host must remain able to
/// install and supersede authority between preparing and submitting, which is
/// exactly what makes the authority-loss paths real.
#[must_use = "a dropped preparation is recorded as NotStarted(Abandoned)"]
pub struct PreparedExecution<'g, 'p, O, C, S>
where
    O: Clone + Eq,
    C: MonotonicClock,
    S: ExecutionIdSource,
{
    governor: &'g mut ExecutionGovernor<O, C, S>,
    operation: &'p NormalizedActionProposal,
    index: usize,
    execution_id: ExecutionId,
    digest: CommandDigest,
    settled: bool,
}

impl<O, C, S> PreparedExecution<'_, '_, O, C, S>
where
    O: Clone + Eq,
    C: MonotonicClock,
    S: ExecutionIdSource,
{
    /// The identifier allocated for this attempt.
    pub fn execution_id(&self) -> ExecutionId {
        self.execution_id
    }

    /// Names the operation this attempt was prepared for.
    ///
    /// Together with [`Self::handle`], this is the binding a host persists
    /// *before* submitting, so its provenance write precedes any possible
    /// physical effect. Kern keeps the digest; the payload stays with the host,
    /// which already owns it.
    pub fn command_digest(&self) -> &CommandDigest {
        &self.digest
    }

    /// The authority that permitted this preparation.
    pub fn handle(&self) -> &LeaseHandle {
        self.governor.records[self.index]
            .as_ref()
            .expect("the record was written by prepare")
            .handle()
    }

    /// Re-checks authority liveness, then invokes the executor at most once.
    ///
    /// # Order
    ///
    /// ```text
    /// session compare -> check_authority -> executor.submit -> apply outcome
    /// ```
    ///
    /// If liveness refuses, the attempt ends as
    /// [`NotStartedReason::AuthorityLost`] and **the executor is not called**.
    /// The semantic authorization from preparation is not re-run: the
    /// preparation is sealed, so the operation cannot have changed, and the
    /// second check is lifetime and supersession only.
    ///
    /// # No `Result`
    ///
    /// Once this method exists there is nothing left that can fail before the
    /// adapter is reached, which is why a post-invocation failure has nowhere to
    /// become a [`GovernError`]. An adapter's own failures are its to classify,
    /// into `Rejected` when it can prove nothing was sent and `Unknown`
    /// otherwise.
    pub fn submit<E, M, R>(mut self, store: &EnforcerStore<M, R>, executor: &mut E) -> SubmitReceipt
    where
        E: Executor<OperationId = O>,
        M: MonotonicClock,
        R: ChallengeSource,
    {
        let index = self.index;
        let execution_id = self.execution_id;
        let subject = TransitionSubject::Execution(execution_id);
        let now = self.governor.clock.uptime();

        let status = if store.session() == &self.governor.session {
            store.check_authority(self.handle())
        } else {
            Err(AuthorityStatusError::AuthorityMissing)
        };

        if let Err(error) = status {
            let reason = AuthorityLapseReason::from(error);
            let record = self.governor.records[index]
                .as_mut()
                .expect("the record was written by prepare");
            record.mark_lapsed(reason, now);
            record.set_not_started(NotStartedReason::AuthorityLost(reason));
            // Nothing to instruct: no operation was ever created.
            record.mark_lapse_handled();
            self.governor
                .push(subject, now, TransitionKind::AuthorityLapsed(reason));
            self.governor.push(
                subject,
                now,
                TransitionKind::NotStarted(NotStartedReason::AuthorityLost(reason)),
            );
            self.settled = true;
            return SubmitReceipt {
                execution_id,
                command_digest: self.digest,
                state: ExecutionState::NotStarted(NotStartedReason::AuthorityLost(reason)),
                executor_invoked: false,
            };
        }

        self.governor.records[index]
            .as_mut()
            .expect("the record was written by prepare")
            .set_submitted_at(now);

        let command = SemanticCommand::new(execution_id, self.operation);
        let outcome = executor.submit(&command);
        let accept_implies_running = self.governor.declaration.accept_implies_running;

        let state = {
            let record = self.governor.records[index]
                .as_mut()
                .expect("the record was written by prepare");
            match outcome {
                SubmitOutcome::Accepted { operation } => {
                    record.accept_operation(operation, accept_implies_running);
                }
                SubmitOutcome::Rejected { reason } => {
                    record.set_not_started(NotStartedReason::Rejected(reason));
                }
                // Never retried. A lost acknowledgement is not evidence that
                // nothing happened.
                SubmitOutcome::Unknown => {
                    record.set_unknown(UnknownPhase::Submission, LastKnown::Prepared);
                }
            }
            record.execution()
        };

        let kind = match state {
            ExecutionState::NotStarted(reason) => TransitionKind::NotStarted(reason),
            ExecutionState::Unknown { .. } => TransitionKind::SubmissionUnknown,
            _ => TransitionKind::SubmissionAccepted,
        };
        self.governor.push(subject, now, kind);

        self.settled = true;
        SubmitReceipt {
            execution_id,
            command_digest: self.digest,
            state,
            executor_invoked: true,
        }
    }
}

impl<O, C, S> Drop for PreparedExecution<'_, '_, O, C, S>
where
    O: Clone + Eq,
    C: MonotonicClock,
    S: ExecutionIdSource,
{
    /// Records an unsubmitted preparation as abandoned.
    ///
    /// Safe to state as fact because [`PreparedExecution::submit`] consumes the
    /// guard: a preparation that reaches here without settling provably never
    /// reached the adapter.
    ///
    /// Performs no executor call, touches no store, marks no authority lapse —
    /// nothing was checked, so nothing may be asserted — allocates nothing, and
    /// cannot panic: the slot is reached fallibly and the journal push is
    /// bounded.
    fn drop(&mut self) {
        if self.settled {
            return;
        }
        let now = self.governor.clock.uptime();
        if let Some(Some(record)) = self.governor.records.get_mut(self.index) {
            record.set_not_started(NotStartedReason::Abandoned);
        }
        self.governor.push(
            TransitionSubject::Execution(self.execution_id),
            now,
            TransitionKind::NotStarted(NotStartedReason::Abandoned),
        );
    }
}
