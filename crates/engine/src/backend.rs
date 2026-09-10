//! The guest invocation backend: the blessed engine on native targets,
//! the reference interpreter on wasm32.
//!
//! One instantiation per guest call — the execution model fuel parity is
//! pinned against — with the session threaded in and out through the
//! host state. Traps come back as deterministic reason strings; the
//! session always survives for the kernel's rollback.
//!
//! The seam is an engine seam and nothing more: the kernel hands over an
//! export name and an argument list it assembled from the transaction's
//! own declaration, so an embedder here can get engine embedding wrong
//! and cannot get manifest semantics wrong.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Arc, Condvar, Mutex};

use arc_swap::ArcSwap;
use hyperscale_vm_effects::PackageHash;

/// The ceiling on what one invocation may consume, whatever its
/// transaction declared.
///
/// Consensus content: exhaustion is a deterministic trap, so the two
/// engines have to meter against one number. It lives outside both
/// backend modules because they are target-gated and never compile
/// together — a per-module constant could drift between targets with
/// nothing to catch it, and the divergence would only surface as two
/// nodes disagreeing on whether a runaway guest trapped.
const FUEL: u64 = 10_000_000;

/// The build verdict for guest code by content address, growable while
/// invocations run.
///
/// Shared between the target-gated backends — each fills it with its own
/// compiled form — so package resolution cannot drift between targets
/// the way a per-module map could. The settled map takes the metadata
/// cache's shape: lock-free loads on the invoke path, clone-and-swap on
/// the rare publish, first write wins by content address. `None` records
/// a build that refused these bytes, which is as settled an answer as a
/// build that landed and is what keeps a refusal from being re-fetched
/// and rebuilt forever. The pending set is what keeps cache state out of
/// verdicts: an invocation arriving while its package compiles waits the
/// work out rather than answering differently than a replica whose
/// compile already finished.
struct PackageSlots<C> {
    settled: ArcSwap<BTreeMap<PackageHash, Option<Arc<C>>>>,
    pending: Mutex<BTreeSet<PackageHash>>,
    done: Condvar,
}

impl<C> PackageSlots<C> {
    fn new() -> Self {
        Self {
            settled: ArcSwap::from_pointee(BTreeMap::new()),
            pending: Mutex::new(BTreeSet::new()),
            done: Condvar::new(),
        }
    }

    /// The runnable form of `package`, waiting out an in-flight compile.
    ///
    /// `None` when the package was never absorbed or its build refused it
    /// — both deterministic functions of committed bytes, so every
    /// replica answers alike.
    fn resolve(&self, package: PackageHash) -> Option<Arc<C>> {
        if let Some(verdict) = self.settled.load().get(&package) {
            return verdict.clone();
        }
        let mut pending = self.pending.lock().expect("package slots lock poisoned");
        while pending.contains(&package) {
            pending = self
                .done
                .wait(pending)
                .expect("package slots lock poisoned");
        }
        drop(pending);
        self.settled.load().get(&package).cloned().flatten()
    }

    /// Claim the build of `package`: `true` exactly once per content
    /// address, `false` when its verdict is settled or in flight.
    fn claim(&self, package: PackageHash) -> bool {
        if self.settled.load().contains_key(&package) {
            return false;
        }
        self.pending
            .lock()
            .expect("package slots lock poisoned")
            .insert(package)
    }

    /// Land a claimed build's verdict — `None` a refusal — and release
    /// its waiters.
    ///
    /// One producer only: the swap over `settled` is a read-modify-write
    /// with no lock around it, so two builds landing at once would lose
    /// one. Every claim reaches exactly one builder — the compile worker
    /// on the blessed engine, the absorbing thread on the reference one —
    /// and construction lands the stdlib before either exists.
    fn fulfil(&self, package: PackageHash, code: Option<C>) {
        let mut next = (**self.settled.load()).clone();
        next.entry(package).or_insert_with(|| code.map(Arc::new));
        self.settled.store(Arc::new(next));
        let mut pending = self.pending.lock().expect("package slots lock poisoned");
        pending.remove(&package);
        drop(pending);
        self.done.notify_all();
    }

    /// Whether `package` resolves without waiting, in-flight work
    /// excluded. A refused build qualifies: it resolves to no code, and
    /// it resolves there on every replica.
    fn is_settled(&self, package: PackageHash) -> bool {
        self.settled.load().contains_key(&package)
    }

    /// Whether `package`'s verdict is settled or its build is in flight
    /// — the probe that keeps a prefetch from re-requesting bytes the
    /// backend has already judged.
    fn is_known(&self, package: PackageHash) -> bool {
        if self.is_settled(package) {
            return true;
        }
        self.pending
            .lock()
            .expect("package slots lock poisoned")
            .contains(&package)
    }
}

#[cfg(not(target_arch = "wasm32"))]
mod native {
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::sync::Arc;
    use std::thread;

    use crossbeam::channel::{Sender, unbounded};
    use hyperscale_effects_bridge::ProtocolHasher;
    use hyperscale_vm_effects::{PackageHash, package_hash};
    use hyperscale_vm_kernel::{
        GuestBackend as Backend, GuestCall, InvokeResult, Invoked, KernelSession,
    };
    use hyperscale_vm_meter::instantiation_cost;
    use hyperscale_vm_runtime::{
        HostRefusal, Invoking, add_kernel_imports, admit, blessed_engine, instantiate_metered,
        invoke_export,
    };
    use hyperscale_vm_types::AbortReason;
    use wasmtime::{Engine, InstancePre, Linker, Module, Store};

    use super::{FUEL, PackageSlots};
    use crate::genesis::GenesisPackages;

    /// One package's runnable form: the instrumented module the meter
    /// made of the artifact, pre-linked, and what instantiating it
    /// prepays off the counter, derived from the same bytes.
    pub struct CompiledPackage {
        pre: InstancePre<Invoking<KernelSession>>,
        cost: u64,
    }

    /// The compiled guests, pre-linked for cheap instantiation.
    pub struct EngineBackend {
        engine: Engine,
        /// Compiled code by content address. A lowered call names the
        /// package it runs, never the instance, because code is what a
        /// backend resolves and code is what a content address covers —
        /// so two instances of one package share one compilation and two
        /// packages in one transaction each get their own.
        slots: Arc<PackageSlots<CompiledPackage>>,
        /// Feed of the compile worker: a dedicated OS thread, never the
        /// shared dispatch pools — wasmtime's internal parallel
        /// compilation nested inside a pooled worker is a known
        /// self-deadlock shape. The thread exits when the last sender
        /// drops.
        compile: Sender<Vec<u8>>,
    }

    impl EngineBackend {
        /// Compile `packages` on the blessed engine and start the
        /// compile worker for everything published after them.
        ///
        /// The artifact admitted is the one the package address covers,
        /// metadata section included: what the chain stores is what the
        /// meter instruments and the engine runs. The set is the
        /// network's genesis set, because a package the chain is born
        /// holding is one no node ever fetches — every node compiles it
        /// at boot instead.
        ///
        /// # Panics
        ///
        /// Panics if a genesis artifact fails admission or compilation —
        /// a build defect, not a runtime condition.
        pub fn new(packages: &GenesisPackages) -> Self {
            let engine = blessed_engine().expect("blessed engine configuration is pinned");
            let linker = kernel_linker(&engine);
            let slots = Arc::new(PackageSlots::new());
            for artifact in packages.artifacts() {
                let pre = build(&engine, &linker, artifact).expect("a genesis artifact compiles");
                let package = package_hash(&ProtocolHasher, artifact);
                assert!(slots.claim(package), "genesis packages are distinct");
                slots.fulfil(package, Some(pre));
            }

            let (compile_tx, compile_rx) = unbounded::<Vec<u8>>();
            let worker_engine = engine.clone();
            let worker_slots = Arc::clone(&slots);
            thread::Builder::new()
                .name("package-compile".into())
                .spawn(move || {
                    let linker = kernel_linker(&worker_engine);
                    for artifact in compile_rx {
                        let package = package_hash(&ProtocolHasher, &artifact);
                        worker_slots.fulfil(package, build(&worker_engine, &linker, &artifact));
                    }
                })
                .expect("the compile worker spawns");

            Self {
                engine,
                slots,
                compile: compile_tx,
            }
        }

        /// Queue a committed package's artifact for compilation.
        ///
        /// Idempotent by content address; the compiled code becomes
        /// resolvable when the worker lands it, and an invocation
        /// arriving sooner waits on exactly that.
        pub fn absorb_artifact(&self, artifact: &[u8]) {
            queue(&self.slots, &self.compile, artifact);
        }

        /// A cheap-clone feed of this backend for the commit path to
        /// hold: [`Self::absorb_artifact`] detached from the borrow.
        pub fn absorber(&self) -> impl Fn(&[u8]) + Send + Sync + 'static {
            let slots = Arc::clone(&self.slots);
            let compile = self.compile.clone();
            move |artifact: &[u8]| queue(&slots, &compile, artifact)
        }

        /// Whether `package`'s code resolves without waiting — landed or
        /// refused.
        #[must_use]
        pub fn code_settled(&self, package: PackageHash) -> bool {
            self.slots.is_settled(package)
        }

        /// Whether `package`'s code is judged or being built.
        #[must_use]
        pub fn code_known(&self, package: PackageHash) -> bool {
            self.slots.is_known(package)
        }
    }

    /// A linker carrying the kernel imports — the one import surface a
    /// deployable module may name.
    fn kernel_linker(engine: &Engine) -> Linker<Invoking<KernelSession>> {
        let mut linker = Linker::<Invoking<KernelSession>>::new(engine);
        add_kernel_imports(&mut linker).expect("kernel import wiring");
        linker
    }

    /// Claim `artifact`'s build and hand it to the compile worker.
    ///
    /// A claim and a send, in that order, so two callers racing the same
    /// bytes queue one build. A send that fails means the worker is gone
    /// — the claim then stands unfulfilled and every call to the package
    /// waits on a build that will never land, which is a dead node
    /// rather than a divergent one. Loud, because nothing downstream can
    /// tell that apart from a slow fetch.
    fn queue(slots: &PackageSlots<CompiledPackage>, compile: &Sender<Vec<u8>>, artifact: &[u8]) {
        let package = package_hash(&ProtocolHasher, artifact);
        if slots.claim(package) && compile.send(artifact.to_vec()).is_err() {
            tracing::error!(
                ?package,
                "the compile worker is gone; its packages cannot run"
            );
        }
    }

    /// Build one artifact, or `None` if admission or the blessed engine
    /// refuses it.
    ///
    /// Admission and compilation are one pass and one pinned wasmtime
    /// over one blessed config, so every way this can end is a function
    /// of the bytes and every replica reaches the same one — an unwind
    /// included, which is why the worker catches rather than dies on it.
    /// What is not deterministic is admission having passed bytes
    /// wasmtime will not take, so a refusal here is logged as the
    /// disagreement it is.
    fn build(
        engine: &Engine,
        linker: &Linker<Invoking<KernelSession>>,
        artifact: &[u8],
    ) -> Option<CompiledPackage> {
        let attempt = catch_unwind(AssertUnwindSafe(|| {
            let admitted = admit(artifact).map_err(|error| format!("admission: {error:#}"))?;
            let module =
                Module::new(engine, &admitted).map_err(|error| format!("compile: {error:#}"))?;
            let pre = linker
                .instantiate_pre(&module)
                .map_err(|error| format!("link: {error:#}"))?;
            let cost = instantiation_cost(artifact)
                .map_err(|error| format!("instantiation cost: {error:#}"))?;
            Ok(CompiledPackage { pre, cost })
        }));
        let reason = match attempt {
            Ok(Ok(pre)) => return Some(pre),
            Ok(Err(reason)) => reason,
            Err(_) => "panic".to_string(),
        };
        tracing::error!(
            package = ?package_hash(&ProtocolHasher, artifact),
            reason,
            "published artifact failed to compile"
        );
        None
    }

    impl Backend for EngineBackend {
        fn invoke(&self, session: KernelSession, call: &GuestCall<'_>) -> InvokeResult {
            // What the transaction has left, under the per-invocation
            // ceiling: a manifest's nodes draw from one signed budget.
            let budget = call.fuel_budget.min(FUEL);
            let mut store = Store::new(&self.engine, Invoking::new(session));
            let Some(package) = self.slots.resolve(call.package) else {
                // This node's own cache, not the transaction: nothing
                // about the batch is decided by a miss here.
                return InvokeResult {
                    session: store.into_data().into_host(),
                    fuel: 0,
                    result: Invoked::Unavailable(AbortReason::CodeUnavailable),
                };
            };
            let instance = match instantiate_metered(&mut store, budget, package.cost, |s| {
                package.pre.instantiate(s)
            }) {
                Ok(instance) => instance,
                // A budget under the prepaid instantiation is the sender's
                // own deterministic refusal, spending the whole of it; any
                // other instantiation failure is this machine's.
                Err(error)
                    if matches!(
                        error.downcast_ref::<HostRefusal>(),
                        Some(HostRefusal(AbortReason::OutOfGas))
                    ) =>
                {
                    return InvokeResult {
                        session: store.into_data().into_host(),
                        fuel: budget,
                        result: Invoked::Aborted(AbortReason::OutOfGas),
                    };
                }
                Err(error) => {
                    tracing::debug!(?error, "module did not instantiate");
                    return InvokeResult {
                        session: store.into_data().into_host(),
                        fuel: 0,
                        result: Invoked::Unavailable(AbortReason::InstantiationFailed),
                    };
                }
            };
            let end = invoke_export(&mut store, &instance, call.export, call.args, budget);
            if let Invoked::Aborted(reason) = &end.result {
                tracing::debug!(export = call.export, ?reason, "guest aborted");
            }
            InvokeResult {
                session: store.into_data().into_host(),
                fuel: end.fuel,
                result: end.result,
            }
        }
    }
}

#[cfg(not(target_arch = "wasm32"))]
pub use native::EngineBackend;

#[cfg(target_arch = "wasm32")]
mod reference {
    use std::sync::Arc;

    use hyperscale_effects_bridge::ProtocolHasher;
    use hyperscale_vm_effects::{PackageHash, package_hash};
    use hyperscale_vm_kernel::{
        GuestBackend as Backend, GuestCall, InvokeResult, Invoked, KernelSession,
    };
    use hyperscale_vm_ref::{InstantiateError, RefModule, RefModuleInstance};
    use hyperscale_vm_runtime::admit;
    use hyperscale_vm_types::AbortReason;

    use super::{FUEL, PackageSlots};
    use crate::genesis::GenesisPackages;

    /// The decoded guests under the reference interpreter.
    pub struct EngineBackend {
        slots: Arc<PackageSlots<RefModule>>,
    }

    impl EngineBackend {
        /// Admit and decode the genesis packages.
        ///
        /// The artifact goes through the same admission it goes through
        /// under the blessed engine: the verdict and the instrumented
        /// module are properties of the bytes, and a build that
        /// interprets modules rather than compiling them has no less
        /// need of either.
        ///
        /// # Panics
        ///
        /// Panics if a genesis artifact fails admission or decoding — a
        /// build defect, not a runtime condition.
        pub fn new(packages: &GenesisPackages) -> Self {
            let slots = Arc::new(PackageSlots::new());
            for artifact in packages.artifacts() {
                let admitted = admit(artifact).expect("a genesis artifact is admitted");
                let module = RefModule::decode(&admitted).expect("a genesis artifact decodes");
                let package = package_hash(&ProtocolHasher, artifact);
                assert!(slots.claim(package), "genesis packages are distinct");
                slots.fulfil(package, Some(module));
            }
            Self { slots }
        }

        /// Absorb a committed package's artifact.
        ///
        /// Admission and decoding are a few parser passes, so this
        /// target does them in place — no worker, and the pending set
        /// never holds an entry long enough for an invocation to wait on
        /// it.
        pub fn absorb_artifact(&self, artifact: &[u8]) {
            absorb_into(&self.slots, artifact);
        }

        /// A cheap-clone feed of this backend for the commit path to
        /// hold: [`Self::absorb_artifact`] detached from the borrow.
        pub fn absorber(&self) -> impl Fn(&[u8]) + Send + Sync + 'static {
            let slots = Arc::clone(&self.slots);
            move |artifact: &[u8]| absorb_into(&slots, artifact)
        }

        /// Whether `package`'s code resolves without waiting — landed or
        /// refused.
        #[must_use]
        pub fn code_settled(&self, package: PackageHash) -> bool {
            self.slots.is_settled(package)
        }

        /// Whether `package`'s code is judged or being built.
        #[must_use]
        pub fn code_known(&self, package: PackageHash) -> bool {
            self.slots.is_known(package)
        }
    }

    fn absorb_into(slots: &PackageSlots<RefModule>, artifact: &[u8]) {
        let package = package_hash(&ProtocolHasher, artifact);
        if !slots.claim(package) {
            return;
        }
        let decoded = admit(artifact)
            .map_err(|error| error.to_string())
            .and_then(|admitted| RefModule::decode(&admitted).map_err(|error| error.to_string()));
        match decoded {
            Ok(module) => slots.fulfil(package, Some(module)),
            Err(error) => {
                tracing::error!(?package, %error, "published artifact was not admitted");
                slots.fulfil(package, None);
            }
        }
    }

    impl Backend for EngineBackend {
        fn invoke(&self, session: KernelSession, call: &GuestCall<'_>) -> InvokeResult {
            let Some(module) = self.slots.resolve(call.package) else {
                // This node's own cache, not the transaction: nothing
                // about the batch is decided by a miss here.
                return InvokeResult {
                    session,
                    fuel: 0,
                    result: Invoked::Unavailable(AbortReason::CodeUnavailable),
                };
            };
            // The same budget the blessed engine sets its counter to,
            // judged against the prepaid instantiation first: a budget
            // under it is the sender's own deterministic refusal; any other
            // instantiation failure is this machine's.
            let budget = call.fuel_budget.min(FUEL);
            let mut instance = match RefModuleInstance::instantiate(&module, session, budget) {
                Ok(instance) => instance,
                Err((host, InstantiateError::OutOfGas)) => {
                    return InvokeResult {
                        session: host,
                        fuel: budget,
                        result: Invoked::Aborted(AbortReason::OutOfGas),
                    };
                }
                Err((host, error)) => {
                    tracing::debug!(?error, "module did not instantiate");
                    return InvokeResult {
                        session: host,
                        fuel: 0,
                        result: Invoked::Unavailable(AbortReason::InstantiationFailed),
                    };
                }
            };
            let end = instance.invoke(call.export, call.args);
            if let Invoked::Aborted(reason) = &end.result {
                tracing::debug!(export = call.export, ?reason, "guest aborted");
            }
            InvokeResult {
                session: instance.into_host(),
                fuel: end.fuel,
                result: end.result,
            }
        }
    }
}

#[cfg(target_arch = "wasm32")]
pub use reference::EngineBackend;
