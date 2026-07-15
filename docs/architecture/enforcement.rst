Architecture Enforcement
========================

The rules in :doc:`layers` are enforced by ArchUnit tests in
``backend/src/test/java/com/tracepcap/architecture/LayerDependencyTest.java``. They run as part of
the normal backend test suite — no separate command.

Why this exists
---------------

#416 established the rule *"dependency direction is always feature → analysis, never the reverse"*
and built the ``analysis.spi`` seam to support it. The rule then eroded anyway: 755 class
dependencies now bypass that seam, and two dependency cycles have appeared.

Nothing objected, because nothing was watching. Documentation alone demonstrably did not hold this
boundary. That is the gap these tests close.


Frozen, not green
-----------------

The rules **fail today** if run plainly — the codebase violates them. Rather than weaken the rules
to match the code, the current violations are recorded in a **frozen baseline** under
``backend/src/test/resources/archunit_store``.

The effect:

* Existing violations are accepted silently — no noise, nothing to wade through.
* **A new violation fails the build**, naming the exact class and field, with the reason.
* The baseline is version-controlled, so the debt is visible and diffable in review.

**The store must only ever shrink.** A PR that grows it is adding architectural debt and must say
why. Each refactor slice should delete entries from it.

Current baseline
----------------

.. list-table::
   :header-rows: 1
   :widths: 55 15 30

   * - Rule
     - Violations
     - Meaning
   * - ``modules_use_analysis_spi_not_its_internals``
     - 755
     - Cross-module reaches into ``analysis`` repositories/entities.
   * - ``no_module_cycles``
     - 71
     - Dependencies participating in ``monitor ↔ insights`` and ``analysis ↔ file``.
   * - ``raw_capture_access_is_confined_to_extract_stage``
     - 6
     - All in ``FilterService`` (validates LLM-generated filters against the pcap) — the one
       grey case in stage rule 4, frozen rather than blessed.
   * - ``analysis_does_not_depend_on_feature_modules``
     - **0**
     - #416's invariant — clean, and frozen to keep it that way.


Working with the rules
----------------------

**Run them:**

.. code-block:: bash

   cd backend
   mvn -Dtest=LayerDependencyTest test

**You added a violation and the build failed.** That is the tests working. Options, best first:

#. **Use the seam.** Depend on ``analysis.spi`` / ``analysis.dto`` instead of the repository or
   entity. If the port you need does not exist, add it — that is the intended path, and the one
   #416 laid out.
#. **Reconsider the placement.** A new cross-module reach often means the code is in the wrong
   module. See :doc:`layers` for where it likely belongs.
#. **Accept it deliberately** — only with a reason stated in the PR:

   .. code-block:: bash

      mvn test -Darchunit.freeze.store.default.allowStoreUpdate=true

   This rewrites the baseline. Reviewers should treat a growing store as a red flag.

**You removed violations** (the good case): re-run with ``allowStoreUpdate=true`` to shrink the
store, and commit the smaller baseline alongside the refactor.

.. note::

   The very first creation of a store also needs
   ``-Darchunit.freeze.store.default.allowStoreCreation=true``. This should not be needed again —
   the store is committed.

Configuration lives in ``backend/src/test/resources/archunit.properties``. Both
``allowStoreCreation`` and ``allowStoreUpdate`` default to ``false`` so the baseline cannot drift
silently — changing it requires an explicit, visible flag.
