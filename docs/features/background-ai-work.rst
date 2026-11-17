Background AI Work
==================

Writing a story or a network's insights takes the LLM minutes on a local model. TracePcap does
that work in the background: you ask, the page shows where the work is, and you can leave the
page, reload it, or keep working elsewhere. The answer lands where you asked for it.

What runs this way
------------------

Everything TracePcap asks the LLM for, except the chat:

- **Story**: written after upload, or with **Write the story** / **Regenerate** on the Story tab.
- **Insights** for a monitored network, and for one capture in it (its **Insights** tab).
- **Suggest with AI** for a host's role (the host card, and the role editor), and for a subnet's
  label.
- The **Trace** view's plain-English explanation of each packet. Explanations already worked out
  for a conversation come back straight away.

Where it shows
--------------

**Where you asked.** The place that started the work shows its state:

- **Waiting for the model · next in line** (or *2nd in line*, …), with when you asked and a
  **Cancel** button.
- **Rewriting the story in the background · started 14:25 · 3 min so far, usually about 7**,
  with a bar against the usual time once TracePcap has seen a few runs.

While a story is rewritten, the current story stays on the page; the new one replaces it when
it's ready. If the rewrite fails, the current story is kept. Insights work the same way on a
monitored network's **Overview**.

In smaller places (the host card, the role and subnet editors, the Trace view) it's one line:
*Waiting for the model · next in line. You can close this card; the suggestion waits here for
you.* Close it and come back, and the suggestion is filled in.

**The header.** While the model has work, a chip appears next to the settings gear:
**AI · 1 running · 1 waiting**. Click it for the list: what each job is, what it's for (a capture
or a network), how long it has run or its place in line, and **Open** to go to where its answer
will land. The chip is gone when there's nothing to do.

**A note when it's done.** When a job you saw running finishes, a note in the bottom corner says
so (*Insights ready · Office Audit — Corp HQ · Open*), unless you're already on that page. A
failed job's note says why.

One thing at a time
-------------------

A local LLM server answers one request at a time, so sending it several only makes each one
slower. TracePcap keeps one line for the model:

- Stories written after upload (*Write the story when analysis finishes*), stories you ask for on
  the **Story** tab, and network insights all wait in the same line, in the order they were
  asked for.
- **Ask about this capture** doesn't wait in line: someone is waiting on a question, so it goes
  straight to the model (see :doc:`capture-chat`).
- Asking for the same thing again while it waits or runs (clicking **Regenerate** twice, or
  reloading and clicking again) doesn't start a second run; it shows the one already on its way.

Cancelling
----------

**Cancel** takes a waiting job out of line. A running job can't be stopped: the model is already
answering, and its answer is saved like any other. With login on, only whoever asked, or an
admin, can cancel.

What isn't kept
---------------

Jobs live in the backend's memory. Finished ones are listed for 30 minutes; the result itself is
saved as usual (the story, the insight). If the backend restarts, waiting and running jobs are
dropped. Stories asked for at upload are queued again by themselves once it's back; anything
else (a Regenerate, insights) you ask for again.

For API clients
---------------

Each kind of work is started from its own resource and returns at once with the job (**201**):

- ``POST /api/v1/files/{fileId}/story-jobs``: the body takes the Story tab's options
  (``additionalContext``, ``maxFindings``, ``maxRiskMatrix``, ``networkId``, ``customPrompt``).
- ``POST /api/v1/monitor/networks/{networkId}/insight-jobs``: ``audience`` and ``focus``.
- ``POST /api/v1/monitor/networks/{networkId}/snapshots/{snapshotId}/insight-jobs``: the same, for
  one capture.
- ``POST /api/v1/node-roles/suggestion-jobs``: ``fileId``, ``entityType``, ``entityKey``, and
  ``preview`` (true: a label for the editor, not saved).
- ``POST /api/v1/subnets/{id}/label-suggestion-jobs``: optional ``networkId`` or ``fileId``. A
  subnet with no members in the scanned captures fails at once (422) instead of waiting in line.
- ``POST /api/v1/tracer/{conversationId}/explanation-jobs``: explanations already worked out come
  back ``DONE`` at once.

Check on it with ``GET /api/v1/ai-jobs/{id}``: ``WAITING`` (with ``position``, 1 being next),
``RUNNING``, then ``DONE`` with ``result`` (the story or insight) or ``FAILED`` with ``error``. A
prompt too large for the model fails with ``errorCode: CONTEXT_LENGTH_EXCEEDED`` and the prompt,
so it can be cut down and sent again as ``customPrompt``. ``GET /api/v1/ai-jobs`` lists waiting
and running jobs, then those finished in the last 30 minutes; ``POST /api/v1/ai-jobs/{id}/cancel``
cancels a waiting one.

The older endpoints (``POST /api/v1/stories``, ``…/insights``, ``/node-roles/suggest``,
``/subnets/{id}/suggest-label``, ``/tracer/{conversationId}/explanations``) still work, but hold the
request open until the model answers.
