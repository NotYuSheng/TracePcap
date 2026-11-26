Settings
========

TracePcap's settings are grouped by who they affect. On the **Settings** page the
sections run down the left, like a capture's analysis: **Personal** under *You*, and
the rest under *This install*. The **»** button at the bottom widens the menu to
the sections' full names.

.. list-table::
   :header-rows: 1
   :widths: 22 30 48

   * - Where
     - Affects
     - Notes
   * - **Settings** page, **Personal**
     - you (or everyone, with login off)
     - Personal look and layout only. Never changes analysis results.
   * - **Settings** page, the other sections
     - everyone using the install
     - Deploy-time settings, custom detection rules, address defaults (subnet labels,
       internal ranges, organisations), who may change what, the audit log, and users.
   * - A network's **Settings** button
     - that network
     - Such as when a device counts as no longer seen (see :doc:`network-monitor`).

Open the **Settings** page from the gear icon at the right of the header. Everyone can open it; anything you can't change
is shown greyed out with a lock, and clicking it says why. (It was two places before: a
Settings dialog for personal settings and a System page; old ``/system`` links still work.)


Personal
--------

- **Theme**: match your device, light, or dark.
- **Network diagram labels**: which labels each node shows.
- **Conversation table columns**: which columns the conversations table shows. Change
  them from the table's Columns menu, or reset them to the default here.

**Where they're saved depends on login:**

- **Login on**: saved to your account, so they follow you to any browser, and two
  analysts on one machine keep separate settings.
- **Login off**: there is no account, so everyone using the install shares **one set**.
  A change made by one person changes it for everyone, and the section says so. This is
  deliberate: a single-analyst laptop or a shared appliance gets the same preferences in
  any browser.

The first time this version loads, whatever a browser already had (theme, labels,
columns) is uploaded, so nobody's existing setup is lost. **Recent files** stay in each
browser: they're history, not a preference.


For Everyone
------------

The **Settings** page's other sections, under *This install*: **System**, **Detection
rules**, **Address defaults**, **Roles**, **Audit log** and **Users**.

**System.** Every deploy-time setting (each environment variable in :doc:`../configuration/environment-variables`)
is listed with its **effective value**, including values derived from ``APP_MEMORY_MB``
such as the upload cap. They are grouped as:

- **Analysis policy**: detection thresholds, retention, display limits.
- **LLM**: the server Story and Insights use. **Change connection…** sets its URL,
  key and model in one form, picking the model from the server's own list, and
  **Test connection** checks it, warning when the model is too small or slow for a
  story (see :doc:`../configuration/llm-setup`).
- **Memory and capacity**: limits tied to how much memory the backend has.
- **Infrastructure**: servers, storage and login.

Most settings can't be changed in the app: each is greyed out with a lock, and clicking
it shows why, which variable sets it, its default, and what it does. **Secrets**
(database password, MinIO keys, LLM API key) only show whether they're set. Their values
are never sent to the browser.

**Changing settings in the app.** A few settings can be changed here without a
redeploy, by whoever has the permission for them (see :ref:`settings-permissions`):

.. list-table::
   :header-rows: 1
   :widths: 40 20 40

   * - Setting
     - Permission
     - Takes effect
   * - ``FILE_RETENTION_HOURS``, ``MONITOR_FILE_RETENTION_HOURS``,
       ``PACKET_RETENTION_HOURS``
     - Edit retention
     - From the next hourly cleanup run.
   * - ``DNS_NXDOMAIN_SUSPICIOUS_RATIO``, ``DNS_NXDOMAIN_MIN_QUERIES``
     - Edit analysis policy
     - At once in a DNS server's DNS tab (its host details); host DNS logs use
       it from the next analysis.
   * - ``HTTP_CLIENT_ERROR_SUSPICIOUS_RATIO``, ``HTTP_MIN_REQUESTS``
     - Edit analysis policy
     - At once in a web server's HTTP tab (its host details).
   * - ``LLM_API_BASE_URL``, ``LLM_API_KEY``, ``LLM_MODEL``, ``LLM_TEMPERATURE``,
       ``LLM_MAX_TOKENS``, ``LLM_TIMEOUT``, ``LLM_TOOL_CALLING``
     - Edit the LLM connection
     - From the next LLM call (tool calling: the next story). The key is never shown
       again once saved.

Click the setting, then **Change…**. The value from the deployment's ``.env`` stays the
default: a setting changed in the app is marked *changed in the app*, and **Reset to the
deployment's value** removes the change. Every change is in the audit log.

Other policy settings, such as whether file retention runs at all
(``FILE_RETENTION_ENABLED``) or whether Suricata runs, stay deploy-time on purpose:
changing them means starting or stopping a component, which needs a restart.


.. _settings-permissions:

Who can change what
-------------------

What someone may do comes from their roles: Viewer, Analyst, Lead and Admin. Who has a
role is set in Keycloak; what each role may do is set on this page's **Roles** tab,
one role at a time. Only the admin role can change it; everyone else
sees it locked. See :doc:`roles-and-permissions`.

Audit log
---------

Every change to these items is recorded with **who** made it, **when**, and the value
**before and after**. With login on, "who" is the username; with login off it's
``system``, because there are no accounts. Entries are recorded in the same transaction
as the change, so a change is never saved without its entry.

**Every other action is recorded too.** Uploading or deleting a capture, marking a
favourite, keeping a capture, creating a monitored network or adding a snapshot to it,
labelling a host, writing a note, asking for a story or a question, downloading a
capture or exporting conversations: any change anyone makes through the app or the API
gets an entry, with who, when, what (the action in words, such as *Added a snapshot to
a network* or *Deleted file: ftp.pcap*) and what it was done to. Attempts refused for
lack of permission are recorded as well (*Tried to delete file: … (refused, no
permission)*). These entries are written automatically for any action that doesn't
write its own, more detailed entry, so a new feature can't be added without being
audited. They hold no before/after values, and never a request's contents (which can
hold secrets or capture data).

Not recorded: page views and other reads, and four requests that change nothing:
previewing a rule, running a packet filter query, previewing an AI role suggestion,
and saving your own layout and theme preferences.

Read it on the Settings page's **Audit log** tab: newest first, paged, and searchable by
who, action or target. It's also available from the API at ``GET /api/v1/audit-log``.

Each change is one line: when, who, a tag for the kind of thing (*Rule*, *Map*,
*Device*, *Address*, *Setting*) and what happened in words (*Changed live_check_tcp:
Enabled*, *Moved 1 device*, *Added the group “Point of sale”*). Narrow it with the
chips (**Rules**, **Maps**, **Devices**, **Addresses**, **Settings and access**,
**Captures**, **Monitoring**, **Labels and notes**) and
the search box. **Select a line** for its details beside the table: when, who, what
it was about, and each field that changed with its old value (struck through) and
new one, or the fields it had when it was added or removed. **Show the raw record**
gives the stored before/after as JSON. Escape closes the details.

Users
-----

With login on, the **Users** tab lists everyone who has signed in, with the roles their last
sign-in carried and what those add up to, and flags roles Keycloak gave that TracePcap doesn't
know (see :doc:`roles-and-permissions`). It's read-only: users, passwords and role assignments
are managed in the Keycloak admin console, which the tab links to (see
:doc:`../configuration/user-management`). With login off there are no accounts, and the tab
says so.

