Settings
========

TracePcap's settings are grouped by who they affect:

.. list-table::
   :header-rows: 1
   :widths: 22 30 48

   * - Where
     - Affects
     - Notes
   * - **Settings** button (header)
     - you (or everyone, with login off)
     - Personal look and layout only. Never changes analysis results.
   * - **System** page (header)
     - everyone using the install
     - Deploy-time settings, who may change what, the audit log, and users.
   * - A network's **Settings** button
     - that network
     - Such as when a device counts as no longer seen (see :doc:`network-monitor`).

Everyone can open the System page. Anything you can't change is shown greyed out with a
lock, and clicking it says why.


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
  A change made by one person changes it for everyone, and the tab says so. This is
  deliberate: a single-analyst laptop or a shared appliance gets the same preferences in
  any browser.

The first time this version loads, whatever a browser already had (theme, labels,
columns) is uploaded, so nobody's existing setup is lost. **Recent files** stay in each
browser: they're history, not a preference.


System page
-----------

The **System** page has four tabs: **Settings**, **Permissions**, **Audit log** and
**Users**.

**Settings.** Every deploy-time setting (each environment variable in :doc:`../configuration/environment-variables`)
is listed with its **effective value**, including values derived from ``APP_MEMORY_MB``
such as the upload cap. They are grouped as:

- **Analysis policy**: detection thresholds, retention, display limits.
- **Memory and capacity**: limits tied to how much memory the backend has.
- **Infrastructure**: servers, storage, login, and the LLM.

Most settings can't be changed in the app: each is greyed out with a lock, and clicking
it shows why, which variable sets it, its default, and what it does. **Secrets**
(database password, MinIO keys, LLM API key) only show whether they're set. Their values
are never sent to the browser.

**Changing policy in the app.** A few analysis-policy settings can be changed here
without a redeploy, by whoever has the permission for them (see
:ref:`settings-permissions`):

.. list-table::
   :header-rows: 1
   :widths: 40 20 40

   * - Setting
     - Permission
     - Takes effect
   * - ``FILE_RETENTION_HOURS``, ``MONITOR_FILE_RETENTION_HOURS``,
       ``PACKET_RETENTION_HOURS``
     - Retention (admins)
     - From the next hourly cleanup run.
   * - ``DNS_NXDOMAIN_SUSPICIOUS_RATIO``, ``DNS_NXDOMAIN_MIN_QUERIES``
     - Analysis policy (analysts)
     - At once in the network cluster view; host DNS logs use it from the next
       analysis.
   * - ``HTTP_CLIENT_ERROR_SUSPICIOUS_RATIO``, ``HTTP_MIN_REQUESTS``
     - Analysis policy (analysts)
     - At once in the network cluster view.

Click the setting, then **Change…**. The value from the deployment's ``.env`` stays the
default: a setting changed in the app is marked *changed in the app*, and **Reset to the
deployment's value** removes the change. Every change is in the audit log.

Other policy settings, such as whether file retention runs at all
(``FILE_RETENTION_ENABLED``) or whether Suricata runs, stay deploy-time on purpose:
changing them means starting or stopping a component, which needs a restart.


.. _settings-permissions:

Who can change what
-------------------

Some settings and rule sets are open to every analyst, and some need an **admin**. Which
is which is configurable per item, and **every change is recorded in the audit log**, so
the defaults favour analysts:

.. list-table::
   :header-rows: 1
   :widths: 40 20

   * - Item
     - Default
   * - Global, network and capture detection rules
     - analysts
   * - Splitting or merging a host's devices (:doc:`address-reuse`)
     - analysts
   * - Network settings, including a network's own address entries
       (:doc:`network-address-config`)
     - analysts
   * - Address defaults: subnet labels, internal/external ranges and
       organisations shared by every network
     - analysts
   * - Analysis policy
     - analysts
   * - Retention
     - admins
   * - Which items need an admin (this table)
     - admins, always

**Who is an admin:**

- **Login on**: users with the Keycloak client role ``admin`` (see
  :doc:`../configuration/user-management`). Everyone else is an analyst.
- **Login off**: everyone is an analyst. Admin-only items can be changed by everyone if
  the server sets ``SYSTEM_SETTINGS_EDITABLE=true``, and by no one otherwise (the
  default).

Change these on the System page's **Permissions** tab. An admin picks *Analysts* or
*Admins only* for each item; an item changed from its default is marked *changed*. For
everyone else the tab is read-only, and clicking an item says why.

An item you can't change is still shown, greyed out, with the reason. Network settings
work this way today.

Audit log
---------

Every change to these items is recorded with **who** made it, **when**, and the value
**before and after**. With login on, "who" is the username; with login off it's
``system``, because there are no accounts. Entries are recorded in the same transaction
as the change, so a change is never saved without its entry.

Read it on the System page's **Audit log** tab: newest first, paged, and searchable by
who, action or target. It's also available from the API at ``GET /api/v1/audit-log``.

Users
-----

With login on, the **Users** tab links to the Keycloak admin console, where users,
passwords and the ``admin`` role are managed (see :doc:`../configuration/user-management`).
With login off there are no accounts, and the tab says so.

