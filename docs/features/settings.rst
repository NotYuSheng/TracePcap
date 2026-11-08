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

**Nothing here can be changed in the app yet.** Each setting is shown greyed out with a
lock. Click it to see why it can't be changed here, which variable sets it, its default,
and what it does. **Secrets** (database password, MinIO keys, LLM API key) only show
whether they're set. Their values are never sent to the browser.

This tab behaves the same with login on or off, since it only reads.


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
   * - Network settings
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

