Roles and Permissions
=====================

What someone may do in TracePcap comes from their **roles**. A role is a set of
permissions: *Ask the AI*, *Delete anyone's captures*, *Edit retention* and so on.

The work is split the way most apps in a shared login realm split it:

- **Who has a role is decided in Keycloak.** Each role is a client role of the same name
  on the ``tracepcap-frontend`` client. Your identity team assigns it there, usually to a
  group (*SOC team* gets ``analyst``), sometimes to one person. TracePcap never creates
  groups or changes who is in them.
- **What a role may do is decided in TracePcap**, on the Settings page's **Roles** tab,
  by an admin.

When someone signs in, their token carries the TracePcap roles Keycloak gave them, and
only those. Other apps' roles and the user's list of groups stay out of it.

The four roles
--------------

.. list-table::
   :header-rows: 1
   :widths: 15 15 70

   * - Role
     - Client role
     - Meant for
   * - Viewer
     - ``viewer``
     - Looking. Reads captures, networks, findings and reports, and changes nothing. For
       managers, auditors, other teams.
   * - Analyst
     - ``analyst``
     - Investigating. Uploads captures, asks the AI, labels hosts, overrides answers, writes
       capture and network rules, deletes their own captures.
   * - Lead
     - ``lead``
     - Curating what everyone shares: global rules, address defaults, network settings,
       anyone's captures, the audit log.
   * - Admin
     - ``admin``
     - Running the install: retention, analysis policy, the LLM connection, and what each
       role may do. **Always has every permission**, and can't be changed, so no one can lock
       the admins out from inside TracePcap.

Someone with several roles may do everything any of them allows. Someone whose sign-in
carries none of them gets the **default role**, set on the Roles tab, under the list of roles:
*Analyst* unless an admin changes it.

**When you upgrade** with login on, everyone without a role becomes an Analyst. They keep
everything they could do before, except four things that were open to everyone and now need
the Lead role: reading the audit log, deleting a network, deleting other people's captures
(and captures from before uploaders were recorded), and cancelling someone else's AI work.
Give the people who do those the ``lead`` role in Keycloak, or tick them for Analyst on the
Roles tab.

The permissions
---------------

.. list-table::
   :header-rows: 1
   :widths: 22 48 30

   * - Group
     - Permission
     - Built-in roles that have it at first
   * - Look
     - See captures, networks and findings (every role, always); download a report
     - Viewer and up
   * -
     - Read the audit log
     - Lead, Admin
   * - Investigate
     - Upload and analyse captures (including merge and re-analyse); ask the AI (story,
       chat, insights, suggestions, packet explanations); export packets (the capture,
       filtered PCAPs, CSVs, extracted files)
     - Analyst and up
   * - Curate findings
     - Label hosts and add notes; override an answer (victim, user, malware, C2) and its
       evidence; split, merge or link devices; edit network maps
     - Analyst and up
   * - Detection rules
     - Capture rules; network rules; global rules
     - Analyst and up
   * - Monitor
     - Add and remove captures in a network (with notes, outside events, baselines and
       reviewing changes); create a network; edit a network's settings
     - Analyst and up
   * -
     - Delete a network
     - Lead, Admin
   * - Keep and delete data
     - Keep a capture longer, or forever; delete your own captures
     - Analyst and up
   * -
     - Delete anyone's captures
     - Lead, Admin
   * -
     - Edit retention
     - Admin
   * - Run the install
     - Edit address defaults; edit analysis policy
     - Analyst and up
   * -
     - Edit the LLM connection
     - Admin
   * -
     - Cancel someone else's AI work
     - Lead, Admin
   * -
     - Change who may do what (this table)
     - Admin, always

Installs that set some of these to *Admins only* before roles existed keep that: those items
start with the admin role alone. The catalogue suggests moving global rules, network settings
and address defaults to Lead, and analysis policy to Admin. An admin can make that change on
the Roles tab.

**Your own captures.** TracePcap records who uploaded each capture. *Delete your own
captures* covers the ones you uploaded. Captures uploaded before this was recorded have no
uploader, so deleting them needs *Delete anyone's captures*.

Changing what a role may do
---------------------------

On the Settings page, open **Roles**. The roles are listed on the left, with how many
permissions each has; pick one to see its permissions, grouped, on the right, along with the
Keycloak client role that gives it. An admin ticks or clears a box, and it applies at once.
Everyone else sees the same page, locked. Two rows can't change: every role may see captures, and only the admin role
may change roles. Every change, and every change of the default role, is in the audit log.

When someone tries something their roles don't allow, the app says which permission it needs
and which roles they have, so they know whom to ask.

Giving someone a role
---------------------

In Keycloak, not TracePcap: see :doc:`../configuration/user-management`. In short, assign the
client role (``viewer``, ``analyst``, ``lead`` or ``admin`` on ``tracepcap-frontend``) to a
group, and everyone in the group has it from their next sign-in.

Login off
---------

With login off there are no accounts, so everyone has every role but admin: everything is
open except the admin-only items, as before roles existed. Admin-only items can be changed by
everyone if the server sets ``SYSTEM_SETTINGS_EDITABLE=true``, and by no one otherwise (the
default).

For API clients
---------------

- ``GET /api/v1/roles`` lists the roles and what each may do.
- ``PATCH /api/v1/roles/{key}`` changes a role: ``permissions`` replaces its set, and
  ``defaultRole: true`` makes it the default. Admin only.
- ``GET /api/v1/permissions`` lists every permission, grouped, and whether you have it.
- ``GET /api/v1/me`` includes ``roles``, the roles that apply to you.

A request your roles don't allow gets **403**, with the permission and the reason in the
message.
