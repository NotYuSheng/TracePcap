Roles and Permissions
=====================

What someone may do in TracePcap comes from their **roles**. A role is a set of
permissions: *Ask the AI*, *Delete anyone's captures*, *Edit retention* and so on.

The work is split the way most apps in a shared login realm split it:

- **Who has a role is decided in Keycloak.** Each role is a client role of the same name
  on the ``tracepcap`` client. Your identity team assigns it there, usually to a
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
     - Read the audit log and who has signed in (the **Users** tab)
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

What your roles don't allow stays on screen, greyed out, so you can see it exists. Next to it is
a lock: click it for the permission it needs, why you haven't got it (which roles you have), and
whom to ask. A page you can only partly use says so at the top (for example *You can see this
answer and its evidence but not change them*). If something slips through, the server refuses it
with the same reason.

Your own roles
--------------

The four built-in roles cover most teams. When they don't (an incident responder who may
export packets but not label hosts, a contractor who may only read reports), an admin adds a
role of their own:

1. On the **Roles** tab, choose **New role**. Give it a name, and check the **Keycloak client
   role** it's given by (filled in from the name: *Incident responder* becomes
   ``incident-responder``). Optionally **start from** another role's permissions.
2. Tick what it may do. **Start from…** on any role replaces its permissions with another
   role's, to start over.
3. In Keycloak, your identity team creates the client role of that name on
   ``tracepcap`` (Clients › tracepcap › Roles › Create role) and assigns it
   to a group.

A custom role can be renamed or have its description changed with **Edit**; its Keycloak name
can't change, because that's what Keycloak assigns. **Delete role** removes it: anyone Keycloak
still gives that client role stops getting anything from it, and if that leaves them with no
TracePcap role they get the default. The four built-in roles, and whichever role is the default,
can't be deleted. Creating, editing and deleting roles are all in the audit log.

Giving someone a role
---------------------

In Keycloak, not TracePcap: see :doc:`../configuration/user-management`. In short, assign the
client role (``viewer``, ``analyst``, ``lead`` or ``admin`` on ``tracepcap``) to a
group, and everyone in the group has it from their next sign-in.

Who has signed in
-----------------

With login on, Settings › **Users** lists everyone who has signed in, most recent first: the
TracePcap roles their last sign-in carried, how many permissions those add up to, and when.
It's read-only; people and role assignments stay in Keycloak. Seeing it needs *Read the audit
log and who has signed in* (Lead and Admin at first).

It also catches mistakes in Keycloak:

- Someone whose sign-in carried a client role TracePcap has **no role for** (a typo, or a role
  deleted here) is flagged: that role gives them nothing.
- Someone with **none** of TracePcap's roles is marked as getting the default role.
- On the **Roles** tab, each role says when a sign-in last carried it, or *No sign-in has
  carried this role yet*. For a new custom role, that usually means its client role hasn't been
  created or assigned in Keycloak.

A sign-in is recorded when the app loads, so the list and the roles show what Keycloak gave
someone the last time they opened TracePcap. Nothing is recorded with login off.

Login off
---------

With login off there are no accounts, so everyone has every role but admin: everything is
open except the admin-only items, as before roles existed. Admin-only items can be changed by
everyone if the server sets ``SYSTEM_SETTINGS_EDITABLE=true``, and by no one otherwise (the
default).

For API clients
---------------

- ``GET /api/v1/roles`` lists the roles and what each may do.
- ``POST /api/v1/roles`` creates a custom role: ``key`` (the Keycloak client role), ``label``,
  ``description``, and ``copyFrom`` to start from another role's permissions. Admin only.
- ``PATCH /api/v1/roles/{key}`` changes a role: ``permissions`` replaces its set,
  ``defaultRole: true`` makes it the default, and ``label`` and ``description`` rename a custom
  role. Admin only.
- ``DELETE /api/v1/roles/{key}`` deletes a custom role. Admin only.
- ``GET /api/v1/permissions`` lists every permission, grouped, and whether you have it.
- ``GET /api/v1/me`` includes ``roles``, the roles that apply to you, and with login on records
  your sign-in.
- ``GET /api/v1/users`` lists who has signed in (paged, with ``search``). Needs *Read the audit
  log and who has signed in*.
- Each role in ``GET /api/v1/roles`` has ``lastSignInAt``: when a sign-in last carried it.

A request your roles don't allow gets **403**, with the permission and the reason in the
message.
