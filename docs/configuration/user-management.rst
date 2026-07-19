Managing Users (Keycloak)
=========================

Application logins are managed in the bundled **Keycloak** identity provider,
not in TracePcap itself. This page covers creating and managing users in the
``tracepcap`` realm. It assumes authentication is already enabled — see
:doc:`authentication` for how to turn it on.

.. note::
   Users only exist when authentication is enabled (the
   ``docker-compose.prod.yml`` overlay). The base stack runs with no login, so
   there are no users to manage.

Prerequisites
-------------

The stack must be running with the production overlay:

.. code-block:: bash

   PUBLIC_URL=http://localhost:8888 \
     docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --build

You also need the **Keycloak admin** credentials (default ``user`` /
``P@ssw0rd`` — override with ``KEYCLOAK_ADMIN`` / ``KEYCLOAK_ADMIN_PASSWORD``).

Create a user via the admin console
-----------------------------------

This is the normal way to add a user after deployment. Changes take effect
immediately — no rebuild or restart.

1. Open the Keycloak admin console at ``<PUBLIC_URL>/admin`` (e.g.
   ``http://localhost:8888/admin``) and sign in with the Keycloak admin
   credentials.
2. In the top-left **realm selector**, switch from ``master`` to **tracepcap**.

   .. warning::
      Always create app users in the **tracepcap** realm. Users created in the
      ``master`` realm are Keycloak administrators and **cannot** log in to
      TracePcap.

3. Go to **Users** → **Add user**.
4. Fill in **Username** (required). Optionally set **Email**, **First name**,
   and **Last name**. Leave **Email verified** on if you don't run email flows.
5. Click **Create**.
6. Open the new user's **Credentials** tab → **Set password**.
7. Enter and confirm a password. Turn **Temporary** **off** unless you want to
   force a password change at first login (email-based reset flows are not
   configured offline, so a temporary password must be changed by the user at
   the login screen).
8. Click **Save**.

The user can now log in at ``<PUBLIC_URL>`` with that username and password.

Reset a password
-----------------

**Users** → select the user → **Credentials** → **Reset password**. Set a new
password (again, leave **Temporary** off) and save.

Disable or delete a user
------------------------

- **Disable** (revoke access, keep the account): **Users** → select the user →
  **Details** → toggle **Enabled** off → **Save**.
- **Delete** (remove entirely): **Users** → select the user → **Action** menu
  (top right) → **Delete**.

Seeding users in the realm export (optional)
--------------------------------------------

To ship a deployment with users **pre-created** on first boot, add them to
``keycloak/realm-export.json``. The realm is imported automatically on startup
(``start-dev --import-realm``). This is how the default ``analyst`` demo user is
provided.

Add an entry to the ``users`` array of that file:

.. code-block:: json

   {
     "username": "analyst2",
     "enabled": true,
     "emailVerified": true,
     "firstName": "Second",
     "lastName": "Analyst",
     "email": "analyst2@example.com",
     "credentials": [
       {
         "type": "password",
         "value": "change-me",
         "temporary": false
       }
     ]
   }

.. warning::
   The realm export stores the password in **plaintext** and is committed to the
   repo. Use it only for demo/default accounts and always change these
   credentials for any real deployment. Prefer the admin console for real users.

Import only runs against a **fresh** realm. Keycloak's data lives in its
container, so re-import requires recreating it:

.. code-block:: bash

   docker compose -f docker-compose.yml -f docker-compose.prod.yml \
     up -d --build --force-recreate keycloak

.. note::
   ``--force-recreate`` on the bundled ``start-dev`` Keycloak resets its
   in-container state, so any users you created through the admin console will
   be lost and the realm re-seeded from the export. Back up first if needed —
   see :doc:`../operations/backup-restore`.

Notes
-----

- TracePcap does not use Keycloak **roles** for access control today; any
  authenticated realm user has full app access. The ``realm-export.json`` roles
  list is intentionally empty.
- Self-service registration and email-based password recovery are off by design
  for offline/air-gapped use. User creation and password resets go through the
  admin console.
