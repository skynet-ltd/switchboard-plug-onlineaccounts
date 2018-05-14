// -*- Mode: vala; indent-tabs-mode: nil; tab-width: 4 -*-
/*-
 * Copyright (c) 2013-2015 Pantheon Developers (https://launchpad.net/switchboard-plug-onlineaccounts)
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Library General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Library General Public License for more details.
 *
 * You should have received a copy of the GNU Library General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Authored by: Corentin Noël <corentin@elementary.io>
 */

public class OnlineAccounts.Account : GLib.Object {
    public Ag.AccountService account_service;

    public signal void removed ();
    public signal void complete ();

    public Account (Ag.Provider provider) {
        var manager = new Ag.Manager ();
        var account = manager.create_account (provider.get_name ());
        account_service = new Ag.AccountService (account, null);
    }

    public async void delete_account () {
        var auth_data = account_service.get_auth_data ();
        var identity = new Signon.Identity.from_db (auth_data.get_credentials_id ());
        identity.remove ((Signon.IdentityRemovedCb) null);
        var account = account_service.account;
        account.delete ();
        try {
            yield account.store_async (null);
        } catch (Error e) {
            critical (e.message);
        }
    }

    /*public async void authenticate () {
        var account = account_service.account;
        var auth_data = account_service.get_auth_data ();
        var session_data = auth_data.get_login_parameters (null);
        var method = auth_data.get_method ();
        var mechanism = translate_mechanism (method, auth_data.get_mechanism ());

        var info = new Signon.IdentityInfo ();
        info.set_caption (account.get_provider_name ());
        info.set_secret ("", true);
        info.set_identity_type (Signon.IdentityType.APP);
        info.set_method (method, {mechanism, null});
        info.access_control_list_append (new Signon.SecurityContext.from_values ("%s/bin/switchboard".printf (Build.CMAKE_INSTALL_PREFIX), "*"));
        var integration_variant = account.get_variant ("integration/executable", null);
        if (integration_variant != null) {
            info.access_control_list_append (new Signon.SecurityContext.from_values (integration_variant.dup_string (), "*"));
        }

        var allowed_realms_val = session_data.lookup_value ("AllowedRealms", null);
        if (allowed_realms_val != null) {
            info.set_realms (allowed_realms_val.dup_strv ());
        }

        var identity = new Signon.Identity ();
        identity.store_credentials_with_info (info, IdentityStoreCredentialsCallback);
        identity.ref ();
    }

    [CCode (instance_pos = -1)]
    public void IdentityStoreCredentialsCallback (Signon.Identity self, uint32 id, GLib.Error error) {
        if (error != null) {
            critical (error.message);
            return;
        }

        continue_authenticate.begin (self);
    }

    private async void continue_authenticate (Signon.Identity identity) {
        var account = account_service.account;
        account.select_service (null);

        var auth_data = account_service.get_auth_data ();
        var session_data = auth_data.get_login_parameters (null);
        var method = auth_data.get_method ();
        var mechanism = auth_data.get_mechanism ();
        try {
            var session = identity.create_session (method);
            var session_result = yield session.process_async (session_data, mechanism, null);
            identity.query_info (IdentityInfoCallback);
        } catch (Error e) {
            critical (e.message);
        }
    }

    [CCode (instance_pos = -1)]
    public void IdentityInfoCallback (Signon.Identity self, Signon.IdentityInfo info, GLib.Error error) {
        if (error != null) {
            critical (error.message);
            return;
        }

        var account = account_service.account;
        account.set_variant ("CredentialsId", new GLib.Variant.uint32 (self.id));
        account.set_enabled (true);
        account.store_async.begin (null);


        AccountsManager.get_default ().add_account (this);
        self.unref ();
    }*/




    public void authenticate () {
        var account = account_service.account;
        var auth_data = account_service.get_auth_data ();
        var method = auth_data.get_method ();
        var mechanism = auth_data.get_mechanism ();

        var info = new Signon.IdentityInfo ();
        info.set_caption (account.get_provider_name ());
        info.set_identity_type (Signon.IdentityType.APP);
        info.set_secret ("", true);
        info.set_method (method, {mechanism, null});
        info.access_control_list_append (new Signon.SecurityContext.from_values ("%s/bin/switchboard".printf (Build.CMAKE_INSTALL_PREFIX), "*"));
        var integration_variant = account.get_variant ("integration/executable", null);
        if (integration_variant != null) {
            info.access_control_list_append (new Signon.SecurityContext.from_values (integration_variant.dup_string (), "*"));
        }

        var session_data = auth_data.get_login_parameters (null);

        var allowed_realms_val = session_data.lookup_value ("AllowedRealms", null);
        if (allowed_realms_val != null) {
            info.set_realms (allowed_realms_val.dup_strv ());
        }

        var identity = new Signon.Identity ();
        identity.store_credentials_with_info (info, IdentityStoreCredentialsCallback);
        identity.ref ();
    }

    public async void setup_authentification (Signon.Identity identity, uint32 id) {
        var auth_data = account_service.get_auth_data ();
        var session_data = auth_data.get_login_parameters (null);

        var method = auth_data.get_method ();
        var mechanism = auth_data.get_mechanism ();

        try {
            var session = identity.create_session (method);
            var session_result = yield session.process_async (session_data, mechanism, null);
            var access_token = session_result.lookup_value ("AccessToken", null).dup_string ();
            warning (access_token);

            identity.query_info (IdentityInfoCallback);
            identity.ref ();
        } catch (Error e) {
            critical (e.message);
        }

        yield;
    }

    [CCode (instance_pos = -1)]
    public void IdentityStoreCredentialsCallback (Signon.Identity self, uint32 id, GLib.Error error) {
        var identity = self;
        self.unref ();

        if (error != null) {
            critical (error.message);
            return;
        }

        setup_authentification.begin (identity, id);
    }

    [CCode (instance_pos = -1)]
    public void IdentityInfoCallback (Signon.Identity self, Signon.IdentityInfo info, GLib.Error error) {
        self.unref ();

        if (error != null) {
            critical (error.message);
            return;
        }

        var account = account_service.account;
        account.set_enabled (true);
        account.store_async.begin (null);

        var integration_variant = account.get_variant ("integration/executable", null);
        if (integration_variant != null) {
            var command = "%s --method=UserName --account-id=%u".printf (integration_variant.get_string (), account.id);
            warning ("%u", account.id);

            try {
                var appinfo = GLib.AppInfo.create_from_commandline (command, "Single Sign On Integration", GLib.AppInfoCreateFlags.NONE);
                appinfo.launch (null, null);
            } catch (Error e) {
                critical (e.message);
            }
        }

        AccountsManager.get_default ().add_account (this);
    }
}
