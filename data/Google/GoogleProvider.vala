/*
 * Copyright (C) 2012 Canonical, Inc
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 *
 * Authors:
 *      Alberto Mardegan <alberto.mardegan@canonical.com>
 */

public class OnlineAccounts.Plugins.Google.Provider : ProviderPlugin {

    public Provider (Ag.Account? account = null) {
        base (account);
        if (account == null) {
            authenticate.begin ();
        }
    }
    
    
    public override async void delete_account () {
        
    }
    
    public override async void authenticate () {
        
        var identity = new Signon.Identity ("switchboard");
        var session = identity.create_session ("oauth");
        var oauth_params_builder = new GLib.VariantBuilder (GLib.VariantType.VARDICT);
        oauth_params_builder.add ("{sv}", "AuthHost", new GLib.Variant.string (Config.auth_host));
        oauth_params_builder.add ("{sv}", "AuthPath", new GLib.Variant.string (Config.auth_path));
        oauth_params_builder.add ("{sv}", "TokenHost", new GLib.Variant.string (Config.auth_host));
        oauth_params_builder.add ("{sv}", "TokenPath", new GLib.Variant.string (Config.token_path));
        oauth_params_builder.add ("{sv}", "RedirectUri", new GLib.Variant.string (Config.redirect_uri));
        oauth_params_builder.add ("{sv}", "ClientId", new GLib.Variant.string (Config.client_id));
        oauth_params_builder.add ("{sv}", "ClientSecret", new GLib.Variant.string (Config.client_secret));
        oauth_params_builder.add ("{sv}", "ResponseType", new GLib.Variant.string (Config.response_type));
        oauth_params_builder.add ("{sv}", "UiPolicy", new GLib.Variant.int32 (Signon.SessionDataUiPolicy.DEFAULT));
        oauth_params_builder.add ("{sv}", "Scope", new GLib.Variant.string (string_from_string_array (Config.scopes)));
        oauth_params_builder.add ("{sv}", "AllowedSchemes", new GLib.Variant.string (string_from_string_array (Config.schemes)));
        oauth_params_builder.add ("{sv}", "ForceClientAuthViaRequestBody", new GLib.Variant.boolean (true));
        var oauth_params = oauth_params_builder.end ();
        try {
            var val = yield session.process_async (oauth_params, "oauth2", null);
            var token_type = val.lookup_value ("TokenType", null).dup_string ();
            var duration = val.lookup_value ("Duration", null).get_int64 ();
            var timestamp = val.lookup_value ("Timestamp", null).get_int64 ();
            var access_token = val.lookup_value ("AccessToken", null).dup_string ();
            string email = query_mail_address (token_type, access_token);
            
            var manager = new Ag.Manager ();
            var account = manager.create_account (plugin_name);
            account.set_display_name (email);
            VariantIter iter = oauth_params.iterator ();
            GLib.Variant? vari = null;
            string? key = null;

            while (iter.next ("{sv}", &key, &vari)) {
                account.set_variant (key, vari);
            }
            account.set_enabled (true);
            yield account.store_async (null);
            //keyring.store_password (int type, account.id, int method, access_token)
        } catch (Error e) {
            warning (e.message);
        }
        yield;
    }
    
    private void auth_ready (GLib.Error error, GLib.DBusConnection? connection, string? bus_name, string? object_path) {
        
        warning (error.message);
        
    }
    
    private string query_mail_address (string token_type, string token) {
        var session = new Soup.SessionSync ();
        var msg = new Soup.Message ("GET", "https://www.googleapis.com/oauth2/v1/userinfo?access_token=" + token);
        msg.request_headers.append ("Authorization", token_type + " " + token);
        session.send_message (msg);
        try {
            var parser = new Json.Parser ();
            parser.load_from_data ((string) msg.response_body.flatten ().data, -1);

            var root_object = parser.get_root ().get_object ();
            string mail = root_object.get_string_member ("email");
            return mail;
        } catch (Error e) {
            critical (e.message);
        }
        return "";
    }
}
