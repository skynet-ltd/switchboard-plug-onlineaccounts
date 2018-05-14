// -*- Mode: vala; indent-tabs-mode: nil; tab-width: 4 -*-
/*-
 * Copyright (c) 2013-2016 Pantheon Developers (https://launchpad.net/switchboard-plug-onlineaccounts)
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

public class OnlineAccounts.SourceSelector : Gtk.Grid {
    public signal void account_selected (OnlineAccounts.Account plugin);
    public signal void new_account_request ();

    private Gtk.ToolButton remove_button;
    private Gtk.ToolButton add_button;
    private Gtk.ListBox list_box;

    public SourceSelector () {
        var accounts_manager = AccountsManager.get_default ();
        foreach (var account in accounts_manager.accounts_available) {
            add_plugin_callback (account);
        }

        accounts_manager.account_added.connect (add_plugin_callback);
    }

    construct {
        orientation = Gtk.Orientation.VERTICAL;
        list_box = new Gtk.ListBox ();
        list_box.selection_mode = Gtk.SelectionMode.BROWSE;
        list_box.activate_on_single_click = true;

        var scroll = new Gtk.ScrolledWindow (null, null);
        scroll.set_size_request (150, 150);
        scroll.hscrollbar_policy = Gtk.PolicyType.NEVER;
        scroll.expand = true;
        scroll.add (list_box);

        add_button = new Gtk.ToolButton (null, null);
        add_button.tooltip_text = _("Add…");
        add_button.icon_name = "list-add-symbolic";
        add_button.clicked.connect (() => {new_account_request ();});

        remove_button = new Gtk.ToolButton (null, null);
        remove_button.tooltip_text = _("Remove");
        remove_button.icon_name = "list-remove-symbolic";
        remove_button.clicked.connect (remove_source);

        var toolbar = new Gtk.Toolbar();
        toolbar.get_style_context ().add_class (Gtk.STYLE_CLASS_INLINE_TOOLBAR);
        toolbar.icon_size = Gtk.IconSize.SMALL_TOOLBAR;
        toolbar.show_arrow = false;
        toolbar.add (add_button);
        toolbar.add (remove_button);

        add (scroll);
        add (toolbar);

        list_box.row_activated.connect ((row) => {
            account_selected (((AccountRow) row).account);
        });
    }

    private void add_plugin_callback (OnlineAccounts.Account account) {
        var ag_account = account.account_service.account;
        var provider = ag_account.manager.get_provider (ag_account.get_provider_name ());
        if (provider == null)
            return;

        var row = new AccountRow (account, provider);
        row.show_all ();
        list_box.add (row);
        if (list_box.get_children ().length () == 1) {
            list_box.select_row (row);
            list_box.row_activated (row);
        }
    }

    public OnlineAccounts.Account? get_selected_account () {
        weak Gtk.ListBoxRow selection = list_box.get_selected_row ();
        if (selection == null)
            return null;

        return ((AccountRow) selection).account;
    }

    private void remove_source () {
        weak Gtk.ListBoxRow selection = list_box.get_selected_row ();
        if (selection == null)
            return;

        var account = ((AccountRow) selection).account;
        AccountsManager.get_default ().remove_account (account);
        selection.destroy ();
        selection = list_box.get_row_at_index (0);
        if (selection != null) {
            list_box.select_row (selection);
            list_box.row_activated (selection);
        }
    }

    public class AccountRow : Gtk.ListBoxRow {
        public OnlineAccounts.Account account;
        private Gtk.Image image;
        private Gtk.Label username;
        private Gtk.Label service;
        public AccountRow (OnlineAccounts.Account account, Ag.Provider provider) {
            this.account = account;
            image.icon_name = provider.get_icon_name ();
            username.label = account.account_service.account.display_name ?? _("New Account");
            service.label = "<span font_size=\"small\">%s</span>".printf (GLib.Markup.escape_text (provider.get_display_name ()));
        }

        construct {
            var grid = new Gtk.Grid ();
            grid.margin = 6;
            grid.column_spacing = 6;
            image = new Gtk.Image ();
            image.icon_size = Gtk.IconSize.DND;
            image.use_fallback = true;
            username = new Gtk.Label (null);
            username.ellipsize = Pango.EllipsizeMode.END;
            username.halign = Gtk.Align.START;
            username.hexpand = true;
            service = new Gtk.Label (null);
            service.ellipsize = Pango.EllipsizeMode.END;
            service.halign = Gtk.Align.START;
            service.hexpand = true;
            service.use_markup = true;
            grid.attach (image, 0, 0, 1, 2);
            grid.attach (username, 1, 0, 1, 1);
            grid.attach (service, 1, 1, 1, 1);
            add (grid);
        }
    }
}
