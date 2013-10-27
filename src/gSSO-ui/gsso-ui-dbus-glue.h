/*
 * Generated by gdbus-codegen 2.34.1. DO NOT EDIT.
 *
 * The license of this code is the same as for the source it was derived from.
 */

#ifndef __GSSO_UI_DBUS_GLUE_H__
#define __GSSO_UI_DBUS_GLUE_H__

#include <gio/gio.h>

G_BEGIN_DECLS


/* ------------------------------------------------------------------------ */
/* Declarations for com.google.code.AccountsSSO.gSingleSignOn.UI */

#define SSO_DBUS_TYPE_UI (sso_dbus_ui_get_type ())
#define SSO_DBUS_UI(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), SSO_DBUS_TYPE_UI, SSODbusUI))
#define SSO_DBUS_IS_UI(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), SSO_DBUS_TYPE_UI))
#define SSO_DBUS_UI_GET_IFACE(o) (G_TYPE_INSTANCE_GET_INTERFACE ((o), SSO_DBUS_TYPE_UI, SSODbusUIIface))

struct _SSODbusUI;
typedef struct _SSODbusUI SSODbusUI;
typedef struct _SSODbusUIIface SSODbusUIIface;

struct _SSODbusUIIface
{
  GTypeInterface parent_iface;

  gboolean (*handle_get_bus_address) (
    SSODbusUI *object,
    GDBusMethodInvocation *invocation);

};

GType sso_dbus_ui_get_type (void) G_GNUC_CONST;

GDBusInterfaceInfo *sso_dbus_ui_interface_info (void);
guint sso_dbus_ui_override_properties (GObjectClass *klass, guint property_id_begin);


/* D-Bus method call completion functions: */
void sso_dbus_ui_complete_get_bus_address (
    SSODbusUI *object,
    GDBusMethodInvocation *invocation,
    const gchar *bus_socket_address);



/* D-Bus method calls: */
void sso_dbus_ui_call_get_bus_address (
    SSODbusUI *proxy,
    GCancellable *cancellable,
    GAsyncReadyCallback callback,
    gpointer user_data);

gboolean sso_dbus_ui_call_get_bus_address_finish (
    SSODbusUI *proxy,
    gchar **out_bus_socket_address,
    GAsyncResult *res,
    GError **error);

gboolean sso_dbus_ui_call_get_bus_address_sync (
    SSODbusUI *proxy,
    gchar **out_bus_socket_address,
    GCancellable *cancellable,
    GError **error);



/* ---- */

#define SSO_DBUS_TYPE_UI_PROXY (sso_dbus_ui_proxy_get_type ())
#define SSO_DBUS_UI_PROXY(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), SSO_DBUS_TYPE_UI_PROXY, SSODbusUIProxy))
#define SSO_DBUS_UI_PROXY_CLASS(k) (G_TYPE_CHECK_CLASS_CAST ((k), SSO_DBUS_TYPE_UI_PROXY, SSODbusUIProxyClass))
#define SSO_DBUS_UI_PROXY_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), SSO_DBUS_TYPE_UI_PROXY, SSODbusUIProxyClass))
#define SSO_DBUS_IS_UI_PROXY(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), SSO_DBUS_TYPE_UI_PROXY))
#define SSO_DBUS_IS_UI_PROXY_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE ((k), SSO_DBUS_TYPE_UI_PROXY))

typedef struct _SSODbusUIProxy SSODbusUIProxy;
typedef struct _SSODbusUIProxyClass SSODbusUIProxyClass;
typedef struct _SSODbusUIProxyPrivate SSODbusUIProxyPrivate;

struct _SSODbusUIProxy
{
  /*< private >*/
  GDBusProxy parent_instance;
  SSODbusUIProxyPrivate *priv;
};

struct _SSODbusUIProxyClass
{
  GDBusProxyClass parent_class;
};

GType sso_dbus_ui_proxy_get_type (void) G_GNUC_CONST;

void sso_dbus_ui_proxy_new (
    GDBusConnection     *connection,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GAsyncReadyCallback  callback,
    gpointer             user_data);
SSODbusUI *sso_dbus_ui_proxy_new_finish (
    GAsyncResult        *res,
    GError             **error);
SSODbusUI *sso_dbus_ui_proxy_new_sync (
    GDBusConnection     *connection,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GError             **error);

void sso_dbus_ui_proxy_new_for_bus (
    GBusType             bus_type,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GAsyncReadyCallback  callback,
    gpointer             user_data);
SSODbusUI *sso_dbus_ui_proxy_new_for_bus_finish (
    GAsyncResult        *res,
    GError             **error);
SSODbusUI *sso_dbus_ui_proxy_new_for_bus_sync (
    GBusType             bus_type,
    GDBusProxyFlags      flags,
    const gchar         *name,
    const gchar         *object_path,
    GCancellable        *cancellable,
    GError             **error);


/* ---- */

#define SSO_DBUS_TYPE_UI_SKELETON (sso_dbus_ui_skeleton_get_type ())
#define SSO_DBUS_UI_SKELETON(o) (G_TYPE_CHECK_INSTANCE_CAST ((o), SSO_DBUS_TYPE_UI_SKELETON, SSODbusUISkeleton))
#define SSO_DBUS_UI_SKELETON_CLASS(k) (G_TYPE_CHECK_CLASS_CAST ((k), SSO_DBUS_TYPE_UI_SKELETON, SSODbusUISkeletonClass))
#define SSO_DBUS_UI_SKELETON_GET_CLASS(o) (G_TYPE_INSTANCE_GET_CLASS ((o), SSO_DBUS_TYPE_UI_SKELETON, SSODbusUISkeletonClass))
#define SSO_DBUS_IS_UI_SKELETON(o) (G_TYPE_CHECK_INSTANCE_TYPE ((o), SSO_DBUS_TYPE_UI_SKELETON))
#define SSO_DBUS_IS_UI_SKELETON_CLASS(k) (G_TYPE_CHECK_CLASS_TYPE ((k), SSO_DBUS_TYPE_UI_SKELETON))

typedef struct _SSODbusUISkeleton SSODbusUISkeleton;
typedef struct _SSODbusUISkeletonClass SSODbusUISkeletonClass;
typedef struct _SSODbusUISkeletonPrivate SSODbusUISkeletonPrivate;

struct _SSODbusUISkeleton
{
  /*< private >*/
  GDBusInterfaceSkeleton parent_instance;
  SSODbusUISkeletonPrivate *priv;
};

struct _SSODbusUISkeletonClass
{
  GDBusInterfaceSkeletonClass parent_class;
};

GType sso_dbus_ui_skeleton_get_type (void) G_GNUC_CONST;

SSODbusUI *sso_dbus_ui_skeleton_new (void);


G_END_DECLS

#endif /* __GSSO_UI_DBUS_GLUE_H__ */
