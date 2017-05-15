import dbus

def get_endpoint(local_public_key, remote_public_key):
    try:
        bus = dbus.SessionBus()
        proxy = bus.get_object('org.manuel.BulletinBoard', '/')
        iface = dbus.Interface(proxy, 'org.manuel.BulletinBoard')
        value_list = iface.Get('wgp2p', b''.join([remote_public_key, local_public_key]))
    except dbus.exceptions.DBusException:
        return []

    return value_list


def get_public_keys(name):
    try:
        bus = dbus.SessionBus()
        proxy = bus.get_object('org.manuel.BulletinBoard', '/')
        iface = dbus.Interface(proxy, 'org.manuel.BulletinBoard')
        enc_value_list = iface.Get('wgp2p', name.encode('ascii'))
    except dbus.exceptions.DBusException:
        return []

    return [bytearray(v) for v in enc_value_list]


def set_public_key(name, public_key, lifetime):
    try:
        bus = dbus.SessionBus()
        proxy = bus.get_object('org.manuel.BulletinBoard', '/')
        iface = dbus.Interface(proxy, 'org.manuel.BulletinBoard')
        iface.Store('wgp2p', name.encode('ascii'), public_key, lifetime)
    except dbus.exceptions.DBusException:
        pass


def set_endpoint(local_public_key, remote_public_key, enc_value, lifetime):
    try:
        bus = dbus.SessionBus()
        proxy = bus.get_object('org.manuel.BulletinBoard', '/')
        iface = dbus.Interface(proxy, 'org.manuel.BulletinBoard')
        iface.Store('wgp2p', b''.join([local_public_key, remote_public_key]), enc_value, lifetime)
    except dbus.exceptions.DBusException:
        pass
    except ValueError:
        pass

