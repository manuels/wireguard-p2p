import dbus

def get_endpoint(local_public_key: bytes, remote_public_key: bytes):
    try:
        bus = dbus.SessionBus()

        proxy = bus.get_object('org.manuel.BulletinBoard', '/')
        iface = dbus.Interface(proxy, 'org.manuel.BulletinBoard')
        value_list = iface.Get('wgp2p', b''.join([remote_public_key, local_public_key]), timeout=60000)
    except dbus.exceptions.DBusException:
        return []

    return value_list


def get_public_keys(name: bytes):
    try:
        bus = dbus.SessionBus()
        proxy = bus.get_object('org.manuel.BulletinBoard', '/')
        iface = dbus.Interface(proxy, 'org.manuel.BulletinBoard')
        enc_value_list = iface.Get('wgp2p', name, timeout=60000)
    except dbus.exceptions.DBusException:
        return []

    return [bytearray(v) for v in enc_value_list]


def set_public_key(name: bytes, public_key: bytes, lifetime: int):
    try:
        bus = dbus.SessionBus()
        proxy = bus.get_object('org.manuel.BulletinBoard', '/')
        iface = dbus.Interface(proxy, 'org.manuel.BulletinBoard')
        iface.Store('wgp2p', name, public_key, lifetime)
    except dbus.exceptions.DBusException:
        pass


def set_endpoint(local_public_key: bytes, remote_public_key: bytes, enc_value: bytes, lifetime: int):
    try:
        bus = dbus.SessionBus()
        proxy = bus.get_object('org.manuel.BulletinBoard', '/')
        iface = dbus.Interface(proxy, 'org.manuel.BulletinBoard')
        iface.Store('wgp2p', b''.join([local_public_key, remote_public_key]), enc_value, lifetime)
    except dbus.exceptions.DBusException:
        pass
    except ValueError:
        pass

