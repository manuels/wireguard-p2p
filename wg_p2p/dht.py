import dbus

def get_endpoint(private_key, public_key):
    bus = dbus.SessionBus()
    proxy = bus.get_object('org.manuel.BulletinBoard', '/')
    iface = dbus.Interface(proxy, 'org.manuel.BulletinBoard')
    value_list = iface.Get('wgp2p', b''.join([private_key, public_key]))

    return value_list


def get_public_keys(name):
    bus = dbus.SessionBus()
    proxy = bus.get_object('org.manuel.BulletinBoard', '/')
    iface = dbus.Interface(proxy, 'org.manuel.BulletinBoard')
    enc_value_list = iface.Get('wgp2p', name.encode('ascii'))

    return [bytearray(v) for v in enc_value_list]


def set_public_key(name, public_key, lifetime):
    bus = dbus.SessionBus()
    proxy = bus.get_object('org.manuel.BulletinBoard', '/')
    iface = dbus.Interface(proxy, 'org.manuel.BulletinBoard')
    iface.Store('wgp2p', name.encode('ascii'), public_key, lifetime)


def set_endpoint(private_key, public_key, enc_value, lifetime):
    bus = dbus.SessionBus()
    proxy = bus.get_object('org.manuel.BulletinBoard', '/')
    iface = dbus.Interface(proxy, 'org.manuel.BulletinBoard')
    iface.Store('wgp2p', b''.join([private_key, public_key]), enc_value, lifetime)

