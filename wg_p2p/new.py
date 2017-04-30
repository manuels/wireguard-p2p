import io
import random
import subprocess
import configparser

def new(args):
    proc = subprocess.run(['/usr/bin/wg', 'genkey'],
                          stdout=subprocess.PIPE,
                          check=True)

    private_key = proc.stdout.decode('ascii').strip()

    config = configparser.ConfigParser(strict=False)
    config.optionxform = str

    config['Interface'] = {
        'ListenPort': 50000 + random.randint(0, 10000),
        'PrivateKey': private_key,
        'Address': '10.0.0.{}/24'.format(random.randint(0, 255)),
    }

    out = io.StringIO()
    config.write(out)
    print(out.getvalue())

