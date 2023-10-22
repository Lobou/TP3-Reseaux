"""\
GLO-2000 Travail pratique 3
Noms et numéros étudiants:
- Loïc Boutet: 536981506
- Raphaël Chheang : 536993135
- Laurie Valcourt-Lachance : 111265649
"""

import argparse
import socket
import sys
from typing import NoReturn

import glosocket
import glocrypto


def _parse_args(argv: list[str]) -> tuple[str, int]:
    """
    Utilise `argparse` pour récupérer les arguments contenus dans argv.

    Retourne un tuple contenant:
    - l'adresse IP du serveur (vide en mode serveur).
    - le port.
    """
    parser = argparse.ArgumentParser()
    parser.add_argument("-g", "--destination-port", dest="port", action="store", required=True)

    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("-s", "--server", dest="server", action="store_true")
    group.add_argument("-d", "--destination", dest="address", action="store")

    arguments = parser.parse_args(sys.argv[1:])

    return arguments.address, int(arguments.port)


def _generate_modulus_base(destination: socket.socket) -> tuple[int, int]:
    """
    Cette fonction génère le modulo et la base à l'aide du module `glocrypto`.

    Elle les transmet respectivement dans deux
    messages distincts à la destination.

    Retourne un tuple contenant respectivement:
    - le modulo,
    - la base.
    """
    a = glocrypto.find_prime()
    b = glocrypto.random_integer(a)

    try:
        glosocket.send_mesg(destination, str(a))
        glosocket.send_mesg(destination, str(b))
    except glosocket.GLOSocketError:
        destination.close()
        sys.exit(199)

    return a, b


def _receive_modulus_base(source: socket.socket) -> tuple[int, int]:
    """
    Cette fonction reçoit le modulo et la base depuis le socket source.

    Retourne un tuple contenant respectivement:
    - le modulo,
    - la base.
    """
    try:
        modulo = glosocket.recv_mesg(source)
        base = glosocket.recv_mesg(source)
    except glosocket.GLOSocketError:
        sys.exit(200)

    return int(modulo), int(base)


def _compute_two_keys(modulus: int, base: int) -> tuple[int, int]:
    """
    Génère une clé privée et en déduit une clé publique.

    Retourne un tuple contenant respectivement:
    - la clé privée,
    - la clé publique.
    """
    private = glocrypto.random_integer(modulus)
    public = glocrypto.modular_exponentiation(base, private, modulus)

    return private, public


def _exchange_publickeys(own_pubkey: int, peer: socket.socket) -> int:
    """
    Envoie sa propre clé publique, récupère la
    clé publique de l'autre et la retourne.
    """
    try:
        glosocket.send_mesg(peer, str(own_pubkey))
        other_pubkey = glosocket.recv_mesg(peer)
    except glosocket.GLOSocketError:
        sys.exit(201)

    return int(other_pubkey)


def _compute_shared_key(private_key: int,
                        public_key: int,
                        modulus: int) -> int:
    """Calcule et retourne la clé partagée."""
    shared_key = glocrypto.modular_exponentiation(
        public_key, private_key, modulus)

    return shared_key


def _server(port: int) -> NoReturn:
    """
    Boucle principale du serveur.

    Prépare son socket, puis gère les clients à l'infini.
    """
    soc_serv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    soc_serv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    soc_serv.bind(("127.0.0.1", port))
    soc_serv.listen()

    while True:

        (soc_client, addr_client) = soc_serv.accept()

        (a, b) = _generate_modulus_base(soc_client)

        own_private, own_public = _compute_two_keys(a, b)

        other_pubkey = _exchange_publickeys(own_public, soc_client)

        shared_key = _compute_shared_key(own_private, other_pubkey, a)
        print("shared key: " + str(shared_key))

        soc_client.close()


def _client(destination: str, port: int) -> None:
    """
    Point d'entrée du client.

    Crée et connecte son socket, puis procède aux échanges.
    """
    soc_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    soc_client.connect((destination, port))

    (a, b) = _receive_modulus_base(soc_client)

    (own_private, own_public) = _compute_two_keys(a, b)

    other_pubkey = _exchange_publickeys(own_public, soc_client)

    shared_key = _compute_shared_key(own_private, other_pubkey, a)
    print("shared key: " + str(shared_key))

    soc_client.close()

# NE PAS ÉDITER PASSÉ CE POINT
# NE PAS ÉDITER PASSÉ CE POINT
# NE PAS ÉDITER PASSÉ CE POINT
# NE PAS ÉDITER PASSÉ CE POINT

def _main() -> int:
    destination, port = _parse_args(sys.argv[1:])
    if destination:
        _client(destination, port)
    else:
        _server(port)
    return 0


if __name__ == '__main__':
    sys.exit(_main())
