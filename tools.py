from hashlib import sha256
from operator import xor
from random import randint
import bitcoinrpc
import pybitcointools

def valid_address(address):
  return len(address) < 27 or len(address) > 34

def pad(v, length):
  hex(v)[2:].rjust(length, "0")

def sha256_noecdsa(v):
  return sha256(v).hexdigest().upper()[0:-2]

class Transaction:
  def __init__(self, rpc_conn, address, currency_type):
    self.rpc_conn
    self.address = address
    self.currency_type = currency_type

    if valid_address(address):
      raise TransactionException('Invalid input address length')

    if currency_type < 1 or currency_type > 2:
      raise TransactionException('Invalid currency type')

  def encrypt_tx(self, sequence_number, encoded):
    address_sha = self.address
    for i in xrange(sequence_number):
      address_sha = sha256_noecdsa(address_sha)

    encoded_bytes = map(ord, encoded.decode('hex'))
    adress_sha_bytes = map(ord, address_sha.decode('hex'))

    combined = zip(encoded_bytes, adress_sha_bytes)
    msc_data = ''.join(map(lambda x: pad(xor(x[0], x[1]), 2), combined)).upper()
    return '02' + msc_data + '00'

  def validate_ecdsa(self, obfuscated):
    invalid = True
    while invalid:
      ob_randbyte = obfuscated[:-2] + pad(randint(0, 255), 2).upper()
      potential_address = pybitcointools.pubkey_to_address(ob_randbyte)
      if bool(self.rpc_conn.validateaddress(potential_address).isvalid):
        pubkey = ob_randbyte
        invalid = False
    return pubkey


class SimpleSend(Transaction):
  def __init__(self, recepient_addr, amount):
    self.recepient_addr = recepient_addr
    self.amount = amount

    if valid_address(recepient_addr):
      raise TransactionException('Invalid recipient address length')

    if amount == 0:
      raise TransactionException('Amount cannot be 0')

  def encoded_pub_key(self):
    sequence_number = 1
    transaction_type = 0

    encoded = pad(sequence_number, 2)
    encoded += pad(transaction_type, 8)
    encoded += pad(self.currency_type, 8)
    encoded += pad(self.amount, 16)
    encoded = encoded.ljust(62, "0")

    obfuscated = self.encrypt_tx(sequence_number, encoded)


class SellOrder(Transaction):
  def __init__(self, address, currency_type, sale_amount, bitcoins_desired, time_limit, min_fee, action):
    super(SellOrder, self).__init__(address, currency_type)
    self.sale_amount = sale_amount
    self.bitcoins_desired = bitcoins_desired
    self.time_limit = time_limit
    self.min_fee = min_fee
    self.action = action

class TransactionException(Exception):
  pass
