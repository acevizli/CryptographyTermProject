# CryptographyTermProject
# A message application implementing signal protocol
usage: python client.py <argument>
arguments: 
  registerIK: use for the first time generates a long term public-private key and register it to server
  verifyIK <CODE>: sends verification code to server
  registerSPK: generates long term signed pre key and registers it to server
  resetSPK: deletes SPK registered in the server
  genHMAC: generates session key with server and stores
  gen0TK: generates 10 one time prekey for client communication and registers it to server
  reset0TK: deletes all one time prekeys in the server