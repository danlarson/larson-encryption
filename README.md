# larson-encryption
A wrapper of the Microsoft encryption libraries. 

# Purpose:
Makes it easy to use RSA public/private key certificate based encryption, and AES encryption using symettrical keys. This simplifies the usage so the IV and padding are used and stored correctly. 

# Usage
Ideally you will use rotating RSA based encryption to encrypt AES keys. In a multitenant scenario, you would use AES encryption keys for each tenant, and you'd use RSA certificate based encrption in order to secure those AES keys. AES has a higher throughput for mass encryption, whereas RSA is ideal for securiing encryption keys. 

## History: 
This is a fork of https://github.com/danlarson/sitrion.security which I've created and maintained as open source before adopting in my former workplace. It was renamed and ported to .NET 6 in 2022 and updated to .NET 7 in 2023. 
