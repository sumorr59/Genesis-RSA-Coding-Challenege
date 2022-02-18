import rsa
from sslib import shamir

def create_keys(n, k):
    '''
    Creates the keys using the n and k parameters which specify shard buckets and number of shards per bucket.

    Args:
        n: Number of shards to reconstruct the private key.
        k: Number of shards to split into.

    Returns:
        None
    '''
    (public_key, private_key) = rsa.newkeys(2048)
    with open('keys/Public.txt', 'wb') as f:
        f.write(public_key.save_pkcs1('PEM'))

    create_shards(private_key,n,k)

def create_shards(key, n, k):
    '''
    Splits the private keys into a number of shards and stores them

    Args:
        key: The private key to split.
        n: Number of shards to reconstruct the private key.
        k: Number of shards to split into.

    Returns:
        The n,k values and stores the split shards.
    '''
    shards = shamir.to_base64(shamir.split_secret(str(key).encode('ascii'), n, k)).get("shares")
    prime_mod = shamir.to_base64(shamir.split_secret(str(key).encode('ascii'), n, k)).get("prime_mod")

    with open('keys/prime_mod.txt', 'w') as f:
        f.write(str(prime_mod))

    for x in range(k):
        with open('keys/Shard[' + str(x) + '].txt', 'w') as f:
            f.write(str(shards[x]))

    return n, k

def retreive_keys(n,k):
    '''
    Load the keys from file.

    Args:
        n: Number of shards to reconstruct the private key.
        k: Number of shards to split into.

    Returns:
        public_key: The public key.
        private_key: The private key
    '''
    with open ('keys/Public.txt', 'rb') as f:
        public_key = rsa.PublicKey.load_pkcs1(f.read())

    with open ('keys/prime_mod.txt', 'r') as f:
        prime_mod = f.read()

    shard_map = {}
    shard_map['required_shares'] = len(n)
    shard_map['prime_mod'] = prime_mod
    shards = []

    for shard in n:
        with open ('keys/Shard[' + str(shard-1) +'].txt', 'r') as f:
            shards.append(str(f.read()))
    
    shard_map['shares'] = shards

    private_key = shamir.recover_secret(shamir.from_base64(shard_map)).decode('ascii')\
        .replace("PrivateKey(","").replace(")","").split(",")
    private_key = rsa.PrivateKey(int(private_key[0]),
                                 int(private_key[1]),
                                 int(private_key[2]),
                                 int(private_key[3]),
                                 int(private_key[4]))
    return public_key, private_key

# Main function for running the CLI
if __name__ == '__main__':
    print("This is the sharding CLI")
    message = input('Please enter a message: ')
    n = 10
    k = 1
    while(n > k):
        k = input("Please enter the number of shards the private key should be split into: ")
        n = input("Please enter the number of shards needed to reconstruct the private key: ")

    shardList = []
    while (len(shardList) < int(n)):
        shardList = input("Please enter a list of which shards should be used to reconstruct the private key (Example: 2,5): ").split(",")

    print([int(numeric_string) for numeric_string in shardList])

    create_keys(int(n),int(k))
    pubKey, privKey = retreive_keys([int(numeric_string) for numeric_string in shardList], int(k))

    ciphertext = rsa.encrypt(message.encode('ascii'), pubKey)

    try:
        plaintext = rsa.decrypt(ciphertext, privKey).decode('ascii')
    except:
        pass

    if plaintext:
        print(f'Plain text: {plaintext}')
    else:
        print("Message failed to decrypt")